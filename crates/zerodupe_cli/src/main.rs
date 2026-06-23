use std::collections::HashSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

mod i18n;

use zerodupe_core::CancelFlag;
use zerodupe_workflow::{Workflow, WorkflowAction};

use camino::Utf8PathBuf;
use clap::{Parser, Subcommand};
use uuid::Uuid;
use zerodupe_core::{ByteCompareReport, DiscoveryOptions, HashingOptions, PartialStrategy};
use zerodupe_fs::discover_roots;
use zerodupe_report::{ScanSummary, to_pretty_json};
use zerodupe_safety::Quarantine;
use zerodupe_scan::{
    build_candidate_groups, byte_compare_groups, full_hash_groups, partial_hash_groups,
};

/// Default directories to exclude when scanning without `--no-default-excludes`.
const DEFAULT_EXCLUDES: &[&str] = &[
    "target",
    "node_modules",
    ".git",
    "research/repos",
    "zerodupe_quarantine",
];

static CANCEL_FLAG: OnceLock<CancelFlag> = OnceLock::new();

fn setup_ctrlc_handler(flag: &CancelFlag) {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    let flag = flag.clone();
    let _ = ctrlc::set_handler(move || {
        static DOUBLE_PRESS: AtomicBool = AtomicBool::new(false);
        static LAST_PRESS: AtomicU64 = AtomicU64::new(0);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last = LAST_PRESS.load(Ordering::SeqCst);

        if DOUBLE_PRESS.load(Ordering::SeqCst) && now.saturating_sub(last) < 2 {
            let lang = i18n::cached_lang();
            eprintln!("\n{}", i18n::t(lang, "hard_abort"));
            std::process::exit(130);
        }

        DOUBLE_PRESS.store(true, Ordering::SeqCst);
        LAST_PRESS.store(now, Ordering::SeqCst);
        flag.cancel();
        let lang = i18n::cached_lang();
        eprintln!("\n{}", i18n::t(lang, "scan_interrupted"));
    });
}

fn is_interrupted() -> bool {
    CANCEL_FLAG.get().map(|f| f.is_cancelled()).unwrap_or(false)
}

fn format_reclaimable_size(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{} B", bytes)
    }
}

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "ZeroDupe — Find & clean duplicate files",
    subcommand_required = false
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Prints a minimal JSON smoke-test summary.
    Smoke,
    /// Discovers filesystem entries under one or more roots.
    Scan {
        /// Include hidden files and directories.
        #[arg(long)]
        include_hidden: bool,
        /// Do not respect .gitignore/.ignore files.
        #[arg(long)]
        no_ignore: bool,
        /// Follow symbolic links. Disabled by default.
        #[arg(long)]
        follow_symlinks: bool,
        /// Do not include symlink entries in the inventory.
        #[arg(long)]
        no_symlink_entries: bool,
        /// Skip the built-in default excludes.
        #[arg(long)]
        no_default_excludes: bool,
        /// Additional path prefixes to exclude. Can be repeated.
        #[arg(long = "exclude", short = 'x')]
        exclude: Vec<String>,
        /// Output the full discovery report instead of just the summary.
        #[arg(long)]
        full_report: bool,
        /// Run size-grouping + hardlink detection and output PhysicalFileReport + CandidateReport.
        #[arg(long)]
        candidates: bool,
        /// Run partial BLAKE3 hashing on candidate groups and output PartialHashReport. Implies --candidates.
        #[arg(long)]
        partial_hash: bool,
        /// Run full BLAKE3 hashing on partial-hash groups and output FullHashReport.
        /// Implies --partial-hash.
        #[arg(long)]
        full_hash: bool,
        /// Run byte-by-byte verification on full-hash groups. Implies --full-hash.
        #[arg(long)]
        byte_compare: bool,
        /// Partial hashing strategy: head-only or head-tail (default).
        #[arg(long, default_value = "head-tail")]
        partial_strategy: String,
        /// Chunk size in bytes for partial hashing (default: 4096).
        #[arg(long, default_value = "4096")]
        partial_chunk_size: usize,
        /// Verify file hasn't changed after reading (TOCTTOU check). Off by default.
        #[arg(long)]
        verify_after_read: bool,
        /// Enable persistent hash cache on disk.
        #[arg(long)]
        cache: bool,
        /// Roots to scan.
        roots: Vec<PathBuf>,
    },
    /// Manage the quarantine: list, add, restore, restore-all, restore-exact, restore-similar.
    Quarantine {
        /// Quarantine directory path (default: ./zerodupe_quarantine).
        #[arg(long, default_value = "zerodupe_quarantine")]
        quarantine_dir: PathBuf,
        #[command(subcommand)]
        action: QuarantineAction,
    },
    /// Interactive duplicate detection with step-by-step progress.
    /// Choose which files to quarantine after analysis.
    Interactive {
        /// Quarantine directory path (default: ./zerodupe_quarantine).
        #[arg(long, default_value = "zerodupe_quarantine")]
        quarantine_dir: PathBuf,
        /// Auto-quarantine all non-keeper files without prompting.
        #[arg(long)]
        auto_quarantine: bool,
        /// Reference directory: only report duplicates outside this directory.
        /// Files inside the reference dir are always keepers.
        #[arg(long)]
        reference_dir: Option<PathBuf>,
        /// Only report duplicates between different root directories.
        /// Files duplicated within the same root are ignored.
        #[arg(long)]
        isolate: bool,
        /// Roots to scan.
        roots: Vec<PathBuf>,
        /// Write a JSON report to the specified file.
        #[arg(long)]
        json: Option<PathBuf>,
    },
    /// Detect near-duplicate (similar but not identical) files using perceptual hashing.
    /// Currently supports: images (phash).
    Similar {
        /// Roots to scan.
        roots: Vec<PathBuf>,
        /// Quarantine directory path (default: ./zerodupe_quarantine/similar_images).
        #[arg(long, default_value = "zerodupe_quarantine/similar_images")]
        quarantine_dir: PathBuf,
        /// Interactive mode: choose which files to quarantine after analysis.
        #[arg(long)]
        interactive: bool,
        /// Auto-quarantine all non-keeper images based on scoring criteria.
        #[arg(long)]
        auto_quarantine: bool,
        /// Path to a TOML file with custom keeper scoring weights.
        #[arg(long)]
        keeper_weights: Option<PathBuf>,
        /// Reference directory: only report duplicates outside this directory.
        /// Files inside the reference dir are always keepers.
        #[arg(long)]
        reference_dir: Option<PathBuf>,
        /// Only report duplicates between different root directories.
        /// Files duplicated within the same root are ignored.
        #[arg(long)]
        isolate: bool,
        /// Geometric invariance: off (exact orientation only), mirror
        /// (default: also detects mirrored copies), full (also detects 90°
        /// rotations; slower fingerprinting).
        #[arg(long, default_value = "mirror")]
        invariance: String,
        /// Write a JSON report to the specified file.
        #[arg(long)]
        json: Option<PathBuf>,
    },
    /// Detect and clean junk files (empty files/dirs, temp files, caches, OS metadata, etc.)
    Hygiene {
        /// Roots to scan.
        roots: Vec<PathBuf>,
        /// Dry run: show what WOULD be cleaned without touching anything.
        #[arg(long)]
        dry_run: bool,
        /// Auto-clean low-risk items (move to OS trash).
        #[arg(long)]
        auto_clean: bool,
        /// Quarantine medium-risk items instead of just reporting them.
        #[arg(long)]
        quarantine: bool,
    },
}

#[derive(Debug, Subcommand)]
enum QuarantineAction {
    /// List all quarantined files (not yet restored).
    List,
    /// Add a file to quarantine.
    Add {
        /// Path of the file to quarantine.
        path: PathBuf,
    },
    /// Restore a single quarantined file by its ID.
    Restore {
        /// The journal entry ID to restore.
        id: u64,
    },
    /// Restore all quarantined files.
    RestoreAll,
    /// Restore only exact duplicate entries (reason LIKE 'exact%').
    RestoreExact,
    /// Restore only similar image entries (reason LIKE 'similar%').
    RestoreSimilar,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = i18n::cached_lang();
    let cli = Cli::parse();

    match cli.command {
        None => run_wizard()?,
        Some(Command::Smoke) => {
            let summary = ScanSummary {
                exact_duplicate_groups: 0,
                reclaimable_bytes: 0,
            };
            println!("{}", to_pretty_json(&summary)?);
        }
        Some(Command::Scan {
            include_hidden,
            no_ignore,
            follow_symlinks,
            no_symlink_entries,
            no_default_excludes,
            exclude,
            full_report,
            candidates,
            partial_hash,
            full_hash,
            byte_compare,
            partial_strategy,
            partial_chunk_size,
            verify_after_read,
            cache: use_cache,
            roots,
        }) => {
            let roots = roots
                .into_iter()
                .map(|path| {
                    Utf8PathBuf::from_path_buf(path)
                        .map_err(|path| format!("path is not valid UTF-8: {}", path.display()))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let mut exclude_prefixes = exclude;
            if !no_default_excludes {
                for default in DEFAULT_EXCLUDES {
                    if !exclude_prefixes.contains(&default.to_string()) {
                        exclude_prefixes.push(default.to_string());
                    }
                }
            }
            {
                let profile = zerodupe_platform::current();
                for path in profile.protected_paths() {
                    exclude_prefixes.push(path.clone());
                }
            }

            let options = DiscoveryOptions {
                include_hidden,
                respect_gitignore: !no_ignore,
                follow_symlinks,
                include_symlink_entries: !no_symlink_entries,
                exclude_prefixes,
            };

            let report = discover_roots(roots, &options, None, None);

            if byte_compare || full_hash || partial_hash || candidates {
                let (phys, cand) = build_candidate_groups(&report.entries, None, None);

                let disk_cache = if use_cache {
                    zerodupe_cache::HashCache::open(&zerodupe_cache::default_cache_path()).ok()
                } else {
                    None
                };
                let cache_ref = disk_cache.as_ref();

                if byte_compare || full_hash || partial_hash {
                    let strategy = parse_partial_strategy(&partial_strategy);
                    let hashing_opts = HashingOptions {
                        partial_chunk_size,
                        partial_strategy: strategy,
                        verify_after_read,
                        ..Default::default()
                    };
                    let partial_report = partial_hash_groups(
                        &phys.physical_files,
                        &cand,
                        &hashing_opts,
                        cache_ref,
                        None,
                        None,
                    );

                    if byte_compare || full_hash {
                        let full_report = full_hash_groups(
                            &phys.physical_files,
                            &partial_report,
                            &hashing_opts,
                            cache_ref,
                            None,
                            None,
                        );

                        if byte_compare {
                            // --byte-compare is an explicit request: always compare.
                            let compare_report = byte_compare_groups(
                                &full_report,
                                &report.entries,
                                &phys.physical_files,
                                zerodupe_core::VerifyMode::Always,
                                None,
                                None,
                            );
                            println!("{}", serde_json::to_string_pretty(&compare_report)?);
                        } else {
                            println!("{}", serde_json::to_string_pretty(&full_report)?);
                        }
                    } else {
                        println!("{}", serde_json::to_string_pretty(&partial_report)?);
                    }
                } else {
                    let combined = serde_json::json!({
                        "physical_files": phys,
                        "candidates": cand,
                    });
                    println!("{}", serde_json::to_string_pretty(&combined)?);
                }
            } else if full_report {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&report.summary)?);
            }
        }
        Some(Command::Quarantine {
            quarantine_dir,
            action,
        }) => {
            let q =
                Quarantine::open(&quarantine_dir).map_err(|e| format!("quarantine open: {e}"))?;

            match action {
                QuarantineAction::List => {
                    let entries = q
                        .list_quarantined(false)
                        .map_err(|e| format!("list: {e}"))?;
                    println!("{}", serde_json::to_string_pretty(&entries)?);
                }
                QuarantineAction::Add { path } => {
                    let session_id = Uuid::new_v4().to_string();
                    let entry = q
                        .quarantine_file(&path, "user-requested", &session_id, Some(30))
                        .map_err(|e| format!("quarantine {path:?}: {e}"))?;
                    println!("{}", serde_json::to_string_pretty(&entry)?);
                }
                QuarantineAction::Restore { id } => {
                    q.restore_file(id)
                        .map_err(|e| format!("restore {id}: {e}"))?;
                    println!("{{ \"restored\": {id} }}");
                }
                QuarantineAction::RestoreAll => {
                    let report = q.restore_all();
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                QuarantineAction::RestoreExact => {
                    let report = q.restore_by_reason("exact%");
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                QuarantineAction::RestoreSimilar => {
                    let report = q.restore_by_reason("similar%");
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
            }
        }
        Some(Command::Interactive {
            quarantine_dir,
            auto_quarantine,
            reference_dir,
            isolate,
            roots,
            json,
        }) => {
            run_interactive(
                &roots,
                &quarantine_dir,
                auto_quarantine,
                reference_dir.as_deref(),
                isolate,
                json.as_deref(),
            )?;
        }
        Some(Command::Similar {
            roots,
            quarantine_dir,
            interactive: _interactive,
            auto_quarantine: _auto_quarantine,
            keeper_weights,
            reference_dir,
            isolate,
            invariance,
            json,
        }) => {
            let invariance = parse_invariance(&invariance)?;
            run_similar(&SimilarOptions {
                roots,
                quarantine_dir,
                keeper_weights_path: keeper_weights,
                reference_dir,
                isolate,
                invariance,
                json_path: json,
            })?;
        }
        Some(Command::Hygiene {
            roots,
            dry_run,
            auto_clean,
            quarantine,
        }) => {
            run_hygiene(&roots, dry_run, auto_clean, quarantine)?;
        }
    }

    Ok(())
}

// ── Interactive mode ──

fn run_interactive(
    roots: &[PathBuf],
    quarantine_dir: &Path,
    auto_quarantine: bool,
    reference_dir: Option<&Path>,
    isolate: bool,
    json_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let utf8_roots: Vec<Utf8PathBuf> = roots
        .iter()
        .map(|p| {
            Utf8PathBuf::from_path_buf(p.clone())
                .map_err(|p| format!("path is not valid UTF-8: {}", p.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if let Some(resume) = zerodupe_config::resume::load_resume_state() {
        let root_match = roots.iter().any(|r| {
            let r_str = r.to_string_lossy().to_string();
            r_str == resume.scan_root || resume.scan_root.starts_with(&r_str)
        });
        if root_match {
            let lang = i18n::cached_lang();
            eprintln!("{}", i18n::t(lang, "scan_interrupted"));
            eprint!("{}", i18n::t(lang, "prompt_mark"));
            let mut ans = String::new();
            std::io::stdin().read_line(&mut ans)?;
            if ans.trim().to_lowercase().starts_with('n') {
                zerodupe_config::resume::clear_resume_state();
            }
        }
    }

    let cancel = CancelFlag::new();
    let _ = CANCEL_FLAG.set(cancel.clone());
    setup_ctrlc_handler(&cancel);

    let lang = i18n::cached_lang();

    // Step 1: Discovery
    eprint!("\r[1/5] {}", i18n::t(lang, "discovering_files"));
    let mut options = DiscoveryOptions::default();
    let profile = zerodupe_platform::current();
    for path in profile.protected_paths() {
        options.exclude_prefixes.push(path.clone());
    }
    // Nunca re-escanear la cuarentena de una limpieza anterior.
    options
        .exclude_prefixes
        .push("zerodupe_quarantine".to_string());
    let report = discover_roots(utf8_roots, &options, None, None);
    eprintln!(
        "\r[1/5] {}       {} entries ({} files, {} dirs)",
        i18n::t(lang, "discovering_files"),
        report.summary.entries,
        report.summary.files,
        report.summary.directories
    );
    if is_interrupted() {
        return Err(i18n::t(lang, "interrupted_by_user").into());
    }

    // Step 2: Size grouping
    eprint!("\r[2/5] {}", i18n::t(lang, "grouping_by_size"));
    let (phys, cand) = build_candidate_groups(&report.entries, None, Some(&cancel));
    eprintln!(
        "\r[2/5] {}         {} candidate groups, {} files",
        i18n::t(lang, "grouping_by_size"),
        cand.size_groups.len(),
        cand.total_candidates()
    );
    if is_interrupted() {
        return Err(i18n::t(lang, "interrupted_by_user").into());
    }

    // Step 3: Partial hash
    eprint!("\r[3/5] {}", i18n::t(lang, "partial_hashing"));
    let hashing = HashingOptions::default();
    // Persistent hash cache: re-scans only hash files that changed.
    let disk_cache = zerodupe_cache::HashCache::open(&zerodupe_cache::default_cache_path()).ok();
    let partial = partial_hash_groups(
        &phys.physical_files,
        &cand,
        &hashing,
        disk_cache.as_ref(),
        None,
        Some(&cancel),
    );
    eprintln!(
        "\r[3/5] {} {} groups → {} files promoted",
        i18n::t(lang, "partial_hashing"),
        partial.groups.len(),
        partial.promoted_to_full
    );
    if is_interrupted() {
        return Err(i18n::t(lang, "interrupted_by_user").into());
    }

    eprint!("\r[4/5] {}", i18n::t(lang, "full_hashing"));
    let full = full_hash_groups(
        &phys.physical_files,
        &partial,
        &hashing,
        disk_cache.as_ref(),
        None,
        Some(&cancel),
    );
    eprintln!(
        "\r[4/5] {}       {} groups, {} duplicates",
        i18n::t(lang, "full_hashing"),
        full.groups.len(),
        full.confirmed_duplicates
    );
    if is_interrupted() {
        return Err(i18n::t(lang, "interrupted_by_user").into());
    }

    eprint!("\r[5/5] {}", i18n::t(lang, "byte_verify"));
    let mut compare = byte_compare_groups(
        &full,
        &report.entries,
        &phys.physical_files,
        zerodupe_core::VerifyMode::default(),
        None,
        Some(&cancel),
    );
    eprintln!(
        "\r[5/5] {}   {} confirmed groups, {} false positives",
        i18n::t(lang, "byte_verify"),
        compare.confirmed_groups.len(),
        compare.eliminated_by_compare,
    );
    // Purge cached hashes proven wrong by byte comparison.
    if let Some(cache) = disk_cache.as_ref() {
        for key in &compare.stale_cache_keys {
            let _ = cache.invalidate(key);
        }
    }
    if is_interrupted() {
        return Err(i18n::t(lang, "interrupted_by_user").into());
    }

    if let Some(dir) = reference_dir {
        let lang = i18n::cached_lang();
        eprintln!(
            "{}",
            i18n::t(lang, "reference_mode").replacen("{}", &dir.display().to_string(), 1)
        );
        filter_ref_dir_bytecompare(&mut compare.confirmed_groups, dir);
    }
    if isolate {
        let lang = i18n::cached_lang();
        eprintln!("{}", i18n::t(lang, "isolate_mode"));
        filter_isolate_bytecompare(&mut compare.confirmed_groups, roots);
    }

    if let Some(json_path) = json_path {
        let lang = i18n::cached_lang();
        let full_report = zerodupe_report::FullScanReport::new_exact(
            env!("CARGO_PKG_VERSION").to_string(),
            roots
                .first()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            chrono_lite(),
            report.clone(),
            compare.clone(),
        );
        if let Err(e) = zerodupe_report::write_json_report(&full_report, json_path) {
            eprintln!("{}: {e}", i18n::t(lang, "json_report_failed"));
        } else {
            eprintln!(
                "  {} {}",
                i18n::t(lang, "json_report_arrow"),
                json_path.display()
            );
        }
        if compare.confirmed_groups.is_empty() {
            return Ok(());
        }
    }

    if compare.confirmed_groups.is_empty() {
        let lang = i18n::cached_lang();
        println!("\n{}", i18n::t(lang, "no_duplicates"));
        return Ok(());
    }
    println!();

    // Show results
    let mut selections: Vec<bool> = Vec::new();
    let mut file_counter = 0usize;

    for (gi, group) in compare.confirmed_groups.iter().enumerate() {
        println!(
            "═══ Group {}/{} — {} bytes — {} files ═══",
            gi + 1,
            compare.confirmed_groups.len(),
            group.size_bytes,
            group.files.len()
        );
        for (fi, file) in group.files.iter().enumerate() {
            file_counter += 1;
            let marker = if fi == group.keeper_index {
                i18n::t(lang, "keeper_star")
            } else {
                "       "
            };
            let note = keeper_note(file.path.as_str(), lang);
            println!(
                "  [{:2}] {}  {}  {}",
                file_counter,
                marker,
                file.path.as_str(),
                note
            );
            selections.push(false); // default: not selected for quarantine
        }
        println!();
    }

    let reclaimable: u64 = compare
        .confirmed_groups
        .iter()
        .map(|g| g.size_bytes * (g.files.len() - 1) as u64)
        .sum();
    let total_dup_files: usize = compare
        .confirmed_groups
        .iter()
        .map(|g| g.files.len() - 1)
        .sum();
    println!("══════════════════════════════════════════════════");
    println!(
        "{}",
        i18n::t(lang, "reclaimable_across")
            .replacen("{}", &format_reclaimable_size(reclaimable), 1)
            .replacen("{}", &total_dup_files.to_string(), 1)
            .replacen("{}", &compare.confirmed_groups.len().to_string(), 1)
    );
    println!("══════════════════════════════════════════════════");

    println!("══════════════════════════════════════════════════");
    println!(
        "{}",
        i18n::t(lang, "actions_prompt").replacen("{}", &file_counter.to_string(), 1)
    );
    println!("{}", i18n::t(lang, "files_marked_keeper"));
    println!("══════════════════════════════════════════════════");

    // Open quarantine
    let q = Quarantine::open(quarantine_dir).map_err(|e| format!("quarantine: {e}"))?;

    // ── Auto-quarantine mode ──
    if auto_quarantine {
        let mut count = 0;
        let session_id = Uuid::new_v4().to_string();
        for group in &compare.confirmed_groups {
            for (i, file) in group.files.iter().enumerate() {
                if i == group.keeper_index {
                    continue; // keep the keeper
                }
                match q.quarantine_file(
                    file.path.as_std_path(),
                    "exact-duplicate",
                    &session_id,
                    None,
                ) {
                    Ok(_) => {
                        println!("  ✓ Quarantined: {}", file.path.as_str());
                        count += 1;
                    }
                    Err(e) => {
                        eprintln!("  ✗ {}: {e}", file.path.as_str());
                    }
                }
            }
        }
        println!(
            "{}",
            i18n::t(lang, "auto_quarantined_keepers")
                .replacen("{}", &count.to_string(), 1)
                .replacen(
                    "{}",
                    &(compare
                        .confirmed_groups
                        .iter()
                        .map(|g| g.files.len())
                        .sum::<usize>()
                        - count)
                        .to_string(),
                    1
                )
        );
        return Ok(());
    }

    // Interactive loop
    loop {
        eprint!("> ");
        io::stderr().flush()?;
        let mut input = String::new();
        // EOF (stdin closed, e.g. piped/non-interactive runs) must behave
        // like "q": retrying read_line on EOF spins forever at 100% CPU.
        if io::stdin().read_line(&mut input)? == 0 {
            input = "q".to_string();
        }
        let input = input.trim().to_lowercase();

        match input.as_str() {
            "q" | "quit" | "exit" => {
                println!("{}", i18n::t(lang, "quarantine_preserved"));
                break;
            }
            "a" | "apply" => {
                let mut count = 0;
                let session_id = Uuid::new_v4().to_string();
                for (i, &selected) in selections.iter().enumerate() {
                    if selected {
                        // Find the file path by index
                        if let Some(file) = find_file_by_index(&compare.confirmed_groups, i + 1) {
                            match q.quarantine_file(
                                file.path.as_std_path(),
                                "user-selected",
                                &session_id,
                                None,
                            ) {
                                Ok(_) => {
                                    println!("  ✓ Quarantined: {}", file.path.as_str());
                                    count += 1;
                                }
                                Err(e) => {
                                    eprintln!("  ✗ {}: {e}", file.path.as_str());
                                }
                            }
                        }
                    }
                }
                println!(
                    "{}",
                    i18n::t(lang, "quarantined_files").replacen("{}", &count.to_string(), 1)
                );
                break;
            }
            "?" | "help" => {
                println!("  {}", i18n::t(lang, "toggle_file"));
                println!("  {}", i18n::t(lang, "apply_quarantine"));
                println!("  {}", i18n::t(lang, "quit_no_quarantine"));
                println!("  {}", i18n::t(lang, "keeper_help"));
            }
            "" => continue,
            _ => {
                if let Ok(num) = input.parse::<usize>() {
                    if num >= 1 && num <= selections.len() {
                        selections[num - 1] = !selections[num - 1];
                        let status = if selections[num - 1] {
                            "✓ selected"
                        } else {
                            "  cleared"
                        };
                        if let Some(file) = find_file_by_index(&compare.confirmed_groups, num) {
                            println!("  [{}] {} — {}", num, status, file.path.as_str());
                        }
                    } else {
                        eprintln!(
                            "  {}",
                            i18n::t(lang, "invalid_number").replacen(
                                "{}",
                                &selections.len().to_string(),
                                1
                            )
                        );
                    }
                } else {
                    eprintln!("  {}", i18n::t(lang, "unknown_cmd"));
                }
            }
        }
    }

    Ok(())
}

fn find_file_by_index(
    groups: &[zerodupe_core::ByteCompareGroup],
    target: usize,
) -> Option<&zerodupe_core::FileCandidate> {
    let mut current = 0usize;
    for group in groups {
        for file in &group.files {
            current += 1;
            if current == target {
                return Some(file);
            }
        }
    }
    None
}

fn find_file_by_index_similar(
    groups: &[zerodupe_similar::NearDuplicateGroup],
    target: usize,
) -> Option<&zerodupe_core::FileCandidate> {
    let mut current = 0usize;
    for group in groups {
        for file in &group.files {
            current += 1;
            if current == target {
                return Some(file);
            }
        }
    }
    None
}

fn keeper_note(path: &str, lang: i18n::Lang) -> &'static str {
    let lower = path.to_lowercase();
    if lower.contains("copy") || lower.contains("copia") {
        i18n::t(lang, "note_copy_name")
    } else if lower.contains("(1)") || lower.contains("(2)") {
        i18n::t(lang, "note_numbered_copy")
    } else if lower.contains("backup") {
        i18n::t(lang, "note_backup")
    } else if lower.contains("old") {
        i18n::t(lang, "note_old_version")
    } else {
        ""
    }
}

fn load_keeper_weights(
    path: &Path,
) -> Result<zerodupe_policy::KeeperWeights, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read keeper weights file {}: {e}", path.display()))?;
    let weights: zerodupe_policy::KeeperWeights = toml::from_str(&content)
        .map_err(|e| format!("failed to parse keeper weights TOML: {e}"))?;
    Ok(weights)
}

fn parse_partial_strategy(s: &str) -> PartialStrategy {
    match s.to_lowercase().as_str() {
        "head-only" | "headonly" => PartialStrategy::HeadOnly,
        _ => PartialStrategy::HeadTail,
    }
}

// ── Post-scan filters ──

fn filter_ref_dir_bytecompare(
    groups: &mut Vec<zerodupe_core::ByteCompareGroup>,
    reference_dir: &Path,
) {
    groups.retain(|group| {
        let has_inside = group
            .files
            .iter()
            .any(|f| f.path.as_std_path().starts_with(reference_dir));
        let has_outside = group
            .files
            .iter()
            .any(|f| !f.path.as_std_path().starts_with(reference_dir));
        has_inside && has_outside
    });
    for group in groups.iter_mut() {
        if let Some(idx) = group
            .files
            .iter()
            .position(|f| f.path.as_std_path().starts_with(reference_dir))
        {
            group.keeper_index = idx;
        }
    }
}

fn filter_ref_dir_similar(
    groups: &mut Vec<zerodupe_similar::NearDuplicateGroup>,
    reference_dir: &Path,
) {
    groups.retain(|group| {
        let has_inside = group
            .files
            .iter()
            .any(|f| f.path.as_std_path().starts_with(reference_dir));
        let has_outside = group
            .files
            .iter()
            .any(|f| !f.path.as_std_path().starts_with(reference_dir));
        has_inside && has_outside
    });
    for group in groups.iter_mut() {
        if let Some(idx) = group
            .files
            .iter()
            .position(|f| f.path.as_std_path().starts_with(reference_dir))
        {
            group.keeper_index = idx;
        }
    }
}

fn filter_isolate_bytecompare(
    groups: &mut Vec<zerodupe_core::ByteCompareGroup>,
    roots: &[PathBuf],
) {
    groups.retain(|group| {
        let unique_roots: HashSet<&Path> = group
            .files
            .iter()
            .filter_map(|f| get_root_for_path(f.path.as_std_path(), roots))
            .collect();
        unique_roots.len() >= 2
    });
}

fn filter_isolate_similar(
    groups: &mut Vec<zerodupe_similar::NearDuplicateGroup>,
    roots: &[PathBuf],
) {
    groups.retain(|group| {
        let unique_roots: HashSet<&Path> = group
            .files
            .iter()
            .filter_map(|f| get_root_for_path(f.path.as_std_path(), roots))
            .collect();
        unique_roots.len() >= 2
    });
}

fn get_root_for_path<'a>(path: &Path, roots: &'a [PathBuf]) -> Option<&'a Path> {
    for root in roots {
        if path.starts_with(root) {
            return Some(root.as_path());
        }
    }
    None
}

// ── Similar (near-duplicate) mode ──

struct SimilarOptions {
    roots: Vec<PathBuf>,
    quarantine_dir: PathBuf,
    keeper_weights_path: Option<PathBuf>,
    reference_dir: Option<PathBuf>,
    isolate: bool,
    invariance: zerodupe_similar_image::GeometricInvariance,
    json_path: Option<PathBuf>,
}

fn parse_invariance(
    s: &str,
) -> Result<zerodupe_similar_image::GeometricInvariance, Box<dyn std::error::Error>> {
    use zerodupe_similar_image::GeometricInvariance;
    match s {
        "off" => Ok(GeometricInvariance::Off),
        "mirror" => Ok(GeometricInvariance::MirrorFlip),
        "full" => Ok(GeometricInvariance::Full),
        other => Err(format!("invalid --invariance value '{other}' (off|mirror|full)").into()),
    }
}

fn run_similar(opts: &SimilarOptions) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use zerodupe_core::FileCandidate;
    use zerodupe_similar::detect_similars;
    use zerodupe_similar_image::ImagePHashDetector;

    // Capture scan path before converting roots
    let scan_path: PathBuf = opts
        .roots
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("."));

    let utf8_roots: Vec<Utf8PathBuf> = opts
        .roots
        .iter()
        .map(|p| {
            Utf8PathBuf::from_path_buf(p.clone())
                .map_err(|p| format!("path is not valid UTF-8: {}", p.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let cancel = CancelFlag::new();
    let _ = CANCEL_FLAG.set(cancel.clone());
    setup_ctrlc_handler(&cancel);

    let lang = i18n::cached_lang();

    // Default quarantine dir inside scan root
    let default_qdir = scan_path.join("zerodupe_quarantine/similar_images");
    let quarantine_dir = if opts.quarantine_dir == Path::new("zerodupe_quarantine/similar_images") {
        &default_qdir
    } else {
        &opts.quarantine_dir
    };

    eprintln!("[1/3] {}", i18n::t(lang, "discovering_files"));
    let mut options = DiscoveryOptions::default();
    let profile = zerodupe_platform::current();
    for path in profile.protected_paths() {
        options.exclude_prefixes.push(path.clone());
    }
    // Nunca re-escanear la cuarentena de una limpieza anterior.
    options
        .exclude_prefixes
        .push("zerodupe_quarantine".to_string());
    let report = zerodupe_fs::discover_roots(utf8_roots, &options, None, None);

    // Filter to image files only (incl. RAW when the feature is on)
    let img_exts = zerodupe_similar_image::supported_extensions();
    let files: Vec<FileCandidate> = report
        .entries
        .iter()
        .filter(|e| {
            let ext = e.path.extension().unwrap_or("").to_lowercase();
            e.size_bytes.unwrap_or(0) > 0 && img_exts.contains(&ext.as_str())
        })
        .map(|e| FileCandidate {
            path: e.path.clone(),
            size_bytes: e.size_bytes.unwrap_or(0),
        })
        .collect();

    let total = files.len();
    eprintln!(
        "[1/3] {}       {} images found",
        i18n::t(lang, "discovering_files"),
        total
    );
    if is_interrupted() {
        return Err(i18n::t(lang, "interrupted_by_user").into());
    }

    eprintln!("[2/3] {}", i18n::t(lang, "fingerprinting"));
    let progress = Arc::new(AtomicUsize::new(0));
    let p_clone = progress.clone();
    let done_flag = Arc::new(AtomicUsize::new(0));
    let d_clone = done_flag.clone();

    // Progress thread
    std::thread::spawn(move || {
        loop {
            if d_clone.load(Ordering::Relaxed) > 0 {
                break;
            }
            let n = p_clone.load(Ordering::Relaxed);
            let pct = n
                .checked_mul(100)
                .and_then(|v| v.checked_div(total))
                .unwrap_or(0);
            eprint!(
                "\r[2/3] {}          {:>3}% ({}/{})",
                i18n::t(lang, "fingerprinting_progress"),
                pct,
                n,
                total
            );
            std::io::Write::flush(&mut std::io::stderr()).ok();
            std::thread::sleep(Duration::from_millis(200));
        }
    });

    let detectors: Vec<Box<dyn zerodupe_similar::SimilarityDetector>> =
        if let Some(ref weights_path) = opts.keeper_weights_path {
            let weights = load_keeper_weights(weights_path)?;
            vec![Box::new(
                ImagePHashDetector::with_weights(weights).with_invariance(opts.invariance),
            )]
        } else {
            vec![Box::new(
                ImagePHashDetector::new().with_invariance(opts.invariance),
            )]
        };
    let detector_refs: Vec<&dyn zerodupe_similar::SimilarityDetector> =
        detectors.iter().map(|d| d.as_ref()).collect();

    let _start = std::time::Instant::now();
    // Persistent fingerprint cache: re-scans only fingerprint files that
    // changed. On any open failure the scan silently runs uncached.
    let fp_cache = zerodupe_cache::HashCache::open(&zerodupe_cache::default_cache_path()).ok();
    let mut similar_report = detect_similars(
        &files,
        &detector_refs,
        fp_cache.as_ref(),
        Some(progress),
        Some(&cancel),
    );
    done_flag.store(1, Ordering::Relaxed);

    eprintln!(
        "\r[2/3] {}          100% ({}/{})",
        i18n::t(lang, "fingerprinting_progress"),
        total,
        total
    );
    eprintln!(
        "[3/3] {}  {} groups, {} errors",
        i18n::t(lang, "clustering"),
        similar_report.groups.len(),
        similar_report.errors.len()
    );

    if let Some(ref dir) = opts.reference_dir {
        eprintln!(
            "{}",
            i18n::t(lang, "reference_mode").replacen("{}", &dir.display().to_string(), 1)
        );
        filter_ref_dir_similar(&mut similar_report.groups, dir);
    }
    if opts.isolate {
        eprintln!("{}", i18n::t(lang, "isolate_mode"));
        filter_isolate_similar(&mut similar_report.groups, &opts.roots);
    }

    // Keepers de limpiezas anteriores (GUI o CLI) registrados en el journal
    // de la cuarentena del scan root: únicos supervivientes de su grupo,
    // se fijan como keeper y nunca se ofrecen para remoción.
    let root_journal = scan_path.join("zerodupe_quarantine");
    if root_journal.join("journal.db").exists()
        && let Ok(q) = zerodupe_safety::Quarantine::open(&root_journal)
        && let Ok(kept) = q.kept_files()
    {
        let kept: std::collections::HashSet<String> =
            kept.into_iter().map(Utf8PathBuf::into_string).collect();
        zerodupe_similar::protect_prior_keepers(&mut similar_report, &kept);
    }

    if let Some(ref json_path) = opts.json_path {
        let full_report = zerodupe_report::FullScanReport::new_similar(
            env!("CARGO_PKG_VERSION").to_string(),
            scan_path.display().to_string(),
            chrono_lite(),
            report.clone(),
            similar_report.clone(),
        );
        if let Err(e) = zerodupe_report::write_json_report(&full_report, json_path) {
            eprintln!("{}: {e}", i18n::t(lang, "json_report_failed"));
        } else {
            eprintln!(
                "  {} {}",
                i18n::t(lang, "json_report_arrow"),
                json_path.display()
            );
        }
        if similar_report.groups.is_empty() {
            return Ok(());
        }
    }

    if similar_report.groups.is_empty() {
        println!("\n  ✓ {}", i18n::t(lang, "no_similar_images"));
        return Ok(());
    }

    let total_sim: usize = similar_report.groups.iter().map(|g| g.files.len()).sum();
    println!("\n═══ {} ═══", i18n::t(lang, "similar_images_found"));
    println!(
        "  {}",
        i18n::t(lang, "similar_groups_summary")
            .replacen("{}", &similar_report.groups.len().to_string(), 1)
            .replacen("{}", &total_sim.to_string(), 1)
    );

    // Show groups
    let mut counter = 0usize;
    for (gi, group) in similar_report.groups.iter().enumerate() {
        println!(
            "\n  {}",
            i18n::t(lang, "similar_display_group")
                .replacen("{}", &(gi + 1).to_string(), 1)
                .replacen("{}", &group.confidence.to_string(), 1)
                .replacen("{}", &group.files.len().to_string(), 1)
        );
        for (fi, file) in group.files.iter().enumerate() {
            counter += 1;
            let marker = if fi == group.keeper_index {
                i18n::t(lang, "keeper_star")
            } else {
                "       "
            };
            println!("    [{:2}] {}  {}", counter, marker, file.path.as_str());
        }
    }

    let reclaimable_sim: u64 = similar_report
        .groups
        .iter()
        .flat_map(|g| {
            g.files
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != g.keeper_index)
                .map(|(_, f)| f.size_bytes)
        })
        .sum();
    let total_non_keepers: usize = similar_report
        .groups
        .iter()
        .map(|g| g.files.len() - 1)
        .sum();
    println!("\n══════════════════════════════════════════════════");
    println!(
        "{}",
        i18n::t(lang, "reclaimable_similar")
            .replacen("{}", &format_reclaimable_size(reclaimable_sim), 1)
            .replacen("{}", &total_non_keepers.to_string(), 1)
            .replacen("{}", &similar_report.groups.len().to_string(), 1)
    );
    println!("══════════════════════════════════════════════════");

    println!("\n──────────────────────────────────────");
    println!("{}", i18n::t(lang, "how_handle"));
    println!("  {}", i18n::t(lang, "review_manually"));
    println!("  {}", i18n::t(lang, "auto_quarantine"));
    println!("  {}", i18n::t(lang, "skip_option"));
    println!("──────────────────────────────────────");
    let choice = ask_123();
    println!("──────────────────────────────────────");

    let start = Instant::now();
    let mut sim_paths: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    match choice {
        1 => {
            run_similar_interactive_wizard(&similar_report, quarantine_dir)?;
        }
        2 => {
            sim_paths = auto_quarantine_similar(&similar_report, quarantine_dir);
        }
        _ => {
            println!("  {}", i18n::t(lang, "skipped_no_files"));
        }
    }

    let report_path = generate_similar_html_report(
        lang,
        &scan_path,
        &similar_report,
        &sim_paths,
        start.elapsed(),
    )?;
    println!("\n  {}: {}", i18n::t(lang, "report"), report_path.display());

    Ok(())
}

fn auto_quarantine_similar(
    report: &zerodupe_similar::SimilarityReport,
    quarantine_dir: &Path,
) -> std::collections::HashMap<String, String> {
    let mut paths: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let q = match Quarantine::open(quarantine_dir) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("  ✗ quarantine open: {e}");
            return paths;
        }
    };
    let mut count = 0;
    let session_id = Uuid::new_v4().to_string();
    for group in &report.groups {
        for (i, file) in group.files.iter().enumerate() {
            if i == group.keeper_index {
                continue;
            }
            match q.quarantine_file(
                file.path.as_std_path(),
                "similar-auto",
                &session_id,
                Some(30),
            ) {
                Ok(entry) => {
                    println!("  ✓ Quarantined: {}", file.path.as_str());
                    paths.insert(
                        file.path.as_str().to_string(),
                        entry.quarantined_path.as_str().to_string(),
                    );
                    count += 1;
                }
                Err(e) => eprintln!("  ✗ {}: {e}", file.path.as_str()),
            }
        }
    }
    let lang = i18n::cached_lang();
    println!(
        "\n  {}",
        i18n::t(lang, "similar_quarantined").replacen("{}", &count.to_string(), 1)
    );
    paths
}

fn run_similar_interactive_wizard(
    report: &zerodupe_similar::SimilarityReport,
    quarantine_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut selections: Vec<bool> = Vec::new();

    // Pre-select non-keepers
    for group in &report.groups {
        for (i, _) in group.files.iter().enumerate() {
            selections.push(i != group.keeper_index);
        }
    }

    let lang = i18n::cached_lang();

    println!("\n  {}", i18n::t(lang, "files_preselected_short"));
    println!("  {}", i18n::t(lang, "toggle_apply_quit"));
    println!("──────────────────────────────────────");

    let q = Quarantine::open(quarantine_dir).map_err(|e| format!("quarantine: {e}"))?;

    loop {
        eprint!("> ");
        io::stderr().flush()?;
        let mut input = String::new();
        // EOF (stdin closed, e.g. piped/non-interactive runs) must behave
        // like "q": retrying read_line on EOF spins forever at 100% CPU.
        if io::stdin().read_line(&mut input)? == 0 {
            input = "q".to_string();
        }
        let input = input.trim().to_lowercase();

        match input.as_str() {
            "q" | "quit" | "exit" => {
                println!("  {}", i18n::t(lang, "exiting_no_files_moved"));
                break;
            }
            "a" | "apply" => {
                let mut count = 0;
                let mut idx = 0;
                let session_id = Uuid::new_v4().to_string();
                for group in &report.groups {
                    for file in &group.files {
                        if selections[idx] {
                            match q.quarantine_file(
                                file.path.as_std_path(),
                                "user-selected-similar",
                                &session_id,
                                None,
                            ) {
                                Ok(_) => {
                                    println!("  ✓ Quarantined: {}", file.path.as_str());
                                    count += 1;
                                }
                                Err(e) => eprintln!("  ✗ {}: {e}", file.path.as_str()),
                            }
                        }
                        idx += 1;
                    }
                }
                println!(
                    "  {}",
                    i18n::t(lang, "quarantined_files").replacen("{}", &count.to_string(), 1)
                );
                break;
            }
            "?" | "help" => {
                println!("  {}", i18n::t(lang, "toggle_item"));
                println!("  {}", i18n::t(lang, "apply_short"));
                println!("  {}", i18n::t(lang, "quit_short"));
            }
            "" => continue,
            _ => {
                if let Ok(num) = input.parse::<usize>() {
                    if num >= 1 && num <= selections.len() {
                        selections[num - 1] = !selections[num - 1];
                        let status = if selections[num - 1] { "✓" } else { " " };
                        if let Some(file) = find_file_by_index_similar(&report.groups, num) {
                            println!("  [{}] {} {}", num, status, file.path.as_str());
                        }
                    } else {
                        eprintln!(
                            "  {}",
                            i18n::t(lang, "invalid").replacen(
                                "{}",
                                &selections.len().to_string(),
                                1
                            )
                        );
                    }
                } else {
                    eprintln!("  {}", i18n::t(lang, "unknown_type_help"));
                }
            }
        }
    }
    Ok(())
}

fn ask_scan_path() -> io::Result<PathBuf> {
    let lang = i18n::cached_lang();
    print!("{}: ", i18n::t(lang, "path_to_scan"));
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let path = PathBuf::from(input.trim());
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: {}", i18n::t(lang, "path_not_found"), path.display()),
        ));
    }
    Ok(path)
}

fn ask_123() -> u8 {
    loop {
        print!("> ");
        let _ = io::stdout().flush();
        let mut input = String::new();
        // EOF returns Ok(0), not Err: treat both as "skip" so piped or
        // non-interactive runs terminate instead of spinning forever.
        match io::stdin().read_line(&mut input) {
            Ok(0) | Err(_) => return 3,
            Ok(_) => {}
        }
        match input.trim() {
            "1" => return 1,
            "2" => return 2,
            "3" => return 3,
            _ => {
                let lang = i18n::cached_lang();
                eprintln!("  {}", i18n::t(lang, "type_123"));
            }
        }
    }
}

fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn format_hygiene_size(bytes: u64) -> String {
    const KB: f64 = 1_000.0;
    const MB: f64 = 1_000_000.0;
    const GB: f64 = 1_000_000_000.0;
    if bytes as f64 >= GB {
        format!("{:.2} GB", bytes as f64 / GB)
    } else if bytes as f64 >= MB {
        format!("{:.2} MB", bytes as f64 / MB)
    } else if bytes as f64 >= KB {
        format!("{:.2} KB", bytes as f64 / KB)
    } else {
        format!("{} B", bytes)
    }
}

fn chrono_lite() -> String {
    use std::time::SystemTime;
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs();
            let days_since_epoch = secs / 86400;
            let mut y = 1970i64;
            let mut remaining = days_since_epoch as i64;
            loop {
                let year_days = if is_leap(y) { 366 } else { 365 };
                if remaining < year_days {
                    break;
                }
                remaining -= year_days;
                y += 1;
            }
            let month_days = if is_leap(y) {
                [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            } else {
                [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            };
            let mut m = 1;
            for &md in &month_days {
                if remaining < md {
                    break;
                }
                remaining -= md;
                m += 1;
            }
            let d = remaining + 1;
            let total_secs_today = secs % 86400;
            let h = total_secs_today / 3600;
            let min = (total_secs_today % 3600) / 60;
            format!("{} {:02}, {} · {:02}:{:02}", month_name(m), d, y, h, min)
        }
        Err(_) => "unknown date".to_string(),
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

fn month_name(m: i64) -> &'static str {
    match m {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "???",
    }
}

fn lang_str(lang: i18n::Lang) -> &'static str {
    match lang {
        i18n::Lang::En => "en",
        i18n::Lang::Es => "es",
    }
}

fn generate_exact_html_report(
    lang: i18n::Lang,
    scan_path: &Path,
    compare: &ByteCompareReport,
    quarantine_paths: &std::collections::HashMap<String, String>,
    elapsed: std::time::Duration,
) -> io::Result<PathBuf> {
    let output_path = scan_path.join("ZeroDupe_Report.html");
    zerodupe_report::html::generate_exact_html_report(
        lang_str(lang),
        scan_path,
        &output_path,
        compare,
        quarantine_paths,
        elapsed,
    )
}

fn generate_similar_html_report(
    lang: i18n::Lang,
    scan_path: &Path,
    report: &zerodupe_similar::SimilarityReport,
    quarantine_paths: &std::collections::HashMap<String, String>,
    elapsed: std::time::Duration,
) -> io::Result<PathBuf> {
    let output_path = scan_path.join("ZeroDupe_Similar_Report.html");
    zerodupe_report::html::generate_similar_html_report(
        lang_str(lang),
        scan_path,
        &output_path,
        report,
        quarantine_paths,
        elapsed,
    )
}
fn interactive_review(
    compare: &ByteCompareReport,
    quarantine_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let lang = i18n::cached_lang();
    let mut selections: Vec<bool> =
        vec![false; compare.confirmed_groups.iter().map(|g| g.files.len()).sum()];
    let mut counter = 0usize;

    for group in &compare.confirmed_groups {
        for (fi, _file) in group.files.iter().enumerate() {
            if fi != group.keeper_index {
                selections[counter] = true;
            }
            counter += 1;
        }
    }

    println!("\n  {}", i18n::t(lang, "files_preselected"));
    println!("  {}", i18n::t(lang, "toggle_apply_quit"));
    println!("──────────────────────────────────────");

    let q = Quarantine::open(quarantine_dir).map_err(|e| format!("quarantine: {e}"))?;

    loop {
        eprint!("> ");
        io::stderr().flush()?;
        let mut input = String::new();
        // EOF (stdin closed, e.g. piped/non-interactive runs) must behave
        // like "q": retrying read_line on EOF spins forever at 100% CPU.
        if io::stdin().read_line(&mut input)? == 0 {
            input = "q".to_string();
        }
        let input = input.trim().to_lowercase();

        match input.as_str() {
            "q" | "quit" | "exit" => {
                println!("  {}", i18n::t(lang, "exiting_no_files_moved"));
                break;
            }
            "a" | "apply" => {
                let mut count = 0;
                let mut idx = 0;
                let session_id = Uuid::new_v4().to_string();
                for group in &compare.confirmed_groups {
                    for file in &group.files {
                        if selections[idx] {
                            match q.quarantine_file(
                                file.path.as_std_path(),
                                "user-selected",
                                &session_id,
                                None,
                            ) {
                                Ok(_) => {
                                    println!("  ✓ Quarantined: {}", file.path.as_str());
                                    count += 1;
                                }
                                Err(e) => eprintln!("  ✗ {}: {e}", file.path.as_str()),
                            }
                        }
                        idx += 1;
                    }
                }
                println!(
                    "  {}",
                    i18n::t(lang, "quarantined_files").replacen("{}", &count.to_string(), 1)
                );
                break;
            }
            "?" | "help" => {
                println!("  {}", i18n::t(lang, "toggle_item"));
                println!("  {}", i18n::t(lang, "apply_short"));
                println!("  {}", i18n::t(lang, "quit_no_quarantine"));
            }
            "" => continue,
            _ => {
                if let Ok(num) = input.parse::<usize>() {
                    if num >= 1 && num <= selections.len() {
                        selections[num - 1] = !selections[num - 1];
                        let status = if selections[num - 1] { "✓" } else { " " };
                        if let Some(file) = find_file_by_index(&compare.confirmed_groups, num) {
                            println!("  [{}] {} {}", num, status, file.path.as_str());
                        }
                    } else {
                        eprintln!(
                            "  {}",
                            i18n::t(lang, "invalid").replacen(
                                "{}",
                                &selections.len().to_string(),
                                1
                            )
                        );
                    }
                } else {
                    eprintln!("  {}", i18n::t(lang, "unknown_type_help"));
                }
            }
        }
    }
    Ok(())
}

fn auto_quarantine_exact(
    compare: &ByteCompareReport,
    quarantine_dir: &Path,
    reason: &str,
) -> std::collections::HashMap<String, String> {
    let lang = i18n::cached_lang();
    let mut paths: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let q = match Quarantine::open(quarantine_dir) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("  ✗ quarantine open: {e}");
            return paths;
        }
    };
    let mut count = 0;
    let session_id = Uuid::new_v4().to_string();
    for group in &compare.confirmed_groups {
        for (i, file) in group.files.iter().enumerate() {
            if i == group.keeper_index {
                continue;
            }
            match q.quarantine_file(file.path.as_std_path(), reason, &session_id, Some(30)) {
                Ok(entry) => {
                    println!("  ✓ Quarantined: {}", file.path.as_str());
                    paths.insert(
                        file.path.as_str().to_string(),
                        entry.quarantined_path.as_str().to_string(),
                    );
                    count += 1;
                }
                Err(e) => eprintln!("  ✗ {}: {e}", file.path.as_str()),
            }
        }
    }
    let kept = compare
        .confirmed_groups
        .iter()
        .map(|g| g.files.len())
        .sum::<usize>()
        - count;
    println!(
        "\n  {}",
        i18n::t(lang, "files_quarantined_keepers")
            .replacen("{}", &count.to_string(), 1)
            .replacen("{}", &kept.to_string(), 1)
    );
    paths
}

fn print_hygiene_summary(report: &zerodupe_hygiene::types::HygieneReport) {
    let lang = i18n::cached_lang();
    println!("\n═══ {} ═══", i18n::t(lang, "hygiene_summary"));
    println!(
        "  {}",
        i18n::t(lang, "items_count")
            .replacen("{}", &report.summary.total_items.to_string(), 1)
            .replacen(
                "{}",
                &format_hygiene_size(report.summary.total_size_bytes),
                1
            )
    );
    for (cat_name, count, size) in &report.summary.by_category {
        println!(
            "    {}: {} items · {}",
            cat_name,
            count,
            format_hygiene_size(*size)
        );
    }
    println!(
        "  {}",
        i18n::t(lang, "risk_levels_summary")
            .replacen("{}", &report.summary.low_risk_count.to_string(), 1)
            .replacen("{}", &report.summary.medium_risk_count.to_string(), 1)
            .replacen("{}", &report.summary.high_risk_count.to_string(), 1)
    );
}

fn run_wizard() -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let lang = i18n::cached_lang();

    let mut wf = Workflow::new();
    let _ = CANCEL_FLAG.set(wf.cancel_flag().clone());
    setup_ctrlc_handler(wf.cancel_flag());

    println!();
    println!("╔══════════════════════════════════╗");
    println!(
        "║           {}       ║",
        i18n::t(lang, "wizard_banner_title")
    );
    println!("║   {}  ║", i18n::t(lang, "wizard_banner_subtitle"));
    println!("╚══════════════════════════════════╝");
    println!();

    if let Some(resume) = zerodupe_config::resume::load_resume_state() {
        eprintln!(
            "Interrupted scan detected from {} (root: {}). Resume? [Y/n]",
            resume.started_at, resume.scan_root
        );
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans)?;
        if ans.trim().to_lowercase().starts_with('n') {
            zerodupe_config::resume::clear_resume_state();
        }
    }

    let scan_path = ask_scan_path()?;
    let quarantine_dir = scan_path.join("zerodupe_quarantine");
    let similar_dir = scan_path.join("zerodupe_quarantine").join("similar_images");

    wf.advance(WorkflowAction::SelectFolder {
        path: scan_path.to_string_lossy().into_owned(),
    })?;

    println!();
    println!("──────────────────────────────────────");

    // STEP 1: Exact Duplicates
    println!("\n▶ {}", i18n::t(lang, "step1_exact"));
    println!("──────────────────────────────────────");

    wf.advance(WorkflowAction::StartScan)?;

    if let Some(compare) = wf.exact_report() {
        if compare.confirmed_groups.is_empty() {
            println!("\n  ✓ {}", i18n::t(lang, "no_duplicates"));
            println!("──────────────────────────────────────");
        } else {
            let dup_count: usize = compare
                .confirmed_groups
                .iter()
                .map(|g| g.files.len() - 1)
                .sum();
            let total_files: usize = compare.confirmed_groups.iter().map(|g| g.files.len()).sum();

            println!();
            println!(
                "═══ {} ═══\n  {}",
                i18n::t(lang, "exact_duplicates_found"),
                i18n::t(lang, "groups_files_duplicates")
                    .replacen("{}", &compare.confirmed_groups.len().to_string(), 1)
                    .replacen("{}", &total_files.to_string(), 1)
                    .replacen("{}", &dup_count.to_string(), 1)
            );

            let mut counter = 0usize;
            for (gi, group) in compare.confirmed_groups.iter().enumerate() {
                println!(
                    "\n  Group {}/{} — {:.1} MB — {} files",
                    gi + 1,
                    compare.confirmed_groups.len(),
                    group.size_bytes as f64 / 1_000_000.0,
                    group.files.len()
                );
                for (fi, file) in group.files.iter().enumerate() {
                    counter += 1;
                    let marker = if fi == group.keeper_index {
                        i18n::t(lang, "keeper_star")
                    } else {
                        "       "
                    };
                    let note = keeper_note(file.path.as_str(), lang);
                    println!(
                        "    [{:2}] {}  {}  {}",
                        counter,
                        marker,
                        file.path.as_str(),
                        note
                    );
                }
            }

            let reclaimable: u64 = compare
                .confirmed_groups
                .iter()
                .map(|g| g.size_bytes * (g.files.len() - 1) as u64)
                .sum();
            println!(
                "\n══════════════════════════════════════════════════\n\
                 {}\n\
                 ══════════════════════════════════════════════════",
                i18n::t(lang, "reclaimable_across")
                    .replacen("{}", &format_reclaimable_size(reclaimable), 1)
                    .replacen("{}", &dup_count.to_string(), 1)
                    .replacen("{}", &compare.confirmed_groups.len().to_string(), 1)
            );

            println!("\n──────────────────────────────────────");
            println!("{}", i18n::t(lang, "how_handle"));
            println!("  {}", i18n::t(lang, "review_manually"));
            println!("  {}", i18n::t(lang, "auto_quarantine"));
            println!("  {}", i18n::t(lang, "skip_option"));
            println!("──────────────────────────────────────");
            let choice = ask_123();
            println!("──────────────────────────────────────");

            let mut quarantine_paths: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();

            match choice {
                1 => {
                    interactive_review(compare, &quarantine_dir)?;
                }
                2 => {
                    quarantine_paths =
                        auto_quarantine_exact(compare, &quarantine_dir, "exact-auto");
                }
                _ => {
                    println!("  {}", i18n::t(lang, "skipped_no_files"));
                }
            }

            let report_path = generate_exact_html_report(
                lang,
                &scan_path,
                compare,
                &quarantine_paths,
                start.elapsed(),
            )?;
            println!("\n  {}: {}", i18n::t(lang, "report"), report_path.display());
        }
    }

    // STEP 2: Similar Images
    println!("\n──────────────────────────────────────");
    println!("\n▶ {}", i18n::t(lang, "step2_similar"));
    println!("──────────────────────────────────────");
    print!("\n{}", i18n::t(lang, "continue_similar"));
    print!("\n> ");
    io::stdout().flush()?;
    let mut ans = String::new();
    io::stdin().read_line(&mut ans)?;
    if !ans.trim().to_lowercase().starts_with('y') {
        wf.advance(WorkflowAction::SkipSimilar)?;
        print_wizard_summary(start);
        return Ok(());
    }

    println!("\n──────────────────────────────────────");
    wf.advance(WorkflowAction::AcceptExact)?;

    if let Some(similar_report) = wf.similar_report() {
        if similar_report.groups.is_empty() {
            println!("\n  ✓ {}", i18n::t(lang, "no_similar_images"));
        } else {
            let total_sim: usize = similar_report.groups.iter().map(|g| g.files.len()).sum();
            println!("\n═══ {} ═══", i18n::t(lang, "similar_images_found"));
            println!(
                "  {}",
                i18n::t(lang, "similar_groups_summary")
                    .replacen("{}", &similar_report.groups.len().to_string(), 1)
                    .replacen("{}", &total_sim.to_string(), 1)
            );

            let mut counter = 0usize;
            for (gi, group) in similar_report.groups.iter().enumerate() {
                println!(
                    "\n  {}",
                    i18n::t(lang, "similar_display_group")
                        .replacen("{}", &(gi + 1).to_string(), 1)
                        .replacen("{}", &group.confidence.to_string(), 1)
                        .replacen("{}", &group.files.len().to_string(), 1)
                );
                for (fi, file) in group.files.iter().enumerate() {
                    counter += 1;
                    let marker = if fi == group.keeper_index {
                        i18n::t(lang, "keeper_star")
                    } else {
                        "       "
                    };
                    println!("    [{:2}] {}  {}", counter, marker, file.path.as_str());
                }
            }

            let reclaimable_sim: u64 = similar_report
                .groups
                .iter()
                .flat_map(|g| {
                    g.files
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != g.keeper_index)
                        .map(|(_, f)| f.size_bytes)
                })
                .sum();
            let total_non_keepers: usize = similar_report
                .groups
                .iter()
                .map(|g| g.files.len() - 1)
                .sum();
            println!("\n══════════════════════════════════════════════════");
            println!(
                "{}",
                i18n::t(lang, "reclaimable_similar")
                    .replacen("{}", &format_reclaimable_size(reclaimable_sim), 1)
                    .replacen("{}", &total_non_keepers.to_string(), 1)
                    .replacen("{}", &similar_report.groups.len().to_string(), 1)
            );
            println!("══════════════════════════════════════════════════");

            println!("\n──────────────────────────────────────");
            println!("{}", i18n::t(i18n::cached_lang(), "how_handle"));
            println!("  {}", i18n::t(i18n::cached_lang(), "review_manually"));
            println!("  {}", i18n::t(i18n::cached_lang(), "auto_quarantine"));
            println!("  {}", i18n::t(i18n::cached_lang(), "skip_option"));
            println!("──────────────────────────────────────");
            let choice = ask_123();
            println!("──────────────────────────────────────");

            let sim_start = Instant::now();
            let mut sim_paths: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();

            match choice {
                1 => {
                    run_similar_interactive_wizard(similar_report, &similar_dir)?;
                }
                2 => {
                    sim_paths = auto_quarantine_similar(similar_report, &similar_dir);
                }
                _ => {
                    println!("  {}", i18n::t(lang, "skipped_no_files"));
                }
            }

            let report_path = generate_similar_html_report(
                lang,
                &scan_path,
                similar_report,
                &sim_paths,
                sim_start.elapsed(),
            )?;
            println!("\n  {}: {}", i18n::t(lang, "report"), report_path.display());
        }
    }

    // STEP 3: Hygiene Cleanup — automatic
    println!("\n──────────────────────────────────────");
    println!("\n▶ {}", i18n::t(lang, "step3_hygiene"));
    println!("──────────────────────────────────────");

    wf.advance(WorkflowAction::SkipSimilar)?;

    if let Some(hygiene_report) = wf.hygiene_report() {
        if hygiene_report.items.is_empty() {
            println!("\n  ✓ {}", i18n::t(lang, "no_junk"));
        } else {
            let cleanable: Vec<_> = hygiene_report
                .items
                .iter()
                .filter(|i| i.can_clean && i.risk != zerodupe_hygiene::types::RiskLevel::High)
                .collect();

            if !cleanable.is_empty() {
                println!(
                    "  {}",
                    i18n::t(lang, "junk_items_found_detail")
                        .replacen("{}", &cleanable.len().to_string(), 1)
                        .replacen(
                            "{}",
                            &format_hygiene_size(hygiene_report.summary.total_size_bytes),
                            1
                        )
                );

                let junk_dir = quarantine_dir.join("junk");
                std::fs::create_dir_all(&junk_dir)?;

                for item in &cleanable {
                    let std_path = item.path.as_std_path();
                    if std_path.is_dir() {
                        let _ = std::fs::remove_dir(std_path);
                    } else {
                        let name = item.path.file_name().unwrap_or("unknown");
                        let dest = junk_dir.join(name);
                        if std::fs::rename(std_path, &dest).is_ok() {
                            println!("    {} {}", i18n::t(lang, "moved_to_junk"), item.path);
                        }
                    }
                }

                if let Some(html_path) = wf.last_report_path() {
                    let _ = zerodupe_report::html::append_hygiene_section(
                        lang_str(lang),
                        html_path,
                        hygiene_report,
                    );
                }
            } else {
                println!("  {}", i18n::t(lang, "no_junk_files_found"));
            }
        }

        let root = Utf8PathBuf::from_path_buf(scan_path.clone())
            .map_err(|p| format!("path is not valid UTF-8: {}", p.display()))?;
        let report_path = zerodupe_hygiene::report::generate_html_report(hygiene_report, &root)
            .map_err(|e| format!("report: {e}"))?;
        println!("\n  {}: {}", i18n::t(lang, "report"), report_path.as_str());
    }

    print_wizard_summary(start);
    Ok(())
}
fn run_hygiene(
    roots: &[PathBuf],
    dry_run: bool,
    auto_clean: bool,
    quarantine: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use zerodupe_hygiene::HygieneService;
    use zerodupe_hygiene::types::RiskLevel;

    let utf8_roots: Vec<Utf8PathBuf> = roots
        .iter()
        .map(|p| {
            Utf8PathBuf::from_path_buf(p.clone())
                .map_err(|p| format!("path is not valid UTF-8: {}", p.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let lang = i18n::cached_lang();

    let mut all_items: Vec<zerodupe_hygiene::types::JunkItem> = Vec::new();

    for root in &utf8_roots {
        eprintln!("\r{}: {}", i18n::t(lang, "scanning_junk_in"), root.as_str());
        let service = HygieneService::new(root.clone());
        let report = service.scan(None, None);
        eprintln!(
            "\r  {}",
            i18n::t(lang, "items_found_at")
                .replacen("{}", &report.summary.total_items.to_string(), 1)
                .replacen("{}", &report.summary.low_risk_count.to_string(), 1)
                .replacen("{}", &report.summary.medium_risk_count.to_string(), 1)
                .replacen("{}", &report.summary.high_risk_count.to_string(), 1)
        );
        all_items.extend(report.items);
    }

    if all_items.is_empty() {
        eprintln!("{}", i18n::t(lang, "no_junk_roots"));
        return Ok(());
    }

    let report = zerodupe_hygiene::types::HygieneReport::new(all_items);

    if dry_run {
        print_hygiene_summary(&report);
    }

    let mut cleaned = 0usize;
    let scan_root = utf8_roots
        .first()
        .cloned()
        .unwrap_or_else(|| Utf8PathBuf::from("."));

    if auto_clean {
        let q = Quarantine::open(&scan_root.as_std_path().join("zerodupe_quarantine"))
            .map_err(|e| format!("quarantine open: {e}"))?;
        let session_id = Uuid::new_v4().to_string();
        for item in &report.items {
            if item.risk == RiskLevel::Low && item.can_clean {
                let std_path = item.path.as_std_path();
                if std_path.try_exists().is_ok_and(|e| e) {
                    match q.quarantine_file(std_path, "hygiene-low-risk", &session_id, Some(30)) {
                        Ok(_) => {
                            eprintln!("  ✓ Quarantined: {}", item.path.as_str());
                            cleaned += 1;
                        }
                        Err(e) => eprintln!("  ✗ {}: {e}", item.path.as_str()),
                    }
                }
            }
        }
        eprintln!(
            "{}",
            i18n::t(lang, "auto_cleaned_items").replacen("{}", &cleaned.to_string(), 1)
        );
    }

    if quarantine {
        let q = Quarantine::open(&scan_root.as_std_path().join("zerodupe_quarantine"))
            .map_err(|e| format!("quarantine open: {e}"))?;
        let mut q_count = 0usize;
        let session_id = Uuid::new_v4().to_string();
        for item in &report.items {
            if item.risk == RiskLevel::Medium {
                let std_path = item.path.as_std_path();
                if std_path.try_exists().is_ok_and(|e| e) {
                    match q.quarantine_file(std_path, "hygiene-medium-risk", &session_id, Some(30))
                    {
                        Ok(_) => {
                            eprintln!("  ✓ Quarantined: {}", item.path.as_str());
                            q_count += 1;
                        }
                        Err(e) => eprintln!("  ✗ {}: {e}", item.path.as_str()),
                    }
                }
            }
        }
        eprintln!(
            "{}",
            i18n::t(lang, "quarantined_medium_items").replacen("{}", &q_count.to_string(), 1)
        );
    }

    let report_path = zerodupe_hygiene::report::generate_html_report(&report, &scan_root)
        .map_err(|e| format!("report: {e}"))?;
    eprintln!("\n  {}: {}", i18n::t(lang, "report"), report_path.as_str());

    Ok(())
}

fn print_wizard_summary(start: Instant) {
    let lang = i18n::cached_lang();
    let elapsed = start.elapsed();
    println!("\n──────────────────────────────────────");
    println!(
        "{}",
        i18n::t(lang, "done_total_time").replacen("{}", &format_duration(elapsed), 1)
    );
    println!("──────────────────────────────────────\n");
}
