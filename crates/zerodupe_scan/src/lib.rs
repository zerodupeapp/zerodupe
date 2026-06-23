//! Exact duplicate scan orchestration.
//!
//! Pipeline:
//! 1. Normalise discovered entries into unique physical files (Stage 2.5).
//! 2. Group physical representatives by size → CandidateReport (Stage 2).
//! 3. Partial head+tail hashing (cache-accelerated) → PartialHashReport (Stage 3).
//! 4. Full hashing (cache-accelerated) + TOCTTOU → FullHashReport (Stage 4).

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use camino::Utf8PathBuf;
use zerodupe_core::{
    ByteCompareGroup, ByteCompareReport, CancelFlag, CandidateReport, DiscoveredEntry,
    DiscoveredKind, EmptyFileGroup, ExactDuplicateGroup, FileCandidate, FileSnapshot, FileVersion,
    FullHashReport, GroupId, HardlinkCluster, HashCacheKey, HashError, HashErrorKind, HashGroup,
    HashRegion, HashingOptions, PartialHashReport, PhysicalFile, PhysicalFileReport, ProgressEvent,
    ProgressReporter, ScanStage, SizeGroup, VerifyMode,
};
use zerodupe_fs::extract_physical_file_key;
use zerodupe_platform::PhysicalFileKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineError {
    Cancelled,
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "pipeline cancelled"),
        }
    }
}

impl std::error::Error for PipelineError {}

// ── Internal helper ──

/// Samples up to 3 files to decide whether the stage runs against rotational
/// storage. **Called once per stage**, not per group — the detection parses
/// `/proc/self/mountinfo` on Linux, which would dwarf the hashing itself if
/// repeated for thousands of size groups.
fn stage_is_rotational(sample: &[usize], physical_files: &[PhysicalFile]) -> bool {
    let profile = zerodupe_platform::current();
    sample.iter().take(3).any(|&pf_idx| {
        physical_files
            .get(pf_idx)
            .and_then(|pf| profile.is_rotational_storage(&pf.canonical_path))
            .unwrap_or(false)
    })
}

/// Orders a group's files for reading: inode order on rotational storage
/// (random reads become sequential, 2-5x), identity order otherwise.
fn order_for_read(
    entry_indices: &[usize],
    physical_files: &[PhysicalFile],
    rotational: bool,
) -> Vec<usize> {
    if !rotational {
        return entry_indices.to_vec();
    }

    let profile = zerodupe_platform::current();
    let mut indexed: Vec<_> = entry_indices
        .iter()
        .filter_map(|&pf_idx| {
            let pf = physical_files.get(pf_idx)?;
            // The key was already extracted during normalisation; stat()
            // only as fallback for hand-built inputs.
            let key = match &pf.physical_key {
                Some(key) => key.clone(),
                None => {
                    let meta = std::fs::symlink_metadata(pf.canonical_path.as_std_path()).ok()?;
                    profile.physical_key(pf.canonical_path.as_path(), &meta)?
                }
            };
            Some((key, pf_idx))
        })
        .collect();

    indexed.sort_by(|(a, _), (b, _)| a.bytes.cmp(&b.bytes));
    indexed.into_iter().map(|(_, idx)| idx).collect()
}

/// Returns indices of entries sorted by (device, inode) for optimal I/O on HDDs.
///
/// On rotational storage, reading files in sequential inode order converts
/// random reads into sequential ones (2-5x speedup). On SSDs or when detection
/// fails, returns the identity ordering (sample check overhead only).
pub fn physical_read_order(entry_indices: &[usize], physical_files: &[PhysicalFile]) -> Vec<usize> {
    let rotational = stage_is_rotational(entry_indices, physical_files);
    order_for_read(entry_indices, physical_files, rotational)
}

#[derive(Debug)]
struct IndexedEntry {
    index: usize,
    path: Utf8PathBuf,
    size_bytes: u64,
}

// ── Stage 2.5: physical normalisation + size grouping ──

/// Normalises discovered entries into unique physical files, then groups by size.
///
/// Returns a `PhysicalFileReport` and a `CandidateReport`.
///
/// Pipeline:
/// 1. Keep only regular files. Separate zero-byte files into `EmptyFileGroup`.
/// 2. Extract `PhysicalFileKey` for each file. Deduplicate by key (overlapping roots).
/// 3. Group hardlinks (same key) under a single representative.
/// 4. Group representatives by size → `CandidateReport`.
pub fn build_candidate_groups(
    entries: &[DiscoveredEntry],
    progress: Option<&dyn ProgressReporter>,
    cancel: Option<&CancelFlag>,
) -> (PhysicalFileReport, CandidateReport) {
    if let Some(c) = cancel
        && c.is_cancelled()
    {
        return (
            PhysicalFileReport {
                physical_files: Vec::new(),
                hardlink_clusters: Vec::new(),
                empty_files: EmptyFileGroup {
                    entry_indices: Vec::new(),
                },
                duplicate_paths_removed: 0,
                overlapping_roots_resolved: false,
            },
            CandidateReport {
                size_groups: Vec::new(),
                hardlink_clusters: Vec::new(),
                empty_file_count: 0,
                skipped_solo: 0,
            },
        );
    }

    // Step 1: index regular files, separate zero-byte.
    let mut indexed: Vec<IndexedEntry> = Vec::new();
    let mut empty_indices: Vec<usize> = Vec::new();

    for (idx, entry) in entries.iter().enumerate() {
        if entry.kind != DiscoveredKind::File {
            continue;
        }
        let size = entry.size_bytes.unwrap_or(0);
        if size == 0 {
            empty_indices.push(idx);
        } else {
            indexed.push(IndexedEntry {
                index: idx,
                path: entry.path.clone(),
                size_bytes: size,
            });
        }
    }

    // Step 2: deduplicate by PhysicalFileKey (overlapping roots, same path).
    let mut seen_keys: HashMap<PhysicalFileKey, usize> = HashMap::new();
    let mut physical_files: Vec<PhysicalFile> = Vec::new();
    let mut duplicate_paths_removed = 0_usize;

    for ie in &indexed {
        // Discovery already captured the identity; stat() only as fallback
        // (entries built by hand or deserialized from old reports).
        let key = entries[ie.index]
            .physical_key
            .clone()
            .unwrap_or_else(|| extract_physical_file_key(&ie.path));
        if let Some(&existing_idx) = seen_keys.get(&key) {
            // Same physical file already registered → add to linked entries
            physical_files[existing_idx]
                .linked_entry_indices
                .push(ie.index);
            duplicate_paths_removed += 1;
        } else {
            let rep_index = physical_files.len();
            seen_keys.insert(key.clone(), rep_index);
            physical_files.push(PhysicalFile {
                representative_index: ie.index,
                linked_entry_indices: vec![ie.index],
                size_bytes: ie.size_bytes,
                physical_key: Some(key.clone()),
                canonical_path: ie.path.clone(),
                snapshot: FileSnapshot {
                    path: ie.path.clone(),
                    size_bytes: ie.size_bytes,
                    modified_unix_seconds: entries[ie.index].timestamps.modified_unix_seconds,
                    physical_key: Some(key),
                    version: FileVersion::from_timestamps(&entries[ie.index].timestamps),
                },
            });
        }
    }

    // Step 3: identify hardlink clusters (PhysicalFiles with multiple linked indices).
    let mut hardlink_clusters: Vec<HardlinkCluster> = Vec::new();
    for (i, pf) in physical_files.iter().enumerate() {
        if pf.linked_entry_indices.len() > 1 {
            hardlink_clusters.push(HardlinkCluster {
                cluster_id: i,
                entry_indices: pf.linked_entry_indices.clone(),
                canonical_path: pf.canonical_path.clone(),
            });
        }
    }

    // Step 4: group representatives by size.
    let mut size_map: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (pf_idx, pf) in physical_files.iter().enumerate() {
        size_map.entry(pf.size_bytes).or_default().push(pf_idx);
    }

    let mut skipped_solo = 0_usize;
    let size_groups: Vec<SizeGroup> = size_map
        .into_iter()
        .filter(|(_, indices)| {
            if indices.len() < 2 {
                skipped_solo += indices.len();
                false
            } else {
                true
            }
        })
        .map(|(size_bytes, physical_file_indices)| SizeGroup {
            size_bytes,
            entry_count: physical_file_indices.len(),
            physical_file_indices,
        })
        .collect();

    let physical_report = PhysicalFileReport {
        physical_files,
        hardlink_clusters: hardlink_clusters.clone(),
        empty_files: EmptyFileGroup {
            entry_indices: empty_indices,
        },
        duplicate_paths_removed,
        overlapping_roots_resolved: duplicate_paths_removed > 0,
    };

    let sg_len = size_groups.len() as u64;
    let candidate_report = CandidateReport {
        size_groups,
        hardlink_clusters,
        empty_file_count: physical_report.empty_files.entry_indices.len(),
        skipped_solo,
    };

    if let Some(p) = progress {
        p.emit(ProgressEvent {
            stage: ScanStage::SizeGrouping,
            current: sg_len,
            total: sg_len,
            current_file: None,
            bytes_processed: None,
            bytes_total: None,
        });
    }

    (physical_report, candidate_report)
}

/// Flushes hashes computed during a stage to the cache in one transaction.
fn flush_pending_puts(
    cache: Option<&zerodupe_cache::HashCache>,
    pending_puts: &[(HashCacheKey, String)],
) {
    if let Some(cache) = cache {
        // A failed flush only costs re-hashing next session.
        let _ = cache.put_batch(pending_puts);
    }
}

// ── Batched (optionally parallel) hashing machinery ──

/// Outcome of hashing one work item, in work-list order.
enum HashOutcome {
    /// Hash obtained — computed this session or served from the cache.
    Done { hash: String, was_cached: bool },
    /// The file failed (I/O error or TOCTTOU mismatch).
    Failed(HashError),
    /// Cancelled before this item was processed.
    Skipped,
}

/// Batch size: large enough to keep the thread pool busy, small enough to
/// keep cancellation and progress responsive between batches.
const HASH_BATCH: usize = 256;

fn make_cache_key(
    pf: &PhysicalFile,
    options: &HashingOptions,
    region: &HashRegion,
) -> HashCacheKey {
    HashCacheKey {
        physical_key: pf.physical_key.clone(),
        size_bytes: pf.size_bytes,
        version: pf.snapshot.version,
        hash_algorithm: options.hash_algorithm,
        region: region.clone(),
    }
}

fn io_to_hash_error(pf: &PhysicalFile, e: &std::io::Error) -> HashError {
    let kind = match e.kind() {
        std::io::ErrorKind::NotFound => HashErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => HashErrorKind::PermissionDenied,
        _ => HashErrorKind::Io,
    };
    HashError {
        entry_index: pf.representative_index,
        path: pf.canonical_path.as_str().to_string(),
        kind,
        message: e.to_string(),
    }
}

/// TOCTTOU check: size AND mtime must still match the discovery snapshot —
/// a file rewritten with the same size since discovery still moves its mtime.
fn snapshot_still_valid(pf: &PhysicalFile) -> Result<(), HashError> {
    let Ok(meta) = std::fs::symlink_metadata(pf.canonical_path.as_std_path()) else {
        return Ok(()); // disappearing files surface as read errors later
    };
    let current_size = meta.len();
    if current_size != pf.snapshot.size_bytes {
        return Err(HashError {
            entry_index: pf.representative_index,
            path: pf.canonical_path.as_str().to_string(),
            kind: HashErrorKind::FileChanged,
            message: format!(
                "size changed: {} → {}",
                pf.snapshot.size_bytes, current_size
            ),
        });
    }
    let current_mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_nanos()).ok());
    if let (Some(snap), Some(now)) = (pf.snapshot.version.mtime_nanos, current_mtime)
        && snap != now
    {
        return Err(HashError {
            entry_index: pf.representative_index,
            path: pf.canonical_path.as_str().to_string(),
            kind: HashErrorKind::FileChanged,
            message: format!("mtime changed: {snap} → {now}"),
        });
    }
    Ok(())
}

/// Hashes every work item (physical-file indices in stage order), returning
/// one outcome per item **in input order**.
///
/// Cache lookups and writes stay sequential — the SQLite connection is not
/// `Sync`, and they cost microseconds. Only the hashing of cache misses
/// goes to the Rayon pool; the order-preserving collect keeps the output
/// byte-identical to a sequential run. On rotational storage (or when
/// `options.parallel_hashing == Some(false)`) the misses are hashed
/// sequentially in the inode order the work list already has.
///
/// Cancellation is honoured at batch boundaries, at the start of every
/// file, and between 64 KB chunks inside full-region hashes.
#[allow(clippy::too_many_arguments)]
fn hash_stage_batched(
    work: &[usize],
    physical_files: &[PhysicalFile],
    options: &HashingOptions,
    region: &HashRegion,
    verify: bool,
    parallel: bool,
    cache: Option<&zerodupe_cache::HashCache>,
    stage: ScanStage,
    progress_offset: u64,
    progress_total: u64,
    progress: Option<&dyn ProgressReporter>,
    cancel: Option<&CancelFlag>,
) -> Vec<HashOutcome> {
    use rayon::prelude::*;

    let mut outcomes: Vec<HashOutcome> = Vec::with_capacity(work.len());
    let mut pending_puts: Vec<(HashCacheKey, String)> = Vec::new();

    'batches: for batch in work.chunks(HASH_BATCH) {
        if cancel.is_some_and(|c| c.is_cancelled()) {
            break 'batches;
        }

        // 1. Sequential cache lookups; misses are queued for hashing.
        let mut slots: Vec<Option<HashOutcome>> = Vec::with_capacity(batch.len());
        let mut misses: Vec<usize> = Vec::new();
        for (pos, &pf_idx) in batch.iter().enumerate() {
            let hit = cache.and_then(|c| {
                c.get(&make_cache_key(&physical_files[pf_idx], options, region))
                    .ok()
                    .flatten()
            });
            match hit {
                Some(hash) => slots.push(Some(HashOutcome::Done {
                    hash,
                    was_cached: true,
                })),
                None => {
                    slots.push(None);
                    misses.push(pos);
                }
            }
        }

        // 2. Hash the misses.
        let compute = |&pos: &usize| -> (usize, HashOutcome) {
            let pf = &physical_files[batch[pos]];
            if cancel.is_some_and(|c| c.is_cancelled()) {
                return (pos, HashOutcome::Skipped);
            }
            if verify && let Err(e) = snapshot_still_valid(pf) {
                return (pos, HashOutcome::Failed(e));
            }
            match zerodupe_hash::hash_file_region_cancellable(
                pf.canonical_path.as_std_path(),
                region,
                cancel,
            ) {
                Ok(hash) => (
                    pos,
                    HashOutcome::Done {
                        hash: hash.to_hex(),
                        was_cached: false,
                    },
                ),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    (pos, HashOutcome::Skipped)
                }
                Err(e) => (pos, HashOutcome::Failed(io_to_hash_error(pf, &e))),
            }
        };
        let computed: Vec<(usize, HashOutcome)> = if parallel {
            misses.par_iter().map(compute).collect()
        } else {
            misses.iter().map(compute).collect()
        };

        // 3. Stitch results back in order, queue cache writes, report.
        for (pos, outcome) in computed {
            if cache.is_some()
                && let HashOutcome::Done {
                    hash,
                    was_cached: false,
                } = &outcome
            {
                pending_puts.push((
                    make_cache_key(&physical_files[batch[pos]], options, region),
                    hash.clone(),
                ));
            }
            slots[pos] = Some(outcome);
        }
        for (pos, slot) in slots.into_iter().enumerate() {
            let outcome = slot.unwrap_or(HashOutcome::Skipped);
            if !matches!(outcome, HashOutcome::Skipped)
                && let Some(p) = progress
            {
                p.emit(ProgressEvent {
                    stage,
                    current: progress_offset + outcomes.len() as u64 + 1,
                    total: progress_total,
                    current_file: Some(
                        physical_files[batch[pos]]
                            .canonical_path
                            .as_str()
                            .to_string(),
                    ),
                    bytes_processed: None,
                    bytes_total: None,
                });
            }
            outcomes.push(outcome);
        }
    }

    outcomes.resize_with(work.len(), || HashOutcome::Skipped);
    flush_pending_puts(cache, &pending_puts);
    outcomes
}

// ── Stage 3.5: partial hashing (head + tail) ──

/// Runs partial BLAKE3 hashing on the physical-file representatives
/// identified by the candidate size groups.
///
/// Uses `HashingOptions` to build the `HashRegion` (default: HeadTail 4 KB).
/// If `cache` is provided, cached hashes are reused when the file mtime hasn't changed.
/// Files are grouped by their combined partial hash.
/// Singletons are eliminated; remaining groups are promoted to full hash.
pub fn partial_hash_groups(
    physical_files: &[PhysicalFile],
    candidates: &CandidateReport,
    options: &HashingOptions,
    cache: Option<&zerodupe_cache::HashCache>,
    progress: Option<&dyn ProgressReporter>,
    cancel: Option<&CancelFlag>,
) -> PartialHashReport {
    let mut report = PartialHashReport {
        groups: Vec::new(),
        eliminated_by_partial: 0,
        promoted_to_full: 0,
        hash_errors: Vec::new(),
    };

    let region = hash_region_from_options(options);

    // One storage-type decision for the whole stage: rotational → inode
    // order + sequential; otherwise identity order + parallel.
    let sample: Vec<usize> = candidates
        .size_groups
        .iter()
        .flat_map(|g| g.physical_file_indices.iter().copied())
        .take(3)
        .collect();
    let rotational = stage_is_rotational(&sample, physical_files);
    let parallel = options.parallel_hashing.unwrap_or(!rotational);

    // Flat work list: groups in candidate order, files in physical read
    // order within each group. Spans remember each group's slice.
    let mut work: Vec<usize> = Vec::new();
    let mut spans: Vec<(u64, std::ops::Range<usize>)> = Vec::new();
    for size_group in &candidates.size_groups {
        if size_group.entry_count < 2 {
            continue;
        }
        let start = work.len();
        work.extend(order_for_read(
            &size_group.physical_file_indices,
            physical_files,
            rotational,
        ));
        spans.push((size_group.size_bytes, start..work.len()));
    }

    let outcomes = hash_stage_batched(
        &work,
        physical_files,
        options,
        &region,
        false,
        parallel,
        cache,
        ScanStage::PartialHash,
        0,
        work.len() as u64,
        progress,
        cancel,
    );

    for (size_bytes, span) in spans {
        // A cancelled stage leaves whole groups unprocessed — drop them
        // silently, like the per-group early-exit used to.
        if outcomes[span.clone()]
            .iter()
            .any(|o| matches!(o, HashOutcome::Skipped))
        {
            continue;
        }

        // (physical file index, was_cached)
        let mut partial_map: HashMap<String, Vec<(usize, bool)>> = HashMap::new();
        for i in span {
            match &outcomes[i] {
                HashOutcome::Done { hash, was_cached } => {
                    partial_map
                        .entry(hash.clone())
                        .or_default()
                        .push((work[i], *was_cached));
                }
                HashOutcome::Failed(e) => report.hash_errors.push(e.clone()),
                HashOutcome::Skipped => unreachable!("skipped groups are dropped above"),
            }
        }

        for (partial_hash, members) in partial_map {
            let count = members.len();
            if count < 2 {
                report.eliminated_by_partial += count;
            } else {
                let any_cached = members.iter().any(|(_, was_cached)| *was_cached);
                report.groups.push(HashGroup {
                    size_bytes,
                    partial_hash,
                    physical_file_indices: members.into_iter().map(|(idx, _)| idx).collect(),
                    any_cached,
                });
                report.promoted_to_full += count;
            }
        }
    }

    report
}

/// True if the partial region read every byte of a file of `size` bytes.
///
/// When it did, the partial hash has the same discriminating power as the
/// full hash (it hashed the whole content in order — proven by the sentinel
/// test `head_tail_equals_full_when_file_fits_in_regions`), so stage 4 can
/// promote the group without reading the files again.
fn region_covers(region: &HashRegion, size: u64) -> bool {
    match region {
        HashRegion::Full => true,
        HashRegion::Prefix { bytes } => size <= *bytes as u64,
        HashRegion::HeadTail {
            head_bytes,
            tail_bytes,
        } => size <= (*head_bytes as u64) + (*tail_bytes as u64),
        // Suffix/Sampled never guarantee full coverage in reading order.
        HashRegion::Suffix { .. } | HashRegion::Sampled { .. } => false,
    }
}

// ── Stage 4: full hashing + exact grouping ──

/// Runs full BLAKE3 hashing on the groups promoted by partial hashing.
///
/// For each `HashGroup` in the partial report, hashes every physical-file
/// representative fully. Groups by full hash. Files matching at this stage
/// are candidate exact duplicates (pending byte-by-byte confirmation).
///
/// If `cache` is provided, full hashes are cached and reused on subsequent scans.
/// TOCTTOU: before hashing, verifies the file snapshot matches current metadata.
pub fn full_hash_groups(
    physical_files: &[PhysicalFile],
    partial_report: &PartialHashReport,
    options: &HashingOptions,
    cache: Option<&zerodupe_cache::HashCache>,
    progress: Option<&dyn ProgressReporter>,
    cancel: Option<&CancelFlag>,
) -> FullHashReport {
    let mut report = FullHashReport {
        groups: Vec::new(),
        eliminated_by_full: 0,
        confirmed_duplicates: 0,
        hash_errors: Vec::new(),
        cache_hits: 0,
        cache_misses: 0,
        covered_by_partial: 0,
    };

    let full_region = HashRegion::Full;
    let partial_region = hash_region_from_options(options);

    // One storage-type decision for the whole stage (see partial stage).
    let sample: Vec<usize> = partial_report
        .groups
        .iter()
        .flat_map(|g| g.physical_file_indices.iter().copied())
        .take(3)
        .collect();
    let rotational = stage_is_rotational(&sample, physical_files);
    let parallel = options.parallel_hashing.unwrap_or(!rotational);

    // First pass: promote covered groups (the partial hash already read
    // every byte — equal partial hash ⇒ equal content) and build the flat
    // work list for the rest.
    let mut work: Vec<usize> = Vec::new();
    let mut spans: Vec<(u64, std::ops::Range<usize>)> = Vec::new();
    for hash_group in &partial_report.groups {
        if hash_group.physical_file_indices.len() < 2 {
            continue;
        }

        if region_covers(&partial_region, hash_group.size_bytes) {
            let files: Vec<FileCandidate> = hash_group
                .physical_file_indices
                .iter()
                .map(|&pf_idx| FileCandidate {
                    path: physical_files[pf_idx].canonical_path.clone(),
                    size_bytes: hash_group.size_bytes,
                })
                .collect();
            report.covered_by_partial += files.len();
            report.groups.push(ExactDuplicateGroup {
                id: GroupId::new(),
                size_bytes: hash_group.size_bytes,
                files,
                any_cached: hash_group.any_cached,
            });
            report.confirmed_duplicates += 1;
            continue;
        }

        let start = work.len();
        work.extend(order_for_read(
            &hash_group.physical_file_indices,
            physical_files,
            rotational,
        ));
        spans.push((hash_group.size_bytes, start..work.len()));
    }

    let covered = report.covered_by_partial as u64;
    let outcomes = hash_stage_batched(
        &work,
        physical_files,
        options,
        &full_region,
        options.verify_after_read,
        parallel,
        cache,
        ScanStage::FullHash,
        covered,
        covered + work.len() as u64,
        progress,
        cancel,
    );

    for (size_bytes, span) in spans {
        if outcomes[span.clone()]
            .iter()
            .any(|o| matches!(o, HashOutcome::Skipped))
        {
            continue;
        }

        // (entry index, canonical path, was_cached)
        let mut full_map: HashMap<String, Vec<(usize, String, bool)>> = HashMap::new();
        for i in span {
            let pf = &physical_files[work[i]];
            match &outcomes[i] {
                HashOutcome::Done { hash, was_cached } => {
                    if *was_cached {
                        report.cache_hits += 1;
                    } else {
                        report.cache_misses += 1;
                    }
                    full_map.entry(hash.clone()).or_default().push((
                        pf.representative_index,
                        pf.canonical_path.as_str().to_string(),
                        *was_cached,
                    ));
                }
                HashOutcome::Failed(e) => report.hash_errors.push(e.clone()),
                HashOutcome::Skipped => unreachable!("skipped groups are dropped above"),
            }
        }

        for (_full_hash, file_tuples) in full_map {
            if file_tuples.len() < 2 {
                report.eliminated_by_full += file_tuples.len();
            } else {
                let any_cached = file_tuples.iter().any(|(_, _, was_cached)| *was_cached);
                let files: Vec<FileCandidate> = file_tuples
                    .into_iter()
                    .map(|(_idx, path, _)| FileCandidate {
                        path: Utf8PathBuf::from(path),
                        size_bytes,
                    })
                    .collect();
                report.groups.push(ExactDuplicateGroup {
                    id: GroupId::new(),
                    size_bytes,
                    files,
                    any_cached,
                });
                report.confirmed_duplicates += 1;
            }
        }
    }

    report
}

// ── Stage 5: byte-by-byte verification ──

/// Verifies each `ExactDuplicateGroup` according to `mode`.
///
/// A BLAKE3 collision is not a practical risk; the real risk is a stale
/// cached hash. With `VerifyMode::CachedOnly` (the default) only groups
/// where some hash came from the cache are compared byte by byte — fresh
/// groups are trusted, so a fresh scan pays no extra I/O.
///
/// If a member of a cached group fails comparison, that proves the cache
/// lied: the physical keys of the whole group are reported in
/// `stale_cache_keys` so the caller can purge them.
///
/// Also computes a keeper recommendation using the default `KeeperPolicy`.
const BYTE_COMPARE_CHUNK: usize = 65536;

pub fn byte_compare_groups(
    full_report: &FullHashReport,
    entries: &[DiscoveredEntry],
    physical_files: &[PhysicalFile],
    mode: VerifyMode,
    progress: Option<&dyn ProgressReporter>,
    cancel: Option<&CancelFlag>,
) -> ByteCompareReport {
    use zerodupe_policy::{EntryIndex, KeeperPolicy, KeeperStrategy, select_keeper_index_with};

    let profile = zerodupe_platform::current();
    let policy = KeeperPolicy::default();
    // One index for every group: keeper selection without it scans the
    // whole entry list per candidate — O(groups × entries).
    let entry_index = EntryIndex::new(entries);
    let mut report = ByteCompareReport {
        confirmed_groups: Vec::new(),
        eliminated_by_compare: 0,
        false_positive_groups: 0,
        compare_errors: Vec::new(),
        groups_trusted: 0,
        stale_cache_keys: Vec::new(),
    };

    let key_by_path: HashMap<&str, &PhysicalFileKey> = physical_files
        .iter()
        .filter_map(|pf| Some((pf.canonical_path.as_str(), pf.physical_key.as_ref()?)))
        .collect();

    let total_groups = full_report.groups.len() as u64;
    let mut group_count: u64 = 0;

    for group in &full_report.groups {
        if group.files.len() < 2 {
            continue;
        }

        if let Some(c) = cancel
            && c.is_cancelled()
        {
            return report;
        }

        let skip_compare = match mode {
            VerifyMode::Never => true,
            VerifyMode::CachedOnly => !group.any_cached,
            VerifyMode::Always => false,
        };

        let (confirmed, false_positives) = if skip_compare {
            report.groups_trusted += 1;
            (group.files.clone(), Vec::new())
        } else {
            let reference = &group.files[0];
            let mut confirmed = vec![reference.clone()];
            let mut false_positives = Vec::new();

            for candidate in &group.files[1..] {
                match compare_two_files(reference, candidate) {
                    Ok(true) => confirmed.push(candidate.clone()),
                    Ok(false) => {
                        false_positives.push(candidate.clone());
                        report.eliminated_by_compare += 1;
                    }
                    Err(e) => {
                        report.compare_errors.push(HashError {
                            entry_index: 0,
                            path: candidate.path.as_str().to_string(),
                            kind: HashErrorKind::Io,
                            message: e.to_string(),
                        });
                    }
                }
            }

            // A mismatch in a cached group proves a stale cached hash. We
            // can't tell which member's hash lied, so purge them all.
            if group.any_cached && !false_positives.is_empty() {
                report.stale_cache_keys.extend(
                    group
                        .files
                        .iter()
                        .filter_map(|f| key_by_path.get(f.path.as_str()).map(|&k| k.clone())),
                );
            }
            (confirmed, false_positives)
        };

        if confirmed.len() < 2 {
            report.false_positive_groups += 1;
            group_count += 1;
            continue;
        }

        // Compute keeper recommendation
        let keeper_idx = select_keeper_index_with(
            profile,
            &confirmed,
            &entry_index,
            KeeperStrategy::LetZeroDupeDecide,
            &policy,
        );
        let keeper_path = confirmed[keeper_idx].path.clone();

        report.confirmed_groups.push(ByteCompareGroup {
            size_bytes: group.size_bytes,
            files: confirmed,
            false_positives,
            keeper_index: keeper_idx,
            keeper_path,
        });

        group_count += 1;
        if let Some(p) = progress {
            p.emit(ProgressEvent {
                stage: ScanStage::ByteCompare,
                current: group_count,
                total: total_groups,
                current_file: None,
                bytes_processed: None,
                bytes_total: None,
            });
        }
    }

    report
}

/// Compares two files byte by byte in 64 KB chunks.
/// Returns `Ok(true)` if identical, `Ok(false)` if different.
fn compare_two_files(
    reference: &FileCandidate,
    candidate: &FileCandidate,
) -> std::io::Result<bool> {
    use std::io::Read;

    let mut f1 = std::fs::File::open(reference.path.as_std_path())?;
    let mut f2 = std::fs::File::open(candidate.path.as_std_path())?;

    let mut buf1 = vec![0u8; BYTE_COMPARE_CHUNK];
    let mut buf2 = vec![0u8; BYTE_COMPARE_CHUNK];

    loop {
        let n1 = f1.read(&mut buf1)?;
        let n2 = f2.read(&mut buf2)?;

        if n1 != n2 {
            return Ok(false);
        }
        if n1 == 0 {
            return Ok(true); // both reached EOF
        }
        if buf1[..n1] != buf2[..n1] {
            return Ok(false);
        }
    }
}

/// Builds a `HashRegion` from `HashingOptions`.
fn hash_region_from_options(options: &HashingOptions) -> HashRegion {
    match options.partial_strategy {
        zerodupe_core::PartialStrategy::HeadOnly => HashRegion::Prefix {
            bytes: options.partial_chunk_size,
        },
        zerodupe_core::PartialStrategy::HeadTail => HashRegion::HeadTail {
            head_bytes: options.partial_chunk_size,
            tail_bytes: options.partial_chunk_size,
        },
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use zerodupe_core::{DiscoveredKind, FileTimestamps, RootId};

    fn make_file(path: &str, size: u64) -> DiscoveredEntry {
        DiscoveredEntry {
            root_id: RootId(0),
            path: Utf8PathBuf::from(path),
            kind: DiscoveredKind::File,
            depth: 1,
            size_bytes: Some(size),
            readonly: false,
            timestamps: FileTimestamps::default(),
            physical_key: None,
        }
    }

    fn make_dir(path: &str) -> DiscoveredEntry {
        DiscoveredEntry {
            root_id: RootId(0),
            path: Utf8PathBuf::from(path),
            kind: DiscoveredKind::Directory,
            depth: 1,
            size_bytes: None,
            readonly: false,
            timestamps: FileTimestamps::default(),
            physical_key: None,
        }
    }

    // ── Physical normalisation tests ──

    #[test]
    fn normalises_files_and_separates_zero_byte() {
        let entries = vec![
            make_file("/a/empty.txt", 0),
            make_file("/a/data.txt", 100),
            make_file("/a/also_empty", 0),
        ];
        let (phys, cand) = build_candidate_groups(&entries, None, None);
        assert_eq!(phys.empty_files.entry_indices.len(), 2);
        assert_eq!(phys.physical_files.len(), 1);
        assert_eq!(cand.skipped_solo, 1);
    }

    #[test]
    fn skips_directories_and_symlinks() {
        let entries = vec![
            make_dir("/a"),
            make_file("/a/f1.txt", 100),
            make_file("/a/f2.txt", 100),
        ];
        let (phys, cand) = build_candidate_groups(&entries, None, None);
        assert_eq!(phys.physical_files.len(), 2);
        assert_eq!(cand.size_groups.len(), 1);
        assert_eq!(cand.size_groups[0].entry_count, 2);
    }

    #[test]
    fn groups_files_by_size() {
        let entries = vec![
            make_file("/a/big.txt", 1000),
            make_file("/b/big_copy.txt", 1000),
            make_file("/a/small.txt", 50),
            make_file("/b/small_copy.txt", 50),
            make_file("/a/medium.txt", 200),
        ];
        let (_phys, cand) = build_candidate_groups(&entries, None, None);
        assert_eq!(cand.skipped_solo, 1); // medium (200) is solo
        assert_eq!(cand.size_groups.len(), 2);
        assert_eq!(cand.multi_entry_groups(), 2);
        assert_eq!(cand.total_candidates(), 4);
    }

    #[test]
    fn solo_files_are_skipped() {
        let entries = vec![
            make_file("/unique.txt", 9999),
            make_file("/a/dup1.txt", 42),
            make_file("/b/dup2.txt", 42),
        ];
        let (_phys, cand) = build_candidate_groups(&entries, None, None);
        assert_eq!(cand.skipped_solo, 1);
        assert_eq!(cand.size_groups.len(), 1);
        assert_eq!(cand.size_groups[0].size_bytes, 42);
    }

    #[test]
    fn empty_entries_yields_empty_report() {
        let (phys, cand) = build_candidate_groups(&[], None, None);
        assert_eq!(phys.physical_files.len(), 0);
        assert_eq!(cand.total_candidates(), 0);
        assert_eq!(cand.multi_entry_groups(), 0);
    }

    #[test]
    fn overlapping_paths_deduplicated_by_physical_key() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("shared.txt");
        fs::write(&path, b"same file twice").expect("write");

        let e1 = DiscoveredEntry {
            root_id: RootId(0),
            path: Utf8PathBuf::from_path_buf(path.clone()).expect("utf8"),
            kind: DiscoveredKind::File,
            depth: 1,
            size_bytes: Some(15),
            readonly: false,
            timestamps: FileTimestamps::default(),
            physical_key: None,
        };
        let e2 = DiscoveredEntry {
            root_id: RootId(1), // different root
            path: Utf8PathBuf::from_path_buf(path).expect("utf8"),
            kind: DiscoveredKind::File,
            depth: 1,
            size_bytes: Some(15),
            readonly: false,
            timestamps: FileTimestamps::default(),
            physical_key: None,
        };

        let entries = vec![e1, e2];
        let (phys, _cand) = build_candidate_groups(&entries, None, None);
        assert_eq!(phys.physical_files.len(), 1);
        assert_eq!(phys.duplicate_paths_removed, 1);
        assert!(phys.overlapping_roots_resolved);
        assert_eq!(phys.physical_files[0].linked_entry_indices.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn detects_real_hardlinks() {
        let temp = tempfile::tempdir().expect("tempdir");
        let original = temp.path().join("original.txt");
        let link = temp.path().join("link.txt");
        fs::write(&original, b"hardlinked content").expect("write");
        fs::hard_link(&original, &link).expect("hard link");

        let e1 = DiscoveredEntry {
            root_id: RootId(0),
            path: Utf8PathBuf::from_path_buf(original).expect("utf8"),
            kind: DiscoveredKind::File,
            depth: 1,
            size_bytes: Some(18),
            readonly: false,
            timestamps: FileTimestamps::default(),
            physical_key: None,
        };
        let e2 = DiscoveredEntry {
            root_id: RootId(0),
            path: Utf8PathBuf::from_path_buf(link).expect("utf8"),
            kind: DiscoveredKind::File,
            depth: 1,
            size_bytes: Some(18),
            readonly: false,
            timestamps: FileTimestamps::default(),
            physical_key: None,
        };

        let entries = vec![e1, e2];
        let (phys, _cand) = build_candidate_groups(&entries, None, None);

        assert_eq!(phys.physical_files.len(), 1);
        assert_eq!(phys.hardlink_clusters.len(), 1);
        assert_eq!(phys.hardlink_clusters[0].entry_indices.len(), 2);
    }

    // ── Partial hashing tests ──

    fn setup_test_files(
        specs: &[(&str, &[u8])],
    ) -> (
        tempfile::TempDir,
        Vec<DiscoveredEntry>,
        PhysicalFileReport,
        CandidateReport,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut entries = Vec::new();

        for (name, data) in specs {
            let path = dir.path().join(name);
            fs::write(&path, data).expect("write");
            // Real timestamps: a file without an mtime witness is treated
            // as uncacheable, so cache-dependent tests need genuine ones.
            let meta = fs::metadata(&path).expect("metadata");
            let mtime_nanos = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|d| i64::try_from(d.as_nanos()).ok());
            let utf8_path = Utf8PathBuf::from_path_buf(path).expect("utf8");
            let physical_key = zerodupe_platform::current().physical_key(&utf8_path, &meta);
            entries.push(DiscoveredEntry {
                root_id: RootId(0),
                path: utf8_path,
                kind: DiscoveredKind::File,
                depth: 1,
                size_bytes: Some(data.len() as u64),
                readonly: false,
                timestamps: FileTimestamps {
                    modified_unix_seconds: mtime_nanos.map(|n| n / 1_000_000_000),
                    modified_unix_nanos: mtime_nanos,
                    changed_unix_nanos: zerodupe_platform::change_time_nanos(&meta),
                    created_unix_seconds: None,
                },
                physical_key,
            });
        }

        let (phys, cand) = build_candidate_groups(&entries, None, None);
        (dir, entries, phys, cand)
    }

    #[test]
    fn partial_hash_keeps_identical_small_files() {
        let (_dir, _entries, phys, cand) = setup_test_files(&[
            ("a.txt", b"hello"),
            ("b.txt", b"hello"),
            ("c.txt", b"world"),
        ]);

        let report = partial_hash_groups(
            &phys.physical_files,
            &cand,
            &HashingOptions::default(),
            None,
            None,
            None,
        );

        assert_eq!(report.eliminated_by_partial, 1);
        assert_eq!(report.promoted_to_full, 2);
        assert_eq!(report.groups.len(), 1);
    }

    #[test]
    fn partial_hash_eliminates_same_size_different_head() {
        let (_dir, _entries, phys, cand) =
            setup_test_files(&[("a.txt", b"AAAA"), ("b.txt", b"BBBB")]);

        let report = partial_hash_groups(
            &phys.physical_files,
            &cand,
            &HashingOptions::default(),
            None,
            None,
            None,
        );

        assert_eq!(report.eliminated_by_partial, 2);
        assert_eq!(report.promoted_to_full, 0);
        assert!(report.groups.is_empty());
    }

    #[test]
    fn partial_hash_eliminates_by_tail() {
        // Same head, different tail
        let head = vec![b'A'; 4096];
        let mut data_a = head.clone();
        data_a.extend_from_slice(b"TAIL_A_1234");
        let mut data_b = head.clone();
        data_b.extend_from_slice(b"TAIL_B_5678");

        let (_dir, _entries, phys, cand) =
            setup_test_files(&[("a.bin", &data_a), ("b.bin", &data_b)]);

        let report = partial_hash_groups(
            &phys.physical_files,
            &cand,
            &HashingOptions::default(),
            None,
            None,
            None,
        );

        assert_eq!(report.eliminated_by_partial, 2);
        assert!(report.groups.is_empty());
    }

    #[test]
    fn partial_hash_large_identical_files_promoted() {
        let data = vec![b'Z'; 20000];
        let (_dir, _entries, phys, cand) = setup_test_files(&[("a.bin", &data), ("b.bin", &data)]);

        let report = partial_hash_groups(
            &phys.physical_files,
            &cand,
            &HashingOptions::default(),
            None,
            None,
            None,
        );

        assert_eq!(report.promoted_to_full, 2);
        assert_eq!(report.groups.len(), 1);
    }

    #[test]
    fn partial_hash_errors_on_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ghost.txt");
        fs::write(&path, b"data").expect("write");

        let e1 = DiscoveredEntry {
            root_id: RootId(0),
            path: Utf8PathBuf::from_path_buf(path.clone()).expect("utf8"),
            kind: DiscoveredKind::File,
            depth: 1,
            size_bytes: Some(4),
            readonly: false,
            timestamps: FileTimestamps::default(),
            physical_key: None,
        };
        // Second file so it's not solo-skipped
        let e2 = DiscoveredEntry {
            root_id: RootId(0),
            path: Utf8PathBuf::from_path_buf(dir.path().join("keep.txt")).expect("utf8"),
            kind: DiscoveredKind::File,
            depth: 1,
            size_bytes: Some(4),
            readonly: false,
            timestamps: FileTimestamps::default(),
            physical_key: None,
        };
        fs::write(dir.path().join("keep.txt"), b"keep").expect("write");

        // Delete ghost so hashing fails
        fs::remove_file(&path).expect("remove");

        let entries = vec![e1, e2];
        let (phys, cand) = build_candidate_groups(&entries, None, None);
        let report = partial_hash_groups(
            &phys.physical_files,
            &cand,
            &HashingOptions::default(),
            None,
            None,
            None,
        );

        assert_eq!(report.hash_errors.len(), 1);
        assert_eq!(report.hash_errors[0].kind, HashErrorKind::NotFound);
    }

    #[test]
    fn partial_hash_empty_candidates_yields_empty_report() {
        let candidates = CandidateReport {
            size_groups: vec![],
            hardlink_clusters: vec![],
            empty_file_count: 0,
            skipped_solo: 0,
        };
        let report = partial_hash_groups(
            &[],
            &candidates,
            &HashingOptions::default(),
            None,
            None,
            None,
        );
        assert!(report.is_empty());
        assert_eq!(report.total_remaining(), 0);
    }

    // ── Stage 4: full hash tests ──

    #[test]
    fn full_hash_groups_identical_files() {
        let data = vec![b'X'; 100];
        let (_dir, _entries, phys, cand) = setup_test_files(&[("a.bin", &data), ("b.bin", &data)]);
        let partial = partial_hash_groups(
            &phys.physical_files,
            &cand,
            &HashingOptions::default(),
            None,
            None,
            None,
        );
        let full = full_hash_groups(
            &phys.physical_files,
            &partial,
            &HashingOptions::default(),
            None,
            None,
            None,
        );
        assert_eq!(full.groups.len(), 1);
        assert_eq!(full.groups[0].files.len(), 2);
        assert_eq!(full.confirmed_duplicates, 1);
        assert_eq!(full.eliminated_by_full, 0);
    }

    #[test]
    fn full_hash_groups_different_content_same_partial() {
        // Same size, same head+tail, different middle → partial groups, full separates
        let head = vec![b'A'; 4096];
        let tail = vec![b'C'; 4096];
        let middle_a = vec![b'X'; 8192];
        let middle_b = vec![b'Y'; 8192];

        let mut data_a = head.clone();
        data_a.extend_from_slice(&middle_a);
        data_a.extend_from_slice(&tail);
        let mut data_b = head.clone();
        data_b.extend_from_slice(&middle_b);
        data_b.extend_from_slice(&tail);

        let (_dir, _entries, phys, cand) =
            setup_test_files(&[("a.bin", &data_a), ("b.bin", &data_b)]);
        let partial = partial_hash_groups(
            &phys.physical_files,
            &cand,
            &HashingOptions::default(),
            None,
            None,
            None,
        );
        // Both pass partial (same head+tail)
        assert_eq!(partial.promoted_to_full, 2);
        // Full should separate them
        let full = full_hash_groups(
            &phys.physical_files,
            &partial,
            &HashingOptions::default(),
            None,
            None,
            None,
        );
        assert_eq!(full.groups.len(), 0);
        assert_eq!(full.eliminated_by_full, 2);
    }

    #[test]
    fn full_hash_groups_empty_partial_yields_empty_full() {
        let partial = PartialHashReport {
            groups: vec![],
            eliminated_by_partial: 0,
            promoted_to_full: 0,
            hash_errors: vec![],
        };
        let full = full_hash_groups(&[], &partial, &HashingOptions::default(), None, None, None);
        assert!(full.is_empty());
        assert_eq!(full.total_files(), 0);
    }

    #[test]
    fn full_hash_groups_with_cache_caches_results() {
        // > head+tail so the files actually reach full hashing (smaller
        // ones are promoted by the covered-by-partial shortcut).
        let data = vec![b'Z'; 10_000];
        let (_dir, _entries, phys, cand) = setup_test_files(&[("a.bin", &data), ("b.bin", &data)]);
        let partial = partial_hash_groups(
            &phys.physical_files,
            &cand,
            &HashingOptions::default(),
            None,
            None,
            None,
        );

        let cache = zerodupe_cache::HashCache::open_memory().expect("cache");

        // First call: cache miss
        let full1 = full_hash_groups(
            &phys.physical_files,
            &partial,
            &HashingOptions::default(),
            Some(&cache),
            None,
            None,
        );
        assert_eq!(full1.cache_misses, 2);
        assert_eq!(full1.cache_hits, 0);

        // Second call: cache hit (same mtime = None in our test entries)
        let full2 = full_hash_groups(
            &phys.physical_files,
            &partial,
            &HashingOptions::default(),
            Some(&cache),
            None,
            None,
        );
        assert_eq!(full2.cache_hits, 2);
        assert_eq!(full2.cache_misses, 0);
        assert_eq!(full2.groups.len(), 1);
    }

    #[test]
    fn small_files_promoted_without_full_hashing() {
        // 1 KB ≤ head+tail (8 KB): the partial hash covered every byte, so
        // stage 4 must promote the group without reading the files again.
        let data = vec![b'S'; 1000];
        let (_dir, _entries, phys, cand) = setup_test_files(&[("a.bin", &data), ("b.bin", &data)]);
        let partial = partial_hash_groups(
            &phys.physical_files,
            &cand,
            &HashingOptions::default(),
            None,
            None,
            None,
        );
        let full = full_hash_groups(
            &phys.physical_files,
            &partial,
            &HashingOptions::default(),
            None,
            None,
            None,
        );
        assert_eq!(full.groups.len(), 1);
        assert_eq!(full.groups[0].files.len(), 2);
        assert_eq!(full.covered_by_partial, 2);
        assert_eq!(full.cache_hits + full.cache_misses, 0, "no full hashing");
    }

    #[test]
    fn large_files_still_fully_hashed() {
        let data = vec![b'L'; 10_000]; // > head+tail
        let (_dir, _entries, phys, cand) = setup_test_files(&[("a.bin", &data), ("b.bin", &data)]);
        let partial = partial_hash_groups(
            &phys.physical_files,
            &cand,
            &HashingOptions::default(),
            None,
            None,
            None,
        );
        let full = full_hash_groups(
            &phys.physical_files,
            &partial,
            &HashingOptions::default(),
            None,
            None,
            None,
        );
        assert_eq!(full.groups.len(), 1);
        assert_eq!(full.covered_by_partial, 0);
    }

    #[test]
    fn region_covers_matches_partial_semantics() {
        let head_tail = HashRegion::HeadTail {
            head_bytes: 4096,
            tail_bytes: 4096,
        };
        assert!(region_covers(&head_tail, 1));
        assert!(region_covers(&head_tail, 8192));
        assert!(!region_covers(&head_tail, 8193));
        assert!(region_covers(&HashRegion::Prefix { bytes: 4096 }, 4096));
        assert!(!region_covers(&HashRegion::Prefix { bytes: 4096 }, 4097));
        assert!(region_covers(&HashRegion::Full, u64::MAX));
        assert!(!region_covers(&HashRegion::Suffix { bytes: 4096 }, 100));
    }

    #[test]
    fn tocttou_detects_mtime_change_with_same_size() {
        let data = vec![b'T'; 20_000];
        let (dir, _entries, phys, cand) = setup_test_files(&[("a.bin", &data), ("b.bin", &data)]);

        // Rewrite b with identical content AFTER the snapshot: same size,
        // same bytes, but the mtime moved — the old size-only check was
        // blind to this.
        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(dir.path().join("b.bin"), &data).expect("rewrite");

        let options = HashingOptions {
            verify_after_read: true,
            ..Default::default()
        };
        let partial = partial_hash_groups(&phys.physical_files, &cand, &options, None, None, None);
        let full = full_hash_groups(&phys.physical_files, &partial, &options, None, None, None);
        assert_eq!(full.hash_errors.len(), 1, "rewritten file must be flagged");
        assert_eq!(full.hash_errors[0].kind, HashErrorKind::FileChanged);
        assert!(full.hash_errors[0].message.contains("mtime"));
        assert_eq!(full.groups.len(), 0, "survivor is a singleton");
    }

    // ── Stage 5: byte compare tests ──

    #[test]
    fn byte_compare_confirms_identical_files() {
        let data = vec![b'X'; 100];
        let (_dir, entries, phys, cand) = setup_test_files(&[("a.bin", &data), ("b.bin", &data)]);
        let partial = partial_hash_groups(
            &phys.physical_files,
            &cand,
            &HashingOptions::default(),
            None,
            None,
            None,
        );
        let full = full_hash_groups(
            &phys.physical_files,
            &partial,
            &HashingOptions::default(),
            None,
            None,
            None,
        );
        let compare = byte_compare_groups(
            &full,
            &entries,
            &phys.physical_files,
            VerifyMode::Always,
            None,
            None,
        );
        assert_eq!(compare.confirmed_groups.len(), 1);
        assert_eq!(compare.confirmed_groups[0].files.len(), 2);
        assert_eq!(compare.false_positive_groups, 0);
        assert_eq!(compare.eliminated_by_compare, 0);
    }

    #[test]
    fn byte_compare_rejects_different_files() {
        let (_dir, entries, phys, cand) =
            setup_test_files(&[("a.txt", b"AAAA"), ("b.txt", b"BBBB")]);
        let partial = partial_hash_groups(
            &phys.physical_files,
            &cand,
            &HashingOptions::default(),
            None,
            None,
            None,
        );
        let full = full_hash_groups(
            &phys.physical_files,
            &partial,
            &HashingOptions::default(),
            None,
            None,
            None,
        );
        let compare = byte_compare_groups(
            &full,
            &entries,
            &phys.physical_files,
            VerifyMode::Always,
            None,
            None,
        );
        assert!(compare.confirmed_groups.is_empty());
    }

    #[test]
    fn byte_compare_empty_full_yields_empty() {
        let full = FullHashReport {
            groups: vec![],
            eliminated_by_full: 0,
            confirmed_duplicates: 0,
            hash_errors: vec![],
            cache_hits: 0,
            cache_misses: 0,
            covered_by_partial: 0,
        };
        let compare = byte_compare_groups(&full, &[], &[], VerifyMode::Always, None, None);
        assert!(compare.is_empty());
    }

    #[test]
    fn byte_compare_handles_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keep_path = dir.path().join("keep.txt");
        let ghost_path = dir.path().join("ghost.txt");
        fs::write(&keep_path, b"same").expect("write");
        fs::write(&ghost_path, b"same").expect("write");

        let group = ExactDuplicateGroup {
            id: GroupId::new(),
            size_bytes: 4,
            files: vec![
                FileCandidate {
                    path: Utf8PathBuf::from_path_buf(keep_path).expect("utf8"),
                    size_bytes: 4,
                },
                FileCandidate {
                    path: Utf8PathBuf::from_path_buf(ghost_path.clone()).expect("utf8"),
                    size_bytes: 4,
                },
            ],
            any_cached: false,
        };
        fs::remove_file(&ghost_path).expect("remove");

        let full = FullHashReport {
            groups: vec![group],
            eliminated_by_full: 0,
            confirmed_duplicates: 1,
            hash_errors: vec![],
            cache_hits: 0,
            cache_misses: 0,
            covered_by_partial: 0,
        };
        let compare = byte_compare_groups(&full, &[], &[], VerifyMode::Always, None, None);
        assert_eq!(compare.compare_errors.len(), 1);
    }
}
