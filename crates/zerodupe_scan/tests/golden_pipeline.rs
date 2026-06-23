//! Golden test of the exact-duplicate pipeline (stages 1–5).
//!
//! Builds a fixture tree with every interesting case — large duplicates,
//! small duplicates fully covered by the partial hash, same-size files that
//! differ at the head, same-head-and-tail files that differ in the middle,
//! a solo file, empty files and (on Unix) a hardlink — runs the full
//! pipeline twice, and pins the exact grouping outcome.
//!
//! This is the contract for the optimisation work (cache wiring, skipping
//! redundant stages, Rayon): if grouping or determinism changes, this fails.

use camino::Utf8PathBuf;
use zerodupe_core::{DiscoveryOptions, HashingOptions, VerifyMode};
use zerodupe_fs::discover_roots;
use zerodupe_scan::{
    build_candidate_groups, byte_compare_groups, full_hash_groups, partial_hash_groups,
};

/// Deterministic content: `len` bytes seeded so different seeds never collide.
fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 ^ seed).collect()
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: Utf8PathBuf,
}

/// Normalised pipeline outcome: per confirmed group, (size, sorted file
/// names, keeper name), sorted — independent of group or member order.
type GroupSummary = Vec<(u64, Vec<String>, String)>;

fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 tempdir");
    let p = |name: &str| root.join(name).into_std_path_buf();

    std::fs::create_dir_all(p("sub/deep")).expect("mkdir");

    // Three large duplicates (100 KB > head+tail): exercise stages 3, 4 and 5.
    let big = pattern(1, 100_000);
    std::fs::write(p("big_a.bin"), &big).expect("write");
    std::fs::write(p("sub/big_b.bin"), &big).expect("write");
    std::fs::write(p("sub/deep/big_c.bin"), &big).expect("write");

    // Two small duplicates (1 KB ≤ head+tail): fully covered by partial hash.
    let small = pattern(2, 1_000);
    std::fs::write(p("small_a.txt"), &small).expect("write");
    std::fs::write(p("small_b.txt"), &small).expect("write");

    // Same size and same head+tail, different middle: the partial hash
    // groups them, the full hash must split them.
    let mut twin = pattern(3, 20_000);
    std::fs::write(p("head_tail_twin_1.bin"), &twin).expect("write");
    for byte in &mut twin[10_000..10_010] {
        *byte = !*byte;
    }
    std::fs::write(p("head_tail_twin_2.bin"), &twin).expect("write");

    // Same size, different head: grouped by size, split by partial hash.
    std::fs::write(p("size_twin_1.bin"), pattern(4, 5_000)).expect("write");
    std::fs::write(p("size_twin_2.bin"), pattern(5, 5_000)).expect("write");

    // Solo size: never a candidate.
    std::fs::write(p("unique.bin"), pattern(6, 77_777)).expect("write");

    // Empty files: separated before grouping, never duplicates.
    std::fs::write(p("empty_1.txt"), b"").expect("write");
    std::fs::write(p("empty_2.txt"), b"").expect("write");

    // Hardlink to big_a: same inode, must collapse into one physical file
    // instead of inflating the duplicate group.
    #[cfg(unix)]
    std::fs::hard_link(p("big_a.bin"), p("link_to_big.bin")).expect("hard link");

    Fixture { _dir: dir, root }
}

/// Runs discovery + the four pipeline stages and returns the reports
/// needed for assertions plus the normalised group summary.
fn run_pipeline(root: &Utf8PathBuf, mode: VerifyMode) -> (GroupSummary, PipelineCounters) {
    run_pipeline_with(root, mode, HashingOptions::default())
}

fn run_pipeline_with(
    root: &Utf8PathBuf,
    mode: VerifyMode,
    options: HashingOptions,
) -> (GroupSummary, PipelineCounters) {
    let discovery = discover_roots(vec![root.clone()], &DiscoveryOptions::default(), None, None);
    assert!(
        discovery.errors.is_empty(),
        "discovery errors: {:?}",
        discovery.errors
    );

    let (phys, cand) = build_candidate_groups(&discovery.entries, None, None);
    let partial = partial_hash_groups(&phys.physical_files, &cand, &options, None, None, None);
    let full = full_hash_groups(&phys.physical_files, &partial, &options, None, None, None);
    let bytes = byte_compare_groups(
        &full,
        &discovery.entries,
        &phys.physical_files,
        mode,
        None,
        None,
    );

    assert!(
        partial.hash_errors.is_empty(),
        "partial hash errors: {:?}",
        partial.hash_errors
    );
    assert!(
        full.hash_errors.is_empty(),
        "full hash errors: {:?}",
        full.hash_errors
    );
    assert!(
        bytes.compare_errors.is_empty(),
        "byte-compare errors: {:?}",
        bytes.compare_errors
    );

    let file_name = |path: &Utf8PathBuf| -> String {
        path.strip_prefix(root)
            .expect("path under root")
            .to_string()
    };

    let mut summary: GroupSummary = bytes
        .confirmed_groups
        .iter()
        .map(|g| {
            let mut names: Vec<String> = g.files.iter().map(|f| file_name(&f.path)).collect();
            names.sort();
            (g.size_bytes, names, file_name(&g.keeper_path))
        })
        .collect();
    summary.sort();

    let counters = PipelineCounters {
        empty_files: phys.empty_files.entry_indices.len(),
        hardlink_clusters: phys.hardlink_clusters.len(),
        eliminated_by_partial: partial.eliminated_by_partial,
        eliminated_by_full: full.eliminated_by_full,
        eliminated_by_compare: bytes.eliminated_by_compare,
        false_positive_groups: bytes.false_positive_groups,
        groups_trusted: bytes.groups_trusted,
    };
    (summary, counters)
}

struct PipelineCounters {
    empty_files: usize,
    hardlink_clusters: usize,
    eliminated_by_partial: usize,
    eliminated_by_full: usize,
    eliminated_by_compare: usize,
    false_positive_groups: usize,
    groups_trusted: usize,
}

#[test]
fn pipeline_groups_known_tree_exactly() {
    let fixture = build_fixture();
    // Always: exercise the byte-comparison path on every group.
    let (summary, counters) = run_pipeline(&fixture.root, VerifyMode::Always);

    // Exactly two confirmed groups: the three big copies and the two small.
    assert_eq!(summary.len(), 2, "confirmed groups: {summary:?}");

    let (small_group, big_group) = (&summary[0], &summary[1]);
    assert_eq!(small_group.0, 1_000);
    assert_eq!(small_group.1, vec!["small_a.txt", "small_b.txt"]);
    assert_eq!(big_group.0, 100_000);
    assert_eq!(
        big_group.1,
        vec!["big_a.bin", "sub/big_b.bin", "sub/deep/big_c.bin"],
        "the hardlink must not appear as a fourth member",
    );

    // The keeper is always a member of its own group.
    for (_, names, keeper) in &summary {
        assert!(
            names.contains(keeper),
            "keeper {keeper} not in group {names:?}"
        );
    }

    assert_eq!(counters.empty_files, 2);
    #[cfg(unix)]
    assert_eq!(counters.hardlink_clusters, 1);

    // size_twin pair: same size, split by partial hash (both become solo).
    assert_eq!(counters.eliminated_by_partial, 2);
    // head_tail_twin pair: same partial hash, split by full hash.
    assert_eq!(counters.eliminated_by_full, 2);
    // Nothing should survive to byte-compare and then fail it.
    assert_eq!(counters.eliminated_by_compare, 0);
    assert_eq!(counters.false_positive_groups, 0);
}

#[test]
fn pipeline_output_is_deterministic_across_runs() {
    let fixture = build_fixture();
    let (first, _) = run_pipeline(&fixture.root, VerifyMode::Always);
    let (second, _) = run_pipeline(&fixture.root, VerifyMode::Always);
    assert_eq!(
        first, second,
        "two runs over the same tree must produce identical groups and keepers",
    );
}

#[test]
fn parallel_and_sequential_hashing_are_bit_identical() {
    // The Fase 3 contract: Rayon must not change a single group or keeper.
    // Force both paths explicitly — the auto mode picks one or the other
    // depending on the machine's storage.
    let fixture = build_fixture();
    let sequential = run_pipeline_with(
        &fixture.root,
        VerifyMode::Always,
        HashingOptions {
            parallel_hashing: Some(false),
            ..Default::default()
        },
    );
    let parallel = run_pipeline_with(
        &fixture.root,
        VerifyMode::Always,
        HashingOptions {
            parallel_hashing: Some(true),
            ..Default::default()
        },
    );
    assert_eq!(
        sequential.0, parallel.0,
        "parallel hashing must produce identical groups and keepers",
    );
}

#[test]
fn trusted_fast_path_matches_paranoid_path() {
    // Without a cache every hash is fresh, so the default mode (CachedOnly)
    // skips byte comparison entirely — and must still produce exactly the
    // same groups and keepers as full verification.
    let fixture = build_fixture();
    let (paranoid, _) = run_pipeline(&fixture.root, VerifyMode::Always);
    let (trusted, counters) = run_pipeline(&fixture.root, VerifyMode::CachedOnly);
    assert_eq!(paranoid, trusted);
    assert_eq!(
        counters.groups_trusted, 2,
        "with no cache in play, every confirmed group must be trusted, not compared",
    );
}
