//! Benchmarks for the exact-duplicate pipeline hashing stages.
//!
//! Baseline for the optimisation work planned in the 2026-06-10 audit:
//! cache wiring (Fase 1), skipping the full hash for small files (Fase 2.1)
//! and Rayon parallelism (Fase 3). Files live in a temp dir and are read
//! repeatedly, so after the first pass the page cache is warm — these
//! numbers measure pipeline overhead, not cold-disk throughput.
//!
//! Scenarios:
//! 1. `small_files`: many 4 KB duplicate pairs — dominated by per-file
//!    overhead; the target of Fase 2.1.
//! 2. `medium_files`: 64 KB duplicate pairs — the typical mixed workload.
//! 3. `large_group`: a few 8 MB duplicates — dominated by sequential
//!    hashing and byte-compare I/O; the target of Fases 1.5 and 3.

use camino::Utf8PathBuf;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use zerodupe_core::{DiscoveryOptions, HashingOptions, VerifyMode};
use zerodupe_fs::discover_roots;
use zerodupe_scan::{
    build_candidate_groups, byte_compare_groups, full_hash_groups, partial_hash_groups,
};

/// Deterministic content: `len` bytes derived from `seed` so different
/// seeds never produce duplicate files by accident.
fn pattern(seed: u32, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u32).wrapping_mul(31).wrapping_add(seed * 7919) % 251) as u8)
        .collect()
}

/// Writes `pairs` duplicate pairs of `file_size` bytes and returns the tree.
fn build_tree(pairs: usize, file_size: usize) -> (tempfile::TempDir, Utf8PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 tempdir");
    for i in 0..pairs {
        let data = pattern(i as u32, file_size);
        std::fs::write(root.join(format!("a_{i}.bin")).into_std_path_buf(), &data).expect("write");
        std::fs::write(root.join(format!("b_{i}.bin")).into_std_path_buf(), &data).expect("write");
    }
    (dir, root)
}

/// Benches the hashing stages (3–5) with discovery and size grouping done
/// once outside the loop — those are not the stages being optimised.
fn bench_hash_stages(c: &mut Criterion, name: &str, pairs: usize, file_size: usize) {
    let (_dir, root) = build_tree(pairs, file_size);
    let discovery = discover_roots(vec![root], &DiscoveryOptions::default(), None, None);
    assert!(discovery.errors.is_empty());
    let (phys, cand) = build_candidate_groups(&discovery.entries, None, None);
    let options = HashingOptions::default();
    let total_bytes = (pairs * 2 * file_size) as u64;

    let mut group = c.benchmark_group("pipeline");
    group.throughput(Throughput::Bytes(total_bytes));
    group.sample_size(20);
    group.bench_function(name, |b| {
        b.iter(|| {
            let partial =
                partial_hash_groups(&phys.physical_files, &cand, &options, None, None, None);
            let full = full_hash_groups(&phys.physical_files, &partial, &options, None, None, None);
            let bytes = byte_compare_groups(
                &full,
                &discovery.entries,
                &phys.physical_files,
                VerifyMode::default(),
                None,
                None,
            );
            assert_eq!(bytes.confirmed_groups.len(), pairs);
            bytes
        });
    });
    group.finish();
}

fn bench_small_files(c: &mut Criterion) {
    bench_hash_stages(c, "small_files_250x2x4KB", 250, 4096);
}

fn bench_medium_files(c: &mut Criterion) {
    bench_hash_stages(c, "medium_files_100x2x64KB", 100, 65536);
}

fn bench_large_group(c: &mut Criterion) {
    bench_hash_stages(c, "large_group_3x2x8MB", 3, 8 * 1024 * 1024);
}

criterion_group!(
    benches,
    bench_small_files,
    bench_medium_files,
    bench_large_group
);
criterion_main!(benches);
