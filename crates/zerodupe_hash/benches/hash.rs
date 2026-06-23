//! Benchmarks for BLAKE3 hashing (zerodupe_hash).
//!
//! Covers the three most performance-critical paths:
//! 1. Raw in-memory hashing throughput (the hot path for cache lookups).
//! 2. File hashing at realistic chunk sizes.
//! 3. Head+Tail combined hashing (the default scan strategy).

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn bench_raw_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_raw");

    for size in [256, 1024, 4096, 65536, 1_048_576usize] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| zerodupe_hash::Blake3Hex::from_bytes(data));
        });
    }
    group.finish();
}

fn bench_file_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_hash");

    for (label, size) in [("4KB", 4096usize), ("1MB", 1_048_576)] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bench.bin");
        let data = vec![0xCDu8; size];
        std::fs::write(&path, &data).expect("write");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new("full", label), |b| {
            b.iter(|| zerodupe_hash::hash_file_full(&path));
        });
        group.bench_function(BenchmarkId::new("head_tail", label), |b| {
            b.iter(|| zerodupe_hash::hash_file_head_tail(&path, 4096, 4096));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_raw_hashing, bench_file_hashing);
criterion_main!(benches);
