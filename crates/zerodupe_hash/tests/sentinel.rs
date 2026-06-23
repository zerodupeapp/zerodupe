//! Sentinel tests: pin the exact BLAKE3 output of the hashing functions
//! against hardcoded hex values.
//!
//! If any of these fail, the hashing algorithm or the region semantics
//! changed — every hash stored in `zerodupe_cache` is now stale and
//! `CACHE_SCHEMA_VERSION` MUST be bumped before shipping.

use std::path::PathBuf;

use zerodupe_hash::{Blake3Hex, hash_file_full, hash_file_head_tail};

/// Deterministic 12 000-byte fixture: byte i = i mod 251.
/// Larger than head+tail (8 192) so partial and full hashes differ,
/// and 251 is prime so head and tail regions never repeat in sync.
const FIXTURE_LEN: usize = 12_000;

fn fixture_bytes() -> Vec<u8> {
    (0..FIXTURE_LEN).map(|i| (i % 251) as u8).collect()
}

fn write_fixture() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sentinel.bin");
    std::fs::write(&path, fixture_bytes()).expect("write fixture");
    (dir, path)
}

/// Pure algorithm sentinel: BLAKE3 of a constant in-memory slice.
#[test]
fn blake3_in_memory_is_stable() {
    assert_eq!(
        Blake3Hex::from_bytes(b"ZeroDupe sentinel").to_hex(),
        "e8e86d6014ee32a9254ce5fae120b2710d8e2668d2b66c86cac1a791eb3a5564",
    );
}

/// Full-file hash sentinel (the stage-4 hash, cached as `HashRegion::Full`).
#[test]
fn blake3_full_file_is_stable() {
    let (_dir, path) = write_fixture();
    let hash = hash_file_full(&path).expect("full hash");
    assert_eq!(
        hash.to_hex(),
        "ee2c59bad59f83254b449c377e3273cde9772288a397770a2849ae54f3d8a8f6",
    );
}

/// Head+tail hash sentinel (the default stage-3 partial strategy,
/// cached as `HashRegion::HeadTail { 4096, 4096 }`).
#[test]
fn blake3_head_tail_is_stable() {
    let (_dir, path) = write_fixture();
    let hash = hash_file_head_tail(&path, 4096, 4096).expect("head+tail hash");
    assert_eq!(
        hash.to_hex(),
        "53185890c54cbfc5dc6cc38da29669ad8e93aa3d0da163c876f23be9e9d9c7ee",
    );

    // Region semantics: head = first 4096 bytes, tail = last 4096 bytes,
    // hashed as one concatenated stream.
    let bytes = fixture_bytes();
    let mut concat = bytes[..4096].to_vec();
    concat.extend_from_slice(&bytes[FIXTURE_LEN - 4096..]);
    assert_eq!(hash, Blake3Hex::from_bytes(&concat));
}

/// Granular cancellation (Fase 3.3): a cancelled flag must abort a full
/// hash between 64 KB chunks instead of finishing a potentially huge file.
#[test]
fn cancelled_full_hash_aborts_quickly() {
    use zerodupe_core::CancelFlag;
    use zerodupe_hash::hash_file_full_cancellable;

    // 64 MB: large enough that hashing it whole would be measurable.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("big.bin");
    std::fs::write(&path, vec![0xAB; 64 * 1024 * 1024]).expect("write");

    let cancel = CancelFlag::new();
    cancel.cancel();
    let start = std::time::Instant::now();
    let result = hash_file_full_cancellable(&path, Some(&cancel));
    let elapsed = start.elapsed();

    let err = result.expect_err("cancelled hash must not complete");
    assert_eq!(err.kind(), std::io::ErrorKind::Interrupted);
    assert!(
        elapsed < std::time::Duration::from_millis(100),
        "abort must be immediate, took {elapsed:?}",
    );

    // Without the flag the same file hashes normally.
    assert!(hash_file_full_cancellable(&path, None).is_ok());
}

/// For files where head+tail covers every byte (size ≤ head + tail),
/// the partial hash reads the whole file in order, so it equals the
/// full hash. Stage 4 can be skipped for these files without any loss
/// of discriminating power — the optimisation planned in Fase 2.1
/// depends on this property holding.
#[test]
fn head_tail_equals_full_when_file_fits_in_regions() {
    for size in [1usize, 4095, 4096, 4097, 8000, 8192] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("small.bin");
        let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &bytes).expect("write");

        let partial = hash_file_head_tail(&path, 4096, 4096).expect("head+tail");
        let full = hash_file_full(&path).expect("full");
        assert_eq!(partial, full, "size {size}: head+tail must equal full");
    }

    // One byte past the boundary the property must break.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("boundary.bin");
    let bytes: Vec<u8> = (0..8193usize).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &bytes).expect("write");
    assert_ne!(
        hash_file_head_tail(&path, 4096, 4096).expect("head+tail"),
        hash_file_full(&path).expect("full"),
        "size 8193: head+tail skips byte 4096..4097 and must differ from full",
    );
}
