//! BK-tree regression tests (Ola 2a) — the standard-insertion rewrite must
//! find exactly the groups a brute-force O(n²) comparison finds, for any
//! insertion order, with and without geometric query variants.

use std::path::Path;

use zerodupe_core::FileCandidate;
use zerodupe_similar::{FingerprintData, SimilarityDetector, detect_similars};

/// Synthetic detector: the fingerprint is the first 16 bytes of the file.
/// Distance = Hamming over those bytes; near-duplicate at ≤ 6 bits.
struct ByteHashDetector;

const THRESHOLD: u32 = 6;

fn hamming(a: &[u8], b: &[u8]) -> u32 {
    // u64-word implementation, mirroring the real detector's inner loop.
    let x = u64::from_ne_bytes(a[..8].try_into().unwrap())
        ^ u64::from_ne_bytes(b[..8].try_into().unwrap());
    let y = u64::from_ne_bytes(a[8..16].try_into().unwrap())
        ^ u64::from_ne_bytes(b[8..16].try_into().unwrap());
    x.count_ones() + y.count_ones()
}

impl SimilarityDetector for ByteHashDetector {
    fn name(&self) -> &'static str {
        "byte-hash-test"
    }
    fn extensions(&self) -> &[&'static str] {
        &["mok"]
    }
    fn fingerprint(&self, path: &Path) -> std::io::Result<FingerprintData> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < 16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "too short",
            ));
        }
        Ok(FingerprintData {
            detector: "byte-hash-test".to_string(),
            data: bytes[..16].to_vec(),
            metadata: serde_json::Value::Null,
        })
    }
    fn distance(&self, a: &FingerprintData, b: &FingerprintData) -> u32 {
        hamming(&a.data[..16], &b.data[..16])
    }
    fn similarity(&self, a: &FingerprintData, b: &FingerprintData) -> f64 {
        1.0 - (self.distance(a, b) as f64 / 128.0)
    }
    fn is_near_duplicate(&self, a: &FingerprintData, b: &FingerprintData) -> bool {
        self.distance(a, b) <= THRESHOLD
    }
    fn confidence_label(&self, _s: f64) -> &'static str {
        "test"
    }
    fn keeper_score(&self, _path: &Path) -> std::io::Result<f64> {
        Ok(0.0)
    }
}

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

/// Builds a corpus of `n` random 16-byte hashes plus planted near-pairs
/// (1-3 bits flipped). Returns the hash list.
fn build_hashes(n: usize, planted_pairs: usize, seed: u64) -> Vec<[u8; 16]> {
    let mut state = seed;
    let mut hashes: Vec<[u8; 16]> = Vec::with_capacity(n + planted_pairs);
    for _ in 0..n {
        let mut h = [0u8; 16];
        for byte in h.iter_mut() {
            *byte = (lcg(&mut state) >> 40) as u8;
        }
        hashes.push(h);
    }
    // Plant near-duplicates of random existing hashes.
    for p in 0..planted_pairs {
        let base = hashes[(lcg(&mut state) as usize) % n];
        let mut near = base;
        let flips = 1 + (p % 3);
        for _ in 0..flips {
            let bit = (lcg(&mut state) as usize) % 128;
            near[bit / 8] ^= 1 << (bit % 8);
        }
        hashes.push(near);
    }
    hashes
}

/// Brute-force expected groups: union-find over all pairs ≤ THRESHOLD,
/// returned as sorted vectors of file indices.
fn brute_force_groups(hashes: &[[u8; 16]]) -> Vec<Vec<usize>> {
    let n = hashes.len();
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(p: &mut [usize], x: usize) -> usize {
        if p[x] != x {
            p[x] = find(p, p[x]);
        }
        p[x]
    }
    for i in 0..n {
        for j in (i + 1)..n {
            if hamming(&hashes[i], &hashes[j]) <= THRESHOLD {
                let (ri, rj) = (find(&mut parent, i), find(&mut parent, j));
                if ri != rj {
                    parent[ri] = rj;
                }
            }
        }
    }
    let mut map: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        map.entry(root).or_default().push(i);
    }
    let mut groups: Vec<Vec<usize>> = map.into_values().filter(|g| g.len() >= 2).collect();
    for g in &mut groups {
        g.sort();
    }
    groups.sort();
    groups
}

fn run_corpus(hashes: &[[u8; 16]], order: &[usize]) -> Vec<Vec<usize>> {
    let dir = tempfile::tempdir().unwrap();
    let mut files = Vec::new();
    for &idx in order {
        let path = dir.path().join(format!("h{idx:04}.mok"));
        std::fs::write(&path, hashes[idx]).unwrap();
        files.push(FileCandidate {
            path: camino::Utf8PathBuf::from_path_buf(path).unwrap(),
            size_bytes: 16,
        });
    }
    let detector = ByteHashDetector;
    let report = detect_similars(&files, &[&detector], None, None, None);
    let mut groups: Vec<Vec<usize>> = report
        .groups
        .iter()
        .map(|g| {
            let mut idxs: Vec<usize> = g
                .files
                .iter()
                .map(|f| {
                    let name = f.path.file_stem().unwrap();
                    name[1..].parse::<usize>().unwrap()
                })
                .collect();
            idxs.sort();
            idxs
        })
        .collect();
    groups.sort();
    groups
}

#[test]
fn bktree_matches_brute_force() {
    let hashes = build_hashes(300, 25, 0xC0FFEE);
    let expected = brute_force_groups(&hashes);
    assert!(
        !expected.is_empty(),
        "corpus must contain planted near-pairs"
    );

    let order: Vec<usize> = (0..hashes.len()).collect();
    let got = run_corpus(&hashes, &order);
    assert_eq!(
        got, expected,
        "BK-tree must find exactly what brute force finds"
    );
}

/// Scaling check for the standard-insertion rewrite. Uniform random hashes
/// are the BK-tree's worst case: distances concentrate around the mean, so
/// the range query degrades toward a linear scan per insert. Measured on
/// this corpus (release, 2026-06-11): 207s before the Ola-2a rewrite
/// (HashSet bookkeeping + unconditional holistic checks), 79s after
/// (stamp vector, range-gated checks, BTreeMap range scan, u64 Hamming).
/// Real photo corpora behave similarly in concentration; if large
/// libraries (≥50K) make the matching phase dominant on warm scans, the
/// structural fix is multi-index Hamming (banded buckets), not BK tuning —
/// noted as a future item in docs/PLAN_SIMILARES_V2_2026-06-11.md.
/// Run explicitly with:
/// `cargo test --release -p zerodupe_similar --test bktree -- --ignored --nocapture`
#[test]
#[ignore = "perf check, run in release on demand"]
fn bktree_scales_to_50k_fingerprints() {
    let hashes = build_hashes(50_000, 500, 0xFEEDFACE);
    let dir = tempfile::tempdir().unwrap();
    let mut files = Vec::with_capacity(hashes.len());
    for (idx, h) in hashes.iter().enumerate() {
        let path = dir.path().join(format!("h{idx:05}.mok"));
        std::fs::write(&path, h).unwrap();
        files.push(FileCandidate {
            path: camino::Utf8PathBuf::from_path_buf(path).unwrap(),
            size_bytes: 16,
        });
    }
    let detector = ByteHashDetector;
    let start = std::time::Instant::now();
    let report = detect_similars(&files, &[&detector], None, None, None);
    let elapsed = start.elapsed();
    println!(
        "50K fingerprints: {} groups in {:.2?}",
        report.groups.len(),
        elapsed
    );
    assert!(!report.groups.is_empty());
    assert!(
        elapsed.as_secs() < 180,
        "regression guard: 50K worst case measured at ~79s in release, took {elapsed:.2?}"
    );
}

#[test]
fn bktree_insertion_order_does_not_matter() {
    let hashes = build_hashes(200, 20, 0xBADA55);
    let expected = brute_force_groups(&hashes);

    // Three different insertion orders, same result.
    let mut order: Vec<usize> = (0..hashes.len()).collect();
    assert_eq!(run_corpus(&hashes, &order), expected);
    order.reverse();
    assert_eq!(run_corpus(&hashes, &order), expected);
    // Deterministic shuffle.
    let mut state = 7u64;
    for i in (1..order.len()).rev() {
        let j = (lcg(&mut state) as usize) % (i + 1);
        order.swap(i, j);
    }
    assert_eq!(run_corpus(&hashes, &order), expected);
}
