//! Ola 1 closing tests — fingerprint cache + hardlink dedup.
//!
//! Verifies the contract of `docs/PLAN_SIMILARES_V2_2026-06-11.md` §Ola 1:
//! - Golden: cold vs warm cache produce identical reports, warm computes 0
//!   fingerprints.
//! - Invalidation: a modified file is re-fingerprinted.
//! - Errors are cached: corrupt files are reported on every scan but only
//!   decoded once.
//! - Hardlinks: one fingerprint per inode, no fake groups.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use zerodupe_cache::HashCache;
use zerodupe_core::FileCandidate;
use zerodupe_similar::{FingerprintData, SimilarityDetector, detect_similars};
use zerodupe_similar_image::ImagePHashDetector;

/// Wraps the real detector counting `fingerprint()` calls, to prove which
/// scans hit the cache. Delegates everything else (including the cache
/// identity: name, algo_version, params) so cache keys match across runs.
struct CountingDetector {
    inner: ImagePHashDetector,
    count: AtomicUsize,
}

impl CountingDetector {
    fn new() -> Self {
        Self {
            inner: ImagePHashDetector::new(),
            count: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

impl SimilarityDetector for CountingDetector {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn algo_version(&self) -> u32 {
        self.inner.algo_version()
    }
    fn cache_params(&self) -> String {
        self.inner.cache_params()
    }
    fn variant_count(&self, fp: &FingerprintData) -> usize {
        self.inner.variant_count(fp)
    }
    fn variant_distance(&self, a: &FingerprintData, k: usize, b: &FingerprintData) -> u32 {
        self.inner.variant_distance(a, k, b)
    }
    fn extensions(&self) -> &[&'static str] {
        self.inner.extensions()
    }
    fn fingerprint(&self, path: &Path) -> std::io::Result<FingerprintData> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.inner.fingerprint(path)
    }
    fn distance(&self, a: &FingerprintData, b: &FingerprintData) -> u32 {
        self.inner.distance(a, b)
    }
    fn similarity(&self, a: &FingerprintData, b: &FingerprintData) -> f64 {
        self.inner.similarity(a, b)
    }
    fn is_near_duplicate(&self, a: &FingerprintData, b: &FingerprintData) -> bool {
        self.inner.is_near_duplicate(a, b)
    }
    fn confidence_label(&self, s: f64) -> &'static str {
        self.inner.confidence_label(s)
    }
    fn keeper_score(&self, path: &Path) -> std::io::Result<f64> {
        self.inner.keeper_score(path)
    }
    fn are_siblings_not_duplicates(&self, a: &Path, b: &Path) -> bool {
        self.inner.are_siblings_not_duplicates(a, b)
    }
}

fn make_noise_image(seed: u64, width: u32, height: u32) -> image::RgbImage {
    let mut state = seed;
    let mut img = image::RgbImage::new(width, height);
    for y in 0..height {
        for x in 0..width {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            img.put_pixel(
                x,
                y,
                image::Rgb([
                    (state >> 56) as u8,
                    (state >> 48) as u8,
                    (state >> 40) as u8,
                ]),
            );
        }
    }
    img
}

fn candidate(path: &Path) -> FileCandidate {
    FileCandidate {
        path: camino::Utf8PathBuf::from_path_buf(path.to_path_buf()).expect("utf8"),
        size_bytes: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
    }
}

/// Normalized view of a report for golden comparison: sorted group file
/// names + group count + error count. (Group ordering is not deterministic
/// — components come from a HashMap — so we sort.)
fn normalize(report: &zerodupe_similar::SimilarityReport) -> (Vec<Vec<String>>, usize, usize) {
    let mut groups: Vec<Vec<String>> = report
        .groups
        .iter()
        .map(|g| {
            let mut names: Vec<String> = g
                .files
                .iter()
                .map(|f| f.path.file_name().unwrap_or("").to_string())
                .collect();
            names.sort();
            names
        })
        .collect();
    groups.sort();
    (groups, report.files_scanned, report.errors.len())
}

/// Writes a similar pair (a, b) and a distinct image (c); returns candidates.
fn write_corpus(dir: &Path) -> Vec<FileCandidate> {
    let img_a = make_noise_image(100, 128, 128);
    let mut img_b = make_noise_image(100, 128, 128);
    let img_c = make_noise_image(777, 128, 128);
    let mut state = 200u64;
    for (_, _, p) in img_b.enumerate_pixels_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        if (state & 0xFF) < 3 {
            p[0] = p[0].wrapping_add(2);
        }
    }
    let pa = dir.join("a.png");
    let pb = dir.join("b.png");
    let pc = dir.join("c.png");
    img_a.save(&pa).unwrap();
    img_b.save(&pb).unwrap();
    img_c.save(&pc).unwrap();
    vec![candidate(&pa), candidate(&pb), candidate(&pc)]
}

#[test]
fn golden_cold_vs_warm_cache_identical_report_zero_recompute() {
    let dir = tempfile::tempdir().unwrap();
    let files = write_corpus(dir.path());
    let cache = HashCache::open_memory().expect("cache");

    // Cold scan: everything is computed and persisted.
    let detector = CountingDetector::new();
    let cold = detect_similars(&files, &[&detector], Some(&cache), None, None);
    assert_eq!(detector.calls(), 3, "cold scan must fingerprint all files");
    assert_eq!(cold.groups.len(), 1, "a+b similar, c apart");

    // Warm scan: identical report, zero fingerprint computations.
    let detector2 = CountingDetector::new();
    let warm = detect_similars(&files, &[&detector2], Some(&cache), None, None);
    assert_eq!(
        detector2.calls(),
        0,
        "warm scan must serve every fingerprint from cache"
    );
    assert_eq!(
        normalize(&cold),
        normalize(&warm),
        "cold and warm reports must be identical"
    );
    assert_eq!(cache.fingerprint_entry_count().unwrap(), 3);
}

#[test]
fn modified_file_is_recomputed() {
    let dir = tempfile::tempdir().unwrap();
    let files = write_corpus(dir.path());
    let cache = HashCache::open_memory().expect("cache");

    let detector = CountingDetector::new();
    detect_similars(&files, &[&detector], Some(&cache), None, None);
    assert_eq!(detector.calls(), 3);

    // Replace c.png with different content: size/mtime witnesses change.
    make_noise_image(999, 128, 128)
        .save(dir.path().join("c.png"))
        .unwrap();
    let files = vec![
        files[0].clone(),
        files[1].clone(),
        candidate(&dir.path().join("c.png")),
    ];

    let detector2 = CountingDetector::new();
    detect_similars(&files, &[&detector2], Some(&cache), None, None);
    assert_eq!(
        detector2.calls(),
        1,
        "only the modified file must be re-fingerprinted"
    );
}

#[test]
fn errors_are_cached_and_still_reported() {
    let dir = tempfile::tempdir().unwrap();
    let mut files = write_corpus(dir.path());

    // A corrupt "image": decode fails on every attempt.
    let broken = dir.path().join("broken.png");
    std::fs::write(&broken, b"this is not a png at all").unwrap();
    files.push(candidate(&broken));

    let cache = HashCache::open_memory().expect("cache");

    let detector = CountingDetector::new();
    let cold = detect_similars(&files, &[&detector], Some(&cache), None, None);
    assert_eq!(detector.calls(), 4, "cold scan attempts all files once");
    assert_eq!(cold.errors.len(), 1, "broken file reported");
    assert!(cold.errors[0].contains("broken.png"));

    // Warm scan: the failure comes from cache — no re-decode, still reported.
    let detector2 = CountingDetector::new();
    let warm = detect_similars(&files, &[&detector2], Some(&cache), None, None);
    assert_eq!(detector2.calls(), 0, "broken file must not be re-decoded");
    assert_eq!(warm.errors.len(), 1, "cached error still reported");
    assert!(warm.errors[0].contains("broken.png"));
    assert_eq!(normalize(&cold), normalize(&warm));
}

#[cfg(unix)]
#[test]
fn hardlinks_fingerprinted_once_and_never_grouped() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("a.png");
    make_noise_image(42, 128, 128).save(&original).unwrap();
    let link = dir.path().join("a_link.png");
    std::fs::hard_link(&original, &link).unwrap();

    let files = vec![candidate(&original), candidate(&link)];
    let detector = CountingDetector::new();
    let report = detect_similars(&files, &[&detector], None, None, None);

    assert_eq!(
        detector.calls(),
        1,
        "one fingerprint per inode (take-1-per-inode)"
    );
    assert!(
        report.groups.is_empty(),
        "two hardlinks to the same data are one file, not a similar pair"
    );
}

#[cfg(unix)]
#[test]
fn hardlink_dedup_keeps_real_similars() {
    // a + hardlink(a) + b(similar to a): the group must still appear,
    // containing one representative of the inode plus b.
    let dir = tempfile::tempdir().unwrap();
    let pa = dir.path().join("a.png");
    make_noise_image(100, 128, 128).save(&pa).unwrap();
    let link = dir.path().join("a_link.png");
    std::fs::hard_link(&pa, &link).unwrap();

    let mut img_b = make_noise_image(100, 128, 128);
    let mut state = 200u64;
    for (_, _, p) in img_b.enumerate_pixels_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        if (state & 0xFF) < 3 {
            p[0] = p[0].wrapping_add(2);
        }
    }
    let pb = dir.path().join("b.png");
    img_b.save(&pb).unwrap();

    let files = vec![candidate(&pa), candidate(&link), candidate(&pb)];
    let detector = CountingDetector::new();
    let report = detect_similars(&files, &[&detector], None, None, None);

    assert_eq!(detector.calls(), 2, "inode of a fingerprinted once, plus b");
    assert_eq!(report.groups.len(), 1);
    let mut names: Vec<&str> = report.groups[0]
        .files
        .iter()
        .map(|f| f.path.file_name().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["a.png", "b.png"]);
}

#[test]
fn mirrored_pair_grouped_from_cache() {
    // Ola 2a + Ola 1 together: multi-block fingerprints round-trip through
    // the cache — the mirrored pair is still grouped on a warm scan with
    // zero recomputations.
    let dir = tempfile::tempdir().unwrap();
    let img = make_noise_image(64, 128, 128);
    let mirrored = image::imageops::flip_horizontal(&img);
    let pa = dir.path().join("a.png");
    let pb = dir.path().join("a_mirror.png");
    img.save(&pa).unwrap();
    image::DynamicImage::ImageRgb8(mirrored).save(&pb).unwrap();
    let files = vec![candidate(&pa), candidate(&pb)];

    let cache = HashCache::open_memory().expect("cache");

    let detector = CountingDetector::new();
    let cold = detect_similars(&files, &[&detector], Some(&cache), None, None);
    assert_eq!(detector.calls(), 2);
    assert_eq!(
        cold.groups.len(),
        1,
        "mirrored pair grouped (MirrorFlip default)"
    );

    let detector2 = CountingDetector::new();
    let warm = detect_similars(&files, &[&detector2], Some(&cache), None, None);
    assert_eq!(
        detector2.calls(),
        0,
        "multi-block fingerprints served from cache"
    );
    assert_eq!(warm.groups.len(), 1);
    assert_eq!(normalize(&cold), normalize(&warm));
}

#[test]
fn scan_without_cache_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let files = write_corpus(dir.path());
    let detector = CountingDetector::new();
    let report = detect_similars(&files, &[&detector], None, None, None);
    assert_eq!(detector.calls(), 3);
    assert_eq!(report.groups.len(), 1);
}
