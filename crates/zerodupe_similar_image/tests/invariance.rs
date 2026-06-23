//! Ola 2a closing tests — geometric invariance (D-008).
//!
//! - MirrorFlip (default) detects mirrored copies; Off does not.
//! - Full also detects 90° rotations; MirrorFlip does not.
//! - Auto-symmetric images drop their redundant variants (FP guard).
//! - Best-alignment similarity keeps mirrored pairs above the 0.80 split.

use zerodupe_core::FileCandidate;
use zerodupe_similar::{SimilarityDetector, detect_similars};
use zerodupe_similar_image::{GeometricInvariance, ImagePHashDetector, fingerprint_image};

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

fn candidate(path: &std::path::Path) -> FileCandidate {
    FileCandidate {
        path: camino::Utf8PathBuf::from_path_buf(path.to_path_buf()).expect("utf8"),
        size_bytes: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
    }
}

fn group_names(report: &zerodupe_similar::SimilarityReport) -> Vec<Vec<String>> {
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
    groups
}

#[test]
fn mirrored_copy_detected_with_mirrorflip_not_with_off() {
    let dir = tempfile::tempdir().unwrap();
    let img = make_noise_image(42, 128, 128);
    let mirrored = image::imageops::flip_horizontal(&img);
    let pa = dir.path().join("a.png");
    let pb = dir.path().join("a_mirror.png");
    img.save(&pa).unwrap();
    mirrored.save(&pb).unwrap();
    let files = vec![candidate(&pa), candidate(&pb)];

    let off = ImagePHashDetector::new().with_invariance(GeometricInvariance::Off);
    let report_off = detect_similars(&files, &[&off], None, None, None);
    assert!(
        report_off.groups.is_empty(),
        "Off must not match a mirrored copy of random noise"
    );

    let mirror = ImagePHashDetector::new(); // MirrorFlip is the default
    let report_mirror = detect_similars(&files, &[&mirror], None, None, None);
    assert_eq!(
        group_names(&report_mirror),
        vec![vec!["a.png".to_string(), "a_mirror.png".to_string()]],
        "MirrorFlip must group an image with its mirrored copy"
    );
}

#[test]
fn vertically_flipped_copy_detected_with_mirrorflip() {
    let dir = tempfile::tempdir().unwrap();
    let img = make_noise_image(77, 128, 128);
    let flipped = image::imageops::flip_vertical(&img);
    let pa = dir.path().join("a.png");
    let pb = dir.path().join("a_flipv.png");
    img.save(&pa).unwrap();
    flipped.save(&pb).unwrap();
    let files = vec![candidate(&pa), candidate(&pb)];

    let detector = ImagePHashDetector::new();
    let report = detect_similars(&files, &[&detector], None, None, None);
    assert_eq!(report.groups.len(), 1);
}

#[test]
fn rotated_90_detected_only_with_full() {
    let dir = tempfile::tempdir().unwrap();
    let img = make_noise_image(99, 128, 128);
    let rotated = image::imageops::rotate90(&img);
    let pa = dir.path().join("a.png");
    let pb = dir.path().join("a_rot90.png");
    img.save(&pa).unwrap();
    rotated.save(&pb).unwrap();
    let files = vec![candidate(&pa), candidate(&pb)];

    let mirror = ImagePHashDetector::new();
    let report_mirror = detect_similars(&files, &[&mirror], None, None, None);
    assert!(
        report_mirror.groups.is_empty(),
        "MirrorFlip must not match a 90°-rotated copy (that is Full's job)"
    );

    let full = ImagePHashDetector::new().with_invariance(GeometricInvariance::Full);
    let report_full = detect_similars(&files, &[&full], None, None, None);
    assert_eq!(
        report_full.groups.len(),
        1,
        "Full must group an image with its 90°-rotated copy"
    );
}

#[test]
fn fingerprint_layout_per_mode() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("noise.png");
    make_noise_image(1234, 128, 128).save(&p).unwrap();

    let fp_off = fingerprint_image(&p, GeometricInvariance::Off).unwrap();
    assert_eq!(
        fp_off.data.len(),
        16,
        "Off: canonical block only (Ola-1 layout)"
    );

    let fp_mirror = fingerprint_image(&p, GeometricInvariance::MirrorFlip).unwrap();
    assert_eq!(
        fp_mirror.data.len(),
        48,
        "MirrorFlip on asymmetric noise: canonical + fliph + flipv"
    );
    assert_eq!(
        &fp_mirror.data[..16],
        &fp_off.data[..],
        "canonical block must be identical across modes"
    );

    let fp_full = fingerprint_image(&p, GeometricInvariance::Full).unwrap();
    assert_eq!(
        fp_full.data.len(),
        176,
        "Full on asymmetric noise: 8 D4 alignments + 3 edit variants (D-011)"
    );
}

#[test]
fn symmetric_image_variants_deduped() {
    // Horizontally symmetric image: fliph(img) == img, so the fliph variant
    // hash equals the canonical one and must be dropped (auto-symmetric
    // false-positive guard from D-008).
    let dir = tempfile::tempdir().unwrap();
    let half = make_noise_image(555, 64, 128);
    let mut img = image::RgbImage::new(128, 128);
    for y in 0..128 {
        for x in 0..64 {
            let p = *half.get_pixel(x, y);
            img.put_pixel(x, y, p);
            img.put_pixel(127 - x, y, p);
        }
    }
    let p = dir.path().join("sym.png");
    img.save(&p).unwrap();

    let fp = fingerprint_image(&p, GeometricInvariance::MirrorFlip).unwrap();
    assert!(
        fp.data.len() <= 32,
        "fliph variant of an H-symmetric image must be deduped, got {} bytes",
        fp.data.len()
    );
}

#[test]
fn mirrored_pair_scores_like_a_duplicate() {
    // Best-alignment similarity: a mirrored pair must stay above the 0.80
    // intra-component split threshold and read as near-certain duplicate.
    let dir = tempfile::tempdir().unwrap();
    let img = make_noise_image(31, 256, 256);
    let mirrored = image::imageops::flip_horizontal(&img);
    let pa = dir.path().join("a.png");
    let pb = dir.path().join("b.png");
    img.save(&pa).unwrap();
    mirrored.save(&pb).unwrap();

    let detector = ImagePHashDetector::new();
    let fa = detector.fingerprint(&pa).unwrap();
    let fb = detector.fingerprint(&pb).unwrap();
    assert!(detector.is_near_duplicate(&fa, &fb));
    assert!(
        detector.similarity(&fa, &fb) > 0.95,
        "best-alignment similarity should be ~1.0, got {}",
        detector.similarity(&fa, &fb)
    );
    // Canonical distance stays large: the BK-tree metric is untouched.
    assert!(detector.distance(&fa, &fb) > 12);
    // Self-comparison unchanged.
    assert_eq!(detector.distance(&fa, &fa), 0);
}
