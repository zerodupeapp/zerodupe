//! Ola 2b (D-009) — RAW support via the embedded JPEG preview.
//!
//! Hermetic tests cover the extension wiring and error behaviour. The
//! pipeline itself needs real camera files, which are too large to vendor:
//! those tests are `#[ignore]` and read a local corpus directory
//! (`ZD_RAW_CORPUS`, default `/tmp/zd_raw`) with CC0 samples from
//! <https://raw.pixls.us> — see `docs/PLAN_SIMILARES_V2_2026-06-11.md` §Ola 2b.
//!
//! Run them with:
//! `cargo test --release -p zerodupe_similar_image --test raw -- --ignored --nocapture`
#![cfg(feature = "raw")]

use std::path::{Path, PathBuf};
use std::time::Instant;

use zerodupe_similar::SimilarityDetector;
use zerodupe_similar_image::{
    GeometricInvariance, ImagePHashDetector, RAW_EXTENSIONS, fingerprint_image,
    is_raw_jpeg_sibling_pair, supported_extensions,
};

#[test]
fn detector_accepts_every_raw_extension() {
    let det = ImagePHashDetector::new();
    for ext in RAW_EXTENSIONS {
        assert!(
            det.extensions().contains(ext),
            "{ext} missing from detector extensions"
        );
    }
    assert_eq!(det.extensions(), supported_extensions());
}

#[test]
fn cr3_is_a_raw_sibling_of_its_jpeg() {
    assert!(is_raw_jpeg_sibling_pair(
        Path::new("shoot/IMG_0042.CR3"),
        Path::new("shoot/IMG_0042.JPG"),
    ));
}

#[test]
fn corrupt_raw_yields_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("garbage.dng");
    std::fs::write(&path, b"definitely not a TIFF container").unwrap();
    let err = fingerprint_image(&path, GeometricInvariance::Off)
        .expect_err("garbage RAW must fail, not panic");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

// ── Corpus tests (opt-in) ──

fn corpus_dir() -> PathBuf {
    std::env::var_os("ZD_RAW_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/zd_raw"))
}

fn corpus_file(name: &str) -> PathBuf {
    let p = corpus_dir().join(name);
    assert!(
        p.exists(),
        "corpus file {} missing — download CC0 samples from raw.pixls.us \
         into {} (see module docs)",
        name,
        corpus_dir().display()
    );
    p
}

/// Every corpus RAW fingerprints without error and records a realistic
/// photo scale for the adaptive thresholds.
#[test]
#[ignore = "needs local RAW corpus (ZD_RAW_CORPUS)"]
fn corpus_raws_fingerprint_via_preview() {
    for name in ["canon.cr2", "nikon.nef", "sony.arw", "pentax.dng"] {
        let path = corpus_file(name);
        let fp = fingerprint_image(&path, GeometricInvariance::MirrorFlip)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let min_side = fp.metadata["min_side"].as_u64().unwrap();
        assert!(
            min_side >= 512,
            "{name}: preview too small ({min_side}px) — fell back to a thumbnail?"
        );
        assert!(fp.data.len() >= 16);
    }
}

/// A RAW and the JPEG exported from it hash as near-duplicates; the
/// same-basename sibling pair stays gated.
#[test]
#[ignore = "needs local RAW corpus (ZD_RAW_CORPUS)"]
fn corpus_raw_matches_its_exported_jpeg() {
    let raw_path = corpus_file("canon.cr2");
    let det = ImagePHashDetector::new();

    // Export = the embedded preview itself, decoded and re-encoded.
    let dir = tempfile::tempdir().unwrap();
    let export = dir.path().join("export_distinto.jpg");
    let fp_raw = fingerprint_image(&raw_path, GeometricInvariance::MirrorFlip).unwrap();
    {
        use rawler::decoders::RawDecodeParams;
        use rawler::rawsource::RawSource;
        let source = RawSource::new(&raw_path).unwrap();
        let decoder = rawler::get_decoder(&source).unwrap();
        let img = decoder
            .full_image(&source, &RawDecodeParams::default())
            .unwrap()
            .expect("canon.cr2 carries a full-size preview");
        img.to_rgb8().save(&export).unwrap();
    }
    let fp_jpg = fingerprint_image(&export, GeometricInvariance::MirrorFlip).unwrap();

    assert!(
        det.is_near_duplicate(&fp_raw, &fp_jpg),
        "RAW and its exported JPEG must match"
    );
    // Same basename ⇒ sibling pair ⇒ gatekeeper holds.
    assert!(det.are_siblings_not_duplicates(Path::new("d/IMG_1.CR2"), Path::new("d/IMG_1.JPG")));
    // RAW wins the keeper duel against its derived JPEG.
    let s_raw = det.keeper_score(&raw_path).unwrap();
    let s_jpg = det.keeper_score(&export).unwrap();
    assert!(
        s_raw > s_jpg,
        "RAW keeper score {s_raw} must beat derived JPEG {s_jpg}"
    );
}

/// Closure criterion D-009: fingerprinting through the embedded preview
/// must be much cheaper than a full develop of the sensor data.
///
/// Measured on a full-sensor RAW (sony.arw): sRAW files like the corpus
/// CR2 are adversarial — their sensor data is *smaller* than their
/// embedded preview, so develop and preview roughly tie there.
#[test]
#[ignore = "needs local RAW corpus (ZD_RAW_CORPUS); run with --release"]
fn corpus_preview_beats_full_develop() {
    use rawler::decoders::RawDecodeParams;
    use rawler::rawsource::RawSource;

    let path = corpus_file("sony.arw");

    let t0 = Instant::now();
    fingerprint_image(&path, GeometricInvariance::MirrorFlip).unwrap();
    let t_preview = t0.elapsed();

    let t0 = Instant::now();
    let source = RawSource::new(&path).unwrap();
    let decoder = rawler::get_decoder(&source).unwrap();
    let raw = decoder
        .raw_image(&source, &RawDecodeParams::default(), false)
        .unwrap();
    let dev = rawler::imgop::develop::RawDevelop::default();
    let _img = dev
        .develop_intermediate(&raw)
        .unwrap()
        .to_dynamic_image()
        .unwrap();
    let t_develop = t0.elapsed();

    println!("preview+fingerprint: {t_preview:?} | develop only: {t_develop:?}");
    assert!(
        t_preview < t_develop,
        "preview path ({t_preview:?}) must be cheaper than develop ({t_develop:?})"
    );
}
