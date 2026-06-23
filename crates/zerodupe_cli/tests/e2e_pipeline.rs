use std::fs;
use std::io::Write;

use camino::Utf8PathBuf;
use zerodupe_core::{CancelFlag, DiscoveryOptions, FileCandidate, HashingOptions};
use zerodupe_fs::discover_roots;
use zerodupe_scan::{
    build_candidate_groups, byte_compare_groups, full_hash_groups, partial_hash_groups,
};

fn create_test_corpus() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");

    let mut a = fs::File::create(dir.path().join("a.txt")).unwrap();
    a.write_all(
        b"aaa...unique content 100 bytes long..............................................",
    )
    .unwrap();

    let content_bc =
        b"bbb...duplicate content 100 bytes long.........................................";
    let mut b = fs::File::create(dir.path().join("b.txt")).unwrap();
    b.write_all(content_bc).unwrap();
    let mut c = fs::File::create(dir.path().join("c.txt")).unwrap();
    c.write_all(content_bc).unwrap();

    fs::create_dir_all(dir.path().join("sub")).unwrap();
    let mut d = fs::File::create(dir.path().join("sub/d.txt")).unwrap();
    d.write_all(b"ddd...unique 50 bytes.........................")
        .unwrap();
    let mut e = fs::File::create(dir.path().join("sub/e.txt")).unwrap();
    e.write_all(
        b"eee...unique content 200 bytes long...................................................................................................",
    )
    .unwrap();

    dir
}

#[test]
fn full_pipeline_detects_one_duplicate_group() {
    let dir = create_test_corpus();
    let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

    let options = DiscoveryOptions::default();
    let discovery = discover_roots(vec![root.clone()], &options, None, None);
    assert!(
        discovery.entries.len() >= 5,
        "should discover at least 5 files"
    );

    let (phys, cand) = build_candidate_groups(&discovery.entries, None, None);
    assert!(
        cand.multi_entry_groups() >= 1,
        "should have at least one size group with multiple files"
    );

    let hashing = HashingOptions::default();
    let partial = partial_hash_groups(&phys.physical_files, &cand, &hashing, None, None, None);

    let full = full_hash_groups(&phys.physical_files, &partial, &hashing, None, None, None);
    assert!(
        full.confirmed_duplicates >= 1,
        "should find at least 1 duplicate group"
    );

    let compare = byte_compare_groups(
        &full,
        &discovery.entries,
        &phys.physical_files,
        zerodupe_core::VerifyMode::Always,
        None,
        None,
    );
    assert_eq!(
        compare.confirmed_groups.len(),
        1,
        "should have exactly 1 duplicate group"
    );
    assert_eq!(
        compare.confirmed_groups[0].files.len(),
        2,
        "group should have 2 files"
    );

    let reclaimable: u64 = compare
        .confirmed_groups
        .iter()
        .map(|g| g.size_bytes * (g.files.len() as u64 - 1))
        .sum();
    assert_eq!(
        reclaimable, 79,
        "reclaimable should be exactly the duplicate file size"
    );
}

#[test]
fn pipeline_with_cancel_flag_stops_early() {
    let dir = create_test_corpus();
    let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

    let cancel = CancelFlag::new();
    cancel.cancel();

    let options = DiscoveryOptions::default();
    let discovery = discover_roots(vec![root], &options, None, None);
    let (_phys, cand) = build_candidate_groups(&discovery.entries, None, Some(&cancel));

    assert!(
        cand.multi_entry_groups() == 0,
        "cancelled pipeline should produce no groups"
    );
}

// ── Quarantine roundtrip tests ──

/// Verifies the full quarantine lifecycle: move → list → restore → list → purge.
/// Ensures the SQLite journal stays consistent and file operations are reversible.
#[test]
fn quarantine_roundtrip_move_restore_purge() {
    let content = b"aaa...quarantine test content 100 bytes long.............................";
    let dir = tempfile::tempdir().expect("tempdir");
    let qdir = dir.path().join("zerodupe_quarantine");

    let keeper = dir.path().join("keeper.txt");
    fs::write(&keeper, content).expect("write keeper");
    let dup1 = dir.path().join("dup1.txt");
    fs::write(&dup1, content).expect("write dup1");
    let dup2 = dir.path().join("dup2.txt");
    fs::write(&dup2, content).expect("write dup2");

    let q = zerodupe_safety::Quarantine::open(&qdir).expect("open quarantine");

    let e1 = q
        .quarantine_file(&dup1, "exact duplicate", "test-session", Some(30))
        .expect("quarantine dup1");
    let e2 = q
        .quarantine_file(&dup2, "exact duplicate", "test-session", Some(30))
        .expect("quarantine dup2");

    assert!(keeper.exists(), "keeper should remain in place");
    assert!(!dup1.exists(), "dup1 should be moved to quarantine");
    assert!(!dup2.exists(), "dup2 should be moved to quarantine");
    assert!(
        e1.quarantined_path.as_std_path().exists(),
        "quarantined dup1 should exist"
    );
    assert!(
        e2.quarantined_path.as_std_path().exists(),
        "quarantined dup2 should exist"
    );

    let list = q.list_quarantined(false).expect("list");
    assert_eq!(list.len(), 2, "should have 2 active entries");
    assert!(list[0].purge_at.is_some(), "entry 0 should have purge_at");
    assert!(list[1].purge_at.is_some(), "entry 1 should have purge_at");

    q.restore_file(e1.id).expect("restore dup1");
    assert!(dup1.exists(), "dup1 should be back at original location");
    let restored_content = fs::read(&dup1).expect("read restored dup1");
    assert_eq!(restored_content, content, "restored content should match");

    let list_after = q.list_quarantined(false).expect("list after restore");
    assert_eq!(list_after.len(), 1, "should have 1 remaining active entry");

    q.purge_file(list_after[0].id).expect("purge remaining");
    assert!(
        !list_after[0].quarantined_path.as_std_path().exists(),
        "purged file should be gone from quarantine"
    );

    let list_final = q.list_quarantined(false).expect("list final");
    assert_eq!(list_final.len(), 0, "should have 0 entries after purge");
}

/// Verifies that a manually deleted quarantined file is cleaned up from the
/// journal when the quarantine is re-opened and listed.
#[test]
fn quarantine_sanitize_handles_manual_deletion() {
    let dir = tempfile::tempdir().expect("tempdir");
    let qdir = dir.path().join("zerodupe_quarantine");

    let f1 = dir.path().join("a.txt");
    fs::write(&f1, b"hello").expect("write");

    let entry_path;
    {
        let q = zerodupe_safety::Quarantine::open(&qdir).expect("open");
        let entry = q
            .quarantine_file(&f1, "test", "session-1", None)
            .expect("quarantine");
        entry_path = entry.quarantined_path.as_std_path().to_path_buf();
    }

    assert!(
        entry_path.exists(),
        "quarantined file should exist before deletion"
    );
    fs::remove_file(&entry_path).expect("manual delete");

    let q2 = zerodupe_safety::Quarantine::open(&qdir).expect("reopen");
    let list = q2.list_quarantined(false).expect("list");
    assert_eq!(list.len(), 0, "orphan entry should be cleaned up");
}

// ── Hygiene tests ──

/// Verifies that the hygiene scanner detects common junk files:
/// empty files, empty directories, temporary files, and system junk.
#[test]
fn hygiene_detects_junk_files() {
    let dir = tempfile::tempdir().expect("tempdir");

    fs::write(dir.path().join("Thumbs.db"), b"dummy").expect("write Thumbs.db");

    let empty_dir = dir.path().join("empty_dir");
    fs::create_dir(&empty_dir).expect("create empty_dir");

    let empty_txt = dir.path().join("empty.txt");
    fs::write(&empty_txt, b"").expect("write empty.txt");

    let tmp_file = dir.path().join("tmp_xxxx.tmp");
    fs::write(&tmp_file, b"temp content").expect("write temp");

    #[cfg(unix)]
    {
        let broken_symlink_target = dir.path().join("nonexistent.txt");
        let broken_link = dir.path().join("broken_link");
        let _ = std::os::unix::fs::symlink(&broken_symlink_target, &broken_link);
    }

    let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8");
    let service = zerodupe_hygiene::HygieneService::new(root);
    let report = service.scan(None, None);

    let categories: std::collections::HashSet<String> = report
        .items
        .iter()
        .map(|i| format!("{}", i.category))
        .collect();

    assert!(
        categories.len() >= 3,
        "should detect at least 3 junk categories, got {categories:?} | items: {:?}",
        report
            .items
            .iter()
            .map(|i| (&i.path, format!("{}", i.category)))
            .collect::<Vec<_>>()
    );

    let has_system_junk = report.items.iter().any(|i| {
        matches!(
            i.category,
            zerodupe_hygiene::types::JunkCategory::SystemJunk
        )
    });
    assert!(has_system_junk, "should detect system junk (Thumbs.db)");

    let has_empty_dirs = report.items.iter().any(|i| {
        matches!(
            i.category,
            zerodupe_hygiene::types::JunkCategory::EmptyDirectory
        )
    });
    assert!(has_empty_dirs, "should detect empty directories");

    let has_empty_files = report
        .items
        .iter()
        .any(|i| matches!(i.category, zerodupe_hygiene::types::JunkCategory::EmptyFile));
    assert!(has_empty_files, "should detect empty files");
}

// ── Similar images test ──

/// Verifies that the image similarity detector finds near-duplicate images.
/// Creates two 256x256 images with random noise (second lightly perturbed).
#[test]
fn similar_images_detects_groups() {
    let dir = tempfile::tempdir().expect("tempdir");

    use image::{Rgb, RgbImage};
    let w = 256u32;
    let h = 256u32;

    fn make_noise(w: u32, h: u32, seed: u64) -> RgbImage {
        let mut img = RgbImage::new(w, h);
        let mut state = seed;
        for pixel in img.pixels_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let r = (state >> 32) as u8;
            let g = (state >> 24) as u8;
            let b = (state >> 16) as u8;
            *pixel = Rgb([r, g, b]);
        }
        img
    }

    let mut img_b = make_noise(w, h, 100);
    let mut state = 200u64;
    for pixel in img_b.pixels_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        if (state & 0xFF) < 5 {
            pixel[0] = pixel[0].wrapping_add(2);
        }
    }
    let img_a = make_noise(w, h, 100);

    let path_a = dir.path().join("img_a.png");
    img_a.save(&path_a).expect("save img_a");
    let path_b = dir.path().join("img_b.png");
    img_b.save(&path_b).expect("save img_b");

    let candidates = vec![
        FileCandidate {
            path: Utf8PathBuf::from_path_buf(path_a.clone()).expect("utf8"),
            size_bytes: 0,
        },
        FileCandidate {
            path: Utf8PathBuf::from_path_buf(path_b.clone()).expect("utf8"),
            size_bytes: 0,
        },
    ];

    let detector = zerodupe_similar_image::ImagePHashDetector::new();
    let detectors: &[&dyn zerodupe_similar::SimilarityDetector] = &[&detector];
    let report = zerodupe_similar::detect_similars(&candidates, detectors, None, None, None);

    assert!(
        !report.groups.is_empty(),
        "should detect at least 1 similar group, got {} errors: {:?}",
        report.errors.len(),
        report.errors
    );
}

// ── Takeout test ──

/// Verifies the Google Takeout JSON sidecar workflow:
/// discovery, parse, metadata extraction, and mtime merge.
#[test]
fn takeout_json_merge_and_quarantine() {
    let dir = tempfile::tempdir().expect("tempdir");
    let photo_path = dir.path().join("photo.jpg");

    let binary_content = [0u8; 50];
    fs::write(&photo_path, binary_content).expect("write photo.jpg");

    let json_path = dir.path().join("photo.jpg.json");
    let json_content = serde_json::json!({
        "title": "test photo",
        "photoTakenTime": {"timestamp": "1700000000"},
        "geoData": {"latitude": 40.7128, "longitude": -74.0060}
    });
    fs::write(
        &json_path,
        serde_json::to_string_pretty(&json_content).unwrap(),
    )
    .expect("write photo.jpg.json");

    let found = zerodupe_hygiene::takeout::takeout_json_for_image(&photo_path);
    assert!(found.is_some(), "should find the takeout JSON sidecar");
    let found_path = found.expect("just checked");

    let metadata =
        zerodupe_hygiene::takeout::parse_takeout_json(&found_path).expect("parse takeout JSON");
    assert_eq!(
        metadata.timestamp_secs,
        Some(1700000000),
        "should extract correct timestamp"
    );
    assert!(
        (metadata.latitude.unwrap() - 40.7128).abs() < 0.001,
        "should extract correct latitude"
    );
    assert!(
        (metadata.longitude.unwrap() - (-74.0060)).abs() < 0.001,
        "should extract correct longitude"
    );
    assert_eq!(
        metadata.title.as_deref(),
        Some("test photo"),
        "should extract correct title"
    );

    zerodupe_hygiene::takeout::merge_takeout_metadata(&photo_path, &metadata)
        .expect("merge metadata");

    let merged_meta = fs::metadata(&photo_path).expect("metadata after merge");
    let merged_mtime = merged_meta
        .modified()
        .expect("modified time")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("duration since epoch")
        .as_secs() as i64;
    assert_eq!(
        merged_mtime, 1700000000,
        "modification time should be updated to taken time"
    );
}
