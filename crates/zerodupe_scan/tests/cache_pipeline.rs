//! Integration tests for the cache-aware pipeline (Fase 1 of the audit):
//! re-scans served from the cache, provenance-directed verification, and
//! self-healing when a cached hash is proven wrong.

use camino::Utf8PathBuf;
use zerodupe_cache::HashCache;
use zerodupe_core::{
    DiscoveryOptions, FullHashReport, HashCacheKey, HashRegion, HashingOptions, PartialHashReport,
    PhysicalFileReport, VerifyMode,
};
use zerodupe_fs::discover_roots;
use zerodupe_scan::{
    build_candidate_groups, byte_compare_groups, full_hash_groups, partial_hash_groups,
};

fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 ^ seed).collect()
}

/// Discovery + stages 2–4 with the given cache, returning fresh reports.
fn run_hash_stages(
    root: &Utf8PathBuf,
    cache: Option<&HashCache>,
) -> (PhysicalFileReport, PartialHashReport, FullHashReport) {
    let discovery = discover_roots(vec![root.clone()], &DiscoveryOptions::default(), None, None);
    assert!(discovery.errors.is_empty());
    let (phys, cand) = build_candidate_groups(&discovery.entries, None, None);
    let options = HashingOptions::default();
    let partial = partial_hash_groups(&phys.physical_files, &cand, &options, cache, None, None);
    let full = full_hash_groups(&phys.physical_files, &partial, &options, cache, None, None);
    (phys, partial, full)
}

fn temp_root() -> (tempfile::TempDir, Utf8PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 tempdir");
    (dir, root)
}

#[test]
fn second_scan_is_served_from_cache() {
    let (_dir, root) = temp_root();
    let data = pattern(1, 20_000);
    std::fs::write(root.join("a.bin").into_std_path_buf(), &data).expect("write");
    std::fs::write(root.join("b.bin").into_std_path_buf(), &data).expect("write");

    let cache = HashCache::open_memory().expect("cache");

    let (phys1, _, full1) = run_hash_stages(&root, Some(&cache));
    assert_eq!(full1.cache_hits, 0);
    assert_eq!(full1.cache_misses, 2);
    assert_eq!(full1.groups.len(), 1);
    assert!(
        !full1.groups[0].any_cached,
        "first scan: every hash is fresh"
    );

    // Same tree, new discovery: everything must come from the cache.
    let (phys2, _, full2) = run_hash_stages(&root, Some(&cache));
    assert_eq!(full2.cache_hits, 2);
    assert_eq!(full2.cache_misses, 0);
    assert_eq!(full2.groups.len(), 1);
    assert!(full2.groups[0].any_cached, "second scan: hashes are cached");

    // CachedOnly: the fresh group is trusted, the cached one is verified.
    let discovery = discover_roots(vec![root.clone()], &DiscoveryOptions::default(), None, None);
    let fresh = byte_compare_groups(
        &full1,
        &discovery.entries,
        &phys1.physical_files,
        VerifyMode::CachedOnly,
        None,
        None,
    );
    assert_eq!(fresh.groups_trusted, 1);
    let cached = byte_compare_groups(
        &full2,
        &discovery.entries,
        &phys2.physical_files,
        VerifyMode::CachedOnly,
        None,
        None,
    );
    assert_eq!(cached.groups_trusted, 0, "cached group must be verified");
    assert_eq!(cached.confirmed_groups.len(), 1);
    assert!(cached.stale_cache_keys.is_empty());
}

#[test]
fn poisoned_cache_is_detected_and_self_heals() {
    // Two files with identical head and tail but different middles: the
    // partial hash genuinely groups them; only the full hash separates them.
    let (_dir, root) = temp_root();
    let data_a = pattern(2, 20_000);
    let mut data_b = data_a.clone();
    for byte in &mut data_b[10_000..10_010] {
        *byte = !*byte;
    }
    std::fs::write(root.join("a.bin").into_std_path_buf(), &data_a).expect("write");
    std::fs::write(root.join("b.bin").into_std_path_buf(), &data_b).expect("write");

    let cache = HashCache::open_memory().expect("cache");

    // Honest run to learn the real full hashes and keys.
    let (phys, _, honest) = run_hash_stages(&root, Some(&cache));
    assert_eq!(
        honest.groups.len(),
        0,
        "honest hashes must separate the files"
    );

    // Poison: overwrite b's cached full hash with a's, with b's *current*
    // witnesses — simulating a modification the witnesses didn't catch.
    let options = HashingOptions::default();
    let key_for = |name: &str| -> HashCacheKey {
        let pf = phys
            .physical_files
            .iter()
            .find(|pf| pf.canonical_path.as_str().ends_with(name))
            .expect("physical file");
        HashCacheKey {
            physical_key: pf.physical_key.clone(),
            size_bytes: pf.size_bytes,
            version: pf.snapshot.version,
            hash_algorithm: options.hash_algorithm,
            region: HashRegion::Full,
        }
    };
    let key_a = key_for("a.bin");
    let key_b = key_for("b.bin");
    let hash_a = cache.get(&key_a).expect("get a").expect("a cached");
    cache.put(&key_b, &hash_a).expect("poison");

    // Re-scan: the poisoned cache groups a and b as exact duplicates.
    let (phys2, _, lied) = run_hash_stages(&root, Some(&cache));
    assert_eq!(lied.groups.len(), 1, "poisoned cache creates a false group");
    assert!(lied.groups[0].any_cached);

    // CachedOnly verification catches the lie and reports the stale keys.
    let discovery = discover_roots(vec![root.clone()], &DiscoveryOptions::default(), None, None);
    let compare = byte_compare_groups(
        &lied,
        &discovery.entries,
        &phys2.physical_files,
        VerifyMode::CachedOnly,
        None,
        None,
    );
    assert_eq!(
        compare.confirmed_groups.len(),
        0,
        "the false group must not reach the user"
    );
    assert_eq!(compare.eliminated_by_compare, 1);
    assert_eq!(compare.false_positive_groups, 1);
    assert_eq!(
        compare.stale_cache_keys.len(),
        2,
        "both members' keys are reported (we can't tell which hash lied)"
    );

    // Self-heal: invalidate and re-scan — the truth is restored.
    for key in &compare.stale_cache_keys {
        cache.invalidate(key).expect("invalidate");
    }
    assert_eq!(cache.get(&key_b).expect("get b"), None, "poison purged");
    let (_, _, healed) = run_hash_stages(&root, Some(&cache));
    assert_eq!(healed.groups.len(), 0, "after healing, no false duplicates");
}

/// Capa 1 of the stale-hash defence: a tool that modifies a file and then
/// restores its mtime still bumps the kernel-maintained ctime, which must
/// invalidate the cache entry. Unix only — Windows has no ctime witness
/// (there the residual risk is covered by CachedOnly verification instead).
#[cfg(unix)]
#[test]
fn mtime_restored_modification_misses_cache_via_ctime() {
    let (_dir, root) = temp_root();
    let path = root.join("f.bin").into_std_path_buf();
    std::fs::write(&path, pattern(3, 20_000)).expect("write");
    // A second identical file so the size group reaches the hash stages.
    std::fs::write(
        root.join("twin.bin").into_std_path_buf(),
        pattern(3, 20_000),
    )
    .expect("write");

    let cache = HashCache::open_memory().expect("cache");
    let (_, _, first) = run_hash_stages(&root, Some(&cache));
    assert_eq!(first.cache_misses, 2);

    // Modify the file, then restore its original mtime (what some backup
    // and sync tools do). Same size, same mtime — but ctime moved.
    let original_mtime = std::fs::metadata(&path)
        .expect("meta")
        .modified()
        .expect("mtime");
    let mut tampered = pattern(3, 20_000);
    for byte in &mut tampered[10_000..10_010] {
        *byte = !*byte;
    }
    std::fs::write(&path, &tampered).expect("rewrite");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open");
    file.set_times(std::fs::FileTimes::new().set_modified(original_mtime))
        .expect("restore mtime");
    drop(file);

    let (_, _, second) = run_hash_stages(&root, Some(&cache));
    // The tampered file must be re-hashed (ctime mismatch), and with its
    // real hash the pair no longer groups.
    assert!(
        second.cache_misses >= 1,
        "tampered file must miss the cache, got hits={} misses={}",
        second.cache_hits,
        second.cache_misses,
    );
    assert_eq!(second.groups.len(), 0, "tampering must break the group");
}

/// Safety net for the Fase 2.1 fast path: small files (≤ head+tail) skip
/// full hashing and their group's provenance comes from the *partial*
/// hashes. A poisoned cached partial hash must therefore flow into
/// `any_cached`, get verified under `CachedOnly`, and be reported stale —
/// the false group never reaches the user.
#[test]
fn poisoned_partial_cache_on_small_files_is_caught() {
    let (_dir, root) = temp_root();
    // Same size, different content, well under head+tail (1 KB).
    std::fs::write(root.join("a.txt").into_std_path_buf(), pattern(4, 1_000)).expect("write");
    std::fs::write(root.join("b.txt").into_std_path_buf(), pattern(5, 1_000)).expect("write");

    let cache = HashCache::open_memory().expect("cache");

    // Honest run: partial hashes separate them, nothing groups.
    let (phys, honest_partial, honest_full) = run_hash_stages(&root, Some(&cache));
    assert_eq!(honest_partial.groups.len(), 0);
    assert_eq!(honest_full.groups.len(), 0);

    // Poison b's cached *partial* hash with a's value.
    let options = HashingOptions::default();
    let partial_region = HashRegion::HeadTail {
        head_bytes: options.partial_chunk_size,
        tail_bytes: options.partial_chunk_size,
    };
    let key_for = |name: &str| -> HashCacheKey {
        let pf = phys
            .physical_files
            .iter()
            .find(|pf| pf.canonical_path.as_str().ends_with(name))
            .expect("physical file");
        HashCacheKey {
            physical_key: pf.physical_key.clone(),
            size_bytes: pf.size_bytes,
            version: pf.snapshot.version,
            hash_algorithm: options.hash_algorithm,
            region: partial_region.clone(),
        }
    };
    let partial_a = cache
        .get(&key_for("a.txt"))
        .expect("get")
        .expect("a cached");
    cache.put(&key_for("b.txt"), &partial_a).expect("poison");

    // Re-scan: the poisoned partial groups them, and the covered-by-partial
    // shortcut promotes the group without full hashing.
    let (phys2, _, lied) = run_hash_stages(&root, Some(&cache));
    assert_eq!(
        lied.groups.len(),
        1,
        "poisoned partial creates a false group"
    );
    assert_eq!(lied.covered_by_partial, 2, "fast path was taken");
    assert!(
        lied.groups[0].any_cached,
        "partial provenance must flow into the promoted group"
    );

    // CachedOnly catches it: the false group dies and the keys are reported.
    let discovery = discover_roots(vec![root.clone()], &DiscoveryOptions::default(), None, None);
    let compare = byte_compare_groups(
        &lied,
        &discovery.entries,
        &phys2.physical_files,
        VerifyMode::CachedOnly,
        None,
        None,
    );
    assert_eq!(compare.confirmed_groups.len(), 0);
    assert_eq!(compare.eliminated_by_compare, 1);
    assert_eq!(compare.stale_cache_keys.len(), 2);
}
