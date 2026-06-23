//! Near-duplicate detection orchestrator — plugin architecture.
//!
//! This crate defines the `SimilarityDetector` trait that each file-type
//! plugin implements. The orchestrator selects the right detector based on
//! file extension and coordinates the similarity analysis.
//!
//! Does NOT touch the exact-duplicate pipeline in any way.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use zerodupe_cache::{CachedFingerprint, FingerprintCacheKey, HashCache};
use zerodupe_core::{CancelFlag, FileCandidate, FileVersion};

/// A detector for near-duplicate files of a specific type.
///
/// Each implementation lives in its own crate (e.g. `zerodupe_similar_image`).
pub trait SimilarityDetector: Send + Sync {
    /// Human-readable name: "image-phash", "audio-chromaprint", etc.
    fn name(&self) -> &'static str;

    /// Version of this detector's fingerprint algorithm. Cached fingerprints
    /// computed with a different version are ignored. Bump on any change to
    /// the fingerprint bytes or their semantics.
    fn algo_version(&self) -> u32 {
        1
    }

    /// Opaque string identifying the detector configuration (hash size,
    /// geometric invariance mode, ...). Part of the fingerprint cache key:
    /// changing configuration invalidates cached fingerprints.
    fn cache_params(&self) -> String {
        String::new()
    }

    /// File extensions this detector handles (lowercase, without dot).
    fn extensions(&self) -> &[&'static str];

    /// Computes a fingerprint for a file at the given path.
    /// Returns an error if the file cannot be read or is not a valid file of this type.
    fn fingerprint(&self, path: &Path) -> std::io::Result<FingerprintData>;

    /// Distance between the *canonical* fingerprints of two files.
    /// Lower = more similar. 0 = identical. The scale depends on the
    /// detector.
    ///
    /// Must be a metric (symmetric, triangle inequality): it drives BK-tree
    /// construction and traversal. Geometric variants are matched through
    /// `variant_distance` / `is_near_duplicate`, never through this.
    fn distance(&self, a: &FingerprintData, b: &FingerprintData) -> u32;

    /// Number of geometric variants encoded in this fingerprint (≥ 1).
    /// Variant 0 is the canonical fingerprint. Detectors without geometric
    /// invariance keep the default of 1.
    fn variant_count(&self, _fp: &FingerprintData) -> usize {
        1
    }

    /// Metric distance from variant `k` of `a` to the *canonical*
    /// fingerprint of `b`. For fixed `k` this must satisfy the triangle
    /// inequality — the BK-tree runs one range query per query variant.
    /// `variant_distance(a, 0, b)` must equal `distance(a, b)`.
    fn variant_distance(&self, a: &FingerprintData, _k: usize, b: &FingerprintData) -> u32 {
        self.distance(a, b)
    }

    /// Normalized similarity score: 0.0 = completely different, 1.0 = identical.
    fn similarity(&self, a: &FingerprintData, b: &FingerprintData) -> f64;

    /// Returns true if two fingerprints likely represent the same content.
    ///
    /// CONTRACT: the BK-tree only evaluates this for nodes reached within
    /// range of some `variant_distance(a, k, ·)`. A detector whose match
    /// criterion considers alignments beyond the canonical distance MUST
    /// expose them through `variant_count`/`variant_distance` (and any
    /// wrapper detector must delegate those methods), or matches will be
    /// silently lost to tree pruning.
    fn is_near_duplicate(&self, a: &FingerprintData, b: &FingerprintData) -> bool;

    /// Human-readable confidence label for a similarity score.
    fn confidence_label(&self, similarity: f64) -> &'static str;

    /// Computes a keeper score for a file (higher = better to keep).
    /// Takes into account type-specific quality factors (resolution, bitrate, etc.).
    fn keeper_score(&self, path: &Path) -> std::io::Result<f64>;

    /// Gatekeeper check: returns true if two files should NOT be considered
    /// duplicates regardless of fingerprint similarity.
    ///
    /// Examples: RAW+JPEG same shot, Live Photo .HEIC+.MOV pair, burst photos.
    /// Default: false (no gatekeeper).
    fn are_siblings_not_duplicates(&self, _a: &Path, _b: &Path) -> bool {
        false
    }
}

/// Opaque fingerprint data produced by a detector.
#[derive(Debug, Clone)]
pub struct FingerprintData {
    /// Detector name that produced this fingerprint.
    pub detector: String,
    /// Raw fingerprint bytes.
    pub data: Vec<u8>,
    /// Optional type-specific metadata (e.g., image dimensions, audio duration).
    pub metadata: serde_json::Value,
}

/// A group of near-duplicate files detected by the same detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearDuplicateGroup {
    /// Name of the detector that found this group.
    pub detector: String,
    /// Files in the group.
    pub files: Vec<FileCandidate>,
    /// Similarity scores between each pair (N×N matrix).
    pub similarity_scores: Vec<Vec<f64>>,
    /// Index of the recommended keeper.
    pub keeper_index: usize,
    /// Average similarity within the group.
    pub avg_similarity: f64,
    /// Human-readable confidence.
    pub confidence: String,
}

/// Result of a near-duplicate analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityReport {
    /// Groups found, grouped by detector.
    pub groups: Vec<NearDuplicateGroup>,
    /// Files processed.
    pub files_scanned: usize,
    /// Files skipped (unsupported type / read error).
    pub files_skipped: usize,
    /// Errors encountered.
    pub errors: Vec<String>,
}

/// Re-pins group keepers to files that survived a previous cleanup.
///
/// `kept` holds the paths recorded as keepers of an earlier pass (exact or
/// similar). Each is the only on-disk survivor of its original duplicate
/// group, so a later similar pass must never offer it for removal:
/// - a group containing a kept file gets it as keeper (the current keeper
///   wins if it is itself kept);
/// - additional kept files are dropped from the group so they can never be
///   listed as removable;
/// - groups left with fewer than two files are removed from the report.
pub fn protect_prior_keepers(
    report: &mut SimilarityReport,
    kept: &std::collections::HashSet<String>,
) {
    if kept.is_empty() {
        return;
    }
    report.groups.retain_mut(|group| {
        let kept_idx: Vec<usize> = group
            .files
            .iter()
            .enumerate()
            .filter(|(_, f)| kept.contains(f.path.as_str()))
            .map(|(i, _)| i)
            .collect();
        if kept_idx.is_empty() {
            return true;
        }

        let keeper = if kept_idx.contains(&group.keeper_index) {
            group.keeper_index
        } else {
            kept_idx[0]
        };

        let retain: Vec<usize> = (0..group.files.len())
            .filter(|&i| i == keeper || !kept_idx.contains(&i))
            .collect();
        if retain.len() < 2 {
            return false;
        }

        if retain.len() != group.files.len() {
            group.files = retain.iter().map(|&i| group.files[i].clone()).collect();
            let sub: Vec<Vec<f64>> = retain
                .iter()
                .map(|&a| {
                    retain
                        .iter()
                        .map(|&b| group.similarity_scores[a][b])
                        .collect()
                })
                .collect();
            let mut total = 0.0;
            let mut pairs = 0u64;
            for (a, row) in sub.iter().enumerate() {
                for v in &row[a + 1..] {
                    total += v;
                    pairs += 1;
                }
            }
            group.similarity_scores = sub;
            group.avg_similarity = if pairs > 0 { total / pairs as f64 } else { 1.0 };
        }
        group.keeper_index = retain
            .iter()
            .position(|&i| i == keeper)
            .expect("keeper index retained above");
        true
    });
}

/// Builds a `SimilarityReport` by scanning files with a set of detectors.
///
/// Optimizations:
/// - Persistent fingerprint cache (`zerodupe_cache`): only files that
///   changed since the last scan are decoded and hashed. Failures are
///   cached too, so corrupt files aren't re-decoded on every scan.
/// - Hardlink dedup: one fingerprint per physical file (inode), so N
///   hardlinks to the same data never form a fake "similar" group.
/// - Uses BK-tree for sublinear Hamming distance search.
pub fn detect_similars(
    files: &[FileCandidate],
    detectors: &[&dyn SimilarityDetector],
    cache: Option<&HashCache>,
    progress_arc: Option<Arc<AtomicUsize>>,
    cancel: Option<&CancelFlag>,
) -> SimilarityReport {
    let mut report = SimilarityReport {
        groups: Vec::new(),
        files_scanned: 0,
        files_skipped: 0,
        errors: Vec::new(),
    };

    let bump = |n: usize| {
        if let Some(ref p) = progress_arc {
            p.fetch_add(n, Ordering::Relaxed);
        }
    };

    for detector in detectors {
        let detector = *detector;
        let matching: Vec<&FileCandidate> = files
            .iter()
            .filter(|f| {
                let ext = f.path.extension().unwrap_or("").to_lowercase();
                detector.extensions().contains(&ext.as_str())
            })
            .collect();

        if matching.len() < 2 {
            report.files_skipped += matching.len();
            continue;
        }

        // ── Stage 1: one stat per candidate ──
        // Yields the physical identity (hardlink dedup) and the version
        // witnesses (fingerprint-cache key) in a single syscall per file.
        let profile = zerodupe_platform::current();
        let detector_params = detector.cache_params();
        let algo_version = detector.algo_version();

        let mut seen_keys: std::collections::HashSet<zerodupe_platform::PhysicalFileKey> =
            std::collections::HashSet::new();
        let mut candidates: Vec<(usize, FingerprintCacheKey)> = Vec::new();

        for (i, file) in matching.iter().enumerate() {
            let meta = match std::fs::metadata(file.path.as_std_path()) {
                Ok(m) => m,
                Err(e) => {
                    report.errors.push(format!(
                        "{}: {} — {}",
                        detector.name(),
                        file.path.as_str(),
                        e
                    ));
                    report.files_skipped += 1;
                    bump(1);
                    continue;
                }
            };
            let physical_key = profile.physical_key(file.path.as_path(), &meta);
            if let Some(ref key) = physical_key
                && !key.is_fallback()
                && !seen_keys.insert(key.clone())
            {
                // Hardlink to an already-seen inode: same physical bytes,
                // one fingerprint per disk (czkawka's take_1_per_inode).
                bump(1);
                continue;
            }
            candidates.push((
                i,
                FingerprintCacheKey {
                    physical_key,
                    size_bytes: meta.len(),
                    version: FileVersion::from_metadata(&meta),
                    detector: detector.name().to_string(),
                    params: detector_params.clone(),
                    algo_version,
                },
            ));
        }

        // ── Stage 2: split cached / uncached ──
        // Cached errors are reported from the cache without re-decoding.
        // Cached fingerprints with unparsable metadata fall back to compute.
        let mut fingerprints: Vec<(usize, FingerprintData)> = Vec::new();
        let mut to_compute: Vec<(usize, FingerprintCacheKey)> = Vec::new();

        for (i, fp_key) in candidates {
            match cache.and_then(|c| c.get_fingerprint(&fp_key).ok().flatten()) {
                Some(CachedFingerprint::Ok {
                    data,
                    metadata_json,
                }) => match serde_json::from_str(&metadata_json) {
                    Ok(metadata) => {
                        bump(1);
                        fingerprints.push((
                            i,
                            FingerprintData {
                                detector: detector.name().to_string(),
                                data,
                                metadata,
                            },
                        ));
                    }
                    Err(_) => to_compute.push((i, fp_key)),
                },
                Some(CachedFingerprint::Error { message }) => {
                    bump(1);
                    report.errors.push(format!(
                        "{}: {} — {}",
                        detector.name(),
                        matching[i].path.as_str(),
                        message
                    ));
                }
                None => to_compute.push((i, fp_key)),
            }
        }

        // ── Stage 3: fingerprint only the uncached files (rayon) ──
        // The Result travels with the file so errors are captured in this
        // single pass — no second fingerprint call just for the message.
        let computed: Vec<(usize, FingerprintCacheKey, Result<FingerprintData, String>)> =
            to_compute
                .into_par_iter()
                .map(|(i, fp_key)| {
                    let result = detector
                        .fingerprint(matching[i].path.as_std_path())
                        .map_err(|e| e.to_string());
                    if let Some(ref p) = progress_arc {
                        p.fetch_add(1, Ordering::Relaxed);
                    }
                    (i, fp_key, result)
                })
                .collect();

        if let Some(c) = cancel
            && c.is_cancelled()
        {
            return report;
        }

        // ── Stage 4: partition results, persist batch (successes + errors) ──
        let mut cache_entries: Vec<(FingerprintCacheKey, CachedFingerprint)> = Vec::new();
        for (i, fp_key, result) in computed {
            match result {
                Ok(fp) => {
                    if cache.is_some() {
                        cache_entries.push((
                            fp_key,
                            CachedFingerprint::Ok {
                                data: fp.data.clone(),
                                metadata_json: fp.metadata.to_string(),
                            },
                        ));
                    }
                    fingerprints.push((i, fp));
                }
                Err(message) => {
                    report.errors.push(format!(
                        "{}: {} — {}",
                        detector.name(),
                        matching[i].path.as_str(),
                        message
                    ));
                    if cache.is_some() {
                        cache_entries.push((fp_key, CachedFingerprint::Error { message }));
                    }
                }
            }
        }
        if let Some(c) = cache {
            // Best-effort: a failed write only means re-computing next scan.
            let _ = c.put_fingerprint_batch(&cache_entries);
        }

        if fingerprints.len() < 2 {
            report.files_skipped += fingerprints.len();
            continue;
        }

        report.files_scanned += fingerprints.len();

        // ── BK-tree search over all fingerprints ──
        // No aspect ratio bucketing — correct perceptual hashes handle
        // different aspect ratios naturally via high Hamming distance.
        let n = fingerprints.len();
        let all_indices: Vec<usize> = (0..n).collect();
        let edges =
            find_near_duplicates_in_bucket(detector, &fingerprints, &all_indices, &matching);

        // ── Connected components from BK-tree edges ──
        // Each pair in `edges` is already verified as near-duplicate.
        // We use Union-Find to group transitive near-duplicates.
        let components = connected_components(&edges, n);

        for comp in &components {
            if comp.len() < 2 {
                continue;
            }

            let files: Vec<FileCandidate> = comp
                .iter()
                .map(|&idx| matching[fingerprints[idx].0].clone())
                .collect();

            // Build pairwise similarity matrix and check for weak links.
            // Connected components can chain A~B~C even if A≁C.
            // We split components where some pairs fall below the split threshold.
            let group_n = comp.len();
            let mut sim_matrix = vec![vec![0.0f64; group_n]; group_n];
            let mut min_pair_sim = 1.0f64;
            for gi in 0..group_n {
                sim_matrix[gi][gi] = 1.0;
                for gj in (gi + 1)..group_n {
                    let sim =
                        detector.similarity(&fingerprints[comp[gi]].1, &fingerprints[comp[gj]].1);
                    sim_matrix[gi][gj] = sim;
                    sim_matrix[gj][gi] = sim;
                    if sim < min_pair_sim {
                        min_pair_sim = sim;
                    }
                }
            }

            // If any pair is well below the detection threshold, split the group
            // by removing edges with similarity < SPLIT_THRESHOLD and repartitioning.
            const SPLIT_THRESHOLD: f64 = 0.65;
            let sub_groups = if group_n > 2 && min_pair_sim < SPLIT_THRESHOLD {
                split_by_similarity(&sim_matrix, group_n)
            } else {
                vec![(0..group_n).collect::<Vec<usize>>()]
            };

            for sub in &sub_groups {
                if sub.len() < 2 {
                    continue;
                }

                let sub_files: Vec<FileCandidate> =
                    sub.iter().map(|&si| files[si].clone()).collect();

                let sub_n = sub.len();
                let mut total_sim = 0.0;
                for (i, &gi) in sub.iter().enumerate() {
                    for &gj in sub.iter().skip(i + 1) {
                        total_sim += sim_matrix[gi][gj];
                    }
                }
                let pair_count = (sub_n * (sub_n.saturating_sub(1)) / 2) as u64;
                let avg_sim = if pair_count > 0 {
                    total_sim / pair_count as f64
                } else {
                    1.0
                };

                // Build sub-group similarity matrix
                let mut sub_sim = vec![vec![0.0f64; sub_n]; sub_n];
                for si in 0..sub_n {
                    sub_sim[si][si] = 1.0;
                    for sj in (si + 1)..sub_n {
                        sub_sim[si][sj] = sim_matrix[sub[si]][sub[sj]];
                        sub_sim[sj][si] = sub_sim[si][sj];
                    }
                }

                // Select keeper
                let mut keeper_idx = 0;
                let mut best_keeper = f64::MIN;
                for (i, file) in sub_files.iter().enumerate() {
                    if let Ok(score) = detector.keeper_score(file.path.as_std_path())
                        && score > best_keeper
                    {
                        best_keeper = score;
                        keeper_idx = i;
                    }
                }

                let confidence = detector.confidence_label(avg_sim).to_string();

                report.groups.push(NearDuplicateGroup {
                    detector: detector.name().to_string(),
                    files: sub_files,
                    similarity_scores: sub_sim,
                    keeper_index: keeper_idx,
                    avg_similarity: avg_sim,
                    confidence,
                });
            }
        }
    }

    report
}

// ── BK-tree search ──

fn find_near_duplicates_in_bucket(
    detector: &dyn SimilarityDetector,
    fingerprints: &[(usize, FingerprintData)],
    bucket: &[usize],
    matching: &[&FileCandidate],
) -> Vec<(usize, usize, f64)> {
    let mut edges = Vec::new();
    if bucket.len() < 2 {
        return edges;
    }

    // Max Hamming distance considered "near-duplicate" for BK-tree range query.
    // This must be ≥ the largest threshold used by any detector's is_near_duplicate(),
    // plus a small margin for the variant-dedup tolerance (auto-symmetric
    // variants within distance 1 of the canonical hash are dropped, so the
    // surviving alignment can sit up to ~2 bits beyond the threshold).
    const BK_RANGE: u32 = 12;

    // ── Phase 1: build the full BK-tree (standard insertion) ──
    // The tree indexes only canonical (variant-0) fingerprints; geometric
    // variants live on the query side. Insertion descends from the root
    // following the child edge that matches the canonical distance and
    // attaches where no such edge exists: O(depth) per insert.
    let mut tree: Vec<BKNode> = Vec::with_capacity(bucket.len());
    for &fi in bucket {
        let (_, fp) = &fingerprints[fi];
        tree.push(BKNode {
            fp_idx: fi,
            children: std::collections::BTreeMap::new(),
        });
        let new_idx = tree.len() - 1;
        if new_idx == 0 {
            continue;
        }
        let mut cur = 0usize;
        loop {
            let d = detector.distance(fp, &fingerprints[tree[cur].fp_idx].1);
            match tree[cur].children.get(&d).copied() {
                Some(next) => cur = next,
                None => {
                    tree[cur].children.insert(d, new_idx);
                    break;
                }
            }
        }
    }

    // ── Phase 2: every file queries the COMPLETE tree ──
    // Querying while building (the previous scheme) made matching
    // order-dependent for non-involutive variants: an edit variant
    // (center crop, slight rotation — D-011) bridges only from the
    // original's side, so the pair was found only when the original
    // happened to be processed after its edited copy. With the full tree,
    // every ordered direction of every pair runs once; a pair reachable
    // from either side is always found. Duplicate edges (pairs reachable
    // from both sides) are harmless: union-find is idempotent and the
    // group similarity matrix is recomputed pairwise afterwards.
    //
    // Each traversal measures variant-k-of-query vs canonical-of-node,
    // which satisfies the triangle inequality for fixed k. The holistic
    // near-duplicate check runs only for nodes within BK_RANGE and at most
    // once per node per query, tracked by a stamp vector (beats a HashSet:
    // the loop visits a large fraction of the tree when distances
    // concentrate, and per-visit hashing dominated the build at 50K files).
    let mut checked_stamp: Vec<u32> = vec![0; tree.len()];
    let mut query_id: u32 = 0;
    let mut stack: Vec<usize> = Vec::new();

    for &fi in bucket {
        let (orig_idx, fp) = &fingerprints[fi];
        query_id += 1;
        for k in 0..detector.variant_count(fp) {
            stack.clear();
            stack.push(0usize);
            while let Some(ti) = stack.pop() {
                let node_fi = tree[ti].fp_idx;
                let node_fp = &fingerprints[node_fi].1;
                let dist = detector.variant_distance(fp, k, node_fp);
                if dist <= BK_RANGE && node_fi != fi && checked_stamp[ti] != query_id {
                    checked_stamp[ti] = query_id;
                    if detector.is_near_duplicate(fp, node_fp) {
                        let path_a = matching[*orig_idx].path.as_std_path();
                        let path_b = matching[fingerprints[node_fi].0].path.as_std_path();
                        if !detector.are_siblings_not_duplicates(path_a, path_b) {
                            let sim = detector.similarity(fp, node_fp);
                            edges.push((fi, node_fi, sim));
                        }
                    }
                }
                // Follow the children within BK_RANGE of this distance.
                for (_, &child) in tree[ti]
                    .children
                    .range(dist.saturating_sub(BK_RANGE)..=dist.saturating_add(BK_RANGE))
                {
                    stack.push(child);
                }
            }
        }
    }

    edges
}

// ── Connected components (Union-Find) ──

/// Groups BK-tree edges into connected components.
/// Files connected transitively through near-duplicate edges form a group.
fn connected_components(edges: &[(usize, usize, f64)], n: usize) -> Vec<Vec<usize>> {
    if n == 0 {
        return Vec::new();
    }

    let mut parent: Vec<usize> = (0..n).collect();
    let mut rank = vec![0usize; n];

    fn find(parent: &mut [usize], x: usize) -> usize {
        if parent[x] != x {
            parent[x] = find(parent, parent[x]);
        }
        parent[x]
    }

    fn union(parent: &mut [usize], rank: &mut [usize], x: usize, y: usize) {
        let rx = find(parent, x);
        let ry = find(parent, y);
        if rx == ry {
            return;
        }
        match rank[rx].cmp(&rank[ry]) {
            std::cmp::Ordering::Less => parent[rx] = ry,
            std::cmp::Ordering::Greater => parent[ry] = rx,
            std::cmp::Ordering::Equal => {
                parent[ry] = rx;
                rank[rx] += 1;
            }
        }
    }

    for &(i, j, _) in edges {
        union(&mut parent, &mut rank, i, j);
    }

    let mut components: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        components.entry(root).or_default().push(i);
    }

    components.into_values().filter(|c| c.len() >= 2).collect()
}

struct BKNode {
    fp_idx: usize,
    children: std::collections::BTreeMap<u32, usize>,
}

// ── Component splitting ──

/// Splits a group into sub-groups by removing edges with similarity < threshold.
/// Prevents transitive chaining (A~B~C where A≁C) from creating false groups.
///
/// The edge threshold (0.80 → distance ~13) is tighter than 0.65 but slightly
/// more lenient than the matching threshold (~0.84 for large photos). This
/// prevents splitting legitimate groups while catching the ~22-distance chains
/// the old 0.65 allowed.
fn split_by_similarity(sim_matrix: &[Vec<f64>], n: usize) -> Vec<Vec<usize>> {
    const EDGE_THRESHOLD: f64 = 0.80;

    let mut parent: Vec<usize> = (0..n).collect();
    let mut rank = vec![0usize; n];

    fn f_find(p: &mut [usize], x: usize) -> usize {
        if p[x] != x {
            p[x] = f_find(p, p[x]);
        }
        p[x]
    }

    fn f_union(p: &mut [usize], r: &mut [usize], x: usize, y: usize) {
        let rx = f_find(p, x);
        let ry = f_find(p, y);
        if rx == ry {
            return;
        }
        match r[rx].cmp(&r[ry]) {
            std::cmp::Ordering::Less => p[rx] = ry,
            std::cmp::Ordering::Greater => p[ry] = rx,
            std::cmp::Ordering::Equal => {
                p[ry] = rx;
                r[rx] += 1;
            }
        }
    }

    for (i, row) in sim_matrix.iter().enumerate() {
        for (j, &val) in row.iter().enumerate().skip(i + 1) {
            if val >= EDGE_THRESHOLD {
                f_union(&mut parent, &mut rank, i, j);
            }
        }
    }

    let mut components: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();
    for i in 0..n {
        let root = f_find(&mut parent, i);
        components.entry(root).or_default().push(i);
    }

    components.into_values().filter(|c| c.len() >= 2).collect()
}
