//! Keeper selection policies for ZeroDupe.
//!
//! When duplicates are found, ZeroDupe automatically selects which file
//! to keep based on a configurable scoring system. The file with the
//! highest score is the "keeper"; the rest can be quarantined or deleted.
//!
//! Scoring is based on:
//! 1. Path canonicity — does the folder look organized or like a dump?
//! 2. Name quality — does the filename look original or derived/generated?
//! 3. KeeperPriority — user-configured priority overrides.

pub mod weights;
pub use weights::KeeperWeights;

use std::collections::HashMap;

use camino::Utf8Path;
use serde::{Deserialize, Serialize};
use zerodupe_core::{DiscoveredEntry, FileCandidate};
use zerodupe_platform::PlatformProfile;

/// Pre-built lookup index over the discovery entries.
///
/// Keeper selection needs the entry behind each candidate path and the
/// folder siblings of each candidate. Scanning the entry list for those
/// made selection O(groups × entries) — with hundreds of thousands of
/// files it dominated the whole pipeline. Build this once per scan and
/// share it across every group.
pub struct EntryIndex<'a> {
    by_path: HashMap<&'a str, &'a DiscoveredEntry>,
    by_parent: HashMap<&'a str, Vec<&'a DiscoveredEntry>>,
}

impl<'a> EntryIndex<'a> {
    #[must_use]
    pub fn new(entries: &'a [DiscoveredEntry]) -> Self {
        let mut by_path: HashMap<&str, &DiscoveredEntry> = HashMap::with_capacity(entries.len());
        let mut by_parent: HashMap<&str, Vec<&DiscoveredEntry>> = HashMap::new();
        for entry in entries {
            by_path.insert(entry.path.as_str(), entry);
            if let Some(parent) = parent_folder(entry.path.as_path()) {
                by_parent.entry(parent.as_str()).or_default().push(entry);
            }
        }
        Self { by_path, by_parent }
    }

    fn entry(&self, path: &Utf8Path) -> Option<&'a DiscoveredEntry> {
        self.by_path.get(path.as_str()).copied()
    }

    fn folder_entries(&self, parent: &Utf8Path) -> &[&'a DiscoveredEntry] {
        self.by_parent
            .get(parent.as_str())
            .map_or(&[], Vec::as_slice)
    }
}

/// User-facing strategy for selecting the file to keep.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeeperStrategy {
    /// Let ZeroDupe decide using the scoring system (path + name quality).
    #[default]
    LetZeroDupeDecide,
    /// Keep the file with the oldest modification time.
    KeepOldest,
    /// Keep the file with the newest modification time.
    KeepNewest,
    /// Keep the file in the shallowest directory.
    PreferShallowest,
    /// Keep the file with the shortest path.
    PreferShortestPath,
    /// Keep the file with the most organized path (highest canonicity score).
    PreferCanonicalPath,
    /// The user will decide manually (no automatic selection).
    Manual,
}

/// Map a user-friendly rule name to a KeeperStrategy.
pub fn keeper_strategy_from_preset(name: &str) -> KeeperStrategy {
    match name.to_lowercase().as_str() {
        "smart" => KeeperStrategy::LetZeroDupeDecide,
        "newest" => KeeperStrategy::KeepNewest,
        "oldest" => KeeperStrategy::KeepOldest,
        "shortest-path" => KeeperStrategy::PreferShortestPath,
        "manual" => KeeperStrategy::Manual,
        _ => KeeperStrategy::LetZeroDupeDecide,
    }
}

/// Returns the list of available preset names for the frontend.
pub fn keeper_preset_names() -> &'static [&'static str] {
    &["smart", "newest", "oldest", "shortest-path", "manual"]
}

/// Fine-grained scoring weights for `LetZeroDupeDecide`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeeperPolicy {
    /// Weight for path canonicity (organized folder structure).
    pub path_canonicity_weight: u64,
    /// Weight for name quality (descriptive vs generated/copy).
    pub name_quality_weight: u64,
    /// Weight for sibling coherence (how well the name fits its folder siblings).
    pub sibling_coherence_weight: u64,
    /// Bonus for being read-only.
    pub readonly_bonus: u64,
    /// Bonus for being older (lower mtime).
    pub older_bonus: u64,
}

impl Default for KeeperPolicy {
    fn default() -> Self {
        Self {
            path_canonicity_weight: 60,
            name_quality_weight: 40,
            sibling_coherence_weight: 30, // Rule 4
            readonly_bonus: 30,
            older_bonus: 30,
        }
    }
}

// ── Rule 1: Path canonicity ──

/// Scores how "canonical" a path is. Higher = more likely to be an original
/// in an organized location rather than a copy in a dump folder.
///
/// Positive signals (organized folder):
/// - Depth of 2-4 (typical for Artist/Album/File or Project/Sub/File)
/// - Folder name contains semantic tokens (years, proper names)
/// - Under standard OS paths (~/Music, ~/Documents, ~/Pictures)
///
/// Negative signals (dump folder):
/// - Name matches known dump/basura patterns in multiple languages
/// - Depth is 1 (bare file at root of scan, often a misplaced copy)
/// - Under known temp/download paths
pub fn path_canonicity_score(profile: &dyn PlatformProfile, path_str: &str, depth: usize) -> i64 {
    let path = Utf8Path::new(path_str);
    let normalized = profile.normalize_for_match(path);
    let normalized_lower = normalized.to_lowercase();
    let mut score: i64 = 0;

    match depth {
        1 => score -= 60,
        2..=4 => score += 40,
        5..=8 => score += 0,
        _ => score -= 30,
    }

    for junk in profile.junk_locations() {
        if normalized_lower.contains(&junk.pattern.to_lowercase()) {
            score += junk.score as i64;
            break;
        }
    }

    for root in profile.canonical_roots() {
        if normalized_lower.contains(&root.pattern.to_lowercase()) {
            score += root.score as i64;
            break;
        }
    }

    let basename = path.file_name().unwrap_or(path_str);
    if basename.contains('.') {
        score += 15;
    } else {
        score -= 15;
    }

    score
}

// ── Rule 2: Name quality ──

/// Scores filename quality. Higher = more likely to be an original,
/// descriptive name rather than a generated/copy name.
pub fn name_quality_score(_profile: &dyn PlatformProfile, path_str: &str) -> i64 {
    let path = Utf8Path::new(path_str);
    let basename = path.file_name().unwrap_or(path_str);
    let stem = if let Some(dot) = basename.rfind('.') {
        &basename[..dot]
    } else {
        basename
    };
    let stem_lower = stem.to_lowercase();

    let mut score: i64 = 0;

    // ── Penalize copy/derivative suffixes ──
    let copy_markers = [
        "copy",
        "copia",
        "kopie",
        "コピー",
        "duplicate",
        "duplicado",
        "draft",
        "borrador",
        "backup",
        "respaldo",
        "old",
        "viejo",
        "ancien",
        "new",
        "nuevo",
        "nouveau",
        "final",
        "definitivo",
        "edit",
        "edited",
        "editado",
        "untitled",
        "sin_titulo",
        "sin título",
        "tmp",
        "temp",
        "v2",
        "v3",
        "v4",
    ];

    for marker in &copy_markers {
        if stem_lower.contains(marker) {
            // Check it's a word boundary, not part of a larger word
            if stem_lower == *marker
                || stem_lower.starts_with(&format!("{marker}_"))
                || stem_lower.starts_with(&format!("{marker} "))
                || stem_lower.starts_with(&format!("{marker}-"))
                || stem_lower.ends_with(&format!("_{marker}"))
                || stem_lower.ends_with(&format!(" {marker}"))
                || stem_lower.ends_with(&format!("-{marker}"))
                || stem_lower.contains(&format!("_{marker}_"))
            {
                score -= 60;
                break;
            }
        }
    }

    // ── Penalize numbered-copy patterns: (1), (2), _1, _2, -1, -2 ──
    if stem_lower.contains("(1)") || stem_lower.contains("(2)") || stem_lower.contains("(3)") {
        score -= 50;
    }

    // ── Bonus: has recognizable separators (Title Case or kebab-case) ──
    let has_dash = stem.contains('-');
    let has_space = stem.contains(' ');
    if has_dash || has_space {
        score += 20;
    }

    // ── Bonus: looks like "Artist - Title" pattern ──
    if has_dash && stem.len() > 10 && !stem.starts_with('-') && !stem.ends_with('-') {
        score += 15;
    }

    // ── Penalize: very short name (< 5 chars) ──
    if stem.len() < 5 {
        score -= 20;
    }

    // ── Bonus: has extension ──
    if basename.contains('.') {
        score += 10;
    }

    // ── Penalize: looks like random/generated name ──
    if looks_random(stem) {
        score -= 40;
    }

    // ── Bonus: contains year-like tokens ──
    if contains_year_pattern(stem) {
        score += 15;
    }

    score
}

/// Heuristic: does the filename look randomly generated?
/// Checks for: high ratio of digits to letters, no vowels, random-looking patterns.
fn looks_random(stem: &str) -> bool {
    if stem.len() < 6 {
        return false;
    }
    let digits = stem.chars().filter(|c| c.is_ascii_digit()).count();
    let letters = stem.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let total = stem.len();

    // >50% digits → suspicious
    if total > 0 && digits * 2 >= total {
        return true;
    }
    // No letters at all → definitely random
    if letters == 0 && digits > 2 {
        return true;
    }
    // No vowels in alphabetic chars → suspicious
    let vowels = stem
        .chars()
        .filter(|c| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u'))
        .count();
    if letters > 4 && vowels == 0 {
        return true;
    }
    // Very long with high digit density and no separators
    if total > 12 && digits * 3 > total && !stem.contains('-') && !stem.contains(' ') {
        return true;
    }
    false
}

/// Checks if the stem contains a plausible year (1900-2099).
fn contains_year_pattern(stem: &str) -> bool {
    for word in stem.split(&['-', '_', ' ', '.', '(', ')', '[', ']']) {
        if let Ok(year) = word.parse::<u32>()
            && (1900..=2099).contains(&year)
        {
            return true;
        }
    }
    false
}

// ── Combined scoring + selection ──

/// Computes a keeper score for a file candidate.
///
/// Higher score = more likely to be the keeper.
pub fn compute_keeper_score(
    profile: &dyn PlatformProfile,
    candidate: &FileCandidate,
    entry: &DiscoveredEntry,
    group_candidates: &[FileCandidate],
    index: &EntryIndex<'_>,
    max_mtime: Option<i64>,
    policy: &KeeperPolicy,
) -> i64 {
    let mut score: i64 = 0;

    // Rule 1: Path canonicity
    let path_score = path_canonicity_score(profile, candidate.path.as_str(), entry.depth);
    score += path_score * policy.path_canonicity_weight as i64 / 100;

    // Rule 2: Name quality
    let name_score = name_quality_score(profile, candidate.path.as_str());
    score += name_score * policy.name_quality_weight as i64 / 100;

    // Rule 4: Sibling coherence
    if policy.sibling_coherence_weight > 0 && group_candidates.len() > 1 {
        let sibling_score = sibling_coherence_score(candidate, group_candidates, index);
        score += sibling_score * policy.sibling_coherence_weight as i64 / 100;
    }

    // Rule 5: Derived extension penalty — thumbnail/sidecar files (.thm, .aae, .xmp, etc.)
    // should never be chosen as keeper over primary files (.jpg, .cr2, .png, etc.)
    if let Some(ext) = candidate.path.extension()
        && is_derived_extension(ext)
    {
        score -= 200; // Strong penalty — only pick if no alternative
    }

    // Read-only bonus
    if entry.readonly {
        score += policy.readonly_bonus as i64;
    }

    // Older bonus (lower mtime = older)
    if let (Some(entry_mtime), Some(max_mtime)) =
        (entry.timestamps.modified_unix_seconds, max_mtime)
        && entry_mtime < max_mtime
    {
        score += policy.older_bonus as i64;
    }

    score
}

/// Rule 4: how well the filename fits with its folder siblings.
///
/// For each candidate, examines the naming patterns of other files
/// in the same parent folder. Files that match the dominant folder pattern
/// are more likely to be originals. Files that break the pattern are
/// more likely to be planted duplicates from other locations.
///
/// This works across all file types without domain-specific knowledge:
/// - Music folders: "NN - Title.ext" or "Artist - Title.ext"
/// - Photo folders: "IMG_NNNN.JPG" or "YYYYMMDD_HHMMSS.jpg"
/// - Document folders: "Report_YYYY_QN.pdf"
/// - Code folders: "snake_case.rs" or "CamelCase.ts"
fn sibling_coherence_score(
    candidate: &FileCandidate,
    _group: &[FileCandidate],
    index: &EntryIndex<'_>,
) -> i64 {
    let parent = parent_folder(candidate.path.as_path());
    let Some(parent) = parent else {
        return 0;
    };

    let siblings: Vec<&DiscoveredEntry> = index
        .folder_entries(parent)
        .iter()
        .filter(|e| e.path != candidate.path)
        .copied()
        .collect();

    if siblings.len() < 2 {
        return 0;
    }

    let mut score: i64 = 0;

    let candidate_ext = file_extension(candidate.path.as_path());
    let same_ext_count = siblings
        .iter()
        .filter(|s| file_extension(s.path.as_path()) == candidate_ext)
        .count();

    if same_ext_count as f64 >= siblings.len() as f64 * 0.5 {
        score += 25;
    } else if candidate_ext.is_some() && same_ext_count == 0 {
        score -= 30;
    }

    let candidate_has_dash = candidate.path.as_str().contains(" - ");
    let candidate_has_underscore = candidate.path.as_str().contains('_');

    let dash_count = siblings
        .iter()
        .filter(|s| s.path.as_str().contains(" - "))
        .count();
    let underscore_count = siblings
        .iter()
        .filter(|s| s.path.as_str().contains('_'))
        .count();

    let majority = siblings.len() / 2 + 1;

    if candidate_has_dash && dash_count >= majority {
        score += 20;
    } else if candidate_has_dash && dash_count < 2 {
        score -= 15;
    }

    if candidate_has_underscore && underscore_count >= majority {
        score += 15;
    } else if candidate_has_underscore && underscore_count < 2 {
        score -= 15;
    }

    let candidate_basename = candidate.path.file_name().unwrap_or("");
    let candidate_prefix = common_prefix_len(candidate_basename, &siblings);

    if candidate_prefix >= 4 {
        score += 20;
    } else if candidate_prefix == 0 && siblings.len() >= 3 {
        let sibling_prefix = avg_sibling_prefix_len(&siblings);
        if sibling_prefix >= 4 {
            score -= 25;
        }
    }

    let candidate_len = candidate_basename.len();
    let avg_len: f64 = siblings
        .iter()
        .map(|s| s.path.file_name().unwrap_or("").len() as f64)
        .sum::<f64>()
        / siblings.len() as f64;

    let len_diff = (candidate_len as f64 - avg_len).abs();
    if len_diff < avg_len * 0.3 {
        score += 10;
    } else if len_diff > avg_len * 1.5 {
        score -= 15;
    }

    score
}

fn parent_folder(path: &Utf8Path) -> Option<&Utf8Path> {
    path.parent()
}

fn file_extension(path: &Utf8Path) -> Option<String> {
    path.extension().map(|ext| ext.to_lowercase())
}

/// Returns true for file extensions that indicate derivative/sidecar files
/// which should never be chosen as keeper over primary files.
fn is_derived_extension(ext: &str) -> bool {
    matches!(
        ext.to_lowercase().as_str(),
        "thm" | "aae" | "xmp" | "tmp" | "bak" | "pp3" | "on1" | "cos"
    )
}

/// Measures how many leading characters the candidate shares with the majority of siblings.
fn common_prefix_len(candidate_basename: &str, siblings: &[&DiscoveredEntry]) -> usize {
    let mut max_shared = 0;
    let threshold = siblings.len() / 2 + 1;

    let sibling_names: Vec<&str> = siblings
        .iter()
        .map(|s| s.path.file_name().unwrap_or(""))
        .collect();

    for prefix_len in 1..=candidate_basename.chars().count().min(20) {
        let candidate_prefix: String = candidate_basename.chars().take(prefix_len).collect();
        let count = sibling_names
            .iter()
            .filter(|s_name| {
                s_name.chars().count() >= prefix_len
                    && s_name.chars().take(prefix_len).eq(candidate_prefix.chars())
            })
            .count();
        if count >= threshold {
            max_shared = prefix_len;
        } else {
            break;
        }
    }

    max_shared
}

fn avg_sibling_prefix_len(siblings: &[&DiscoveredEntry]) -> usize {
    if siblings.len() < 2 {
        return 0;
    }
    let first = siblings[0].path.file_name().unwrap_or("");
    let mut total = 0usize;
    for s in &siblings[1..] {
        let s_name = s.path.file_name().unwrap_or("");
        let shared = first
            .chars()
            .zip(s_name.chars())
            .take_while(|(a, b)| a == b)
            .count();
        total += shared;
    }
    total / (siblings.len() - 1)
}

/// Selects the best keeper from a list of duplicate file candidates.
pub fn select_keeper_index(
    profile: &dyn PlatformProfile,
    candidates: &[FileCandidate],
    entries: &[DiscoveredEntry],
    strategy: KeeperStrategy,
    policy: &KeeperPolicy,
) -> usize {
    // One-shot convenience: builds the index per call. Callers selecting
    // keepers for many groups should build one `EntryIndex` and use
    // `select_keeper_index_with` instead.
    select_keeper_index_with(
        profile,
        candidates,
        &EntryIndex::new(entries),
        strategy,
        policy,
    )
}

/// Like [`select_keeper_index`], with a pre-built [`EntryIndex`] shared
/// across groups.
pub fn select_keeper_index_with(
    profile: &dyn PlatformProfile,
    candidates: &[FileCandidate],
    index: &EntryIndex<'_>,
    strategy: KeeperStrategy,
    policy: &KeeperPolicy,
) -> usize {
    if candidates.is_empty() {
        return 0;
    }
    if candidates.len() == 1 {
        return 0;
    }

    match strategy {
        KeeperStrategy::LetZeroDupeDecide => {
            let max_mtime = candidates
                .iter()
                .filter_map(|c| index.entry(&c.path))
                .filter_map(|e| e.timestamps.modified_unix_seconds)
                .max();

            let mut best_idx = 0;
            let mut best_score = i64::MIN;

            for (i, candidate) in candidates.iter().enumerate() {
                if let Some(entry) = index.entry(&candidate.path) {
                    let score = compute_keeper_score(
                        profile, candidate, entry, candidates, index, max_mtime, policy,
                    );
                    if score > best_score {
                        best_score = score;
                        best_idx = i;
                    }
                }
            }
            best_idx
        }
        KeeperStrategy::PreferCanonicalPath => {
            let mut best_idx = 0;
            let mut best_score = i64::MIN;
            for (i, candidate) in candidates.iter().enumerate() {
                if let Some(entry) = index.entry(&candidate.path) {
                    let score =
                        path_canonicity_score(profile, candidate.path.as_str(), entry.depth);
                    if score > best_score {
                        best_score = score;
                        best_idx = i;
                    }
                }
            }
            best_idx
        }
        KeeperStrategy::KeepOldest => {
            let mut best_idx = 0;
            let mut best_mtime = i64::MAX;
            for (i, candidate) in candidates.iter().enumerate() {
                if let Some(entry) = index.entry(&candidate.path) {
                    let mtime = entry.timestamps.modified_unix_seconds.unwrap_or(0);
                    if mtime < best_mtime {
                        best_mtime = mtime;
                        best_idx = i;
                    }
                }
            }
            best_idx
        }
        KeeperStrategy::KeepNewest => {
            let mut best_idx = 0;
            let mut best_mtime = i64::MIN;
            for (i, candidate) in candidates.iter().enumerate() {
                if let Some(entry) = index.entry(&candidate.path) {
                    let mtime = entry.timestamps.modified_unix_seconds.unwrap_or(0);
                    if mtime > best_mtime {
                        best_mtime = mtime;
                        best_idx = i;
                    }
                }
            }
            best_idx
        }
        KeeperStrategy::PreferShallowest => {
            let mut best_idx = 0;
            let mut best_depth = usize::MAX;
            for (i, candidate) in candidates.iter().enumerate() {
                if let Some(entry) = index.entry(&candidate.path)
                    && entry.depth < best_depth
                {
                    best_depth = entry.depth;
                    best_idx = i;
                }
            }
            best_idx
        }
        KeeperStrategy::PreferShortestPath => {
            let mut best_idx = 0;
            let mut best_len = usize::MAX;
            for (i, candidate) in candidates.iter().enumerate() {
                let len = candidate.path.as_str().len();
                if len < best_len {
                    best_len = len;
                    best_idx = i;
                }
            }
            best_idx
        }
        KeeperStrategy::Manual => 0,
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use zerodupe_core::{DiscoveredKind, FileTimestamps, RootId};

    fn profile() -> &'static dyn PlatformProfile {
        zerodupe_platform::current()
    }

    fn make_entry(path: &str, depth: usize, mtime: Option<i64>, readonly: bool) -> DiscoveredEntry {
        DiscoveredEntry {
            root_id: RootId(0),
            path: Utf8PathBuf::from(path),
            kind: DiscoveredKind::File,
            depth,
            size_bytes: Some(100),
            readonly,
            timestamps: FileTimestamps {
                modified_unix_seconds: mtime,
                ..FileTimestamps::default()
            },
            physical_key: None,
        }
    }

    fn make_candidate(path: &str) -> FileCandidate {
        FileCandidate {
            path: Utf8PathBuf::from(path),
            size_bytes: 100,
        }
    }

    // ── Rule 1: Path canonicity ──

    #[test]
    fn organized_artist_album_scores_higher_than_dump_folder() {
        let p = profile();
        let organized = path_canonicity_score(
            p,
            "/home/user/Music/Michael Jackson - Michael (2010)/Michael Jackson - Michael.nfo",
            2,
        );
        let dump = path_canonicity_score(
            p,
            "/home/user/Test/Archivos_Sin_Clasificar/sub_bailable_5/rapida_popular.nfo",
            3,
        );
        assert!(
            organized > dump,
            "organized {organized} should beat dump {dump}"
        );
    }

    #[test]
    fn backup_folder_penalized() {
        let backup = path_canonicity_score(profile(), "/home/user/Backup_Audios/file.mp3", 1);
        assert!(backup < 0, "backup folder should be penalized");
    }

    #[test]
    fn tmp_folder_penalized() {
        let tmp = path_canonicity_score(profile(), "/home/user/tmp_files/file.mp3", 1);
        assert!(tmp < 0, "tmp folder should be penalized");
    }

    #[test]
    fn usb_recuperado_penalized() {
        let usb = path_canonicity_score(profile(), "/home/user/USB_Recuperado/file.mp3", 1);
        assert!(usb < 0, "USB_Recuperado should be penalized");
    }

    #[test]
    fn depth_2_to_4_gets_bonus() {
        let p = profile();
        let depth2 = path_canonicity_score(p, "/home/Music/Album/file.mp3", 2);
        let depth4 = path_canonicity_score(p, "/home/Proj/src/lib/file.rs", 4);
        assert!(depth2 > 0);
        assert!(depth4 > 0);
    }

    #[test]
    fn depth_1_bare_file_penalized() {
        let bare = path_canonicity_score(profile(), "/home/user/file.mp3", 1);
        assert!(bare < 0, "bare file at depth 1 should be penalized");
    }

    #[test]
    fn path_with_extension_bonus_vs_without() {
        let p = profile();
        let with_ext = path_canonicity_score(p, "/home/user/file.txt", 2);
        let without_ext = path_canonicity_score(p, "/home/user/file", 2);
        assert!(
            with_ext > without_ext,
            "file with extension should score higher"
        );
    }

    // ── Rule 2: Name quality ──

    #[test]
    fn original_name_beats_copy_suffix() {
        let p = profile();
        let orig = name_quality_score(p, "/Music/Artist - Song.mp3");
        let copy = name_quality_score(p, "/Music/Artist - Song - Copy.mp3");
        assert!(orig > copy, "original {orig} should beat copy {copy}");
    }

    #[test]
    fn original_name_beats_numbered_copy() {
        let p = profile();
        let orig = name_quality_score(p, "/docs/report.pdf");
        let copy = name_quality_score(p, "/docs/report (1).pdf");
        assert!(orig > copy);
    }

    #[test]
    fn descriptive_name_beats_random() {
        let p = profile();
        let desc = name_quality_score(p, "/Music/Michael Jackson - Thriller.mp3");
        let rand = name_quality_score(p, "/tmp_files/rec_6751.mp3");
        assert!(desc > rand, "descriptive {desc} should beat random {rand}");
    }

    #[test]
    fn artist_title_pattern_gets_bonus() {
        let p = profile();
        let with_dash = name_quality_score(p, "/Music/Molotov - Frijolero.mp3");
        let no_sep = name_quality_score(p, "/tmp_files/grabacion_version_hermosa.mp3");
        assert!(with_dash > no_sep);
    }

    #[test]
    fn backup_in_name_penalized() {
        let p = profile();
        let orig = name_quality_score(p, "/docs/report.pdf");
        let bak = name_quality_score(p, "/docs/report_backup.pdf");
        assert!(orig > bak);
    }

    #[test]
    fn old_in_name_penalized() {
        let p = profile();
        let orig = name_quality_score(p, "/data/analysis.py");
        let old = name_quality_score(p, "/data/analysis_old.py");
        assert!(orig > old);
    }

    #[test]
    fn looks_random_detects_generated_names() {
        assert!(looks_random("tmp_4837"));
        assert!(looks_random("a3f9b2c7"));
        assert!(looks_random("84736291"));
        assert!(!looks_random("report"));
        assert!(!looks_random("Michael Jackson - Thriller"));
    }

    // ── Integration: real-world scenarios ──

    #[test]
    fn organized_original_beats_dump_copy() {
        let candidates = vec![
            make_candidate("/home/Test/Archivos_Sin_Clasificar/sub_bailable_5/rapida_popular.nfo"),
            make_candidate(
                "/home/Test/Michael Jackson/Michael Jackson - Michael (2010)/Michael Jackson - Michael.nfo",
            ),
        ];
        let entries = vec![
            make_entry(
                "/home/Test/Archivos_Sin_Clasificar/sub_bailable_5/rapida_popular.nfo",
                3,
                None,
                false,
            ),
            make_entry(
                "/home/Test/Michael Jackson/Michael Jackson - Michael (2010)/Michael Jackson - Michael.nfo",
                2,
                None,
                false,
            ),
        ];

        let idx = select_keeper_index(
            profile(),
            &candidates,
            &entries,
            KeeperStrategy::LetZeroDupeDecide,
            &KeeperPolicy::default(),
        );
        assert_eq!(idx, 1, "Michael Jackson file should be keeper");
    }

    #[test]
    fn original_beats_usb_recuperado() {
        let candidates = vec![
            make_candidate("/home/Test/USB_Recuperado/sub_compartido_36/rec.txt"),
            make_candidate(
                "/home/Test/Michael Jackson/Michael Jackson - Michael (2010)/Michael Jackson – Michael.txt",
            ),
        ];
        let entries = vec![
            make_entry(
                "/home/Test/USB_Recuperado/sub_compartido_36/rec.txt",
                2,
                None,
                false,
            ),
            make_entry(
                "/home/Test/Michael Jackson/Michael Jackson - Michael (2010)/Michael Jackson – Michael.txt",
                2,
                None,
                false,
            ),
        ];

        let idx = select_keeper_index(
            profile(),
            &candidates,
            &entries,
            KeeperStrategy::LetZeroDupeDecide,
            &KeeperPolicy::default(),
        );
        assert_eq!(idx, 1, "Michael Jackson file should beat USB_Recuperado");
    }

    #[test]
    fn album_cover_beats_tmp_random() {
        let candidates = vec![
            make_candidate("/home/Test/Molotov/Con Todo Respeto/Molotov - Con Todo Respeto.jpg"),
            make_candidate("/home/Test/Pendientes/sub_edicion_30/noche.jpg"),
        ];
        let entries = vec![
            make_entry(
                "/home/Test/Molotov/Con Todo Respeto/Molotov - Con Todo Respeto.jpg",
                3,
                None,
                false,
            ),
            make_entry(
                "/home/Test/Pendientes/sub_edicion_30/noche.jpg",
                3,
                None,
                false,
            ),
        ];

        let idx = select_keeper_index(
            profile(),
            &candidates,
            &entries,
            KeeperStrategy::LetZeroDupeDecide,
            &KeeperPolicy::default(),
        );
        assert_eq!(idx, 0, "Molotov cover should be keeper over Pendientes");
    }

    // ── Legacy tests (adapted) ──

    #[test]
    fn empty_candidates_returns_zero() {
        let idx = select_keeper_index(
            profile(),
            &[],
            &[],
            KeeperStrategy::LetZeroDupeDecide,
            &KeeperPolicy::default(),
        );
        assert_eq!(idx, 0);
    }

    #[test]
    fn keep_oldest_still_works() {
        let candidates = vec![make_candidate("/a/new.txt"), make_candidate("/a/old.txt")];
        let entries = vec![
            make_entry("/a/new.txt", 1, Some(2_000_000), false),
            make_entry("/a/old.txt", 1, Some(1_000_000), false),
        ];
        let idx = select_keeper_index(
            profile(),
            &candidates,
            &entries,
            KeeperStrategy::KeepOldest,
            &KeeperPolicy::default(),
        );
        assert_eq!(idx, 1);
    }

    #[test]
    fn prefer_canonical_path_strategy() {
        let candidates = vec![
            make_candidate("/home/test/tmp_files/rec.mp3"),
            make_candidate("/home/test/Music/Artist - Song.mp3"),
        ];
        let entries = vec![
            make_entry("/home/test/tmp_files/rec.mp3", 1, None, false),
            make_entry("/home/test/Music/Artist - Song.mp3", 2, None, false),
        ];
        let idx = select_keeper_index(
            profile(),
            &candidates,
            &entries,
            KeeperStrategy::PreferCanonicalPath,
            &KeeperPolicy::default(),
        );
        assert_eq!(idx, 1, "canonical path should beat tmp");
    }

    // ── Rule 4: sibling coherence ──

    #[test]
    fn sibling_coherence_prefers_folder_majority_pattern() {
        let all_entries = vec![
            make_entry("/Music/Album/01 - Song One.mp3", 2, None, false),
            make_entry("/Music/Album/02 - Song Two.mp3", 2, None, false),
            make_entry("/Music/Album/03 - Song Three.mp3", 2, None, false),
            make_entry("/Music/Album/Artist - Title.mp3", 2, None, false),
            make_entry("/tmp/rec_123.mp3", 1, None, false),
            make_entry("/tmp/backup_old.mp3", 1, None, false),
            make_entry("/tmp/random_file.mp3", 1, None, false),
        ];

        let score_a = sibling_coherence_score(
            &make_candidate("/Music/Album/Artist - Title.mp3"),
            &[],
            &EntryIndex::new(&all_entries),
        );
        let score_b = sibling_coherence_score(
            &make_candidate("/tmp/random_file.mp3"),
            &[],
            &EntryIndex::new(&all_entries),
        );
        assert!(
            score_a > score_b,
            "album coherence {score_a} should beat tmp {score_b}"
        );
    }

    #[test]
    fn sibling_coherence_penalizes_wrong_extension() {
        let all_entries = vec![
            make_entry("/Photos/IMG_001.jpg", 2, None, false),
            make_entry("/Photos/IMG_002.jpg", 2, None, false),
            make_entry("/Photos/IMG_003.jpg", 2, None, false),
            make_entry("/Photos/weird_file.png", 2, None, false),
        ];
        let score = sibling_coherence_score(
            &make_candidate("/Photos/weird_file.png"),
            &[],
            &EntryIndex::new(&all_entries),
        );
        assert!(
            score < 0,
            "wrong extension should be penalized, got {score}"
        );
    }

    #[test]
    fn sibling_coherence_bonus_for_matching_prefix() {
        let all_entries = vec![
            make_entry("/Camera/DCIM_0001.jpg", 2, None, false),
            make_entry("/Camera/DCIM_0002.jpg", 2, None, false),
            make_entry("/Camera/DCIM_0003.jpg", 2, None, false),
            make_entry("/Camera/DCIM_0004.jpg", 2, None, false),
        ];
        let score = sibling_coherence_score(
            &make_candidate("/Camera/DCIM_0004.jpg"),
            &[],
            &EntryIndex::new(&all_entries),
        );
        assert!(
            score > 20,
            "matching prefix should get good score, got {score}"
        );
    }

    // ── Cross-platform MockProfile tests ──

    #[test]
    fn windows_downloads_path_penalized_as_junk() {
        let profile = zerodupe_platform::mock::MockProfile::windows_like();
        let download = path_canonicity_score(&profile, r"C:\Users\rene\Downloads\IMG.jpg", 2);
        let picture = path_canonicity_score(&profile, r"C:\Users\rene\Pictures\IMG.jpg", 2);
        assert!(
            download < picture,
            "Downloads ({download}) should be penalized vs Pictures ({picture})"
        );
    }

    #[test]
    fn windows_pictures_path_gets_canonical_bonus() {
        let profile = zerodupe_platform::mock::MockProfile::windows_like();
        let score = path_canonicity_score(&profile, r"C:\Users\rene\Pictures\IMG.jpg", 2);
        assert!(
            score > 0,
            "Windows Pictures should get canonical bonus, got {score}"
        );
    }

    #[test]
    fn macos_case_insensitive_normalization() {
        let profile = zerodupe_platform::mock::MockProfile::macos_like();
        let normalized = profile.normalize_for_match(Utf8Path::new("/Users/Rene/Pictures/IMG.JPG"));
        assert_eq!(normalized, "/users/rene/pictures/img.jpg");
    }

    #[test]
    fn windows_backslash_normalize_for_match_produces_forward_slashes() {
        let profile = zerodupe_platform::mock::MockProfile::windows_like();
        let normalized =
            profile.normalize_for_match(Utf8Path::new(r"C:\Users\Rene\Pictures\IMG.JPG"));
        assert!(
            !normalized.contains('\\'),
            "normalized path should not contain backslashes: '{normalized}'"
        );
        assert_eq!(normalized, "c:/users/rene/pictures/img.jpg");
    }

    #[test]
    fn macos_case_insensitive_pictures_pattern_matches_uppercase_path() {
        let profile = zerodupe_platform::mock::MockProfile::macos_like();
        let path = Utf8Path::new("/Users/Rene/Pictures/IMG.JPG");
        let normalized = profile.normalize_for_match(path);
        assert!(
            normalized.contains("/pictures/"),
            "case-insensitive match should find /pictures/ pattern in '{normalized}'"
        );
    }
}
