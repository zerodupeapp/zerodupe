use serde::{Deserialize, Serialize};

/// A canonical user directory (Pictures, Documents, etc.) that scores bonus points in keeper selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalRoot {
    /// Human-readable label for debugging/reports.
    pub label: &'static str,
    /// Pattern to match against the normalized path string.
    pub pattern: &'static str,
    /// Points awarded (positive) or deducted (negative) in keeper scoring.
    pub score: i32,
}

/// A known junk/temporary/cache location that scores penalty points in keeper selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JunkLocation {
    pub label: &'static str,
    pub pattern: &'static str,
    pub score: i32,
}

/// A system file or pattern that should always be excluded from scans (blacklist).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemExclude {
    pub label: &'static str,
    /// Glob-like pattern or path prefix. Matched against file_name or full path.
    pub pattern: &'static str,
    /// If true, match against the full normalized path. If false, match only the file name.
    pub match_full_path: bool,
}
