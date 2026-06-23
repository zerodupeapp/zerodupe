//! Mock profile for testing cross-platform logic from any host.
//!
//! Enabled via `#[cfg(feature = "testing")]` on the crate.

use camino::Utf8Path;

use crate::{
    CanonicalRoot, JunkLocation, NoopLockDetector, NoopTrashBackend, PhysicalFileKey,
    PlatformProfile, ProtectionFlags, SystemExclude, TrashBackend,
};

/// A mock platform profile for testing cross-platform keeper scoring logic
/// without needing a Windows/macOS CI runner.
pub struct MockProfile {
    pub canonical_roots: Vec<CanonicalRoot>,
    pub junk_locations: Vec<JunkLocation>,
    pub system_excludes: Vec<SystemExclude>,
    pub case_sensitive: bool,
}

impl MockProfile {
    /// A profile that simulates Linux-like behavior.
    pub fn linux_like() -> Self {
        Self {
            canonical_roots: vec![
                CanonicalRoot {
                    label: "Linux home",
                    pattern: "/home/",
                    score: 20,
                },
                CanonicalRoot {
                    label: "Pictures",
                    pattern: "/pictures/",
                    score: 20,
                },
                CanonicalRoot {
                    label: "Documents",
                    pattern: "/documents/",
                    score: 10,
                },
                CanonicalRoot {
                    label: "Downloads",
                    pattern: "/downloads/",
                    score: -10,
                },
            ],
            junk_locations: vec![
                JunkLocation {
                    label: "/tmp",
                    pattern: "/tmp/",
                    score: -100,
                },
                JunkLocation {
                    label: "Downloads",
                    pattern: "/downloads/",
                    score: -70,
                },
                JunkLocation {
                    label: "Trash",
                    pattern: "/trash/",
                    score: -80,
                },
            ],
            system_excludes: vec![
                SystemExclude {
                    label: ".DS_Store",
                    pattern: ".DS_Store",
                    match_full_path: false,
                },
                SystemExclude {
                    label: "Thumbs.db",
                    pattern: "Thumbs.db",
                    match_full_path: false,
                },
                SystemExclude {
                    label: ".git",
                    pattern: ".git",
                    match_full_path: true,
                },
            ],
            case_sensitive: true,
        }
    }

    /// A profile that simulates Windows-like behavior with backslash paths.
    pub fn windows_like() -> Self {
        Self {
            canonical_roots: vec![
                CanonicalRoot {
                    label: "Windows Users",
                    pattern: "users/",
                    score: 20,
                },
                CanonicalRoot {
                    label: "Pictures",
                    pattern: "/pictures/",
                    score: 20,
                },
                CanonicalRoot {
                    label: "Downloads",
                    pattern: "/downloads/",
                    score: -10,
                },
                CanonicalRoot {
                    label: "Desktop",
                    pattern: "/desktop/",
                    score: 5,
                },
            ],
            junk_locations: vec![
                JunkLocation {
                    label: "Temp",
                    pattern: "/temp/",
                    score: -100,
                },
                JunkLocation {
                    label: "Downloads",
                    pattern: "/downloads/",
                    score: -70,
                },
                JunkLocation {
                    label: "Trash",
                    pattern: "$recycle.bin",
                    score: -80,
                },
            ],
            system_excludes: vec![
                SystemExclude {
                    label: "Thumbs.db",
                    pattern: "Thumbs.db",
                    match_full_path: false,
                },
                SystemExclude {
                    label: "desktop.ini",
                    pattern: "desktop.ini",
                    match_full_path: false,
                },
                SystemExclude {
                    label: ".git",
                    pattern: ".git",
                    match_full_path: true,
                },
            ],
            case_sensitive: false,
        }
    }

    /// A profile that simulates macOS-like behavior.
    pub fn macos_like() -> Self {
        Self {
            canonical_roots: vec![
                CanonicalRoot {
                    label: "macOS Users",
                    pattern: "/users/",
                    score: 20,
                },
                CanonicalRoot {
                    label: "Pictures",
                    pattern: "/pictures/",
                    score: 20,
                },
                CanonicalRoot {
                    label: "Downloads",
                    pattern: "/downloads/",
                    score: -10,
                },
            ],
            junk_locations: vec![
                JunkLocation {
                    label: "/tmp",
                    pattern: "/tmp/",
                    score: -100,
                },
                JunkLocation {
                    label: "Downloads",
                    pattern: "/downloads/",
                    score: -70,
                },
                JunkLocation {
                    label: ".Trash",
                    pattern: "/.trash/",
                    score: -80,
                },
            ],
            system_excludes: vec![
                SystemExclude {
                    label: ".DS_Store",
                    pattern: ".DS_Store",
                    match_full_path: false,
                },
                SystemExclude {
                    label: "._*",
                    pattern: "._",
                    match_full_path: false,
                },
                SystemExclude {
                    label: ".git",
                    pattern: ".git",
                    match_full_path: true,
                },
            ],
            case_sensitive: false,
        }
    }
}

impl PlatformProfile for MockProfile {
    fn canonical_roots(&self) -> &[CanonicalRoot] {
        &self.canonical_roots
    }

    fn junk_locations(&self) -> &[JunkLocation] {
        &self.junk_locations
    }

    fn system_excludes(&self) -> &[SystemExclude] {
        &self.system_excludes
    }

    fn normalize_for_match(&self, path: &Utf8Path) -> String {
        crate::normalizer::normalize_for_match(path, self.case_sensitive)
    }

    fn fs_case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    fn trash_backend(&self) -> &dyn TrashBackend {
        &NoopTrashBackend
    }

    fn lock_detector(&self) -> &dyn crate::LockDetector {
        &NoopLockDetector
    }

    fn physical_key(
        &self,
        _path: &Utf8Path,
        _metadata: &std::fs::Metadata,
    ) -> Option<PhysicalFileKey> {
        None
    }

    fn read_protection_flags(&self, _path: &Utf8Path) -> ProtectionFlags {
        ProtectionFlags::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_windows_like_normalizes_backslashes() {
        let profile = MockProfile::windows_like();
        let path = Utf8Path::new(r"C:\Users\rene\Pictures\IMG.jpg");
        let normalized = profile.normalize_for_match(path);
        assert!(normalized.contains("users/rene/pictures/img.jpg"));
    }

    #[test]
    fn mock_linux_like_preserves_case() {
        let profile = MockProfile::linux_like();
        let path = Utf8Path::new("/home/Rene/Pictures");
        let normalized = profile.normalize_for_match(path);
        assert_eq!(normalized, "/home/Rene/Pictures");
    }

    #[test]
    fn mock_windows_like_is_case_insensitive() {
        assert!(!MockProfile::windows_like().fs_case_sensitive());
    }

    #[test]
    fn mock_linux_like_is_case_sensitive() {
        assert!(MockProfile::linux_like().fs_case_sensitive());
    }

    #[test]
    fn keeper_prefers_canonical_over_junk_windows() {
        let profile = MockProfile::windows_like();

        let canonical = Utf8Path::new(r"C:\Users\rene\Pictures\IMG.jpg");
        let junk = Utf8Path::new(r"C:\Users\rene\Downloads\IMG.jpg");

        let cn = profile.normalize_for_match(canonical);
        let jn = profile.normalize_for_match(junk);

        assert!(cn.contains("users/"));
        assert!(jn.contains("/downloads/"));
    }

    #[test]
    fn system_excludes_include_all_os_patterns_in_linux_like() {
        let profile = MockProfile::linux_like();
        let excludes = profile.system_excludes();
        let patterns: Vec<&str> = excludes.iter().map(|e| e.pattern).collect();
        assert!(
            patterns.contains(&".DS_Store"),
            "should exclude .DS_Store (macOS)"
        );
        assert!(
            patterns.contains(&"Thumbs.db"),
            "should exclude Thumbs.db (Windows)"
        );
        assert!(patterns.contains(&".git"), "should exclude .git (all OSes)");
    }

    #[test]
    fn macos_like_is_case_insensitive() {
        assert!(!MockProfile::macos_like().fs_case_sensitive());
    }
}
