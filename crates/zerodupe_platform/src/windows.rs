//! Windows platform profile.

use std::sync::LazyLock;

use camino::Utf8Path;

use crate::{
    CanonicalRoot, JunkLocation, PhysicalFileKey, PlatformProfile, ProtectionFlags, SystemExclude,
    TrashBackend, assets,
};

use crate::backends::{FsLockDetector, OsTrashBackend};

use super::linux::{CANONICAL_ROOTS, JUNK_LOCATIONS, SYSTEM_EXCLUDES};

#[allow(dead_code)]
static MERGED_CANONICAL_ROOTS: LazyLock<Vec<CanonicalRoot>> = LazyLock::new(|| {
    let mut v = CANONICAL_ROOTS.to_vec();
    v.extend_from_slice(assets::toml_canonical_roots());
    v.extend(runtime_dirs_roots());
    v
});

#[allow(dead_code)]
static MERGED_JUNK_LOCATIONS: LazyLock<Vec<JunkLocation>> = LazyLock::new(|| {
    let mut v = JUNK_LOCATIONS.to_vec();
    v.extend_from_slice(assets::toml_junk_locations());
    v
});

#[allow(dead_code)]
static MERGED_SYSTEM_EXCLUDES: LazyLock<Vec<SystemExclude>> = LazyLock::new(|| {
    let mut v = SYSTEM_EXCLUDES.to_vec();
    v.extend_from_slice(assets::toml_system_excludes());
    v
});

#[allow(dead_code)]
fn runtime_dirs_roots() -> Vec<CanonicalRoot> {
    let mut v = Vec::new();
    let entries = [
        ("dirs: Pictures", dirs::picture_dir(), 20),
        ("dirs: Documents", dirs::document_dir(), 10),
        ("dirs: Downloads", dirs::download_dir(), -10),
        ("dirs: Desktop", dirs::desktop_dir(), 5),
        ("dirs: Music", dirs::audio_dir(), 10),
        ("dirs: Videos", dirs::video_dir(), 15),
    ];
    for (label, dir_opt, score) in entries {
        if let Some(dir) = dir_opt {
            let path = dir.to_string_lossy().to_lowercase();
            v.push(CanonicalRoot {
                label: assets::leak_str(label.to_string()),
                pattern: assets::leak_str(path),
                score,
            });
        }
    }
    v
}

#[allow(dead_code)]
pub struct WindowsProfile;

impl PlatformProfile for WindowsProfile {
    fn canonical_roots(&self) -> &[CanonicalRoot] {
        &MERGED_CANONICAL_ROOTS
    }

    fn junk_locations(&self) -> &[JunkLocation] {
        &MERGED_JUNK_LOCATIONS
    }

    fn system_excludes(&self) -> &[SystemExclude] {
        &MERGED_SYSTEM_EXCLUDES
    }

    fn normalize_for_match(&self, path: &Utf8Path) -> String {
        crate::normalizer::normalize_for_match(path, self.fs_case_sensitive())
    }

    fn fs_case_sensitive(&self) -> bool {
        false
    }

    fn trash_backend(&self) -> &dyn TrashBackend {
        &OsTrashBackend
    }

    fn lock_detector(&self) -> &dyn crate::LockDetector {
        &FsLockDetector
    }

    fn physical_key(
        &self,
        path: &Utf8Path,
        _metadata: &std::fs::Metadata,
    ) -> Option<PhysicalFileKey> {
        PhysicalFileKey::from_path_windows(path)
    }

    fn is_rotational_storage(&self, path: &Utf8Path) -> Option<bool> {
        let path_str = path.as_str();
        if path_str.len() >= 2 && path_str.as_bytes()[1] == b':' {
            let drive_letter = path_str.as_bytes()[0].to_ascii_uppercase();
            if drive_letter == b'C' {
                Some(false)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn read_protection_flags(&self, path: &Utf8Path) -> ProtectionFlags {
        let mut flags = ProtectionFlags::default();
        if let Ok(meta) = std::fs::metadata(path) {
            flags.other_protected = meta.permissions().readonly();
        }
        #[cfg(windows)]
        {
            use std::path::Path;
            let ads_path = format!("{}:Zone.Identifier", path.as_str());
            flags.has_zone_identifier = Path::new(&ads_path).exists();
        }
        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_profile_has_roots() {
        assert!(!WindowsProfile.canonical_roots().is_empty());
    }

    #[test]
    fn windows_profile_case_insensitive() {
        assert!(!WindowsProfile.fs_case_sensitive());
    }

    #[test]
    fn toml_assets_loaded() {
        let roots = WindowsProfile.canonical_roots();
        let has_toml_entry = roots.iter().any(|r| r.label.contains("(toml:"));
        assert!(has_toml_entry, "TOML assets should be merged");
    }
}
