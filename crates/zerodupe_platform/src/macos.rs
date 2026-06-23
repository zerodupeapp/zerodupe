//! macOS platform profile.

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
        ("dirs: Movies", dirs::video_dir(), 15),
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
pub struct MacosProfile;

impl PlatformProfile for MacosProfile {
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
        _path: &Utf8Path,
        metadata: &std::fs::Metadata,
    ) -> Option<PhysicalFileKey> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let device = metadata.dev();
            let inode = metadata.ino();
            if device == 0 && inode == 0 {
                None
            } else {
                Some(PhysicalFileKey::from_unix(device, inode))
            }
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            None
        }
    }

    fn is_rotational_storage(&self, path: &Utf8Path) -> Option<bool> {
        use std::process::Command;

        let canonical = std::fs::canonicalize(path.as_std_path()).ok()?;

        let output = Command::new("df").arg(canonical.to_str()?).output().ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let device = stdout.lines().nth(1)?.split_whitespace().next()?;
        let disk = device.trim_end_matches(|c: char| c.is_ascii_digit() || c == 's');

        let output = Command::new("diskutil")
            .args(["info", disk])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("Solid State: Yes") {
            Some(false)
        } else if stdout.contains("Solid State: No") {
            Some(true)
        } else {
            None
        }
    }

    fn read_protection_flags(&self, path: &Utf8Path) -> ProtectionFlags {
        let mut flags = ProtectionFlags::default();
        if let Ok(meta) = std::fs::metadata(path) {
            flags.other_protected = meta.permissions().readonly();
        }
        // DEFERRED: detect uchg via stat st_flags & UF_IMMUTABLE.
        // Requires adding libc as a dependency. Rare on user files.
        // DEFERRED: detect com.apple.metadata:_kMDItemUserTags xattr.
        // Requires adding xattr crate. Low priority — Finder tags are advisory.
        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_profile_has_roots() {
        assert!(!MacosProfile.canonical_roots().is_empty());
    }

    #[test]
    fn macos_profile_case_insensitive() {
        assert!(!MacosProfile.fs_case_sensitive());
    }

    #[test]
    fn toml_assets_loaded() {
        let roots = MacosProfile.canonical_roots();
        let has_toml_entry = roots.iter().any(|r| r.label.contains("(toml:"));
        assert!(has_toml_entry, "TOML assets should be merged");
    }
}
