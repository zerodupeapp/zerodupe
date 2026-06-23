use serde::{Deserialize, Serialize};

/// Filesystem-level protection flags that prevent a file from being touched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtectionFlags {
    /// macOS/BSD: user immutable flag (uchg). The file cannot be changed, moved, or deleted.
    pub immutable: bool,
    /// Linux: chattr +i (immutable attribute).
    pub chattr_immutable: bool,
    /// macOS: file has Finder tags (com.apple.metadata:_kMDItemUserTags xattr).
    pub has_finder_tags: bool,
    /// Windows: file has an NTFS Zone.Identifier alternate data stream (downloaded from internet).
    pub has_zone_identifier: bool,
    /// Any other platform-specific protection that should block cleanup.
    pub other_protected: bool,
}

impl ProtectionFlags {
    /// True if any protection flag is set — the file should NOT be touched.
    pub fn is_protected(&self) -> bool {
        self.immutable
            || self.chattr_immutable
            || self.has_finder_tags
            || self.has_zone_identifier
            || self.other_protected
    }
}

/// Classification of a file's safety for deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectionLevel {
    /// File can be deleted normally.
    Allow,
    /// File can be deleted but user should be warned (e.g., Downloads folder).
    WarnBefore,
    /// File can be indexed and reported but NEVER deleted (e.g., .exe in system dirs).
    NeverDelete,
    /// Directory should not even be scanned.
    NeverScan,
}

/// Classifies a file's protection level based on its path, extension, and metadata.
///
/// Rules (checked in order, first match wins):
/// 1. System directories → NeverDelete for executable/system extensions
/// 2. Setuid/setgid → NeverDelete
/// 3. Symlinks → NeverDelete (breaking symlinks can break system paths)
/// 4. Executable extensions (.exe, .dll, .so, .dylib, .sys) → NeverDelete (but see rule 1)
/// 5. Downloads/temp directories → WarnBefore
/// 6. Default → Allow
pub fn classify_file(path: &camino::Utf8Path, metadata: &std::fs::Metadata) -> ProtectionLevel {
    let path_str = path.as_str().to_lowercase();
    let path_str = path_str.replace('\\', "/");
    let file_type = metadata.file_type();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o4000 != 0 || mode & 0o2000 != 0 {
            return ProtectionLevel::NeverDelete;
        }
    }

    if file_type.is_symlink() {
        return ProtectionLevel::NeverDelete;
    }

    let ext = path.extension().unwrap_or("").to_lowercase();
    let is_system_ext = matches!(
        ext.as_str(),
        "exe"
            | "dll"
            | "sys"
            | "drv"
            | "ocx"
            | "msi"
            | "so"
            | "ko"
            | "a"
            | "dylib"
            | "bundle"
            | "kext"
            | "app"
            | "wasm"
    );

    if is_system_ext {
        let in_system_dir = path_str.contains("/windows/")
            || path_str.contains("/program files/")
            || path_str.contains("/program files (x86)/")
            || path_str.contains("/system/")
            || path_str.contains("/library/")
            || path_str.contains("/usr/lib")
            || path_str.contains("/usr/bin")
            || path_str.contains("/usr/sbin")
            || path_str.contains("/bin/")
            || path_str.contains("/sbin/")
            || path_str.contains("/boot/")
            || path_str.contains("/lib/")
            || path_str.contains("/lib64/");
        if in_system_dir {
            return ProtectionLevel::NeverDelete;
        }
    }

    let in_downloads_or_temp = path_str.contains("/downloads/")
        || path_str.contains("/descargas/")
        || path_str.contains("/tmp/")
        || path_str.contains("/var/tmp/");
    if in_downloads_or_temp {
        return ProtectionLevel::WarnBefore;
    }

    ProtectionLevel::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_normal_file_is_allow() {
        let tmp_dir = tempfile::Builder::new()
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let file_path = tmp_dir.path().join("normal.txt");
        std::fs::write(&file_path, b"test").unwrap();
        let meta = std::fs::metadata(&file_path).unwrap();
        let path = camino::Utf8Path::from_path(&file_path).unwrap();
        assert_eq!(classify_file(path, &meta), ProtectionLevel::Allow);
    }

    #[test]
    fn classify_exe_in_program_files_is_never_delete() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let program_files = tmp_dir.path().join("Program Files").join("app.exe");
        std::fs::create_dir_all(program_files.parent().unwrap()).unwrap();
        std::fs::write(&program_files, b"fake exe").unwrap();

        let meta = std::fs::metadata(&program_files).unwrap();
        let path = camino::Utf8Path::from_path(&program_files).unwrap();
        assert_eq!(classify_file(path, &meta), ProtectionLevel::NeverDelete);
    }

    #[test]
    fn classify_exe_in_downloads_is_warn_before() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let downloads = tmp_dir.path().join("Downloads").join("setup.exe");
        std::fs::create_dir_all(downloads.parent().unwrap()).unwrap();
        std::fs::write(&downloads, b"fake exe").unwrap();

        let meta = std::fs::metadata(&downloads).unwrap();
        let path = camino::Utf8Path::from_path(&downloads).unwrap();
        assert_eq!(classify_file(path, &meta), ProtectionLevel::WarnBefore);
    }

    #[test]
    fn protected_paths_not_empty() {
        let paths = crate::assets::toml_protected_paths();
        assert!(
            !paths.is_empty(),
            "should have at least some protected paths"
        );
    }
}
