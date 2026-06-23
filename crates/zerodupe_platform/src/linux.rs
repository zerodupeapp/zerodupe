//! Linux platform profile.

use std::sync::LazyLock;

use camino::Utf8Path;

use crate::{
    CanonicalRoot, JunkLocation, PhysicalFileKey, PlatformProfile, ProtectionFlags, SystemExclude,
    TrashBackend, assets,
};

use crate::backends::{FsLockDetector, OsTrashBackend};

pub(crate) const CANONICAL_ROOTS: &[CanonicalRoot] = &[
    CanonicalRoot {
        label: "Linux home",
        pattern: "/home/",
        score: 20,
    },
    CanonicalRoot {
        label: "XDG Pictures",
        pattern: "/pictures/",
        score: 20,
    },
    CanonicalRoot {
        label: "XDG Documents",
        pattern: "/documents/",
        score: 10,
    },
    CanonicalRoot {
        label: "XDG Music",
        pattern: "/music/",
        score: 10,
    },
    CanonicalRoot {
        label: "XDG Videos",
        pattern: "/videos/",
        score: 15,
    },
    CanonicalRoot {
        label: "XDG Desktop",
        pattern: "/desktop/",
        score: 5,
    },
    CanonicalRoot {
        label: "XDG Downloads",
        pattern: "/downloads/",
        score: -10,
    },
    CanonicalRoot {
        label: "macOS Users",
        pattern: "/users/",
        score: 20,
    },
    CanonicalRoot {
        label: "macOS Pictures",
        pattern: "/pictures/",
        score: 20,
    },
    CanonicalRoot {
        label: "macOS Movies",
        pattern: "/movies/",
        score: 15,
    },
    CanonicalRoot {
        label: "macOS Music",
        pattern: "/music/",
        score: 10,
    },
    CanonicalRoot {
        label: "macOS Downloads",
        pattern: "/downloads/",
        score: -10,
    },
    CanonicalRoot {
        label: "macOS Desktop",
        pattern: "/desktop/",
        score: 5,
    },
    CanonicalRoot {
        label: "Photos.app originals",
        pattern: "photoslibrary/originals/",
        score: 20,
    },
    CanonicalRoot {
        label: "Photos Library",
        pattern: "photos library.photoslibrary/originals/",
        score: 20,
    },
    CanonicalRoot {
        label: "Windows Users",
        pattern: "users/",
        score: 20,
    },
    CanonicalRoot {
        label: "Windows Pictures",
        pattern: "/pictures/",
        score: 20,
    },
    CanonicalRoot {
        label: "Windows Documents",
        pattern: "/documents/",
        score: 10,
    },
    CanonicalRoot {
        label: "Windows Music",
        pattern: "/music/",
        score: 10,
    },
    CanonicalRoot {
        label: "Windows Videos",
        pattern: "/videos/",
        score: 15,
    },
    CanonicalRoot {
        label: "Windows Downloads",
        pattern: "/downloads/",
        score: -10,
    },
    CanonicalRoot {
        label: "Windows Desktop",
        pattern: "/desktop/",
        score: 5,
    },
    CanonicalRoot {
        label: "DCIM",
        pattern: "dcim/",
        score: 20,
    },
    CanonicalRoot {
        label: "Canon 100",
        pattern: "100canon/",
        score: 20,
    },
    CanonicalRoot {
        label: "Nikon 100",
        pattern: "100nikon/",
        score: 20,
    },
    CanonicalRoot {
        label: "MSDCF 100",
        pattern: "100msdcf/",
        score: 20,
    },
    CanonicalRoot {
        label: "Camera Roll",
        pattern: "camera roll",
        score: 10,
    },
    CanonicalRoot {
        label: "Camera folder",
        pattern: "camera/",
        score: 10,
    },
    CanonicalRoot {
        label: "Photos folder",
        pattern: "/photos/",
        score: 15,
    },
    CanonicalRoot {
        label: "Fotos folder",
        pattern: "/fotos/",
        score: 15,
    },
    CanonicalRoot {
        label: "Im\u{00e1}genes folder",
        pattern: "/imagenes/",
        score: 15,
    },
    CanonicalRoot {
        label: "Projects",
        pattern: "/projects/",
        score: 20,
    },
    CanonicalRoot {
        label: "Data",
        pattern: "/data/",
        score: 10,
    },
    CanonicalRoot {
        label: "srv",
        pattern: "/srv/",
        score: 10,
    },
    CanonicalRoot {
        label: "opt",
        pattern: "/opt/",
        score: 10,
    },
];

pub(crate) const JUNK_LOCATIONS: &[JunkLocation] = &[
    JunkLocation {
        label: "/tmp",
        pattern: "/tmp/",
        score: -100,
    },
    JunkLocation {
        label: "/var/tmp",
        pattern: "/var/tmp/",
        score: -100,
    },
    JunkLocation {
        label: "/temp",
        pattern: "/temp/",
        score: -100,
    },
    JunkLocation {
        label: "cache folder",
        pattern: "/cache/",
        score: -80,
    },
    JunkLocation {
        label: "WhatsApp",
        pattern: "whatsapp/",
        score: -80,
    },
    JunkLocation {
        label: "Telegram",
        pattern: "telegram/",
        score: -80,
    },
    JunkLocation {
        label: "Downloads",
        pattern: "/downloads/",
        score: -70,
    },
    JunkLocation {
        label: "Descargas",
        pattern: "/descargas/",
        score: -70,
    },
    JunkLocation {
        label: "Trash",
        pattern: "/trash/",
        score: -80,
    },
    JunkLocation {
        label: ".Trash",
        pattern: "/.trash/",
        score: -80,
    },
    JunkLocation {
        label: "Papelera",
        pattern: "/papelera/",
        score: -80,
    },
    JunkLocation {
        label: "Recycle Bin",
        pattern: "$recycle.bin",
        score: -80,
    },
    JunkLocation {
        label: "Desktop",
        pattern: "/desktop/",
        score: -30,
    },
    JunkLocation {
        label: "Escritorio",
        pattern: "/escritorio/",
        score: -30,
    },
    JunkLocation {
        label: "Screenshots",
        pattern: "/screenshots/",
        score: -30,
    },
    JunkLocation {
        label: "Capturas",
        pattern: "/capturas/",
        score: -30,
    },
    JunkLocation {
        label: "node_modules",
        pattern: "node_modules/",
        score: -50,
    },
    JunkLocation {
        label: "__pycache__",
        pattern: "__pycache__/",
        score: -50,
    },
    JunkLocation {
        label: ".venv",
        pattern: ".venv/",
        score: -50,
    },
    JunkLocation {
        label: "target/",
        pattern: "/target/",
        score: -50,
    },
    JunkLocation {
        label: "build/",
        pattern: "/build/",
        score: -50,
    },
    JunkLocation {
        label: "tmp (loose)",
        pattern: "tmp",
        score: -80,
    },
    JunkLocation {
        label: "temp (loose)",
        pattern: "temp",
        score: -80,
    },
    JunkLocation {
        label: "temporary",
        pattern: "temporary",
        score: -80,
    },
    JunkLocation {
        label: "cache (loose)",
        pattern: "cache",
        score: -80,
    },
    JunkLocation {
        label: "backup",
        pattern: "backup",
        score: -80,
    },
    JunkLocation {
        label: "backups",
        pattern: "backups",
        score: -80,
    },
    JunkLocation {
        label: "respaldo",
        pattern: "respaldo",
        score: -80,
    },
    JunkLocation {
        label: "respaldos",
        pattern: "respaldos",
        score: -80,
    },
    JunkLocation {
        label: "recuperado",
        pattern: "recuperado",
        score: -80,
    },
    JunkLocation {
        label: "recovered",
        pattern: "recovered",
        score: -80,
    },
    JunkLocation {
        label: "usb_recuperado",
        pattern: "usb_recuperado",
        score: -80,
    },
    JunkLocation {
        label: "viejo",
        pattern: "viejo",
        score: -80,
    },
    JunkLocation {
        label: "old",
        pattern: "old",
        score: -80,
    },
    JunkLocation {
        label: "old_downloads",
        pattern: "old_downloads",
        score: -80,
    },
    JunkLocation {
        label: "descargas_viejas",
        pattern: "descargas_viejas",
        score: -80,
    },
    JunkLocation {
        label: "old downloads",
        pattern: "old downloads",
        score: -80,
    },
    JunkLocation {
        label: "nueva carpeta",
        pattern: "nueva carpeta",
        score: -80,
    },
    JunkLocation {
        label: "new folder",
        pattern: "new folder",
        score: -80,
    },
    JunkLocation {
        label: "carpeta_sin_nombre",
        pattern: "carpeta_sin_nombre",
        score: -80,
    },
    JunkLocation {
        label: "untitled folder",
        pattern: "untitled folder",
        score: -80,
    },
    JunkLocation {
        label: "pendiente",
        pattern: "pendiente",
        score: -80,
    },
    JunkLocation {
        label: "pendientes",
        pattern: "pendientes",
        score: -80,
    },
    JunkLocation {
        label: "por_revisar",
        pattern: "por_revisar",
        score: -80,
    },
    JunkLocation {
        label: "sin clasificar",
        pattern: "sin clasificar",
        score: -80,
    },
    JunkLocation {
        label: "archivos_sin_clasificar",
        pattern: "archivos_sin_clasificar",
        score: -80,
    },
    JunkLocation {
        label: "unclassified",
        pattern: "unclassified",
        score: -80,
    },
    JunkLocation {
        label: "coleccion_random",
        pattern: "coleccion_random",
        score: -80,
    },
    JunkLocation {
        label: "coleccion_x",
        pattern: "coleccion_x",
        score: -80,
    },
    JunkLocation {
        label: "misc",
        pattern: "misc",
        score: -80,
    },
    JunkLocation {
        label: "varios",
        pattern: "varios",
        score: -80,
    },
    JunkLocation {
        label: "random",
        pattern: "random",
        score: -80,
    },
    JunkLocation {
        label: "dump",
        pattern: "dump",
        score: -80,
    },
    JunkLocation {
        label: "lost+found",
        pattern: "lost+found",
        score: -80,
    },
];

pub(crate) const SYSTEM_EXCLUDES: &[SystemExclude] = &[
    SystemExclude {
        label: ".DS_Store",
        pattern: ".DS_Store",
        match_full_path: false,
    },
    SystemExclude {
        label: "._* (AppleDouble)",
        pattern: "._",
        match_full_path: false,
    },
    SystemExclude {
        label: "__MACOSX (zip residue)",
        pattern: "__MACOSX",
        match_full_path: true,
    },
    SystemExclude {
        label: "Icon\r (macOS custom icon)",
        pattern: "Icon\r",
        match_full_path: false,
    },
    SystemExclude {
        label: ".localized",
        pattern: ".localized",
        match_full_path: false,
    },
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
        label: ".nomedia (Android)",
        pattern: ".nomedia",
        match_full_path: false,
    },
    SystemExclude {
        label: ".git",
        pattern: ".git",
        match_full_path: true,
    },
    SystemExclude {
        label: ".svn",
        pattern: ".svn",
        match_full_path: true,
    },
    SystemExclude {
        label: ".hg",
        pattern: ".hg",
        match_full_path: true,
    },
    SystemExclude {
        label: ".bzr",
        pattern: ".bzr",
        match_full_path: true,
    },
];

static MERGED_CANONICAL_ROOTS: LazyLock<Vec<CanonicalRoot>> = LazyLock::new(|| {
    let mut v = CANONICAL_ROOTS.to_vec();
    v.extend_from_slice(assets::toml_canonical_roots());
    v.extend(runtime_dirs_roots());
    v
});

static MERGED_JUNK_LOCATIONS: LazyLock<Vec<JunkLocation>> = LazyLock::new(|| {
    let mut v = JUNK_LOCATIONS.to_vec();
    v.extend_from_slice(assets::toml_junk_locations());
    v
});

static MERGED_SYSTEM_EXCLUDES: LazyLock<Vec<SystemExclude>> = LazyLock::new(|| {
    let mut v = SYSTEM_EXCLUDES.to_vec();
    v.extend_from_slice(assets::toml_system_excludes());
    v
});

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

pub struct LinuxProfile;

impl PlatformProfile for LinuxProfile {
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
        true
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
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        let path_str = path.as_str();

        let mut best_major_minor: Option<&str> = None;
        let mut best_len = 0;

        for line in mountinfo.lines() {
            let fields: Vec<&str> = line.split(' ').collect();
            if fields.len() < 5 {
                continue;
            }
            let mount_point = fields[4];

            let is_under = mount_point == "/"
                || path_str == mount_point
                || (path_str.starts_with(mount_point)
                    && path_str.as_bytes().get(mount_point.len()) == Some(&b'/'));

            if !is_under {
                continue;
            }

            let mp_len = mount_point.len();
            if mp_len >= best_len {
                best_len = mp_len;
                best_major_minor = Some(fields[2]);
            }
        }

        let major_minor = best_major_minor?;
        let rotational =
            std::fs::read_to_string(format!("/sys/dev/block/{}/queue/rotational", major_minor))
                .ok()?;

        let trimmed = rotational.trim();
        if trimmed == "1" {
            Some(true)
        } else if trimmed == "0" {
            Some(false)
        } else {
            None
        }
    }

    fn read_protection_flags(&self, path: &Utf8Path) -> ProtectionFlags {
        let mut flags = ProtectionFlags::default();
        if let Ok(meta) = std::fs::metadata(path) {
            flags.other_protected = meta.permissions().readonly();
        }
        // DEFERRED: detect chattr +i via ioctl FS_IOC_GETFLAGS.
        // Requires adding libc as a dependency. Not critical for initial release
        // because immutable files are rare in home directories.
        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_profile_has_roots() {
        assert!(!LinuxProfile.canonical_roots().is_empty());
    }

    #[test]
    fn linux_profile_case_sensitive() {
        assert!(LinuxProfile.fs_case_sensitive());
    }

    #[test]
    fn linux_profile_has_excludes() {
        assert!(!LinuxProfile.system_excludes().is_empty());
    }

    #[test]
    fn toml_assets_loaded() {
        let roots = LinuxProfile.canonical_roots();
        let has_toml_entry = roots.iter().any(|r| r.label.contains("(toml:"));
        assert!(has_toml_entry, "TOML assets should be merged");
    }
}
