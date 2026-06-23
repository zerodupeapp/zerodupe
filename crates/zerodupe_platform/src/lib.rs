mod assets;
mod backends;
pub mod normalizer;
pub mod patterns;
pub mod physkey;
pub mod protection;

#[cfg(feature = "testing")]
pub mod mock;

use std::path::Path;

use camino::Utf8Path;
pub use patterns::{CanonicalRoot, JunkLocation, SystemExclude};
pub use physkey::PhysicalFileKey;
pub use protection::{ProtectionFlags, ProtectionLevel, classify_file};

// ── Backend traits (stubs for now — P1/P2) ──

/// Cross-platform trash backend.
pub trait TrashBackend: Send + Sync {
    /// Move a file to the OS trash. Returns the new path in trash, or an error.
    fn trash_file(&self, path: &Path) -> Result<(), String>;
}

/// Cross-platform lock detection.
pub trait LockDetector: Send + Sync {
    /// Check if a file is locked by a running process.
    fn is_locked(&self, path: &Path) -> bool;
}

/// A no-op trash backend for platforms where trash is unavailable.
#[derive(Debug)]
pub struct NoopTrashBackend;

impl TrashBackend for NoopTrashBackend {
    fn trash_file(&self, _path: &Path) -> Result<(), String> {
        Err("trash backend not available on this platform".into())
    }
}

/// A no-op lock detector for platforms without lsof or equivalent.
#[derive(Debug)]
pub struct NoopLockDetector;

impl LockDetector for NoopLockDetector {
    fn is_locked(&self, _path: &Path) -> bool {
        false
    }
}

// ── PlatformProfile trait ──

/// Centralized abstraction for all OS-dependent knowledge.
///
/// **Patterns (what to look for):** All OS patterns are always active,
/// because the scan target may contain files from any OS.
///
/// **Mechanics (how to operate):** Only the host OS determines these —
/// physical key extraction, trash backend, lock detection, case sensitivity.
pub trait PlatformProfile: Send + Sync {
    // ── Patterns (always active — all OSes) ──

    /// Canonical user directories that score bonus points in keeper selection.
    /// e.g., Pictures, Documents, Music, etc. — from all OSes.
    fn canonical_roots(&self) -> &[CanonicalRoot];

    /// Known junk/temporary/cache locations that score penalty points.
    /// e.g., /tmp, Downloads, WhatsApp, Telegram — from all OSes.
    fn junk_locations(&self) -> &[JunkLocation];

    /// System files/patterns that should always be excluded.
    /// e.g., .DS_Store, Thumbs.db, desktop.ini, __MACOSX/ — from all OSes.
    fn system_excludes(&self) -> &[SystemExclude];

    // ── Mechanics (host OS only) ──

    /// Normalize a path for pattern matching (separator + case).
    fn normalize_for_match(&self, path: &Utf8Path) -> String;

    /// Whether the host filesystem treats filenames as case-sensitive.
    fn fs_case_sensitive(&self) -> bool;

    /// Trash backend for moving files to OS trash.
    fn trash_backend(&self) -> &dyn TrashBackend;

    /// Lock detector for checking if a file is in use.
    fn lock_detector(&self) -> &dyn LockDetector;

    /// Extract a platform-specific physical file identity key.
    /// `path` is needed on Windows to open the file handle for
    /// `GetFileInformationByHandle`; on Unix it is unused.
    /// Returns `None` if the identity cannot be determined (fallback).
    fn physical_key(
        &self,
        path: &Utf8Path,
        metadata: &std::fs::Metadata,
    ) -> Option<PhysicalFileKey>;

    /// Read platform-specific protection flags for a path.
    fn read_protection_flags(&self, path: &Utf8Path) -> ProtectionFlags;

    /// Whether the filesystem containing this path is on rotational storage (HDD).
    /// Returns `None` if detection is not possible on this platform.
    fn is_rotational_storage(&self, _path: &Utf8Path) -> Option<bool> {
        None
    }

    /// System directories that should never be scanned.
    /// These are injected into DiscoveryOptions.exclude_prefixes at scan start.
    fn protected_paths(&self) -> &[String] {
        assets::toml_protected_paths()
    }

    // ── Convenience: compose patterns from all profiles ──

    /// All canonical roots from all known OSes merged.
    fn all_canonical_roots(&self) -> &[CanonicalRoot] {
        self.canonical_roots()
    }

    /// All junk locations from all known OSes merged.
    fn all_junk_locations(&self) -> &[JunkLocation] {
        self.junk_locations()
    }

    /// All system excludes from all known OSes merged.
    fn all_system_excludes(&self) -> &[SystemExclude] {
        self.system_excludes()
    }
}

// ── Factory ──

mod linux;
mod macos;
mod windows;

/// Change time (ctime) in nanoseconds since the Unix epoch, or `None` on
/// platforms that don't expose it (Windows).
///
/// On Unix the ctime is maintained by the kernel and cannot be set from
/// userspace: a tool that modifies a file and then restores its mtime with
/// `utimes()` still bumps the ctime. The hash cache uses it as a second
/// witness that a file is unchanged.
pub fn change_time_nanos(metadata: &std::fs::Metadata) -> Option<i64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata
            .ctime()
            .checked_mul(1_000_000_000)?
            .checked_add(metadata.ctime_nsec())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// Returns the platform profile for the current host OS.
///
/// This is the **only** `#[cfg]` gate in the entire codebase outside of `zerodupe_platform`.
/// All other crates query this trait — they never use `#[cfg(target_os)]` directly.
pub fn current() -> &'static dyn PlatformProfile {
    #[cfg(target_os = "linux")]
    {
        &linux::LinuxProfile
    }
    #[cfg(target_os = "macos")]
    {
        &macos::MacosProfile
    }
    #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
    {
        &windows::WindowsProfile
    }
}
