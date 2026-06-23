//! Backend implementations for platform-specific mechanics.
//!
//! These are used by the platform profiles (LinuxProfile, MacosProfile, WindowsProfile)
//! to provide OS-native functionality: moving files to trash, detecting locked files.

use crate::{LockDetector, TrashBackend};
use std::path::Path;

// ── Trash Backend (all platforms via `trash` crate) ──────────────

/// Moves files to the OS trash/recycle bin using the `trash` crate.
/// Works on Windows (Recycle Bin), macOS (Trash), and Linux (FreeDesktop Trash).
#[derive(Debug)]
pub(crate) struct OsTrashBackend;

impl TrashBackend for OsTrashBackend {
    fn trash_file(&self, path: &Path) -> Result<(), String> {
        trash::delete(path).map_err(|e| format!("trash: {e}"))
    }
}

// ── Lock Detector ────────────────────────────────────────────────

/// Detects if a file is locked by another process.
///
/// Strategy: attempts to open the file with exclusive write access.
/// If it fails with a sharing/locking error, the file is considered locked.
#[derive(Debug)]
pub(crate) struct FsLockDetector;

impl LockDetector for FsLockDetector {
    fn is_locked(&self, path: &Path) -> bool {
        match std::fs::OpenOptions::new()
            .write(true)
            .create(false)
            .truncate(false)
            .open(path)
        {
            Ok(_) => false,
            Err(e) => {
                use std::io::ErrorKind;
                matches!(e.kind(), ErrorKind::PermissionDenied)
            }
        }
    }
}
