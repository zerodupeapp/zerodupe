//! Quarantine and reversible safety operations for ZeroDupe.
//!
//! Files are moved to a quarantine directory instead of being deleted.
//! Every move is recorded in a SQLite journal, allowing full restoration.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use camino::Utf8PathBuf;
use rusqlite::{Connection, params};
use zerodupe_core::{QuarantineEntry, QuarantineReport, QuarantineSession};

/// Snapshot of file metadata taken during scanning.
#[derive(Debug, Clone)]
pub struct FileSnapshot {
    pub size_bytes: u64,
    pub modified_unix_seconds: Option<i64>,
    pub physical_key: Option<zerodupe_platform::PhysicalFileKey>,
}

/// Verify that a file hasn't changed since it was scanned.
///
/// Returns `Ok(())` if safe to act, or `Err` with explanation if the file changed.
///
/// The snapshot's size is **always** checked. The `modified_unix_seconds` and
/// `physical_key` witnesses are optional: when a field is `None` it means that
/// witness wasn't captured at scan time, so the corresponding check is skipped.
/// This lets callers that only carry the scanned size (e.g. the cleaning loop,
/// where group entries propagate `size_bytes` but not mtime/inode) still get a
/// real TOCTTOU guard: a file edited, truncated or replaced between scan and
/// action changes size and is refused. Callers that capture the full snapshot
/// get the stronger mtime + physical-identity guarantee on top.
pub fn verify_safe_to_act(
    path: &camino::Utf8Path,
    snapshot: &FileSnapshot,
    profile: &dyn zerodupe_platform::PlatformProfile,
) -> Result<(), String> {
    let std_path = path.as_std_path();
    let metadata =
        std::fs::symlink_metadata(std_path).map_err(|e| format!("cannot stat file: {e}"))?;

    let current_size = metadata.len();
    if current_size != snapshot.size_bytes {
        return Err(format!(
            "file changed since scan: size {}→{} ({path})",
            snapshot.size_bytes, current_size,
        ));
    }

    // mtime: only verified when it was captured at scan time.
    if let Some(expected_mtime) = snapshot.modified_unix_seconds {
        let current_mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64);
        match current_mtime {
            Some(c) if c == expected_mtime => {}
            Some(c) => {
                return Err(format!(
                    "file changed since scan: mtime {expected_mtime}→{c} ({path})"
                ));
            }
            None => {
                return Err(format!(
                    "file changed since scan: mtime no longer readable ({path})"
                ));
            }
        }
    }

    // Physical identity (inode/device): only verified when it was captured.
    if let Some(ref expected_key) = snapshot.physical_key {
        let current_key = profile.physical_key(path, &metadata);
        if current_key.as_ref() != Some(expected_key) {
            return Err(format!(
                "file changed since scan: physical identity mismatch ({path})"
            ));
        }
    }

    Ok(())
}

/// Manages a quarantine directory with a SQLite journal for reversibility.
pub struct Quarantine {
    dir: PathBuf,
    journal: Connection,
}

impl Quarantine {
    /// Opens or creates a quarantine at the given directory path.
    /// The directory is created if it doesn't exist.
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let journal_path = dir.join("journal.db");
        let journal = Connection::open(&journal_path)
            .map_err(|e| io::Error::other(format!("journal open: {e}")))?;
        journal
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| io::Error::other(format!("busy_timeout: {e}")))?;

        let q = Self {
            dir: dir.to_path_buf(),
            journal,
        };
        q.ensure_schema()
            .map_err(|e| io::Error::other(format!("schema: {e}")))?;
        q.reconcile_orphans();
        Ok(q)
    }

    /// Opens an in-memory quarantine (for testing).
    pub fn open_memory() -> io::Result<Self> {
        let dir = tempfile::tempdir().map_err(|e| io::Error::other(format!("tempdir: {e}")))?;
        let dir_path = dir.path().to_path_buf();
        // Prevent tempdir from being dropped
        std::mem::forget(dir);

        let journal =
            Connection::open_in_memory().map_err(|e| io::Error::other(format!("journal: {e}")))?;

        let q = Self {
            dir: dir_path,
            journal,
        };
        q.ensure_schema()
            .map_err(|e| io::Error::other(format!("schema: {e}")))?;
        Ok(q)
    }

    fn ensure_schema(&self) -> rusqlite::Result<()> {
        self.journal.execute_batch(
            "CREATE TABLE IF NOT EXISTS quarantine_journal (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path       TEXT    NOT NULL,
                original_path_blob  BLOB,
                quarantined_path    TEXT    NOT NULL,
                size_bytes          INTEGER NOT NULL,
                reason              TEXT    NOT NULL DEFAULT '',
                moved_at            TEXT    NOT NULL DEFAULT (datetime('now')),
                restored            INTEGER NOT NULL DEFAULT 0,
                permissions_mode    INTEGER,
                session_id          TEXT    NOT NULL DEFAULT '',
                purge_at            TEXT
            );
            CREATE TABLE IF NOT EXISTS kept_files (
                path        TEXT    NOT NULL PRIMARY KEY,
                session_id  TEXT    NOT NULL DEFAULT '',
                kept_at     TEXT    NOT NULL DEFAULT (datetime('now'))
            );",
        )?;
        for col in &[
            "original_path_blob BLOB",
            "permissions_mode INTEGER",
            "session_id TEXT NOT NULL DEFAULT ''",
            "purge_at TEXT",
        ] {
            let sql = format!("ALTER TABLE quarantine_journal ADD COLUMN {col}");
            let _ = self.journal.execute(&sql, []);
        }
        Ok(())
    }

    /// Recover orphaned files — files physically present in the quarantine
    /// directory but missing from the journal (e.g., crash between `rename`
    /// and the journal `INSERT`).  Registers them so they appear in the UI
    /// and are subject to the normal 30-day auto-purge.
    fn reconcile_orphans(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            // Skip SQLite database files (journal.db, journal.db-wal, journal.db-shm)
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with("journal.db") {
                continue;
            }
            // Already tracked?
            let tracked: Result<i64, _> = self.journal.query_row(
                "SELECT COUNT(*) FROM quarantine_journal WHERE quarantined_path = ?1",
                rusqlite::params![path.to_string_lossy().as_ref()],
                |row| row.get(0),
            );
            if tracked.is_ok_and(|c| c > 0) {
                continue;
            }
            // Orphan — register with best-guess metadata
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let _ = self.journal.execute(
                "INSERT INTO quarantine_journal (original_path, quarantined_path, size_bytes, reason, session_id)
                 VALUES (?1, ?2, ?3, 'recovered-orphan', 'recovery')",
                rusqlite::params![
                    format!("(orphan) {name}"),
                    path.to_string_lossy().as_ref(),
                    size as i64,
                ],
            );
        }
    }

    /// Moves a file into quarantine.
    ///
    /// The file is renamed to a unique name in the quarantine directory
    /// and a journal entry is recorded. Returns the journal entry.
    pub fn quarantine_file(
        &self,
        original: &Path,
        reason: &str,
        session_id: &str,
        purge_in_days: Option<u32>,
    ) -> io::Result<QuarantineEntry> {
        let metadata = fs::symlink_metadata(original)?;
        let size = metadata.len();

        let permissions = metadata.permissions();
        #[cfg(unix)]
        let permissions_mode: Option<u32> = {
            use std::os::unix::fs::PermissionsExt;
            Some(permissions.mode())
        };
        #[cfg(not(unix))]
        let permissions_mode: Option<u32> = None;

        let original_path_buf = original.to_path_buf();
        let utf8_original = Utf8PathBuf::from_path_buf(original_path_buf).map_err(|p| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("non-UTF-8 path: {}", p.to_string_lossy()),
            )
        })?;

        let original_path_bytes: &[u8] = original.as_os_str().as_encoded_bytes();

        let file_name = original
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let unique_name = format!("{}_{}", self.next_id(), file_name);
        let quarantined_path = self.dir.join(&unique_name);

        let utf8_quarantined =
            Utf8PathBuf::from_path_buf(quarantined_path.clone()).map_err(|p| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("non-UTF-8 quarantine path: {}", p.to_string_lossy()),
                )
            })?;

        fs::rename(original, &quarantined_path).or_else(|_| {
            // Cross-device or permission issue — fall back to copy + remove
            fs::copy(original, &quarantined_path)?;
            fs::remove_file(original)?;
            Ok::<(), io::Error>(())
        })?;

        let moved_at = chrono_now();
        let purge_at = purge_in_days.map(compute_purge_at);
        self.journal
            .execute(
                "INSERT INTO quarantine_journal (original_path, original_path_blob, quarantined_path, size_bytes, reason, moved_at, permissions_mode, session_id, purge_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    utf8_original.as_str(),
                    original_path_bytes,
                    utf8_quarantined.as_str(),
                    size as i64,
                    reason,
                    moved_at,
                    permissions_mode.map(|m| m as i64),
                    session_id,
                    purge_at,
                ],
            )
            .map_err(|e| io::Error::other(format!("journal insert: {e}")))?;

        let id = self.journal.last_insert_rowid() as u64;

        Ok(QuarantineEntry {
            id,
            original_path: utf8_original,
            quarantined_path: utf8_quarantined,
            size_bytes: size,
            reason: reason.to_string(),
            moved_at,
            restored: false,
            session_id: session_id.to_string(),
            purge_at,
        })
    }

    /// Records an already-moved file into the quarantine journal.
    ///
    /// Use this when the file has been moved to the quarantine directory
    /// externally (e.g., via `std::fs::rename`) instead of via
    /// `quarantine_file`.
    pub fn record_entry(
        &self,
        original_path: &camino::Utf8Path,
        quarantined_path: &camino::Utf8Path,
        size_bytes: u64,
        reason: &str,
        session_id: &str,
        purge_in_days: Option<u32>,
    ) -> io::Result<QuarantineEntry> {
        let original_path_bytes: &[u8] = original_path.as_std_path().as_os_str().as_encoded_bytes();
        let moved_at = chrono_now();
        let purge_at = purge_in_days.map(compute_purge_at);

        self.journal
            .execute(
                "INSERT INTO quarantine_journal (original_path, original_path_blob, quarantined_path, size_bytes, reason, moved_at, session_id, purge_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    original_path.as_str(),
                    original_path_bytes,
                    quarantined_path.as_str(),
                    size_bytes as i64,
                    reason,
                    moved_at,
                    session_id,
                    purge_at,
                ],
            )
            .map_err(|e| io::Error::other(format!("journal insert: {e}")))?;

        let id = self.journal.last_insert_rowid() as u64;

        Ok(QuarantineEntry {
            id,
            original_path: original_path.to_owned(),
            quarantined_path: quarantined_path.to_owned(),
            size_bytes,
            reason: reason.to_string(),
            moved_at,
            restored: false,
            session_id: session_id.to_string(),
            purge_at,
        })
    }

    /// Records a file that survived a cleanup as the keeper of its group.
    ///
    /// Kept files are the only on-disk survivors of their duplicate group:
    /// a later automated pass (e.g. similar images after an exact cleanup)
    /// must never quarantine them, or the group loses its last copy on disk.
    /// Re-recording the same path just refreshes its session/timestamp.
    pub fn record_kept_file(&self, path: &camino::Utf8Path, session_id: &str) -> io::Result<()> {
        self.journal
            .execute(
                "INSERT OR REPLACE INTO kept_files (path, session_id) VALUES (?1, ?2)",
                params![path.as_str(), session_id],
            )
            .map_err(|e| io::Error::other(format!("kept_files insert: {e}")))?;
        Ok(())
    }

    /// Returns every path recorded as a cleanup keeper in this quarantine.
    pub fn kept_files(&self) -> io::Result<Vec<Utf8PathBuf>> {
        let mut stmt = self
            .journal
            .prepare("SELECT path FROM kept_files")
            .map_err(|e| io::Error::other(format!("kept_files query: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| io::Error::other(format!("kept_files query: {e}")))?;
        let mut paths = Vec::new();
        for row in rows {
            let path = row.map_err(|e| io::Error::other(format!("kept_files row: {e}")))?;
            paths.push(Utf8PathBuf::from(path));
        }
        Ok(paths)
    }

    /// Restores a single quarantined file back to its original location.
    ///
    /// If the original path's parent directory no longer exists, it is recreated.
    pub fn restore_file(&self, entry_id: u64) -> io::Result<()> {
        let (entry, original_path_blob, permissions_mode): (
            QuarantineEntry,
            Option<Vec<u8>>,
            Option<u32>,
        ) = self
            .journal
            .query_row(
                "SELECT id, original_path, quarantined_path, original_path_blob, size_bytes, reason, moved_at, restored, permissions_mode, session_id, purge_at
                 FROM quarantine_journal WHERE id = ?1",
                params![entry_id as i64],
                |row| {
                    let entry = QuarantineEntry {
                        id: row.get::<_, i64>(0)? as u64,
                        original_path: {
                            let s: String = row.get(1)?;
                            Utf8PathBuf::from(s)
                        },
                        quarantined_path: {
                            let s: String = row.get(2)?;
                            Utf8PathBuf::from(s)
                        },
                        size_bytes: row.get::<_, i64>(4)? as u64,
                        reason: row.get(5)?,
                        moved_at: row.get(6)?,
                        restored: row.get(7)?,
                        session_id: row.get::<_, String>(9).unwrap_or_default(),
                        purge_at: row.get::<_, Option<String>>(10)?,
                    };
                    let blob: Option<Vec<u8>> = row.get(3)?;
                    let mode: Option<i64> = row.get(8)?;
                    Ok((entry, blob, mode.map(|v| v as u32)))
                },
            )
            .map_err(|e| io::Error::other(format!("query: {e}")))?;

        if !entry.quarantined_path.as_std_path().exists() {
            self.remove_entry(entry.id)?;
            return Ok(());
        }

        if entry.restored {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("entry {} already restored", entry_id),
            ));
        }

        let original: PathBuf = if let Some(ref blob) = original_path_blob {
            let lossy = String::from_utf8_lossy(blob);
            PathBuf::from(lossy.as_ref())
        } else {
            entry.original_path.as_std_path().to_path_buf()
        };

        let quarantined = entry.quarantined_path.as_std_path();

        if let Some(parent) = original.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::copy(quarantined, &original)?;
        fs::remove_file(quarantined)?;

        #[cfg(unix)]
        if let Some(mode) = permissions_mode {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(mode);
            fs::set_permissions(&original, perms)?;
        }

        self.journal
            .execute(
                "UPDATE quarantine_journal SET restored = 1 WHERE id = ?1",
                params![entry_id as i64],
            )
            .map_err(|e| io::Error::other(format!("update: {e}")))?;

        Ok(())
    }

    /// Restores all non-restored quarantined files.
    pub fn restore_all(&self) -> QuarantineReport {
        let mut report = QuarantineReport {
            files_quarantined: 0,
            files_restored: 0,
            bytes_affected: 0,
            entries: Vec::new(),
            errors: Vec::new(),
        };

        let entries = match self.list_quarantined(false) {
            Ok(entries) => entries,
            Err(e) => {
                report.errors.push(format!("list: {e}"));
                return report;
            }
        };

        for entry in &entries {
            match self.restore_file(entry.id) {
                Ok(()) => {
                    report.files_restored += 1;
                    report.bytes_affected += entry.size_bytes;
                }
                Err(e) => {
                    report.errors.push(format!("restore {} ({})", entry.id, e));
                }
            }
        }

        report.entries = entries;
        report
    }

    /// Restores all non-restored files matching a reason pattern (SQL LIKE).
    ///
    /// Use "exact%" to restore exact duplicates only, or "similar%" for
    /// similar images only. This allows independent undo of the two stages.
    pub fn restore_by_reason(&self, reason_pattern: &str) -> QuarantineReport {
        let mut report = QuarantineReport {
            files_quarantined: 0,
            files_restored: 0,
            bytes_affected: 0,
            entries: Vec::new(),
            errors: Vec::new(),
        };

        let entries = match self.list_by_reason(reason_pattern) {
            Ok(entries) => entries,
            Err(e) => {
                report.errors.push(format!("list: {e}"));
                return report;
            }
        };

        for entry in &entries {
            match self.restore_file(entry.id) {
                Ok(()) => {
                    report.files_restored += 1;
                    report.bytes_affected += entry.size_bytes;
                }
                Err(e) => {
                    report.errors.push(format!("restore {} ({})", entry.id, e));
                }
            }
        }

        report.entries = entries;
        report
    }

    /// Lists non-restored entries matching a reason pattern (SQL LIKE).
    /// Entries whose quarantined file was deleted from disk are silently removed
    /// from the journal and excluded from the result.
    fn list_by_reason(&self, reason_pattern: &str) -> io::Result<Vec<QuarantineEntry>> {
        let sql = "SELECT id, original_path, quarantined_path, size_bytes, reason, moved_at, restored, session_id, purge_at
                   FROM quarantine_journal WHERE restored = 0 AND reason LIKE ?1 ORDER BY id";

        let mut stmt = self
            .journal
            .prepare(sql)
            .map_err(|e| io::Error::other(format!("prepare: {e}")))?;

        let entries = stmt
            .query_map(params![reason_pattern], |row| {
                Ok(QuarantineEntry {
                    id: row.get::<_, i64>(0)? as u64,
                    original_path: {
                        let s: String = row.get(1)?;
                        Utf8PathBuf::from(s)
                    },
                    quarantined_path: {
                        let s: String = row.get(2)?;
                        Utf8PathBuf::from(s)
                    },
                    size_bytes: row.get::<_, i64>(3)? as u64,
                    reason: row.get(4)?,
                    moved_at: row.get(5)?,
                    restored: row.get(6)?,
                    session_id: row.get::<_, String>(7).unwrap_or_default(),
                    purge_at: row.get::<_, Option<String>>(8)?,
                })
            })
            .map_err(|e| io::Error::other(format!("query: {e}")))?;

        let mut result = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| io::Error::other(format!("row: {e}")))?;
            if !entry.quarantined_path.as_std_path().exists() {
                self.remove_entry(entry.id)?;
                continue;
            }
            result.push(entry);
        }
        Ok(result)
    }

    /// Lists all journal entries.
    ///
    /// If `include_restored` is false, only non-restored entries are returned.
    /// Entries whose quarantined file was deleted from disk are silently removed
    /// from the journal and excluded from the result.
    pub fn list_quarantined(&self, include_restored: bool) -> io::Result<Vec<QuarantineEntry>> {
        let sql = if include_restored {
            "SELECT id, original_path, quarantined_path, size_bytes, reason, moved_at, restored, session_id, purge_at
             FROM quarantine_journal ORDER BY id"
        } else {
            "SELECT id, original_path, quarantined_path, size_bytes, reason, moved_at, restored, session_id, purge_at
             FROM quarantine_journal WHERE restored = 0 ORDER BY id"
        };

        let mut stmt = self
            .journal
            .prepare(sql)
            .map_err(|e| io::Error::other(format!("prepare: {e}")))?;

        let entries = stmt
            .query_map([], |row| {
                Ok(QuarantineEntry {
                    id: row.get::<_, i64>(0)? as u64,
                    original_path: {
                        let s: String = row.get(1)?;
                        Utf8PathBuf::from(s)
                    },
                    quarantined_path: {
                        let s: String = row.get(2)?;
                        Utf8PathBuf::from(s)
                    },
                    size_bytes: row.get::<_, i64>(3)? as u64,
                    reason: row.get(4)?,
                    moved_at: row.get(5)?,
                    restored: row.get(6)?,
                    session_id: row.get::<_, String>(7).unwrap_or_default(),
                    purge_at: row.get::<_, Option<String>>(8)?,
                })
            })
            .map_err(|e| io::Error::other(format!("query: {e}")))?;

        let mut result = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| io::Error::other(format!("row: {e}")))?;
            if !entry.quarantined_path.as_std_path().exists() {
                self.remove_entry(entry.id)?;
                continue;
            }
            result.push(entry);
        }
        Ok(result)
    }

    /// Returns the quarantine directory path.
    #[must_use]
    pub fn dir_path(&self) -> &Path {
        &self.dir
    }

    /// Permanently delete a quarantined file (actual rm).
    /// If the file was already deleted from disk, the journal entry is
    /// cleaned up silently and `Ok(())` is returned.
    pub fn purge_file(&self, entry_id: u64) -> io::Result<()> {
        let entry = self.get_entry(entry_id)?;

        if !entry.quarantined_path.as_std_path().exists() {
            self.remove_entry(entry.id)?;
            return Ok(());
        }

        std::fs::remove_file(&entry.quarantined_path)?;

        self.journal
            .execute(
                "UPDATE quarantine_journal SET restored = 1, reason = reason || ' (purged)' WHERE id = ?1",
                params![entry_id as i64],
            )
            .map_err(|e| io::Error::other(format!("update: {e}")))?;

        Ok(())
    }

    /// Permanently delete all non-restored quarantined files.
    pub fn purge_all(&self) -> io::Result<u32> {
        let entries = self.list_quarantined(false)?;
        let mut count = 0u32;
        for entry in &entries {
            self.purge_file(entry.id)?;
            count += 1;
        }
        Ok(count)
    }

    /// Permanently delete all non-restored quarantined files for a session.
    pub fn purge_session(&self, session_id: &str) -> io::Result<u32> {
        let entries = self.list_quarantined(false)?;
        let mut count = 0u32;
        for entry in &entries {
            if entry.session_id == session_id {
                self.purge_file(entry.id)?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Purge all entries past their purge_at date.
    pub fn purge_expired(&self) -> io::Result<u32> {
        let entries = self.list_quarantined(false)?;
        let now_str = chrono_now();
        let mut count = 0u32;

        for entry in &entries {
            if let Some(ref purge_at_str) = entry.purge_at
                && purge_at_str < &now_str
            {
                self.purge_file(entry.id)?;
                count += 1;
            }
        }

        Ok(count)
    }

    /// Group quarantine entries by session_id.
    pub fn list_sessions(&self) -> io::Result<Vec<QuarantineSession>> {
        let entries = self.list_quarantined(false)?;
        let mut sessions: std::collections::HashMap<String, Vec<QuarantineEntry>> =
            std::collections::HashMap::new();

        for entry in entries {
            sessions
                .entry(entry.session_id.clone())
                .or_default()
                .push(entry);
        }

        Ok(sessions
            .into_iter()
            .map(|(id, files)| {
                let first = files.first().expect("session must have at least one entry");
                let mode = if first.reason.contains("junk") {
                    "junk"
                } else if first.reason.contains("similar") {
                    "similar"
                } else {
                    "exact"
                }
                .to_string();
                let label = if mode == "junk" {
                    format!("Junk cleanup · {}", first.original_path.as_str())
                } else {
                    format!("{} cleanup · {}", mode, first.original_path.as_str())
                };
                let source_path = first
                    .original_path
                    .parent()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_else(|| first.original_path.as_str().to_string());
                let cleaned_at = first.moved_at.clone();
                QuarantineSession {
                    id,
                    mode,
                    label,
                    source_path,
                    cleaned_at,
                    purge_in_days: 30,
                    files,
                }
            })
            .collect())
    }

    /// Remove a journal entry by ID.
    fn remove_entry(&self, entry_id: u64) -> io::Result<()> {
        self.journal
            .execute(
                "DELETE FROM quarantine_journal WHERE id = ?1",
                params![entry_id as i64],
            )
            .map_err(|e| io::Error::other(format!("delete entry: {e}")))?;
        Ok(())
    }

    /// Look up a single quarantine journal entry by its ID.
    pub fn get_entry(&self, entry_id: u64) -> io::Result<QuarantineEntry> {
        self.journal
            .query_row(
                "SELECT id, original_path, quarantined_path, size_bytes, reason, moved_at, restored, session_id, purge_at
                 FROM quarantine_journal WHERE id = ?1",
                params![entry_id as i64],
                |row| {
                    Ok(QuarantineEntry {
                        id: row.get::<_, i64>(0)? as u64,
                        original_path: {
                            let s: String = row.get(1)?;
                            Utf8PathBuf::from(s)
                        },
                        quarantined_path: {
                            let s: String = row.get(2)?;
                            Utf8PathBuf::from(s)
                        },
                        size_bytes: row.get::<_, i64>(3)? as u64,
                        reason: row.get(4)?,
                        moved_at: row.get(5)?,
                        restored: row.get(6)?,
                        session_id: row.get::<_, String>(7).unwrap_or_default(),
                        purge_at: row.get::<_, Option<String>>(8)?,
                    })
                },
            )
            .map_err(|e| io::Error::other(format!("query entry: {e}")))
    }

    fn next_id(&self) -> u64 {
        self.journal
            .query_row(
                "SELECT COALESCE(MAX(id), 0) + 1 FROM quarantine_journal",
                [],
                |row| row.get::<_, i64>(0).map(|v| v as u64),
            )
            .unwrap_or(1)
    }
}

/// Check and purge expired quarantine entries.
/// Returns the number of files purged.
/// Safe to call on app startup — no-op if quarantine dir doesn't exist.
pub fn auto_purge_quarantine(quarantine_dir: &Path) -> io::Result<u32> {
    if !quarantine_dir.exists() {
        return Ok(0);
    }
    let q = Quarantine::open(quarantine_dir)?;
    q.purge_expired()
}

fn chrono_now() -> String {
    // ISO 8601 timestamp without external chrono dependency
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Simple UTC format: YYYY-MM-DD HH:MM:SS
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    // Approximate Gregorian calendar (good enough for journal timestamps)
    let (year, month, day) = civil_from_days(days_since_epoch as i64);
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02}")
}

fn compute_purge_at(purge_in_days: u32) -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() + (purge_in_days as u64 * 86400);
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let (year, month, day) = civil_from_days(days_since_epoch as i64);
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;
    format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02}")
}

/// Convert days since Unix epoch to (year, month, day).
/// Algorithm from Howard Hinnant.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn profile() -> &'static dyn zerodupe_platform::PlatformProfile {
        zerodupe_platform::current()
    }

    fn phys_key_available() -> bool {
        std::fs::symlink_metadata(".")
            .ok()
            .and_then(|m| profile().physical_key(camino::Utf8Path::new("."), &m))
            .is_some()
    }

    #[test]
    fn verify_unchanged_file_ok() {
        let p = profile();
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("unchanged.txt");
        std::fs::write(&file_path, b"stable content").expect("write");

        let meta = std::fs::symlink_metadata(&file_path).expect("metadata");
        let snapshot = FileSnapshot {
            size_bytes: meta.len(),
            modified_unix_seconds: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
            physical_key: p.physical_key(
                camino::Utf8Path::from_path(&file_path).expect("utf8"),
                &meta,
            ),
        };

        let utf8_path = camino::Utf8Path::from_path(&file_path).expect("utf8");
        assert!(
            verify_safe_to_act(utf8_path, &snapshot, p).is_ok(),
            "unchanged file should be safe to act on"
        );
    }

    /// A size-only snapshot (mtime/physical_key not captured) — the exact shape
    /// the cleaning loop builds — passes when the file is unchanged.
    #[test]
    fn verify_size_only_snapshot_ok_when_unchanged() {
        let p = profile();
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("size_only_ok.txt");
        std::fs::write(&file_path, b"scanned content").expect("write");

        let snapshot = FileSnapshot {
            size_bytes: b"scanned content".len() as u64,
            modified_unix_seconds: None,
            physical_key: None,
        };

        let utf8_path = camino::Utf8Path::from_path(&file_path).expect("utf8");
        assert!(
            verify_safe_to_act(utf8_path, &snapshot, p).is_ok(),
            "unchanged file with size-only snapshot should be safe to act on"
        );
    }

    /// A size-only snapshot still catches a file edited/replaced since the scan
    /// when the edit changes the byte length — the TOCTTOU case the cleaning
    /// loop now guards against.
    #[test]
    fn verify_size_only_snapshot_detects_size_change() {
        let p = profile();
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("size_only_changed.txt");
        std::fs::write(&file_path, b"original").expect("write");

        let snapshot = FileSnapshot {
            size_bytes: b"original".len() as u64,
            modified_unix_seconds: None,
            physical_key: None,
        };

        // File replaced with different-length content between scan and action.
        std::fs::write(&file_path, b"tampered, longer content").expect("write");

        let utf8_path = camino::Utf8Path::from_path(&file_path).expect("utf8");
        let result = verify_safe_to_act(utf8_path, &snapshot, p);
        assert!(
            result.is_err(),
            "size-only snapshot should reject a resized file: {result:?}"
        );
        assert!(
            result.as_ref().unwrap_err().contains("size"),
            "error should mention size"
        );
    }

    #[test]
    fn verify_size_changed_errors() {
        let p = profile();
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("size_change.txt");
        std::fs::write(&file_path, b"before").expect("write");

        let meta = std::fs::symlink_metadata(&file_path).expect("metadata");
        let snapshot = FileSnapshot {
            size_bytes: meta.len(),
            modified_unix_seconds: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
            physical_key: p.physical_key(
                camino::Utf8Path::from_path(&file_path).expect("utf8"),
                &meta,
            ),
        };

        std::fs::write(&file_path, b"after, different size").expect("write");

        let utf8_path = camino::Utf8Path::from_path(&file_path).expect("utf8");
        let result = verify_safe_to_act(utf8_path, &snapshot, p);
        assert!(
            result.is_err(),
            "size change should be detected: {result:?}"
        );
        assert!(
            result.as_ref().unwrap_err().contains("size"),
            "error should mention size"
        );
    }

    #[test]
    fn verify_mtime_changed_errors() {
        let p = profile();
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("mtime_change.txt");
        std::fs::write(&file_path, b"same content").expect("write");

        let meta = std::fs::symlink_metadata(&file_path).expect("metadata");
        let snapshot = FileSnapshot {
            size_bytes: meta.len(),
            modified_unix_seconds: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
            physical_key: p.physical_key(
                camino::Utf8Path::from_path(&file_path).expect("utf8"),
                &meta,
            ),
        };

        let file = std::fs::File::open(&file_path).expect("open");
        file.set_modified(std::time::SystemTime::UNIX_EPOCH)
            .expect("set_modified");

        let utf8_path = camino::Utf8Path::from_path(&file_path).expect("utf8");
        let result = verify_safe_to_act(utf8_path, &snapshot, p);
        assert!(
            result.is_err(),
            "mtime change should be detected: {result:?}"
        );
        let err = result.unwrap_err();
        assert!(err.contains("mtime"), "error should mention mtime: {err}");
    }

    #[test]
    fn verify_deleted_file_errors() {
        let p = profile();
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("to_delete.txt");
        std::fs::write(&file_path, b"will be deleted").expect("write");

        let meta = std::fs::symlink_metadata(&file_path).expect("metadata");
        let snapshot = FileSnapshot {
            size_bytes: meta.len(),
            modified_unix_seconds: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
            physical_key: p.physical_key(
                camino::Utf8Path::from_path(&file_path).expect("utf8"),
                &meta,
            ),
        };

        let utf8_path = camino::Utf8Path::from_path(&file_path).expect("utf8");
        std::fs::remove_file(&file_path).expect("remove");

        let result = verify_safe_to_act(utf8_path, &snapshot, p);
        assert!(
            result.is_err(),
            "deleted file should produce an error: {result:?}"
        );
    }

    #[test]
    fn verify_physical_key_mismatch_errors() {
        if !phys_key_available() {
            eprintln!("skipped — no physical key support on this filesystem");
            return;
        }
        let p = profile();
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("pk_test.txt");
        std::fs::write(&file_path, b"pk content").expect("write");

        let meta = std::fs::symlink_metadata(&file_path).expect("metadata");
        let real_key = p.physical_key(
            camino::Utf8Path::from_path(&file_path).expect("utf8"),
            &meta,
        );
        assert!(real_key.is_some(), "expected a physical key, got None");

        let fake_key = zerodupe_platform::PhysicalFileKey::from_unix(99999, 88888);
        let snapshot = FileSnapshot {
            size_bytes: meta.len(),
            modified_unix_seconds: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
            physical_key: Some(fake_key),
        };

        let utf8_path = camino::Utf8Path::from_path(&file_path).expect("utf8");
        let result = verify_safe_to_act(utf8_path, &snapshot, p);
        assert!(
            result.is_err(),
            "physical key mismatch should be detected: {result:?}"
        );
    }

    #[test]
    fn quarantine_and_restore_file() {
        let q = Quarantine::open_memory().expect("open");
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, b"hello quarantine").expect("write");

        let entry = q
            .quarantine_file(&file_path, "duplicate", NIL_UUID, None)
            .expect("quarantine");
        assert!(!file_path.exists(), "original should be moved");
        assert!(
            entry.quarantined_path.as_std_path().exists(),
            "quarantined should exist"
        );
        assert_eq!(entry.size_bytes, 16);

        q.restore_file(entry.id).expect("restore");
        assert!(file_path.exists(), "original should be restored");
        let content = fs::read_to_string(&file_path).expect("read");
        assert_eq!(content, "hello quarantine");
    }

    #[test]
    fn list_quarantined_excludes_restored() {
        let q = Quarantine::open_memory().expect("open");
        let dir = tempfile::tempdir().expect("tempdir");
        let f1 = dir.path().join("a.txt");
        let f2 = dir.path().join("b.txt");
        fs::write(&f1, b"a").expect("write");
        fs::write(&f2, b"b").expect("write");

        let e1 = q
            .quarantine_file(&f1, "test", "session-1", None)
            .expect("q1");
        let _e2 = q
            .quarantine_file(&f2, "test", "session-1", None)
            .expect("q2");
        q.restore_file(e1.id).expect("restore");

        let list = q.list_quarantined(false).expect("list");
        assert_eq!(list.len(), 1);
        assert!(!list[0].restored);
    }

    #[test]
    fn restore_all_restores_everything() {
        let q = Quarantine::open_memory().expect("open");
        let dir = tempfile::tempdir().expect("tempdir");
        let f1 = dir.path().join("x.txt");
        fs::write(&f1, b"x").expect("write");

        q.quarantine_file(&f1, "test", "session-1", None)
            .expect("q");
        let report = q.restore_all();
        assert_eq!(report.files_restored, 1);
        assert!(f1.exists());
    }

    #[test]
    fn quarantine_nonexistent_file_errors() {
        let q = Quarantine::open_memory().expect("open");
        let result = q.quarantine_file(
            Path::new("/nonexistent/zerodupe/file.txt"),
            "test",
            "session-1",
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn quarantine_preserves_content() {
        let q = Quarantine::open_memory().expect("open");
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("data.bin");
        let data = vec![0u8, 1, 2, 3, 255];
        fs::write(&file_path, &data).expect("write");

        let entry = q
            .quarantine_file(&file_path, "dup", "session-1", None)
            .expect("q");
        let quarantined_content = fs::read(entry.quarantined_path.as_std_path()).expect("read");
        assert_eq!(quarantined_content, data);
    }

    #[test]
    fn restore_recreates_parent_dirs() {
        let q = Quarantine::open_memory().expect("open");
        let dir = tempfile::tempdir().expect("tempdir");
        let original = dir.path().join("deeply/nested/path/file.txt");
        fs::create_dir_all(original.parent().unwrap()).expect("mkdir");
        fs::write(&original, b"nested").expect("write");

        let entry = q
            .quarantine_file(&original, "test", "session-1", None)
            .expect("q");
        // Remove the original parent dirs
        fs::remove_dir_all(dir.path().join("deeply")).expect("rm");

        q.restore_file(entry.id).expect("restore");
        assert!(original.exists());
        assert_eq!(fs::read_to_string(&original).expect("read"), "nested");
    }

    #[test]
    fn quarantine_preserves_permissions() {
        let q = Quarantine::open_memory().expect("open");
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("permissions_test.bin");
        fs::write(&file_path, b"permissions test").expect("write");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode_before = 0o600;
            fs::set_permissions(&file_path, fs::Permissions::from_mode(mode_before))
                .expect("set_permissions");

            let entry = q
                .quarantine_file(&file_path, "permission-test", "session-1", None)
                .expect("quarantine");

            q.restore_file(entry.id).expect("restore");

            let restored_meta = fs::metadata(&file_path).expect("metadata");
            let restored_mode = restored_meta.permissions().mode();
            assert_eq!(
                restored_mode & 0o777,
                mode_before,
                "permissions mode should be preserved after quarantine/restore"
            );
            let content = fs::read_to_string(&file_path).expect("read");
            assert_eq!(content, "permissions test");
        }

        #[cfg(not(unix))]
        {
            let entry = q
                .quarantine_file(&file_path, "permission-test", "session-1", None)
                .expect("quarantine");
            q.restore_file(entry.id).expect("restore");
            assert!(file_path.exists());
            let content = fs::read_to_string(&file_path).expect("read");
            assert_eq!(content, "permissions test");
        }
    }
}
