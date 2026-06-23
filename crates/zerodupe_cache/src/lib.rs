//! SQLite-backed hash cache for ZeroDupe.
//!
//! Caches partial and full file hashes keyed by physical identity, size, mtime,
//! hash algorithm, and region. Used transparently by the scan pipeline to avoid
//! re-hashing files that haven't changed since the last scan.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};
use zerodupe_core::{FileVersion, HashAlgorithm, HashCacheKey, HashRegion};

/// Version of the cache schema + hash algorithm.
///
/// Bump this when hash algorithm or schema changes in a way that makes
/// old cached entries incompatible. Stored in the `fingerprint_algo_version`
/// column and checked on every `get()` to prevent stale cache hits.
///
/// ⚠️ DISCIPLINE: if you touch `zerodupe_hash` (algorithm, regions, chunking)
/// or `region_to_db`, bump this constant — otherwise the cache will serve
/// hashes computed by the old logic. The sentinel tests in
/// `zerodupe_hash/tests/sentinel.rs` exist to catch exactly that.
///
/// History: 4 = opaque physical key migration; 5 = nanosecond mtime +
/// ctime witness validation (entries from v4 lack the witness columns).
pub const CACHE_SCHEMA_VERSION: u32 = 5;

/// Maximum number of cache entries before auto-pruning kicks in.
const MAX_CACHE_ENTRIES: usize = 100_000;

/// Target number of cache entries after max-entries pruning.
const TARGET_CACHE_ENTRIES: usize = 90_000;

/// Key for a cached perceptual fingerprint (similar-files pipeline).
///
/// Identity: physical file + detector + params. Witnesses (size, mtime,
/// ctime) and `algo_version` validate the entry on lookup, mirroring the
/// rules of the exact-hash cache. `params` encodes the detector
/// configuration (hash size, geometric invariance mode, ...) so changing
/// configuration invalidates cached fingerprints — see D-007/D-008.
#[derive(Debug, Clone)]
pub struct FingerprintCacheKey {
    pub physical_key: Option<zerodupe_platform::PhysicalFileKey>,
    pub size_bytes: u64,
    pub version: FileVersion,
    /// Detector name, e.g. "image-phash".
    pub detector: String,
    /// Opaque detector configuration string.
    pub params: String,
    /// Fingerprint algorithm version (e.g. `FP_ALGO_VERSION` of the detector).
    pub algo_version: u32,
}

/// A cached fingerprint result: either the fingerprint itself or the error
/// the detector produced (corrupt file, degenerate hash). Caching failures
/// avoids re-decoding broken files on every scan; the error is still
/// reported to the user from the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CachedFingerprint {
    Ok {
        data: Vec<u8>,
        metadata_json: String,
    },
    Error {
        message: String,
    },
}

/// Persistent hash cache backed by SQLite.
///
/// Key: (key_discriminant, key_blob, size, algorithm, region)
/// Value: (hash_hex, mtime_at_cache_time)
///
/// The physical file identity is stored opaquely as (discriminant, blob)
/// so the cache works cross-platform without OS-specific knowledge.
/// Cache hits are validated by comparing the current file mtime with the cached mtime.
/// If mtime differs, the entry is treated as a miss and the old entry is invalidated.
pub struct HashCache {
    conn: Connection,
}

impl HashCache {
    /// Opens (or creates) a persistent cache at the given file path.
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        // WAL avoids an fsync per insert; NORMAL is durable enough for a
        // cache that can always be recomputed from the files themselves.
        let _ = conn.query_row("PRAGMA journal_mode = WAL", [], |_row| Ok(()));
        conn.execute_batch("PRAGMA synchronous = NORMAL;")?;
        let cache = Self { conn };
        cache.ensure_schema()?;
        cache.prune_on_open();
        Ok(cache)
    }

    /// Opens an in-memory cache (useful for testing or when persistence is not desired).
    pub fn open_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let cache = Self { conn };
        cache.ensure_schema()?;
        Ok(cache)
    }

    fn ensure_schema(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS hash_cache (
                key_discriminant INTEGER NOT NULL,
                key_blob        BLOB NOT NULL,
                size_bytes      INTEGER NOT NULL,
                mtime_secs      INTEGER,
                mtime_nanos     INTEGER,
                ctime_nanos     INTEGER,
                algorithm       TEXT    NOT NULL,
                region_kind     TEXT    NOT NULL,
                region_head     INTEGER,
                region_tail     INTEGER,
                hash_hex        TEXT    NOT NULL,
                created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                fingerprint_algo_version INTEGER NOT NULL DEFAULT 4,
                PRIMARY KEY (key_discriminant, key_blob, size_bytes, algorithm, region_kind, region_head, region_tail)
            );
            CREATE INDEX IF NOT EXISTS idx_hash_cache_key_blob
                ON hash_cache(key_discriminant, key_blob);
            CREATE TABLE IF NOT EXISTS fingerprint_cache (
                key_discriminant INTEGER NOT NULL,
                key_blob        BLOB NOT NULL,
                detector        TEXT NOT NULL,
                params          TEXT NOT NULL,
                size_bytes      INTEGER NOT NULL,
                mtime_nanos     INTEGER,
                ctime_nanos     INTEGER,
                status          TEXT NOT NULL,
                fp_blob         BLOB,
                metadata_json   TEXT,
                error_msg       TEXT,
                algo_version    INTEGER NOT NULL,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (key_discriminant, key_blob, detector, params)
            );
            ",
        )?;
        // Migrations: add columns to existing databases that lack them.
        // Ignore error if the column already exists (new DBs created above).
        // NOTE: old cache files from before the opaque key migration
        // (key_discriminant/key_blob columns) are incompatible with the new
        // schema. If the ALTER fails because the old device/inode schema
        // is still present, the cache will be treated as empty.
        let _ = self.conn.execute(
            "ALTER TABLE hash_cache ADD COLUMN fingerprint_algo_version INTEGER NOT NULL DEFAULT 4",
            [],
        );
        // v5: nanosecond mtime + ctime witnesses. v4 entries keep NULL here
        // and are already excluded by the fingerprint_algo_version check.
        let _ = self
            .conn
            .execute("ALTER TABLE hash_cache ADD COLUMN mtime_nanos INTEGER", []);
        let _ = self
            .conn
            .execute("ALTER TABLE hash_cache ADD COLUMN ctime_nanos INTEGER", []);
        Ok(())
    }

    /// Looks up a cached hash.
    ///
    /// Returns `Some(hash_hex)` if a valid entry exists and the file-version
    /// witnesses in `key.version` match the ones stored when the hash was
    /// computed. Returns `None` on miss or if the file was modified.
    pub fn get(&self, key: &HashCacheKey) -> rusqlite::Result<Option<String>> {
        let physical_key = match key.physical_key.as_ref() {
            Some(pk) if pk.discriminant != 2 => pk,
            _ => return Ok(None),
        };

        let (region_kind, region_head, region_tail) = region_to_db(&key.region);

        let mut stmt = self.conn.prepare_cached(
            "SELECT hash_hex, mtime_nanos, ctime_nanos FROM hash_cache
             WHERE key_discriminant = ?1 AND key_blob = ?2 AND size_bytes = ?3
               AND algorithm = ?4 AND region_kind = ?5
               AND region_head = ?6 AND region_tail = ?7
               AND fingerprint_algo_version = ?8",
        )?;

        let result: rusqlite::Result<Option<String>> = stmt
            .query_row(
                params![
                    physical_key.discriminant as i64,
                    &physical_key.bytes,
                    key.size_bytes as i64,
                    algorithm_to_str(key.hash_algorithm),
                    region_kind,
                    region_head,
                    region_tail,
                    CACHE_SCHEMA_VERSION,
                ],
                |row| {
                    let hash: String = row.get(0)?;
                    let stored = FileVersion {
                        mtime_nanos: row.get(1)?,
                        ctime_nanos: row.get(2)?,
                    };
                    if version_matches(&stored, &key.version) {
                        Ok(Some(hash))
                    } else {
                        Ok(None)
                    }
                },
            )
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            });

        result
    }

    /// Stores a hash in the cache.
    ///
    /// Uses INSERT OR REPLACE so that re-hashing the same file updates the entry.
    pub fn put(&self, key: &HashCacheKey, hash: &str) -> rusqlite::Result<()> {
        let physical_key = match key.physical_key.as_ref() {
            Some(pk) if pk.discriminant != 2 => pk,
            _ => return Ok(()),
        };

        let (region_kind, region_head, region_tail) = region_to_db(&key.region);

        let mut stmt = self.conn.prepare_cached(
            "INSERT OR REPLACE INTO hash_cache
                (key_discriminant, key_blob, size_bytes, mtime_secs, mtime_nanos, ctime_nanos, algorithm, region_kind, region_head, region_tail, hash_hex, fingerprint_algo_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )?;
        stmt.execute(params![
            physical_key.discriminant as i64,
            &physical_key.bytes,
            key.size_bytes as i64,
            // Kept at second precision for the age-based pruning queries.
            key.version.mtime_nanos.map(|n| n / 1_000_000_000),
            key.version.mtime_nanos,
            key.version.ctime_nanos,
            algorithm_to_str(key.hash_algorithm),
            region_kind,
            region_head,
            region_tail,
            hash,
            CACHE_SCHEMA_VERSION,
        ])?;

        Ok(())
    }

    /// Stores many hashes in a single transaction.
    ///
    /// The scan pipeline collects the hashes computed during a stage and
    /// flushes them here, paying one fsync per stage instead of one per file.
    pub fn put_batch(&self, entries: &[(HashCacheKey, String)]) -> rusqlite::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let tx = self.conn.unchecked_transaction()?;
        for (key, hash) in entries {
            self.put(key, hash)?;
        }
        tx.commit()
    }

    /// Deletes every cached entry for a physical file.
    ///
    /// Called when byte comparison proves a cached hash wrong (the file
    /// changed without its witnesses changing): the entry lied once, so all
    /// regions for that file are purged and will be recomputed.
    pub fn invalidate(
        &self,
        physical_key: &zerodupe_platform::PhysicalFileKey,
    ) -> rusqlite::Result<usize> {
        self.conn.execute(
            "DELETE FROM hash_cache WHERE key_discriminant = ?1 AND key_blob = ?2",
            params![physical_key.discriminant as i64, &physical_key.bytes],
        )
    }

    /// Gets a cached hash or computes it, storing the result in the cache.
    ///
    /// This is the main entry point for the scan pipeline.
    pub fn get_or_compute(
        &self,
        key: &HashCacheKey,
        compute: impl FnOnce() -> std::io::Result<zerodupe_hash::Blake3Hex>,
    ) -> std::io::Result<(zerodupe_hash::Blake3Hex, bool)> {
        // `bool` = true if cache hit, false if computed
        // Malformed hex in a cache row is treated as a miss.
        if let Ok(Some(cached)) = self.get(key)
            && let Some(hash) = zerodupe_hash::Blake3Hex::from_hex(&cached)
        {
            return Ok((hash, true));
        }

        let hash = compute()?;
        let _ = self.put(key, &hash.to_hex());
        Ok((hash, false))
    }

    /// Deletes cache entries older than 30 days.
    pub fn prune_expired(&self) -> rusqlite::Result<usize> {
        let deleted = self.conn.execute(
            "DELETE FROM hash_cache WHERE created_at < datetime('now', '-30 days')",
            [],
        )?;
        Ok(deleted)
    }

    /// Deletes the oldest cache entries until the total count is ≤ `target`.
    pub fn prune_max_entries(&self, max: usize, target: usize) -> rusqlite::Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM hash_cache", [], |row| row.get(0))?;
        let current = count as usize;
        if current <= max {
            return Ok(0);
        }
        let excess = current.saturating_sub(target);
        if excess == 0 {
            return Ok(0);
        }
        let deleted = self.conn.execute(
            "DELETE FROM hash_cache WHERE rowid NOT IN (
                SELECT rowid FROM hash_cache ORDER BY created_at DESC LIMIT ?1
            )",
            rusqlite::params![target as i64],
        )?;
        Ok(deleted)
    }

    fn prune_on_open(&self) {
        // Best-effort maintenance; a failed prune only means a fatter cache.
        let _ = self.prune_expired();
        let _ = self.prune_max_entries(MAX_CACHE_ENTRIES, TARGET_CACHE_ENTRIES);
        let _ = self.prune_expired_fingerprints();
        let _ = self.prune_max_fingerprints(MAX_CACHE_ENTRIES, TARGET_CACHE_ENTRIES);
    }

    /// Returns the number of cached entries.
    pub fn entry_count(&self) -> rusqlite::Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM hash_cache", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    // ── Fingerprint cache (similar-files pipeline) ──

    /// Looks up a cached fingerprint.
    ///
    /// Returns `Some` only if an entry exists for this physical file +
    /// detector + params, AND the witnesses (size, mtime, ctime) and
    /// algorithm version match. The same validation rules as `get()` apply:
    /// fallback physical keys and files without an mtime witness are never
    /// served from cache.
    pub fn get_fingerprint(
        &self,
        key: &FingerprintCacheKey,
    ) -> rusqlite::Result<Option<CachedFingerprint>> {
        let physical_key = match key.physical_key.as_ref() {
            Some(pk) if !pk.is_fallback() => pk,
            _ => return Ok(None),
        };

        let mut stmt = self.conn.prepare_cached(
            "SELECT status, fp_blob, metadata_json, error_msg, mtime_nanos, ctime_nanos
             FROM fingerprint_cache
             WHERE key_discriminant = ?1 AND key_blob = ?2
               AND detector = ?3 AND params = ?4
               AND size_bytes = ?5 AND algo_version = ?6",
        )?;

        stmt.query_row(
            params![
                physical_key.discriminant as i64,
                &physical_key.bytes,
                key.detector,
                key.params,
                key.size_bytes as i64,
                key.algo_version,
            ],
            |row| {
                let stored = FileVersion {
                    mtime_nanos: row.get(4)?,
                    ctime_nanos: row.get(5)?,
                };
                if !version_matches(&stored, &key.version) {
                    return Ok(None);
                }
                let status: String = row.get(0)?;
                if status == "ok" {
                    Ok(Some(CachedFingerprint::Ok {
                        data: row.get(1)?,
                        metadata_json: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    }))
                } else {
                    Ok(Some(CachedFingerprint::Error {
                        message: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    }))
                }
            },
        )
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
    }

    /// Stores a fingerprint (or a fingerprint failure) in the cache.
    pub fn put_fingerprint(
        &self,
        key: &FingerprintCacheKey,
        value: &CachedFingerprint,
    ) -> rusqlite::Result<()> {
        let physical_key = match key.physical_key.as_ref() {
            Some(pk) if !pk.is_fallback() => pk,
            _ => return Ok(()),
        };

        let (status, fp_blob, metadata_json, error_msg): (
            &str,
            Option<&[u8]>,
            Option<&str>,
            Option<&str>,
        ) = match value {
            CachedFingerprint::Ok {
                data,
                metadata_json,
            } => ("ok", Some(data.as_slice()), Some(metadata_json), None),
            CachedFingerprint::Error { message } => ("error", None, None, Some(message)),
        };

        let mut stmt = self.conn.prepare_cached(
            "INSERT OR REPLACE INTO fingerprint_cache
                (key_discriminant, key_blob, detector, params, size_bytes,
                 mtime_nanos, ctime_nanos, status, fp_blob, metadata_json,
                 error_msg, algo_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )?;
        stmt.execute(params![
            physical_key.discriminant as i64,
            &physical_key.bytes,
            key.detector,
            key.params,
            key.size_bytes as i64,
            key.version.mtime_nanos,
            key.version.ctime_nanos,
            status,
            fp_blob,
            metadata_json,
            error_msg,
            key.algo_version,
        ])?;
        Ok(())
    }

    /// Stores many fingerprints in a single transaction (one fsync per scan
    /// stage instead of one per file, same pattern as `put_batch`).
    pub fn put_fingerprint_batch(
        &self,
        entries: &[(FingerprintCacheKey, CachedFingerprint)],
    ) -> rusqlite::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let tx = self.conn.unchecked_transaction()?;
        for (key, value) in entries {
            self.put_fingerprint(key, value)?;
        }
        tx.commit()
    }

    /// Returns the number of cached fingerprint entries.
    pub fn fingerprint_entry_count(&self) -> rusqlite::Result<usize> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM fingerprint_cache", [], |row| {
                    row.get(0)
                })?;
        Ok(count as usize)
    }

    /// Deletes fingerprint entries older than 30 days.
    pub fn prune_expired_fingerprints(&self) -> rusqlite::Result<usize> {
        let deleted = self.conn.execute(
            "DELETE FROM fingerprint_cache WHERE created_at < datetime('now', '-30 days')",
            [],
        )?;
        Ok(deleted)
    }

    /// Deletes the oldest fingerprint entries until the count is ≤ `target`.
    pub fn prune_max_fingerprints(&self, max: usize, target: usize) -> rusqlite::Result<usize> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM fingerprint_cache", [], |row| {
                    row.get(0)
                })?;
        if count as usize <= max {
            return Ok(0);
        }
        let deleted = self.conn.execute(
            "DELETE FROM fingerprint_cache WHERE rowid NOT IN (
                SELECT rowid FROM fingerprint_cache ORDER BY created_at DESC LIMIT ?1
            )",
            rusqlite::params![target as i64],
        )?;
        Ok(deleted)
    }
}

/// Returns the default cache path: `~/.cache/zerodupe/hash_cache.db`.
///
/// If the system cache directory is not available, falls back to
/// `./zerodupe_cache.db` in the current working directory.
/// Creates the parent directory if it doesn't exist.
pub fn default_cache_path() -> PathBuf {
    let path = dirs::cache_dir()
        .map(|d| d.join("zerodupe").join("hash_cache.db"))
        .unwrap_or_else(|| PathBuf::from("zerodupe_cache.db"));
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    path
}

// ── helpers ──

/// A cached entry is valid only if the mtime witness matches exactly at
/// nanosecond precision, and — when both sides have one — the ctime witness
/// matches too. A missing mtime on either side is a miss: a file we can't
/// version-check can't be safely cached.
fn version_matches(stored: &FileVersion, current: &FileVersion) -> bool {
    let mtime_ok = matches!(
        (stored.mtime_nanos, current.mtime_nanos),
        (Some(a), Some(b)) if a == b
    );
    let ctime_ok = match (stored.ctime_nanos, current.ctime_nanos) {
        (Some(a), Some(b)) => a == b,
        // Windows (or an exotic FS) has no ctime: nothing to compare.
        _ => true,
    };
    mtime_ok && ctime_ok
}

fn algorithm_to_str(algo: HashAlgorithm) -> &'static str {
    match algo {
        HashAlgorithm::Blake3 => "blake3",
    }
}

/// `-1` means "not applicable" for the region columns. NULL would be the
/// natural encoding, but the columns are part of the primary key and SQLite
/// treats NULLs as pairwise distinct there — `INSERT OR REPLACE` would never
/// replace, leaving duplicate rows that shadow fresh entries on lookup.
fn region_to_db(region: &HashRegion) -> (&'static str, i64, i64) {
    match region {
        HashRegion::Full => ("full", -1, -1),
        HashRegion::Prefix { bytes } => ("prefix", *bytes as i64, -1),
        HashRegion::Suffix { bytes } => ("suffix", *bytes as i64, -1),
        HashRegion::HeadTail {
            head_bytes,
            tail_bytes,
        } => ("headtail", *head_bytes as i64, *tail_bytes as i64),
        HashRegion::Sampled { .. } => ("sampled", -1, -1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MTIME: i64 = 1_700_000_000_123_456_789;
    const TEST_CTIME: i64 = 1_700_000_000_987_654_321;

    fn test_key() -> HashCacheKey {
        HashCacheKey {
            physical_key: Some(zerodupe_platform::PhysicalFileKey::from_unix(2050, 99999)),
            size_bytes: 1234,
            version: FileVersion {
                mtime_nanos: Some(TEST_MTIME),
                ctime_nanos: Some(TEST_CTIME),
            },
            hash_algorithm: HashAlgorithm::Blake3,
            region: HashRegion::HeadTail {
                head_bytes: 4096,
                tail_bytes: 4096,
            },
        }
    }

    #[test]
    fn opens_memory_connection() {
        let cache = HashCache::open_memory().expect("open memory");
        assert_eq!(cache.entry_count().unwrap(), 0);
    }

    #[test]
    fn put_and_get_returns_hash() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_key();
        cache.put(&key, "abc123").expect("put");
        let result = cache.get(&key).expect("get");
        assert_eq!(result, Some("abc123".to_string()));
    }

    #[test]
    fn get_miss_when_no_entry() {
        let cache = HashCache::open_memory().expect("open memory");
        let result = cache.get(&test_key()).expect("get");
        assert_eq!(result, None);
    }

    #[test]
    fn get_miss_when_mtime_changed() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_key();
        cache.put(&key, "abc123").expect("put");
        // Different mtime (even by one nanosecond) → cache miss
        let mut changed = key.clone();
        changed.version.mtime_nanos = Some(TEST_MTIME + 1);
        let result = cache.get(&changed).expect("get");
        assert_eq!(result, None);
    }

    #[test]
    fn get_miss_when_ctime_changed() {
        // A sync tool restored the mtime after modifying the file: the
        // kernel-maintained ctime still moves and must invalidate the entry.
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_key();
        cache.put(&key, "abc123").expect("put");
        let mut changed = key.clone();
        changed.version.ctime_nanos = Some(TEST_CTIME + 1);
        let result = cache.get(&changed).expect("get");
        assert_eq!(result, None);
    }

    #[test]
    fn get_hit_when_ctime_unavailable() {
        // Windows rule: with no ctime on either side, mtime alone decides.
        let cache = HashCache::open_memory().expect("open memory");
        let mut key = test_key();
        key.version.ctime_nanos = None;
        cache.put(&key, "abc123").expect("put");
        let result = cache.get(&key).expect("get");
        assert_eq!(result, Some("abc123".to_string()));
    }

    #[test]
    fn get_miss_when_mtime_unavailable() {
        // A file we can't version-check can't be safely cached.
        let cache = HashCache::open_memory().expect("open memory");
        let mut key = test_key();
        key.version.mtime_nanos = None;
        cache.put(&key, "abc123").expect("put");
        let result = cache.get(&key).expect("get");
        assert_eq!(result, None);
    }

    #[test]
    fn invalidate_removes_all_regions_for_file() {
        let cache = HashCache::open_memory().expect("open memory");
        let partial_key = test_key();
        let full_key = HashCacheKey {
            region: HashRegion::Full,
            ..test_key()
        };
        cache.put(&partial_key, "partial").expect("put");
        cache.put(&full_key, "full").expect("put");
        assert_eq!(cache.entry_count().unwrap(), 2);

        let removed = cache
            .invalidate(partial_key.physical_key.as_ref().unwrap())
            .expect("invalidate");
        assert_eq!(removed, 2);
        assert_eq!(cache.get(&partial_key).expect("get"), None);
        assert_eq!(cache.get(&full_key).expect("get"), None);
    }

    #[test]
    fn put_batch_stores_all_entries() {
        let cache = HashCache::open_memory().expect("open memory");
        let entries: Vec<(HashCacheKey, String)> = (0..5)
            .map(|i| {
                let mut key = test_key();
                key.size_bytes = 1000 + i;
                (key, format!("hash_{i}"))
            })
            .collect();
        cache.put_batch(&entries).expect("put_batch");
        assert_eq!(cache.entry_count().unwrap(), 5);
        for (key, hash) in &entries {
            assert_eq!(cache.get(key).expect("get").as_deref(), Some(hash.as_str()));
        }
    }

    #[test]
    fn get_miss_when_size_differs() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_key();
        cache.put(&key, "abc123").expect("put");
        let mut different_key = key.clone();
        different_key.size_bytes = 9999;
        let result = cache.get(&different_key).expect("get");
        assert_eq!(result, None);
    }

    #[test]
    fn put_replace_updates_entry() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_key();
        cache.put(&key, "old").expect("put");
        cache.put(&key, "new").expect("put");
        let result = cache.get(&key).expect("get");
        assert_eq!(result, Some("new".to_string()));
    }

    #[test]
    fn get_or_compute_uses_cache_on_hit() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_key();
        let real = zerodupe_hash::Blake3Hex::from_bytes(b"cached");
        cache.put(&key, &real.to_hex()).expect("put");

        let (hash, was_cached) = cache
            .get_or_compute(&key, || {
                panic!("should not be called on cache hit");
            })
            .expect("get_or_compute");

        assert!(was_cached);
        assert_eq!(hash, real);
    }

    #[test]
    fn get_or_compute_calls_compute_on_miss() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_key();

        let (hash, was_cached) = cache
            .get_or_compute(&key, || {
                Ok(zerodupe_hash::Blake3Hex::from_bytes(b"computed"))
            })
            .expect("get_or_compute");

        assert!(!was_cached);
        assert_eq!(hash, zerodupe_hash::Blake3Hex::from_bytes(b"computed"));

        // Second call should be cached
        let (hash2, was_cached2) = cache
            .get_or_compute(&key, || {
                panic!("should not recompute");
            })
            .expect("get_or_compute 2");

        assert!(was_cached2);
        assert_eq!(hash2, zerodupe_hash::Blake3Hex::from_bytes(b"computed"));
    }

    #[test]
    fn fallback_keys_not_cached() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = HashCacheKey {
            physical_key: Some(zerodupe_platform::PhysicalFileKey::from_fallback(
                camino::Utf8Path::new("/tmp/test.txt"),
            )),
            size_bytes: 100,
            version: FileVersion {
                mtime_nanos: Some(TEST_MTIME),
                ctime_nanos: Some(TEST_CTIME),
            },
            hash_algorithm: HashAlgorithm::Blake3,
            region: HashRegion::Full,
        };
        // Put should be a no-op for fallback keys
        cache.put(&key, "should_not_store").expect("put");
        let result = cache.get(&key).expect("get");
        assert_eq!(result, None);
    }

    #[test]
    fn different_regions_are_independent() {
        let cache = HashCache::open_memory().expect("open memory");
        let partial_key = HashCacheKey {
            region: HashRegion::HeadTail {
                head_bytes: 4096,
                tail_bytes: 4096,
            },
            ..test_key()
        };
        let full_key = HashCacheKey {
            region: HashRegion::Full,
            ..test_key()
        };

        cache.put(&partial_key, "partial_hash").expect("put");
        cache.put(&full_key, "full_hash").expect("put");

        assert_eq!(
            cache.get(&partial_key).expect("get"),
            Some("partial_hash".to_string())
        );
        assert_eq!(
            cache.get(&full_key).expect("get"),
            Some("full_hash".to_string())
        );
    }

    #[test]
    fn prune_by_age_deletes_old_entries() {
        let cache = HashCache::open_memory().expect("open memory");
        let key_old = test_key();

        let mut key_new = test_key();
        key_new.size_bytes = 9999;

        cache.put(&key_old, "old_hash").expect("put old");
        cache.put(&key_new, "new_hash").expect("put new");

        // Artificially age the first entry
        cache
            .conn
            .execute(
                "UPDATE hash_cache SET created_at = datetime('now', '-60 days') WHERE size_bytes = 1234",
                [],
            )
            .expect("update created_at");

        assert_eq!(cache.entry_count().unwrap(), 2);

        let deleted = cache.prune_expired().expect("prune_expired");
        assert_eq!(deleted, 1);
        assert_eq!(cache.entry_count().unwrap(), 1);

        // Verify only the new entry remains
        let result = cache.get(&key_new).expect("get new");
        assert_eq!(result, Some("new_hash".to_string()));
    }

    // ── Fingerprint cache tests ──

    fn test_fp_key() -> FingerprintCacheKey {
        FingerprintCacheKey {
            physical_key: Some(zerodupe_platform::PhysicalFileKey::from_unix(2050, 4242)),
            size_bytes: 5678,
            version: FileVersion {
                mtime_nanos: Some(TEST_MTIME),
                ctime_nanos: Some(TEST_CTIME),
            },
            detector: "image-phash".to_string(),
            params: "8x8;inv=off".to_string(),
            algo_version: 1,
        }
    }

    fn test_fp_value() -> CachedFingerprint {
        CachedFingerprint::Ok {
            data: vec![0xAB; 16],
            metadata_json: r#"{"min_side":512}"#.to_string(),
        }
    }

    #[test]
    fn fingerprint_put_and_get_roundtrip() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_fp_key();
        cache.put_fingerprint(&key, &test_fp_value()).expect("put");
        let result = cache.get_fingerprint(&key).expect("get");
        assert_eq!(result, Some(test_fp_value()));
    }

    #[test]
    fn fingerprint_miss_when_mtime_changed() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_fp_key();
        cache.put_fingerprint(&key, &test_fp_value()).expect("put");
        let mut changed = key.clone();
        changed.version.mtime_nanos = Some(TEST_MTIME + 1);
        assert_eq!(cache.get_fingerprint(&changed).expect("get"), None);
    }

    #[test]
    fn fingerprint_miss_when_ctime_changed() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_fp_key();
        cache.put_fingerprint(&key, &test_fp_value()).expect("put");
        let mut changed = key.clone();
        changed.version.ctime_nanos = Some(TEST_CTIME + 1);
        assert_eq!(cache.get_fingerprint(&changed).expect("get"), None);
    }

    #[test]
    fn fingerprint_miss_when_size_changed() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_fp_key();
        cache.put_fingerprint(&key, &test_fp_value()).expect("put");
        let mut changed = key.clone();
        changed.size_bytes = 9999;
        assert_eq!(cache.get_fingerprint(&changed).expect("get"), None);
    }

    #[test]
    fn fingerprint_miss_when_algo_version_bumped() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_fp_key();
        cache.put_fingerprint(&key, &test_fp_value()).expect("put");
        let mut changed = key.clone();
        changed.algo_version = 2;
        assert_eq!(cache.get_fingerprint(&changed).expect("get"), None);
    }

    #[test]
    fn fingerprint_params_are_part_of_key() {
        // Changing detector configuration (e.g. invariance mode) must not
        // serve fingerprints computed with the old configuration.
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_fp_key();
        cache.put_fingerprint(&key, &test_fp_value()).expect("put");
        let mut other_params = key.clone();
        other_params.params = "8x8;inv=mirrorflip".to_string();
        assert_eq!(cache.get_fingerprint(&other_params).expect("get"), None);
        // Both configurations can coexist as separate entries.
        let mirror_value = CachedFingerprint::Ok {
            data: vec![0xCD; 48],
            metadata_json: String::new(),
        };
        cache
            .put_fingerprint(&other_params, &mirror_value)
            .expect("put");
        assert_eq!(
            cache.get_fingerprint(&key).expect("get"),
            Some(test_fp_value())
        );
        assert_eq!(
            cache.get_fingerprint(&other_params).expect("get"),
            Some(mirror_value)
        );
    }

    #[test]
    fn fingerprint_error_entries_cached() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_fp_key();
        let err = CachedFingerprint::Error {
            message: "degenerate hash (pHash popcount=0, dHash popcount=0)".to_string(),
        };
        cache.put_fingerprint(&key, &err).expect("put");
        assert_eq!(cache.get_fingerprint(&key).expect("get"), Some(err));
    }

    #[test]
    fn fingerprint_fallback_keys_not_cached() {
        let cache = HashCache::open_memory().expect("open memory");
        let mut key = test_fp_key();
        key.physical_key = Some(zerodupe_platform::PhysicalFileKey::from_fallback(
            camino::Utf8Path::new("/tmp/img.png"),
        ));
        cache.put_fingerprint(&key, &test_fp_value()).expect("put");
        assert_eq!(cache.get_fingerprint(&key).expect("get"), None);
    }

    #[test]
    fn fingerprint_miss_when_mtime_unavailable() {
        let cache = HashCache::open_memory().expect("open memory");
        let mut key = test_fp_key();
        key.version.mtime_nanos = None;
        cache.put_fingerprint(&key, &test_fp_value()).expect("put");
        assert_eq!(cache.get_fingerprint(&key).expect("get"), None);
    }

    #[test]
    fn fingerprint_batch_stores_all() {
        let cache = HashCache::open_memory().expect("open memory");
        let entries: Vec<(FingerprintCacheKey, CachedFingerprint)> = (0..5)
            .map(|i| {
                let mut key = test_fp_key();
                key.physical_key = Some(zerodupe_platform::PhysicalFileKey::from_unix(
                    2050,
                    9000 + i,
                ));
                (key, test_fp_value())
            })
            .collect();
        cache.put_fingerprint_batch(&entries).expect("batch");
        assert_eq!(cache.fingerprint_entry_count().unwrap(), 5);
        for (key, value) in &entries {
            assert_eq!(
                cache.get_fingerprint(key).expect("get").as_ref(),
                Some(value)
            );
        }
    }

    #[test]
    fn fingerprint_replace_updates_entry() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_fp_key();
        cache.put_fingerprint(&key, &test_fp_value()).expect("put");
        let newer = CachedFingerprint::Ok {
            data: vec![0xEE; 16],
            metadata_json: String::new(),
        };
        cache.put_fingerprint(&key, &newer).expect("put");
        assert_eq!(cache.get_fingerprint(&key).expect("get"), Some(newer));
    }

    #[test]
    fn fingerprint_prune_by_age() {
        let cache = HashCache::open_memory().expect("open memory");
        let key = test_fp_key();
        cache.put_fingerprint(&key, &test_fp_value()).expect("put");
        cache
            .conn
            .execute(
                "UPDATE fingerprint_cache SET created_at = datetime('now', '-60 days')",
                [],
            )
            .expect("age entry");
        assert_eq!(cache.prune_expired_fingerprints().expect("prune"), 1);
        assert_eq!(cache.fingerprint_entry_count().unwrap(), 0);
    }

    #[test]
    fn prune_by_max_entries_deletes_oldest() {
        let cache = HashCache::open_memory().expect("open memory");

        // Insert 3 entries with distinct sizes so we can age them individually
        for (size, age_days) in [(100, -90), (200, -60), (300, 0)] {
            let mut key = test_key();
            key.size_bytes = size;
            cache.put(&key, &format!("hash_{size}")).expect("put");
            if age_days < 0 {
                cache
                    .conn
                    .execute(
                        &format!(
                            "UPDATE hash_cache SET created_at = datetime('now', '{} days') WHERE size_bytes = {}",
                            age_days, size
                        ),
                        [],
                    )
                    .expect("update created_at");
            }
        }

        assert_eq!(cache.entry_count().unwrap(), 3);

        // Prune with max=2, target=1: should keep only the most recent
        let deleted = cache.prune_max_entries(2, 1).expect("prune_max_entries");
        assert!(deleted >= 1, "expected at least 1 deleted, got {deleted}");
        assert_eq!(cache.entry_count().unwrap(), 1);

        // Only the most recent entry (size=300, not aged) should remain
        let mut key_newest = test_key();
        key_newest.size_bytes = 300;
        let result = cache.get(&key_newest).expect("get newest");
        assert_eq!(result, Some("hash_300".to_string()));
    }
}
