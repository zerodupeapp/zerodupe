//! Hashing primitives for ZeroDupe.
//!
//! Provides BLAKE3 hashing for in-memory slices and on-disk files.
//! All functions are cross-platform (Linux, macOS, Windows).

use std::{
    fs,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

use serde::{Deserialize, Serialize};
use zerodupe_core::{CancelFlag, HashRegion};

/// Default chunk size for partial hashing (4 KB).
pub const PARTIAL_CHUNK_SIZE: usize = 4096;

/// A BLAKE3 hash, stored as raw bytes.
///
/// Half the memory of the old hex `String` (32 bytes inline vs 64 on the
/// heap) and faster to compare and hash as a map key. Hex only exists at
/// the boundaries (cache rows, serialized reports) via [`Self::to_hex`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Blake3Hex([u8; 32]);

impl Blake3Hex {
    /// Hashes an in-memory byte slice.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    /// Parses a 64-character hex string (e.g. a cached hash row).
    /// Returns `None` for malformed input — callers treat that as a miss.
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        let bytes = hex.as_bytes();
        if bytes.len() != 64 {
            return None;
        }
        let nibble = |b: u8| -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            }
        };
        let mut out = [0u8; 32];
        for (i, chunk) in bytes.chunks_exact(2).enumerate() {
            out[i] = (nibble(chunk[0])? << 4) | nibble(chunk[1])?;
        }
        Some(Self(out))
    }

    /// Returns the lowercase hex representation.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write;
            let _ = write!(s, "{byte:02x}");
        }
        s
    }
}

/// Hashes the first `num_bytes` (or the whole file if smaller) using BLAKE3.
///
/// Cross-platform: uses `std::fs::File` and `std::io::Read`.
pub fn hash_file_prefix(path: &Path, num_bytes: usize) -> io::Result<Blake3Hex> {
    let mut file = fs::File::open(path)?;
    let file_len = file.metadata()?.len();

    let read_len = num_bytes.min(file_len as usize);
    let mut buf = vec![0u8; read_len];
    file.read_exact(&mut buf)?;

    Ok(Blake3Hex::from_bytes(&buf))
}

/// Hashes the last `num_bytes` (or the whole file if smaller) using BLAKE3.
///
/// Cross-platform: uses `SeekFrom::End` which works on all platforms.
pub fn hash_file_suffix(path: &Path, num_bytes: usize) -> io::Result<Blake3Hex> {
    let mut file = fs::File::open(path)?;
    let file_len = file.metadata()?.len();

    let read_len = num_bytes.min(file_len as usize);
    let mut buf = vec![0u8; read_len];

    if (read_len as u64) < file_len {
        file.seek(SeekFrom::End(-(read_len as i64)))?;
    }
    // If read_len == file_len, seek to start (default after open).
    file.read_exact(&mut buf)?;

    Ok(Blake3Hex::from_bytes(&buf))
}

/// Hashes a slice from the middle of the file.
///
/// Reads `num_bytes` starting at `offset` from the beginning of the file.
/// Clamps to file boundaries. Cross-platform.
pub fn hash_file_middle(path: &Path, offset: u64, num_bytes: usize) -> io::Result<Blake3Hex> {
    let mut file = fs::File::open(path)?;
    let file_len = file.metadata()?.len();

    let clamped_offset = offset.min(file_len);
    let max_readable = (file_len - clamped_offset) as usize;
    let read_len = num_bytes.min(max_readable);

    let mut buf = vec![0u8; read_len];
    file.seek(SeekFrom::Start(clamped_offset))?;
    file.read_exact(&mut buf)?;

    Ok(Blake3Hex::from_bytes(&buf))
}

/// Hashes the entire file using BLAKE3.
///
/// Cross-platform. Reads the file in chunks to avoid loading large files into memory.
pub fn hash_file_full(path: &Path) -> io::Result<Blake3Hex> {
    hash_file_full_cancellable(path, None)
}

/// Like [`hash_file_full`], but checks the cancellation flag between 64 KB
/// chunks so a multi-gigabyte file doesn't hold the pipeline hostage.
///
/// Returns `io::ErrorKind::Interrupted` when cancelled — the cost is one
/// branch per chunk, negligible next to the read itself.
pub fn hash_file_full_cancellable(
    path: &Path,
    cancel: Option<&CancelFlag>,
) -> io::Result<Blake3Hex> {
    let mut file = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 65536]; // 64 KB chunks

    loop {
        if let Some(c) = cancel
            && c.is_cancelled()
        {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "hash cancelled"));
        }
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(Blake3Hex(*hasher.finalize().as_bytes()))
}

/// Hashes the first `head_bytes` and the last `tail_bytes` of a file
/// in a single BLAKE3 hasher pass, producing one combined partial hash.
///
/// If the file is ≤ `head_bytes`, hashes the entire file as head only.
/// If `head_bytes + tail_bytes` ≥ file size, the regions are clamped so they
/// don't overlap (tail may read fewer bytes).
///
/// Cross-platform.
pub fn hash_file_head_tail(
    path: &Path,
    head_bytes: usize,
    tail_bytes: usize,
) -> io::Result<Blake3Hex> {
    let mut file = fs::File::open(path)?;
    let file_len = file.metadata()?.len() as usize;
    let mut hasher = blake3::Hasher::new();

    // Head
    let head_len = head_bytes.min(file_len);
    let mut buf = vec![0u8; head_len];
    file.read_exact(&mut buf)?;
    hasher.update(&buf);

    // Tail (only if file is larger than head_bytes and we have meaningful tail data)
    if file_len > head_bytes {
        let effective_tail = tail_bytes.min(file_len - head_bytes);
        if effective_tail > 0 {
            let seek_pos = -(effective_tail as i64);
            file.seek(SeekFrom::End(seek_pos))?;
            let mut tail_buf = vec![0u8; effective_tail];
            file.read_exact(&mut tail_buf)?;
            hasher.update(&tail_buf);
        }
    }

    Ok(Blake3Hex(*hasher.finalize().as_bytes()))
}

/// Hashes a file region described by a `HashRegion`.
///
/// Cross-platform dispatch to the appropriate hashing function.
pub fn hash_file_region(path: &Path, region: &HashRegion) -> io::Result<Blake3Hex> {
    hash_file_region_cancellable(path, region, None)
}

/// Like [`hash_file_region`], with cancellation support.
///
/// `Full` regions check the flag between chunks (they can be huge); the
/// partial regions read at most a few KB, so one check at entry suffices.
pub fn hash_file_region_cancellable(
    path: &Path,
    region: &HashRegion,
    cancel: Option<&CancelFlag>,
) -> io::Result<Blake3Hex> {
    if let Some(c) = cancel
        && c.is_cancelled()
    {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "hash cancelled"));
    }
    match region {
        HashRegion::Full => hash_file_full_cancellable(path, cancel),
        HashRegion::Prefix { bytes } => hash_file_prefix(path, *bytes),
        HashRegion::Suffix { bytes } => hash_file_suffix(path, *bytes),
        HashRegion::HeadTail {
            head_bytes,
            tail_bytes,
        } => hash_file_head_tail(path, *head_bytes, *tail_bytes),
        HashRegion::Sampled { samples } => {
            let mut file = fs::File::open(path)?;
            let mut hasher = blake3::Hasher::new();
            let mut buf = vec![0u8; samples.iter().map(|s| s.length).max().unwrap_or(0)];

            for sample in samples {
                file.seek(SeekFrom::Start(sample.offset))?;
                let read_len = sample.length.min(buf.len());
                file.read_exact(&mut buf[..read_len])?;
                hasher.update(&buf[..read_len]);
            }

            Ok(Blake3Hex(*hasher.finalize().as_bytes()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_bytes_have_same_hash() {
        assert_eq!(
            Blake3Hex::from_bytes(b"zero"),
            Blake3Hex::from_bytes(b"zero")
        );
    }

    /// Helper: creates a temp dir, writes data to a file, returns the path.
    fn write_temp_file(name: &str, data: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(name);
        fs::write(&path, data).expect("write");
        (dir, path)
    }

    #[test]
    fn hash_file_prefix_reads_first_bytes() {
        let (_dir, path) = write_temp_file("test.bin", b"abcdefghijklmnop");
        let hash = hash_file_prefix(&path, 4).expect("hash prefix");
        assert_eq!(hash, Blake3Hex::from_bytes(b"abcd"));
    }

    #[test]
    fn hash_file_prefix_smaller_than_chunk_reads_whole_file() {
        let (_dir, path) = write_temp_file("test.bin", b"hi");
        let hash = hash_file_prefix(&path, 4096).expect("hash prefix");
        assert_eq!(hash, Blake3Hex::from_bytes(b"hi"));
    }

    #[test]
    fn hash_file_suffix_reads_last_bytes() {
        let (_dir, path) = write_temp_file("test.bin", b"abcdefghijklmnop");
        let hash = hash_file_suffix(&path, 4).expect("hash suffix");
        assert_eq!(hash, Blake3Hex::from_bytes(b"mnop"));
    }

    #[test]
    fn hash_file_suffix_small_file_reads_whole() {
        let (_dir, path) = write_temp_file("test.bin", b"x");
        let hash = hash_file_suffix(&path, 4096).expect("hash suffix");
        assert_eq!(hash, Blake3Hex::from_bytes(b"x"));
    }

    #[test]
    fn hash_file_middle_reads_offset_chunk() {
        let (_dir, path) = write_temp_file("test.bin", b"0123456789ABCDEF");
        // Read 4 bytes starting at offset 6 → "6789"
        let hash = hash_file_middle(&path, 6, 4).expect("hash middle");
        assert_eq!(hash, Blake3Hex::from_bytes(b"6789"));
    }

    #[test]
    fn hash_file_middle_clamps_to_file_boundary() {
        let (_dir, path) = write_temp_file("test.bin", b"abc");
        // Offset 1, chunk 10 → only "bc" available
        let hash = hash_file_middle(&path, 1, 10).expect("hash middle");
        assert_eq!(hash, Blake3Hex::from_bytes(b"bc"));
    }

    #[test]
    fn hash_file_full_matches_prefix_for_small_file() {
        let (_dir, path) = write_temp_file("test.bin", b"small");
        let prefix = hash_file_prefix(&path, 4096).expect("prefix");
        let full = hash_file_full(&path).expect("full");
        assert_eq!(prefix, full);
    }

    #[test]
    fn hash_file_full_differs_from_prefix_for_large_file() {
        let data = vec![b'A'; 10000];
        let (_dir, path) = write_temp_file("test.bin", &data);
        let prefix = hash_file_prefix(&path, 4).expect("prefix");
        let full = hash_file_full(&path).expect("full");
        assert_ne!(prefix, full);
    }

    #[test]
    fn prefix_suffix_middle_cover_different_regions() {
        // 20 bytes: AAAA BBBBBBBB CCCC DDDD
        let data: Vec<u8> = (0..4)
            .map(|_| b'A')
            .chain((0..8).map(|_| b'B'))
            .chain((0..4).map(|_| b'C'))
            .chain((0..4).map(|_| b'D'))
            .collect();
        let (_dir, path) = write_temp_file("test.bin", &data);

        let prefix = hash_file_prefix(&path, 4).expect("prefix");
        let suffix = hash_file_suffix(&path, 4).expect("suffix");
        // middle at offset 8, 4 bytes → bytes 8-11 = "BBBB"
        let middle = hash_file_middle(&path, 8, 4).expect("middle");

        assert_eq!(prefix, Blake3Hex::from_bytes(b"AAAA"));
        assert_eq!(middle, Blake3Hex::from_bytes(b"BBBB"));
        assert_eq!(suffix, Blake3Hex::from_bytes(b"DDDD"));
        assert_ne!(prefix, middle);
        assert_ne!(prefix, suffix);
        assert_ne!(middle, suffix);
    }
}
