//! Perceptual image similarity plugin — uses image_hasher crate.
//!
//! - pHash (DCT) + dHash (Gradient) via image_hasher (rustdct backend)
//! - EXIF Orientation applied before hashing
//! - Weighted combined matching score (pHash + dHash*0.7 ≤ threshold)
//! - Separate matching vs keeper scoring
//! - EXIF-based keeper: camera, MakerNote, GPS, dates, software, RAW
//! - Cache-ready fingerprint function

use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use camino::Utf8Path;
use image::GenericImageView;
use image_hasher::{HashAlg, HasherConfig};
use serde::{Deserialize, Serialize};
use zerodupe_platform::PlatformProfile;
use zerodupe_policy::KeeperWeights;
use zerodupe_similar::{FingerprintData, SimilarityDetector};

/// Version of the image fingerprint algorithm: hash layout (16-byte blocks
/// of 8B pHash + 8B dHash; block 0 canonical, blocks 1.. geometric
/// variants), popcount degenerate filter, EXIF orientation handling.
///
/// ⚠️ DISCIPLINE: bump this when any of those change — cached fingerprints
/// from other versions are ignored (never served, never trusted). This is
/// deliberately independent from `zerodupe_cache::CACHE_SCHEMA_VERSION`,
/// which versions the *exact-hash* pipeline (BLAKE3/regions); bumping one
/// must not invalidate the other's entries. See D-007 in DECISIONS.md.
///
/// Note: Ola 2a (multi-block variants) did NOT bump this — the invariance
/// mode is part of `cache_params()`, so entries from different modes never
/// collide, and `inv=off` entries keep the exact Ola-1 layout.
pub const FP_ALGO_VERSION: u32 = 1;

/// Geometric invariance mode for fingerprinting (D-008).
///
/// EXIF orientation is always applied before hashing, so metadata-rotated
/// photos are already canonical. These modes cover *physically* transformed
/// pixels (editor exports, social media mirroring, scans):
/// - `Off`: canonical hash only (Ola-1 behaviour).
/// - `MirrorFlip` (default): + horizontal and vertical mirror. Cheap (the
///   decode dominates and is shared) and covers the common cases.
/// - `Full`: + the four 90° rotation alignments (the dihedral group D4,
///   8 alignments total) + the edit variants (D-011): center-80% crop and
///   ±3° rotation on an expanded white canvas, covering edited copies no
///   D4 alignment can reach. This is what the GUI uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GeometricInvariance {
    Off,
    #[default]
    MirrorFlip,
    Full,
}

impl GeometricInvariance {
    /// Stable identifier used in the fingerprint-cache `params` key.
    /// "full2" = D4 + edit variants; cached "full" fingerprints (D4 only)
    /// lack the edit blocks, so the tag bump recomputes them once.
    #[must_use]
    pub fn cache_tag(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::MirrorFlip => "mirror",
            Self::Full => "full2",
        }
    }
}

/// RAW camera formats (D-009). Single source of truth: the detector's
/// `extensions()` (behind the `raw` feature), the RAW+JPEG sibling
/// gatekeeper and the keeper-score RAW bonus all build on this list.
/// Detection works through the embedded JPEG preview, not a demosaic.
pub const RAW_EXTENSIONS: &[&str] = &[
    "cr2", "cr3", "nef", "arw", "dng", "orf", "rw2", "raf", "pef", "srw", "x3f", "erf", "mrw",
    "dcr", "kdc", "fff", "mef", "mos", "nrw", "ptx", "r3d",
];

static SUPPORTED_EXTENSIONS: std::sync::LazyLock<Vec<&'static str>> =
    std::sync::LazyLock::new(|| {
        let mut v = vec![
            "jpg", "jpeg", "png", "gif", "bmp", "webp", "tiff", "tif", "ico",
        ];
        #[cfg(feature = "heif")]
        v.extend(["heic", "heif"]);
        #[cfg(feature = "raw")]
        v.extend_from_slice(RAW_EXTENSIONS);
        v
    });

/// Every extension the image detector accepts with the active feature set.
/// Pre-filters in the CLI/workflow must use this instead of local lists so
/// they never diverge from what `fingerprint()` can actually handle.
pub fn supported_extensions() -> &'static [&'static str] {
    &SUPPORTED_EXTENSIONS
}

pub struct ImagePHashDetector {
    weights: KeeperWeights,
    invariance: GeometricInvariance,
}

impl ImagePHashDetector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            weights: KeeperWeights::default(),
            invariance: GeometricInvariance::default(),
        }
    }

    #[must_use]
    pub fn with_weights(weights: KeeperWeights) -> Self {
        Self {
            weights,
            invariance: GeometricInvariance::default(),
        }
    }

    #[must_use]
    pub fn with_invariance(mut self, invariance: GeometricInvariance) -> Self {
        self.invariance = invariance;
        self
    }
}

impl Default for ImagePHashDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SimilarityDetector for ImagePHashDetector {
    fn name(&self) -> &'static str {
        "image-phash"
    }

    fn algo_version(&self) -> u32 {
        FP_ALGO_VERSION
    }

    fn cache_params(&self) -> String {
        // Hash size + geometric invariance mode. Changing the mode changes
        // the key, so cached fingerprints from another mode never collide.
        format!("8x8;inv={}", self.invariance.cache_tag())
    }
    fn extensions(&self) -> &[&'static str] {
        supported_extensions()
    }

    fn fingerprint(&self, path: &Path) -> io::Result<FingerprintData> {
        fingerprint_image(path, self.invariance)
    }

    fn distance(&self, a: &FingerprintData, b: &FingerprintData) -> u32 {
        // Canonical (block 0 vs block 0) — the BK-tree metric.
        if a.data.len() < 16 || b.data.len() < 16 {
            return 64;
        }
        (combined_block_distance(&a.data[..16], &b.data[..16]).ceil() as u32).min(64)
    }

    fn variant_count(&self, fp: &FingerprintData) -> usize {
        (fp.data.len() / 16).max(1)
    }

    fn variant_distance(&self, a: &FingerprintData, k: usize, b: &FingerprintData) -> u32 {
        let start = k * 16;
        if a.data.len() < start + 16 || b.data.len() < 16 {
            return 64;
        }
        (combined_block_distance(&a.data[start..start + 16], &b.data[..16]).ceil() as u32).min(64)
    }

    fn similarity(&self, a: &FingerprintData, b: &FingerprintData) -> f64 {
        // Best alignment over geometric variants: a mirrored pair scores as
        // high as an identical pair, so the 0.80 intra-component split and
        // the confidence labels treat it as the near-duplicate it is.
        match min_alignment_distance(a, b) {
            Some(d) => 1.0 - (d.min(64.0) / 64.0),
            None => 0.0,
        }
    }

    fn is_near_duplicate(&self, a: &FingerprintData, b: &FingerprintData) -> bool {
        let dist = match min_alignment_distance(a, b) {
            Some(d) => d,
            None => return false,
        };

        // Adaptive threshold based on original image dimensions.
        let min_a = a
            .metadata
            .get("min_side")
            .and_then(|v| v.as_u64())
            .unwrap_or(9999) as u32;
        let min_b = b
            .metadata
            .get("min_side")
            .and_then(|v| v.as_u64())
            .unwrap_or(9999) as u32;
        let min_side = min_a.min(min_b);

        let limit: f64 = if min_side <= 128 {
            4.0 // stickers, emojis: very strict
        } else if min_side <= 256 {
            6.0 // thumbnails
        } else if min_side <= 512 {
            8.0 // medium images
        } else {
            10.0 // large photos: standard pHash near-duplicate range
        };

        dist <= limit
    }

    fn confidence_label(&self, s: f64) -> &'static str {
        if s >= 0.96 {
            "Casi seguro duplicado (re-encode/resize)"
        } else if s >= 0.88 {
            "Muy probable duplicado"
        } else if s >= 0.80 {
            "Probable duplicado (edición ligera)"
        } else if s >= 0.72 {
            "Posible duplicado — revisar"
        } else {
            "Baja confianza"
        }
    }

    fn keeper_score(&self, path: &Path) -> io::Result<f64> {
        image_keeper_score(path, &self.weights)
    }

    fn are_siblings_not_duplicates(&self, a: &Path, b: &Path) -> bool {
        is_raw_jpeg_sibling_pair(a, b) || is_live_photo_pair(a, b)
    }
}

/// Compute Hamming distance between two byte slices.
/// Processes 8-byte words at a time: this is the innermost loop of the
/// BK-tree search, evaluated O(n²)-ish times on large concentrated corpora.
fn hamming_bytes(a: &[u8], b: &[u8]) -> u32 {
    let mut ca = a.chunks_exact(8);
    let mut cb = b.chunks_exact(8);
    let mut total = 0u32;
    for (x, y) in (&mut ca).zip(&mut cb) {
        let xv = u64::from_ne_bytes(x.try_into().unwrap());
        let yv = u64::from_ne_bytes(y.try_into().unwrap());
        total += (xv ^ yv).count_ones();
    }
    total
        + ca.remainder()
            .iter()
            .zip(cb.remainder())
            .map(|(x, y)| (x ^ y).count_ones())
            .sum::<u32>()
}

/// Weighted combined distance between two 16-byte blocks
/// (8B pHash + 8B dHash): pHash + 0.7·dHash. The double-hash verification
/// applies to every alignment, not just the canonical one.
fn combined_block_distance(a: &[u8], b: &[u8]) -> f64 {
    let ph = hamming_bytes(&a[..8], &b[..8]);
    let dh = hamming_bytes(&a[8..16], &b[8..16]);
    ph as f64 + dh as f64 * 0.7
}

/// Minimum combined distance over all geometric alignments:
/// every variant block of `a` against the canonical block of `b`, and the
/// canonical block of `a` against every variant block of `b`. Flips and
/// rotations are involutions, so this covers both directions of each
/// transform without comparing variant-vs-variant.
fn min_alignment_distance(a: &FingerprintData, b: &FingerprintData) -> Option<f64> {
    if a.data.len() < 16 || b.data.len() < 16 {
        return None;
    }
    let b0 = &b.data[..16];
    let mut best = f64::INFINITY;
    for a_block in a.data.chunks_exact(16) {
        best = best.min(combined_block_distance(a_block, b0));
    }
    let a0 = &a.data[..16];
    for b_block in b.data.chunks_exact(16).skip(1) {
        best = best.min(combined_block_distance(a0, b_block));
    }
    Some(best)
}

// ═══════════════════════════════════════════════════════════════════════════
// Gatekeepers — Capa 0 (precision, not speed)
// ═══════════════════════════════════════════════════════════════════════════
// These run per-file or per-group to prevent false positives and improve
// keeper selection. Cost: O(1) per file — negligible vs fingerprint decode.

fn is_jpeg_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| matches!(e.to_lowercase().as_str(), "jpg" | "jpeg"))
        .unwrap_or(false)
}

/// JPEG EOF marker check. Verifies the last 2 bytes are 0xFF 0xD9.
/// A truncated JPEG should never be selected as keeper.
pub fn jpeg_is_truncated(path: &Path) -> io::Result<bool> {
    if !is_jpeg_ext(path) {
        return Ok(false);
    }
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len < 2 {
        return Ok(true); // too small to be valid
    }
    file.seek(SeekFrom::End(-2))?;
    let mut buf = [0u8; 2];
    file.read_exact(&mut buf)?;
    Ok(buf[0] != 0xFF || buf[1] != 0xD9)
}

/// Check if file modification time is older than EXIF DateTimeOriginal.
/// If mtime < original date: impossible for this to be the original copy.
pub fn mtime_older_than_exif(path: &Path) -> io::Result<bool> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };
    let mtime = match meta.modified() {
        Ok(t) => t,
        Err(_) => return Ok(false),
    };
    let mtime_secs = mtime
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Read EXIF DateTimeOriginal
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };
    let mut r = io::BufReader::new(file);
    let exif = match exif::Reader::new().read_from_container(&mut r) {
        Ok(e) => e,
        Err(_) => return Ok(false),
    };
    let dto = exif.get_field(exif::Tag::DateTimeOriginal, exif::In::PRIMARY);
    let dto_str = match dto.and_then(|f| f.value.get_uint(0)) {
        Some(_) => dto.map(|f| f.display_value().to_string()),
        None => {
            // DateTimeOriginal might be stored as ASCII string "2024:03:15 10:30:00"
            dto.and_then(|f| {
                if let exif::Value::Ascii(ref v) = f.value {
                    v.first()
                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                        .map(|s| s.trim_end_matches('\0').to_string())
                } else {
                    None
                }
            })
        }
    };
    let dto_str = match dto_str {
        Some(s) => s,
        None => return Ok(false),
    };

    // Parse "YYYY:MM:DD HH:MM:SS" to unix timestamp
    let dto_secs = parse_exif_datetime_to_unix(&dto_str);
    match dto_secs {
        Some(ds) => Ok(mtime_secs < ds),
        None => Ok(false),
    }
}

/// Parse EXIF datetime string "YYYY:MM:DD HH:MM:SS" to unix timestamp.
fn parse_exif_datetime_to_unix(s: &str) -> Option<i64> {
    // Format: "2024:03:15 10:30:00" — split by space and colon
    let parts: Vec<&str> = s.split(&[' ', ':'][..]).collect();
    if parts.len() < 6 {
        return None;
    }
    let year: i64 = parts[0].parse().ok()?;
    let month: u32 = parts[1].parse().ok()?;
    let day: u32 = parts[2].parse().ok()?;
    let hour: u32 = parts[3].parse().ok()?;
    let min: u32 = parts[4].parse().ok()?;
    let sec: u32 = parts[5].parse().ok()?;

    // Simple date→unix conversion (valid for 2000-2100 range)
    let days_before_month: [u32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut total_days = (year - 1970) * 365;
    // leap years from 1970 to year-1
    total_days += ((year - 1) / 4 - 1969 / 4) - ((year - 1) / 100 - 1969 / 100)
        + ((year - 1) / 400 - 1969 / 400);
    total_days += days_before_month[(month - 1) as usize] as i64;
    // leap day in current year if past Feb
    if month > 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) {
        total_days += 1;
    }
    total_days += (day - 1) as i64;
    Some(total_days * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64)
}

// ═══════════════════════════════════════════════════════════════════════════
// Double-compression detection — Benford's Law on DCT via Q-table analysis
// ═══════════════════════════════════════════════════════════════════════════
// Camera-original JPEGs use fine, manufacturer-specific quantization tables.
// Social-media re-compressed JPEGs use coarse, generic tables. By reading the
// DQT markers we can fingerprint the compression origin without decoding pixels.
//
// Audit recommendation: penalty −25 for double-compressed images.

/// Known "coarse" Q-table signatures (generic/social-media re-compression).
/// These luminance Q-table patterns indicate software re-encoding.
const COARSE_Q_SIGNATURES: &[&[u8]] = &[
    // Standard IJG "75% quality" — very common in social media / WhatsApp
    &[
        8, 9, 9, 11, 13, 15, 17, 18, 9, 10, 11, 12, 14, 16, 18, 20, 9, 11, 12, 14, 15, 17, 20, 22,
        11, 12, 14, 16, 18, 20, 23, 25, 13, 14, 15, 18, 21, 24, 27, 30, 15, 16, 17, 20, 24, 28, 32,
        36, 17, 18, 20, 23, 27, 32, 37, 42, 18, 20, 22, 25, 30, 36, 42, 48,
    ],
];

/// Known "fine" Q-table signatures (camera-original, manufacturer-specific).
/// These luminance tables indicate direct-from-camera JPEGs.
const FINE_Q_SIGNATURES: &[&[u8]] = &[
    // Canon "Fine" — typical for PowerShot / EOS JPEG
    &[
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 2, 3, 1, 1, 1, 1, 1, 2,
        3, 4, 1, 1, 1, 1, 2, 3, 4, 5, 1, 1, 1, 2, 3, 4, 5, 6, 1, 1, 2, 3, 4, 5, 6, 7, 1, 2, 3, 4,
        5, 6, 7, 8,
    ],
    // Nikon "Fine" — D-series and Z-series JPEG
    &[
        1, 1, 1, 2, 2, 3, 4, 5, 1, 1, 1, 2, 2, 3, 4, 5, 1, 1, 1, 2, 3, 4, 5, 6, 2, 2, 2, 3, 4, 5,
        6, 7, 2, 2, 3, 4, 5, 6, 7, 8, 3, 3, 4, 5, 6, 7, 8, 9, 4, 4, 5, 6, 7, 8, 9, 10, 5, 5, 6, 7,
        8, 9, 10, 11,
    ],
    // Sony "Fine" — Alpha series
    &[
        1, 1, 1, 1, 1, 1, 2, 2, 1, 1, 1, 1, 1, 2, 2, 3, 1, 1, 1, 1, 1, 2, 3, 3, 1, 1, 1, 1, 2, 3,
        3, 4, 1, 1, 1, 2, 3, 4, 4, 5, 1, 2, 2, 3, 4, 4, 5, 6, 2, 2, 3, 3, 4, 5, 6, 7, 2, 3, 3, 4,
        5, 6, 7, 8,
    ],
    // Apple / iOS camera "Fine"
    &[
        2, 2, 2, 2, 3, 4, 5, 6, 2, 2, 2, 2, 3, 4, 5, 6, 2, 2, 2, 3, 4, 5, 6, 7, 2, 2, 3, 4, 5, 6,
        7, 8, 3, 3, 4, 5, 6, 7, 8, 9, 4, 4, 5, 6, 7, 8, 9, 10, 5, 5, 6, 7, 8, 9, 10, 11, 6, 6, 7,
        8, 9, 10, 11, 12,
    ],
];

/// Read JPEG quantization tables from DQT markers.
/// Returns the luminance table (table_id=0) as a 64-byte vector in zigzag order.
fn read_jpeg_luma_qtable(path: &Path) -> io::Result<Option<Vec<u8>>> {
    if !is_jpeg_ext(path) {
        return Ok(None);
    }
    let data = std::fs::read(path)?;
    if data.len() < 4 {
        return Ok(None);
    }
    // JPEG starts with 0xFF 0xD8
    if data[0] != 0xFF || data[1] != 0xD8 {
        return Ok(None);
    }
    let mut pos = 2usize;
    while pos + 3 < data.len() {
        if data[pos] != 0xFF {
            break;
        }
        let marker = data[pos + 1];
        // SOS (0xDA) — end of header, stop scanning
        if marker == 0xDA {
            break;
        }
        // Standalone markers (no length)
        if matches!(marker, 0x00 | 0xD0..=0xD7) {
            pos += 2;
            continue;
        }
        let length = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        if pos + 2 + length > data.len() {
            break;
        }
        if marker == 0xDB {
            // DQT marker — parse quantization table
            let dqt_data = &data[pos + 4..pos + 2 + length];
            let mut dqt_pos = 0usize;
            while dqt_pos < dqt_data.len() {
                if dqt_pos + 65 > dqt_data.len() {
                    break;
                }
                let info = dqt_data[dqt_pos];
                let precision = (info >> 4) & 0x0F; // 0 = 8-bit, 1 = 16-bit
                let table_id = info & 0x0F;
                let elem_size = if precision == 0 { 1 } else { 2 };
                let table_start = dqt_pos + 1;
                let table_len = 64 * elem_size;
                if table_start + table_len > dqt_data.len() {
                    break;
                }
                if table_id == 0 && precision == 0 {
                    let mut table = vec![0u8; 64];
                    for i in 0..64 {
                        table[ZIGZAG[i]] = dqt_data[table_start + i];
                    }
                    return Ok(Some(table));
                }
                dqt_pos += 1 + table_len;
            }
        }
        pos += 2 + length;
    }
    Ok(None)
}

/// Zigzag order index mapping (standard JPEG).
const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// Calculate mean L1 distance between two 64-element Q-tables.
fn qtable_distance(a: &[u8], b: &[u8]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x.abs_diff(*y)) as f64)
        .sum::<f64>()
        / 64.0
}

/// Detect double JPEG compression by comparing the quantization table
/// against known camera-original vs re-compressed signatures.
///
/// Returns true if the file appears to have been re-compressed
/// (social media, messaging app, editor export).
pub fn is_double_compressed(path: &Path) -> io::Result<bool> {
    let qtable = match read_jpeg_luma_qtable(path)? {
        Some(q) => q,
        None => return Ok(false), // can't determine → assume original
    };

    // Check against coarse (re-compressed) signatures
    for sig in COARSE_Q_SIGNATURES {
        if qtable_distance(&qtable, sig) < 3.0 {
            return Ok(true);
        }
    }

    // Check against fine (camera-original) signatures
    for sig in FINE_Q_SIGNATURES {
        if qtable_distance(&qtable, sig) < 5.0 {
            return Ok(false); // matches camera → original
        }
    }

    // Unknown Q-table: use heuristics
    // Cameras use small Q values (≤16), re-compressors use larger ones
    let avg_q = qtable.iter().map(|&v| v as f64).sum::<f64>() / 64.0;
    let high_count = qtable.iter().filter(|&&v| v > 20).count();
    Ok(avg_q > 12.0 && high_count > 10)
}

// ═══════════════════════════════════════════════════════════════════════════
// XMP History detection — xmpMM:History persists even when MakerNote is
// preserved. Strongest signal of editing (Lightroom, Photoshop, etc.)
// ═══════════════════════════════════════════════════════════════════════════

/// Parse JPEG APP1 XMP segment to detect xmpMM:History marker.
/// Returns true if the file has been processed by editing software.
pub fn has_xmp_history(path: &Path) -> io::Result<bool> {
    if !is_jpeg_ext(path) {
        return Ok(false);
    }
    let data = std::fs::read(path)?;
    if data.len() < 4 {
        return Ok(false);
    }
    if data[0] != 0xFF || data[1] != 0xD8 {
        return Ok(false);
    }
    let mut pos = 2usize;
    while pos + 3 < data.len() {
        if data[pos] != 0xFF {
            break;
        }
        let marker = data[pos + 1];
        if marker == 0xDA {
            break;
        }
        if matches!(marker, 0x00 | 0xD0..=0xD7) {
            pos += 2;
            continue;
        }
        let length = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        if pos + 2 + length > data.len() {
            break;
        }
        if marker == 0xE1 {
            // APP1 — check if it's XMP
            let segment = &data[pos + 4..pos + 2 + length];
            // XMP namespace identifier
            const XMP_NS: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
            if segment.starts_with(XMP_NS) || segment.windows(XMP_NS.len()).any(|w| w == XMP_NS) {
                // Look for xmpMM:History or stEvt:action (edited)
                let haystack = String::from_utf8_lossy(segment);
                if haystack.contains("xmpMM:History")
                    || haystack.contains("stEvt:action")
                    || haystack.contains("xmp:MetadataDate")
                {
                    return Ok(true);
                }
                // If XMP packet exists but no history tag → not edited
                return Ok(false);
            }
        }
        pos += 2 + length;
    }
    Ok(false)
}

/// Kebab-case to lower_snake_case: checks if a RAW file and a non-RAW file
/// share the same basename (e.g., "IMG_1234.CR2" and "IMG_1234.JPG").
/// These are siblings — different formats of the same original, NOT duplicates.
pub fn is_raw_jpeg_sibling_pair(a: &Path, b: &Path) -> bool {
    let stem_a = a.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let stem_b = b.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if stem_a != stem_b {
        return false;
    }
    let ext_a = a
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let ext_b = b
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let img_exts = ["jpg", "jpeg", "png", "heic", "heif", "tiff", "tif", "webp"];
    (RAW_EXTENSIONS.contains(&ext_a.as_str()) && img_exts.contains(&ext_b.as_str()))
        || (RAW_EXTENSIONS.contains(&ext_b.as_str()) && img_exts.contains(&ext_a.as_str()))
}

/// Detect Live Photo pair: .HEIC + .MOV with same basename.
pub fn is_live_photo_pair(a: &Path, b: &Path) -> bool {
    let stem_a = a.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let stem_b = b.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if stem_a != stem_b {
        return false;
    }
    let ext_a = a
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let ext_b = b
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    (ext_a == "heic" && ext_b == "mov") || (ext_a == "mov" && ext_b == "heic")
}

// ── Fingerprint ──

pub fn fingerprint_image(
    path: &Path,
    invariance: GeometricInvariance,
) -> io::Result<FingerprintData> {
    #[cfg(feature = "raw")]
    {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if RAW_EXTENSIONS.contains(&ext.as_str()) {
            return fingerprint_raw(path, invariance);
        }
    }

    // Read EXIF orientation (applied before hashing)
    let orientation = read_orientation(path);

    // Get original dimensions from header only (~1ms, no full decode)
    let orig_dims: Option<(u32, u32)> = image::image_dimensions(path).ok();

    // Full decode — all formats use the same pipeline via image crate.
    // image_hasher handles resize internally with fast_image_resize.
    let img = image::open(path)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("open: {e}")))?;
    let img = apply_orientation(img, orientation);
    fingerprint_decoded(img, orig_dims, path, invariance)
}

/// RAW pipeline (D-009): fingerprint the embedded JPEG preview instead of
/// demosaicing the sensor data. The preview is what the camera itself
/// rendered, so it hashes like the JPEG the user exports from it — and
/// extraction is orders of magnitude cheaper than a full develop.
#[cfg(feature = "raw")]
fn fingerprint_raw(path: &Path, invariance: GeometricInvariance) -> io::Result<FingerprintData> {
    use rawler::decoders::RawDecodeParams;
    use rawler::rawsource::RawSource;

    let to_io = |e: rawler::RawlerError| io::Error::new(io::ErrorKind::InvalidData, e.to_string());

    let source = RawSource::new(path)?;
    let decoder = rawler::get_decoder(&source).map_err(to_io)?;
    let params = RawDecodeParams::default();

    // Largest embedded render first: `full_image` is the full-resolution
    // preview, `preview_image` the medium one. Thumbnails are skipped —
    // below ~256px the adaptive thresholds tighten and hashes lose
    // stability, so a tiny preview is treated as "no preview".
    let preview = decoder
        .full_image(&source, &params)
        .ok()
        .flatten()
        .or_else(|| decoder.preview_image(&source, &params).ok().flatten())
        .filter(|p| {
            let (w, h) = p.dimensions();
            w.min(h) >= 256
        });

    let img = match preview {
        Some(p) => p,
        // Fallback (D-009): full develop only when no usable preview
        // exists. Slow path, but keeps coverage at 100% of decodable RAWs.
        None => {
            let raw = decoder.raw_image(&source, &params, false).map_err(to_io)?;
            let dev = rawler::imgop::develop::RawDevelop::default();
            dev.develop_intermediate(&raw)
                .map_err(to_io)?
                .to_dynamic_image()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "raw develop: unsupported buffer",
                    )
                })?
        }
    };

    // The full-size preview matches the sensor dimensions in practice; if
    // we fell back to a develop these *are* the sensor dimensions. Either
    // way the adaptive threshold sees the real photo scale.
    let orig_dims = Some(img.dimensions());

    // The render only feeds 8×8 perceptual hashes, but cameras embed
    // 10–20MP previews: hashing variants at that size wastes hundreds of
    // ms per file in flips and DCT preprocessing. Downscale once up front
    // (the hasher resizes internally anyway) before rotating.
    let img = if img.width().max(img.height()) > 1024 {
        img.thumbnail(1024, 1024)
    } else {
        img
    };

    // Orientation comes from the RAW container's metadata (rawler reads it
    // for every format, including non-TIFF ones like CR3). Embedded
    // previews are stored sensor-oriented, same as a sibling JPEG, so the
    // pipeline stays symmetric: read the tag, then rotate.
    let orientation = decoder
        .raw_metadata(&source, &params)
        .ok()
        .and_then(|m| m.exif.orientation)
        .unwrap_or(1) as u32;
    let img = apply_orientation(img, orientation);

    fingerprint_decoded(img, orig_dims, path, invariance)
}

/// Shared hashing core: perceptual hashes + geometric variants + metadata
/// over an already decoded and EXIF-oriented image. `orig_dims` carries the
/// on-disk dimensions when the decoded image is not the original (None means
/// the decoded dimensions are the original ones).
fn fingerprint_decoded(
    img: image::DynamicImage,
    orig_dims: Option<(u32, u32)>,
    path: &Path,
    invariance: GeometricInvariance,
) -> io::Result<FingerprintData> {
    let (w, h) = img.dimensions();

    // Generate perceptual hashes using image_hasher (rustdct backend).
    // pHash = Median algorithm + DCT preprocessing (standard Krawetz pHash).
    // Median is robust against DC coefficient dominance; Mean gives popcount=1.
    let hasher_phash = HasherConfig::new()
        .hash_size(8, 8)
        .hash_alg(HashAlg::Median)
        .preproc_dct()
        .to_hasher();
    // dHash = Gradient algorithm (row-wise pixel comparisons).
    let hasher_dhash = HasherConfig::new()
        .hash_size(8, 8)
        .hash_alg(HashAlg::Gradient)
        .to_hasher();

    let hash_pair = |image: &image::DynamicImage| -> [u8; 16] {
        let ph = hasher_phash.hash_image(image);
        let dh = hasher_dhash.hash_image(image);
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(ph.as_bytes());
        block[8..].copy_from_slice(dh.as_bytes());
        block
    };

    let canonical = hash_pair(&img);

    let ph_bits = canonical[..8].iter().map(|b| b.count_ones()).sum::<u32>();
    let dh_bits = canonical[8..].iter().map(|b| b.count_ones()).sum::<u32>();

    // Filter degenerate hashes: images with very low or very high popcount
    // produce unreliable fingerprints (uniform areas, extreme brightness).
    // We reject if EITHER hash is degenerate (OR, not AND) to prevent
    // cases where pHash is noise but dHash is normal from slipping through.
    // Range 10..=54 is conservative but catches genuine degenerates.
    // Checked on the canonical block only: flips/rotations preserve the
    // pixel distribution, so variants of a valid image are valid.
    let is_ph_degen = !(10..=54).contains(&ph_bits);
    let is_dh_degen = !(10..=54).contains(&dh_bits);
    if is_ph_degen || is_dh_degen {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "degenerate hash (pHash popcount={}, dHash popcount={})",
                ph_bits, dh_bits
            ),
        ));
    }

    // ── Geometric variant blocks (D-008) ──
    // Each variant carries the full pHash+dHash pair so the double-hash
    // verification applies to mirrored/rotated matches too. Variant dedup:
    // an auto-symmetric image produces a variant hash ~equal to the
    // canonical one — it adds no information and only costs queries, so
    // blocks within distance ≤ 1 of any kept block are dropped. Variants
    // are generated one at a time to avoid holding several full-size
    // copies of a large photo in memory.
    //
    // `gate_degenerate`: D4 alignments preserve the pixel distribution, so
    // a valid image always yields valid D4 blocks — but the edit variants
    // (crop, slight rotation) change it: a center crop can be uniform sky
    // even when the full photo is not. Degenerate edit blocks are silently
    // skipped instead of failing the whole fingerprint.
    let mut data = Vec::with_capacity(16 * 11);
    data.extend_from_slice(&canonical);
    let mut push_variant = |variant: &image::DynamicImage, gate_degenerate: bool| {
        let block = hash_pair(variant);
        if gate_degenerate {
            let ph = block[..8].iter().map(|b| b.count_ones()).sum::<u32>();
            let dh = block[8..].iter().map(|b| b.count_ones()).sum::<u32>();
            if !(10..=54).contains(&ph) || !(10..=54).contains(&dh) {
                return;
            }
        }
        let duplicate = data
            .chunks_exact(16)
            .any(|kept| combined_block_distance(kept, &block) <= 1.0);
        if !duplicate {
            data.extend_from_slice(&block);
        }
    };
    match invariance {
        GeometricInvariance::Off => {}
        GeometricInvariance::MirrorFlip => {
            push_variant(&img.fliph(), false);
            push_variant(&img.flipv(), false);
        }
        GeometricInvariance::Full => {
            // The 8 alignments of the dihedral group D4 (canonical + 7).
            push_variant(&img.fliph(), false);
            push_variant(&img.flipv(), false);
            push_variant(&img.rotate90(), false);
            push_variant(&img.rotate180(), false);
            push_variant(&img.rotate270(), false);
            let flipped = img.fliph();
            push_variant(&flipped.rotate90(), false);
            push_variant(&flipped.rotate270(), false);
            drop(flipped);

            // ── Edit variants (D-011) ──
            // Validated on the ground-truth corpus 2026-06-12: center-80%
            // crops land at combined distance 0.0–2.7 and ±3° white-canvas
            // rotations at 0.0–2.0 from their originals, while no D4
            // alignment gets them below ~16. Computed on a ≤1024 thumbnail:
            // the hash downscales to 32×32 anyway, and bilinear rotation of
            // a 12MP frame would cost hundreds of ms for identical quality.
            let thumb = if w.max(h) > 1024 {
                img.thumbnail(1024, 1024)
            } else {
                img.clone()
            };
            let (tw, th) = thumb.dimensions();
            push_variant(
                &thumb.crop_imm(tw / 10, th / 10, tw * 8 / 10, th * 8 / 10),
                true,
            );
            push_variant(&rotate_expand_white(&thumb, 3.0), true);
            push_variant(&rotate_expand_white(&thumb, -3.0), true);
        }
    }

    let exif_info = read_exif_info(path);

    // Original dimensions for adaptive threshold.
    let (ow, oh) = orig_dims.unwrap_or((w, h));
    let min_side = ow.min(oh);

    let metadata = serde_json::json!({
        "width": w, "height": h,
        "orig_width": ow, "orig_height": oh,
        "min_side": min_side,
        "aspect_ratio": w as f64 / h as f64,
        "megapixels": (w as f64 * h as f64) / 1_000_000.0,
        "exif": exif_info,
        "fingerprint_algo_version": FP_ALGO_VERSION,
    });

    Ok(FingerprintData {
        detector: "image-phash".to_string(),
        data,
        metadata,
    })
}

/// Arbitrary-angle rotation on an expanded canvas with white fill — the
/// convention desktop editors (and ImageMagick `-rotate`) use for slight
/// straightening, so the variant hash matches their output. Inverse-mapped
/// bilinear sampling; the canvas grows to hold the rotated frame and the
/// corner wedges stay white. Public so tests can generate the exact images
/// the edit variant is meant to catch.
#[must_use]
pub fn rotate_expand_white(img: &image::DynamicImage, degrees: f32) -> image::DynamicImage {
    let rad = degrees.to_radians();
    let (sin, cos) = rad.sin_cos();
    let src = img.to_rgb8();
    let (w, h) = (src.width() as f32, src.height() as f32);
    let new_w = (w * cos.abs() + h * sin.abs()).ceil() as u32;
    let new_h = (w * sin.abs() + h * cos.abs()).ceil() as u32;
    let (cx, cy) = (w / 2.0, h / 2.0);
    let (ncx, ncy) = (new_w as f32 / 2.0, new_h as f32 / 2.0);
    let mut out = image::RgbImage::from_pixel(new_w, new_h, image::Rgb([255, 255, 255]));
    for y in 0..new_h {
        for x in 0..new_w {
            // Destination pixel center → source coordinates (inverse map).
            let dx = x as f32 + 0.5 - ncx;
            let dy = y as f32 + 0.5 - ncy;
            let sx = cos * dx + sin * dy + cx - 0.5;
            let sy = -sin * dx + cos * dy + cy - 0.5;
            if sx < 0.0 || sy < 0.0 || sx > w - 1.0 || sy > h - 1.0 {
                continue; // outside the source frame: stays white (wedge)
            }
            let (x0, y0) = (sx.floor() as u32, sy.floor() as u32);
            let x1 = (x0 + 1).min(src.width() - 1);
            let y1 = (y0 + 1).min(src.height() - 1);
            let (fx, fy) = (sx - x0 as f32, sy - y0 as f32);
            let p = |xx: u32, yy: u32| src.get_pixel(xx, yy).0;
            let (p00, p10, p01, p11) = (p(x0, y0), p(x1, y0), p(x0, y1), p(x1, y1));
            let mut px = [0u8; 3];
            for c in 0..3 {
                let top = f32::from(p00[c]) * (1.0 - fx) + f32::from(p10[c]) * fx;
                let bottom = f32::from(p01[c]) * (1.0 - fx) + f32::from(p11[c]) * fx;
                px[c] = (top * (1.0 - fy) + bottom * fy).round() as u8;
            }
            out.put_pixel(x, y, image::Rgb(px));
        }
    }
    image::DynamicImage::ImageRgb8(out)
}

// ── EXIF Orientation ──

fn read_orientation(path: &Path) -> u32 {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return 1,
    };
    let mut r = io::BufReader::new(file);
    let exif = match exif::Reader::new().read_from_container(&mut r) {
        Ok(e) => e,
        Err(_) => return 1,
    };
    exif.get_field(exif::Tag::Orientation, exif::In::PRIMARY)
        .and_then(|f| f.value.get_uint(0))
        .unwrap_or(1)
}

fn apply_orientation(mut img: image::DynamicImage, orientation: u32) -> image::DynamicImage {
    use image::imageops as ops;
    match orientation {
        2 => {
            ops::flip_horizontal_in_place(&mut img);
            img
        }
        3 => {
            ops::rotate180_in_place(&mut img);
            img
        }
        4 => {
            ops::flip_vertical_in_place(&mut img);
            img
        }
        5 => {
            img = ops::flip_horizontal(&img).into();
            img = ops::rotate90(&img).into();
            img
        }
        6 => {
            img = ops::rotate90(&img).into();
            img
        }
        7 => {
            img = ops::flip_horizontal(&img).into();
            img = ops::rotate180(&img).into();
            img = ops::rotate90(&img).into();
            img
        }
        8 => {
            img = ops::rotate180(&img).into();
            img = ops::rotate90(&img).into();
            img
        }
        _ => img,
    }
}

// ── EXIF info ──

fn read_exif_info(path: &Path) -> serde_json::Value {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return serde_json::json!({}),
    };
    let mut r = io::BufReader::new(file);
    let exif = match exif::Reader::new().read_from_container(&mut r) {
        Ok(e) => e,
        Err(_) => return serde_json::json!({}),
    };
    let get = |t| {
        exif.get_field(t, exif::In::PRIMARY)
            .map(|f| f.display_value().to_string())
    };
    let has = |t| exif.get_field(t, exif::In::PRIMARY).is_some();
    serde_json::json!({
        "make": get(exif::Tag::Make), "model": get(exif::Tag::Model),
        "software": get(exif::Tag::Software),
        "date_time_original": get(exif::Tag::DateTimeOriginal),
        "modify_date": get(exif::Tag::DateTime),
        "gps": has(exif::Tag::GPSLatitude),
    })
}

// ── Keeper score (comprehensive) ──

/// Explains why a file was chosen (or not) as keeper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeeperReasoning {
    pub total_score: f64,
    pub breakdown: Vec<RuleVote>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleVote {
    pub category: String,
    pub rule: String,
    pub weight: f64,
    pub applied: bool,
}

/// Category caps: prevent one dimension from dominating.
const CAP_CONTENT: f64 = 50.0;
const CAP_EXIF: f64 = 60.0;
const CAP_FILENAME: f64 = 40.0;
const CAP_PATH: f64 = 30.0;
const CAP_FS: f64 = 20.0;

fn image_keeper_score(path: &Path, weights: &KeeperWeights) -> io::Result<f64> {
    let (score, _) = image_keeper_score_detailed(
        path,
        zerodupe_platform::current(),
        None,
        None,
        None,
        weights,
    )?;
    Ok(score)
}

/// Full keeper scoring with cluster context for relative normalization.
pub fn image_keeper_score_detailed(
    path: &Path,
    profile: &dyn PlatformProfile,
    cluster_max_res: Option<(u32, u32)>,
    cluster_max_bytes_per_px: Option<f64>,
    cluster_oldest_birthtime: Option<i64>,
    weights: &KeeperWeights,
) -> io::Result<(f64, KeeperReasoning)> {
    let mut content = 0.0f64;
    let mut exif_score = 0.0f64;
    let mut filename_sc = 0.0f64;
    let mut path_sc = 0.0f64;
    let mut fs_sc = 0.0f64;
    let mut votes: Vec<RuleVote> = Vec::new();

    let meta = std::fs::symlink_metadata(path).ok();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let nl = name.to_lowercase();
    let lossy = path.to_string_lossy();
    let utf8_path = Utf8Path::new(lossy.as_ref());
    let pl = profile.normalize_for_match(utf8_path);
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // ── GATEKEEPERS Capa 0 — hard disqualifiers / strong penalties ──
    // These run O(1) per file and detect corruption, copies, or edits.

    // EOF truncation: truncated JPEG can never be keeper
    match jpeg_is_truncated(path) {
        Ok(true) => {
            let w = weights.content_jpeg_truncated_penalty;
            content += w;
            votes.push(v("content", "JPEG truncated (missing EOF marker)", w, true));
        }
        Ok(false) => {}
        Err(_) => {} // can't check → no penalty
    }

    // mtime < DateTimeOriginal: file is a copy, not original
    match mtime_older_than_exif(path) {
        Ok(true) => {
            let w = weights.fs_copy_mtime_penalty;
            exif_score += w;
            votes.push(v(
                "exif",
                "mtime older than DateTimeOriginal (copy)",
                w,
                true,
            ));
        }
        Ok(false) => {}
        Err(_) => {}
    }

    // Double JPEG compression (Benford/DQT proxy): re-saved by WhatsApp/IG/editor
    match is_double_compressed(path) {
        Ok(true) => {
            let w = weights.exif_double_compression_penalty;
            exif_score += w;
            votes.push(v("exif", "double JPEG compression (re-saved)", w, true));
        }
        Ok(false) => {}
        Err(_) => {}
    }

    // XMP History: definitive proof of editing (Lightroom, Photoshop, etc.)
    match has_xmp_history(path) {
        Ok(true) => {
            let w = weights.exif_xmp_history_penalty;
            exif_score += w;
            votes.push(v("exif", "XMP History present (edited)", w, true));
        }
        Ok(false) => {}
        Err(_) => {}
    }

    // ── CONTENT category (cap 50) ──

    // RAW format
    let is_raw = RAW_EXTENSIONS.contains(&ext.as_str());
    if is_raw {
        let w = weights.content_raw_bonus;
        content += w;
        votes.push(v("content", "RAW format", w, true));
    }

    // Read image dimensions ONCE (header-only, no full decode).
    // image_dimensions() reads just the image header — ~1000× faster than image::open().
    let dims: Option<(u32, u32)> = image::image_dimensions(path).ok();

    // Resolution (relative to cluster max)
    if let Some((w, h)) = dims {
        let mp = (w as f64 * h as f64) / 1_000_000.0;
        if let Some((mw, mh)) = cluster_max_res {
            let max_mp = (mw as f64 * mh as f64) / 1_000_000.0;
            if mp > 0.0 && max_mp > 0.0 {
                let ratio = mp / max_mp;
                if ratio >= 0.99 {
                    let sc = weights.content_resolution_bonus;
                    content += sc;
                    votes.push(v("content", "highest resolution in cluster", sc, true));
                } else if ratio >= 0.5 {
                    let sc = 5.0;
                    content += sc;
                    votes.push(v("content", "high resolution", sc, true));
                }
            }
        } else {
            let sc = (mp * 5.0).min(15.0);
            content += sc;
            votes.push(v("content", format!("resolution {mp:.1}MP"), sc, true));
        }
        // Suspicious "round" resolutions (common export/thumbnail sizes)
        if (w == 1920 && h == 1080)
            || (w == 1280 && h == 720)
            || (w == 2048 && h == 1024)
            || (w == 640 && h == 480)
        {
            let sc = -8.0;
            content += sc;
            votes.push(v(
                "content",
                "suspicious round resolution (export/thumbnail)",
                sc,
                true,
            ));
        }
    }

    // Bytes per pixel at same resolution (relative)
    // Reuses dimensions read above — no extra file open.
    if let (Some(m), Some((w, h))) = (meta.as_ref(), dims) {
        let bytes = m.len() as f64;
        let px = (w * h) as f64;
        if px > 0.0 {
            let bpp = bytes / px;
            if let Some(max_bpp) = cluster_max_bytes_per_px {
                if max_bpp > 0.0 && (bpp / max_bpp) >= 0.95 {
                    let sc = 10.0;
                    content += sc;
                    votes.push(v("content", "highest bytes/pixel in cluster", sc, true));
                }
            } else {
                let sc = (bpp * 100.0).min(10.0);
                content += sc;
                votes.push(v("content", format!("bytes/pixel {bpp:.3}"), sc, true));
            }
        }
    }

    content = content.clamp(-50.0, CAP_CONTENT);

    // ── EXIF category (cap 60) ──

    if let Ok(file) = std::fs::File::open(path) {
        let mut r = io::BufReader::new(file);
        if let Ok(exif) = exif::Reader::new().read_from_container(&mut r) {
            let has = |t| exif.get_field(t, exif::In::PRIMARY).is_some();
            let get = |t| {
                exif.get_field(t, exif::In::PRIMARY)
                    .map(|f| f.display_value().to_string())
            };

            // MakerNote — strongest signal
            if has(exif::Tag::MakerNote) {
                let w = weights.exif_makernote_bonus;
                exif_score += w;
                votes.push(v("exif", "MakerNote present", w, true));
            }
            // Make + Model
            if has(exif::Tag::Make) && has(exif::Tag::Model) {
                let w = weights.exif_make_model_bonus;
                exif_score += w;
                votes.push(v("exif", "camera Make+Model", w, true));
            }
            // GPS
            if has(exif::Tag::GPSLatitude) {
                let w = 15.0;
                exif_score += w;
                votes.push(v("exif", "GPS present", w, true));
            }
            // Serial number (try common variants)
            // Note: exif crate may not have all variants — skip if unavailable
            // Consistent dates
            if let (Some(o), Some(m)) = (get(exif::Tag::DateTimeOriginal), get(exif::Tag::DateTime))
                && o == m
            {
                let w = 8.0;
                exif_score += w;
                votes.push(v("exif", "dates consistent (unedited)", w, true));
            }
            // Software tag
            if let Some(sw) = get(exif::Tag::Software) {
                let swl = sw.to_lowercase();
                let editors = [
                    "photoshop",
                    "lightroom",
                    "instagram",
                    "whatsapp",
                    "snapseed",
                    "vsco",
                    "gimp",
                    "canva",
                    "snapchat",
                    "telegram",
                    "pixelmator",
                    "affinity",
                    "picasa",
                    "express",
                ];
                if editors.iter().any(|e| swl.contains(e)) {
                    let w = weights.exif_software_editor_penalty;
                    exif_score += w;
                    votes.push(v("exif", format!("edited by {sw}"), w, true));
                }
                // Empty or camera firmware → good
                if swl.is_empty()
                    || swl.contains("ios")
                    || swl.contains("android")
                    || swl.contains("firmware")
                {
                    let w = 5.0;
                    exif_score += w;
                    votes.push(v("exif", "camera/firmware software tag", w, true));
                }
            }
            // ICC profile (detected via ColorSpace tag)
            if has(exif::Tag::ColorSpace) {
                let w = 5.0;
                exif_score += w;
                votes.push(v("exif", "color space info", w, true));
            }
        } else {
            // EXIF completely stripped
            let w = -10.0;
            exif_score += w;
            votes.push(v("exif", "EXIF completely stripped", w, true));
        }
    }

    exif_score = exif_score.clamp(-60.0, CAP_EXIF);

    // ── FILENAME category (cap 40) ──

    // Camera patterns (bonus)
    let camera_prefixes = [
        "img_", "dsc_", "dscf", "pxl_", "_mg_", "gopr", "gh01", "dji_",
    ];
    if camera_prefixes.iter().any(|p| nl.starts_with(p)) {
        let w = weights.filename_camera_pattern_bonus;
        filename_sc += w;
        votes.push(v("filename", "camera naming pattern", w, true));
    }
    // WhatsApp pattern IMG-YYYYMMDD-WAxxxx
    if nl.len() > 20 && nl.starts_with("img-") && nl.contains("-wa") {
        let w = weights.filename_whatsapp_penalty;
        filename_sc += w;
        votes.push(v("filename", "WhatsApp shared image", w, true));
    }
    // Messenger pattern received_NNNNNNNN
    if nl.len() > 9 && nl.starts_with("received_") && nl[9..].chars().all(|c| c.is_ascii_digit()) {
        let w = -25.0;
        filename_sc += w;
        votes.push(v("filename", "Messenger received image", w, true));
    }
    // Facebook pattern
    if nl.starts_with("fb_img_") {
        let w = -25.0;
        filename_sc += w;
        votes.push(v("filename", "Facebook download", w, true));
    }
    // Snapchat pattern
    if nl.starts_with("snapchat-") {
        let w = -25.0;
        filename_sc += w;
        votes.push(v("filename", "Snapchat image", w, true));
    }
    // Telegram pattern
    if nl.starts_with("photo_") && nl.contains("@") {
        let w = -20.0;
        filename_sc += w;
        votes.push(v("filename", "Telegram image", w, true));
    }
    // Generic copy/derivative patterns
    let copy_markers = [
        "copy",
        "copia",
        "kopie",
        "(1)",
        "(2)",
        "(3)",
        "backup",
        "respaldo",
        "duplicate",
        "duplicado",
        "_edit",
        "_final",
        "_v2",
        "_v3",
        "-edit",
        "-final",
        "-v2",
    ];
    if copy_markers.iter().any(|m| nl.contains(m)) {
        let w = weights.filename_copy_marker_penalty;
        filename_sc += w;
        votes.push(v("filename", "copy/derivative name pattern", w, true));
    }
    // Download/genérico
    if [
        "image.jpg",
        "photo.jpg",
        "download.jpg",
        "untitled",
        "output.jpg",
        "unnamed",
    ]
    .iter()
    .any(|g| nl == *g)
    {
        let w = -15.0;
        filename_sc += w;
        votes.push(v("filename", "generic download name", w, true));
    }
    // Screenshot pattern
    if nl.starts_with("screenshot") || nl.starts_with("captura") {
        let w = -10.0;
        filename_sc += w;
        votes.push(v("filename", "screenshot filename", w, true));
    }
    // High entropy (hash) — crude check: >50% digits in basename
    let stem = if let Some(d) = nl.rfind('.') {
        &nl[..d]
    } else {
        &nl
    };
    let digit_ratio =
        stem.chars().filter(|c| c.is_ascii_digit()).count() as f64 / stem.len().max(1) as f64;
    if digit_ratio > 0.6 {
        let w = -5.0;
        filename_sc += w;
        votes.push(v("filename", "high-entropy/hash-like name", w, true));
    }

    filename_sc = filename_sc.clamp(-40.0, CAP_FILENAME);

    // ── PATH category (cap 30) ──

    for root in profile.canonical_roots() {
        if pl.contains(root.pattern) {
            let w = root.score as f64;
            path_sc += w;
            votes.push(v(
                "path",
                format!("canonical: {} ({})", root.label, root.score),
                w,
                true,
            ));
        }
    }

    for junk in profile.junk_locations() {
        if pl.contains(junk.pattern) {
            let w = junk.score as f64;
            path_sc += w;
            votes.push(v(
                "path",
                format!("junk: {} ({})", junk.label, junk.score),
                w,
                true,
            ));
        }
    }

    path_sc = path_sc.clamp(-30.0, CAP_PATH);

    // ── FILESYSTEM category (cap 20) ──

    // birthtime
    if let (Some(m), Some(oldest)) = (meta.as_ref(), cluster_oldest_birthtime)
        && let Ok(created) = m.created()
        && let Ok(secs) = created.duration_since(std::time::UNIX_EPOCH)
    {
        let birth = secs.as_secs() as i64;
        if birth <= oldest {
            let w = weights.fs_older_file_bonus;
            fs_sc += w;
            votes.push(v("fs", "oldest file in cluster (birthtime)", w, true));
        }
    }

    // xattrs (platform-specific, deferred)
    // Linux: user.xdg.origin.url, macOS: com.apple.quarantine
    // These require platform-specific crates; defer for now.

    // Hardlink detection: already handled by PhysicalFile in exact pipeline.
    // Skip platform-specific nlink check here.

    fs_sc = fs_sc.clamp(-20.0, CAP_FS);

    // ── Total ──
    let total = content + exif_score + filename_sc + path_sc + fs_sc;
    let reasoning = KeeperReasoning {
        total_score: total,
        breakdown: votes,
    };

    Ok((total, reasoning))
}

fn v(cat: &str, rule: impl Into<String>, weight: f64, applied: bool) -> RuleVote {
    RuleVote {
        category: cat.to_string(),
        rule: rule.into(),
        weight,
        applied,
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    fn make_random(w: u32, h: u32, seed: u64) -> image::DynamicImage {
        let mut img = image::DynamicImage::new_rgb8(w, h);
        let mut state = seed;
        for (_, _, p) in img.as_mut_rgb8().unwrap().enumerate_pixels_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let r = (state >> 32) as u8;
            let g = (state >> 24) as u8;
            let b = (state >> 16) as u8;
            *p = image::Rgb([r, g, b]);
        }
        img
    }

    #[test]
    fn identical_same_hash() {
        let dir = tempfile::tempdir().unwrap();
        let i = make_random(200, 200, 42);
        let p = dir.path().join("test.png");
        i.save(&p).unwrap();
        let d = ImagePHashDetector::new();
        let fp = d.fingerprint(&p).unwrap();
        assert_eq!(d.distance(&fp, &fp), 0);
        assert!(d.similarity(&fp, &fp) > 0.99);
    }

    #[test]
    fn similar_near_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_random(200, 200, 100);
        let mut b_img = make_random(200, 200, 100);
        // Slightly perturb: change ~1% of pixels
        let mut state = 200u64;
        for (_, _, p) in b_img.as_mut_rgb8().unwrap().enumerate_pixels_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            if (state & 0xFF) < 3 {
                p[0] = p[0].wrapping_add(2);
            }
        }
        let pa = dir.path().join("a.png");
        a.save(&pa).unwrap();
        let pb = dir.path().join("b.png");
        b_img.save(&pb).unwrap();
        let d = ImagePHashDetector::new();
        assert!(d.is_near_duplicate(&d.fingerprint(&pa).unwrap(), &d.fingerprint(&pb).unwrap()));
    }

    #[test]
    fn different_not_near() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_random(200, 200, 1);
        let b = make_random(200, 200, 999);
        let pa = dir.path().join("a.png");
        a.save(&pa).unwrap();
        let pb = dir.path().join("b.png");
        b.save(&pb).unwrap();
        let d = ImagePHashDetector::new();
        assert!(!d.is_near_duplicate(&d.fingerprint(&pa).unwrap(), &d.fingerprint(&pb).unwrap()));
    }

    #[test]
    fn hd_beats_sd() {
        let dir = tempfile::tempdir().unwrap();
        let hd = make_random(1920, 1080, 500);
        let sd = make_random(640, 480, 500);
        let ph = dir.path().join("hd.png");
        hd.save(&ph).unwrap();
        let ps = dir.path().join("sd.png");
        sd.save(&ps).unwrap();
        assert!(
            ImagePHashDetector::new().keeper_score(&ph).unwrap()
                > ImagePHashDetector::new().keeper_score(&ps).unwrap()
        );
    }

    // ── Cross-platform MockProfile tests ──

    #[test]
    fn path_category_scoring_with_windows_paths() {
        let profile = zerodupe_platform::mock::MockProfile::windows_like();
        let (score, reasoning) = image_keeper_score_detailed(
            Path::new(r"C:\Users\rene\Pictures\IMG_0001.jpg"),
            &profile,
            None,
            None,
            None,
            &KeeperWeights::default(),
        )
        .unwrap();

        let path_votes: Vec<_> = reasoning
            .breakdown
            .iter()
            .filter(|v| v.category == "path")
            .collect();
        assert!(
            !path_votes.is_empty(),
            "should have at least one PATH category vote for Windows Pictures path"
        );
        let has_canonical = path_votes.iter().any(|v| v.rule.contains("canonical"));
        assert!(
            has_canonical,
            "should recognize canonical path, got votes: {path_votes:?}"
        );
        assert!(
            score > -100.0,
            "total score should be reasonable, got {score}"
        );
    }

    #[test]
    fn path_category_penalizes_windows_junk_locations() {
        let profile = zerodupe_platform::mock::MockProfile::windows_like();
        let (_score, reasoning) = image_keeper_score_detailed(
            Path::new(r"C:\Users\rene\Downloads\IMG_0001.jpg"),
            &profile,
            None,
            None,
            None,
            &KeeperWeights::default(),
        )
        .unwrap();

        let path_votes: Vec<_> = reasoning
            .breakdown
            .iter()
            .filter(|v| v.category == "path")
            .collect();
        assert!(
            !path_votes.is_empty(),
            "should have PATH category votes for Windows Downloads path"
        );
        let has_junk = path_votes.iter().any(|v| v.rule.contains("junk"));
        assert!(
            has_junk,
            "should penalize junk location, got votes: {path_votes:?}"
        );
    }

    #[test]
    fn macos_case_insensitive_pictures_matches_in_image_keeper() {
        let profile = zerodupe_platform::mock::MockProfile::macos_like();
        let (_score, reasoning) = image_keeper_score_detailed(
            Path::new("/Users/Rene/Pictures/IMG.JPG"),
            &profile,
            None,
            None,
            None,
            &KeeperWeights::default(),
        )
        .unwrap();

        let path_votes: Vec<_> = reasoning
            .breakdown
            .iter()
            .filter(|v| v.category == "path")
            .collect();
        assert!(
            !path_votes.is_empty(),
            "case-insensitive match should recognize /pictures/ canonical root"
        );
        let has_canonical = path_votes.iter().any(|v| v.rule.contains("canonical"));
        assert!(
            has_canonical,
            "should find canonical bonus via case-insensitive match, got votes: {path_votes:?}"
        );
    }

    fn make_noise_image(seed: u64, width: u32, height: u32) -> image::RgbImage {
        let mut state = seed;
        let mut img = image::RgbImage::new(width, height);
        for y in 0..height {
            for x in 0..width {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let r = (state >> 56) as u8;
                let g = (state >> 48) as u8;
                let b = (state >> 40) as u8;
                img.put_pixel(x, y, image::Rgb([r, g, b]));
            }
        }
        img
    }

    #[test]
    fn identical_images_have_same_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let img_a = make_noise_image(42, 64, 64);
        let img_b = make_noise_image(42, 64, 64);
        let pa = dir.path().join("a.png");
        let pb = dir.path().join("b.png");
        img_a.save(&pa).unwrap();
        img_b.save(&pb).unwrap();

        let d = ImagePHashDetector::new();
        let fpa = d.fingerprint(&pa).unwrap();
        let fpb = d.fingerprint(&pb).unwrap();
        assert_eq!(d.distance(&fpa, &fpb), 0);
        assert!(d.similarity(&fpa, &fpb) > 0.99);
        assert!(d.is_near_duplicate(&fpa, &fpb));
    }

    #[test]
    fn different_images_have_different_fingerprints() {
        let dir = tempfile::tempdir().unwrap();
        let img_a = make_noise_image(42, 64, 64);
        let img_b = make_noise_image(999, 64, 64);
        let pa = dir.path().join("a.png");
        let pb = dir.path().join("b.png");
        img_a.save(&pa).unwrap();
        img_b.save(&pb).unwrap();

        let d = ImagePHashDetector::new();
        let fpa = d.fingerprint(&pa).unwrap();
        let fpb = d.fingerprint(&pb).unwrap();
        assert!(d.distance(&fpa, &fpb) > 0);
        assert!(!d.is_near_duplicate(&fpa, &fpb));
    }

    #[test]
    fn phash_popcount_not_degenerate() {
        let dir = tempfile::tempdir().unwrap();
        let img = make_noise_image(77, 128, 128);
        let p = dir.path().join("noise.png");
        img.save(&p).unwrap();

        let result = ImagePHashDetector::new().fingerprint(&p);
        assert!(
            result.is_ok(),
            "fingerprint should succeed for noise image, got error: {:?}",
            result.err()
        );
        let fp = result.unwrap();
        let ph_bytes = &fp.data[..8];
        let popcount: u32 = ph_bytes.iter().map(|b| b.count_ones()).sum();
        assert!(
            (10..=54).contains(&popcount),
            "pHash popcount {} should be in 10..=54",
            popcount
        );
    }

    #[test]
    fn similar_images_grouped_by_bktree() {
        use zerodupe_core::FileCandidate;
        use zerodupe_similar::detect_similars;

        let dir = tempfile::tempdir().unwrap();

        let img_a = make_noise_image(100, 128, 128);
        let mut img_b = make_noise_image(100, 128, 128);
        let img_c = make_noise_image(777, 128, 128);

        let mut state = 200u64;
        for (_, _, p) in img_b.enumerate_pixels_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            if (state & 0xFF) < 3 {
                p[0] = p[0].wrapping_add(2);
            }
        }

        let pa = dir.path().join("a.png");
        let pb = dir.path().join("b.png");
        let pc = dir.path().join("c.png");
        img_a.save(&pa).unwrap();
        img_b.save(&pb).unwrap();
        img_c.save(&pc).unwrap();

        let files = vec![
            FileCandidate {
                path: camino::Utf8PathBuf::from_path_buf(pa.clone()).unwrap(),
                size_bytes: std::fs::metadata(&pa).unwrap().len(),
            },
            FileCandidate {
                path: camino::Utf8PathBuf::from_path_buf(pb.clone()).unwrap(),
                size_bytes: std::fs::metadata(&pb).unwrap().len(),
            },
            FileCandidate {
                path: camino::Utf8PathBuf::from_path_buf(pc.clone()).unwrap(),
                size_bytes: std::fs::metadata(&pc).unwrap().len(),
            },
        ];

        let detector = ImagePHashDetector::new();
        let report = detect_similars(&files, &[&detector], None, None, None);

        assert_eq!(
            report.groups.len(),
            1,
            "A and B should form one group, C should be separate"
        );

        let group = &report.groups[0];
        assert_eq!(
            group.files.len(),
            2,
            "group should contain exactly 2 files (A and B)"
        );

        let group_paths: Vec<&str> = group
            .files
            .iter()
            .map(|f| f.path.file_name().unwrap())
            .collect();
        assert!(group_paths.contains(&"a.png"));
        assert!(group_paths.contains(&"b.png"));
        assert!(
            !group_paths.contains(&"c.png"),
            "C should not be grouped with A and B"
        );
    }
}
