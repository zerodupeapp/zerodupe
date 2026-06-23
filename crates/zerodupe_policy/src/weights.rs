use serde::{Deserialize, Serialize};

/// Configurable weights for keeper scoring.
/// All values match current hardcoded defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeeperWeights {
    // ── Content category (cap 50) ──
    pub content_raw_bonus: f64,
    pub content_resolution_bonus: f64,
    pub content_jpeg_truncated_penalty: f64,

    // ── EXIF category (cap 60) ──
    pub exif_makernote_bonus: f64,
    pub exif_make_model_bonus: f64,
    pub exif_software_editor_penalty: f64,
    pub exif_xmp_history_penalty: f64,
    pub exif_double_compression_penalty: f64,

    // ── FILENAME category (cap 40) ──
    pub filename_camera_pattern_bonus: f64,
    pub filename_whatsapp_penalty: f64,
    pub filename_copy_marker_penalty: f64,

    // ── PATH category (cap 30) ──
    pub path_dcim_bonus: f64,
    pub path_dump_folder_penalty: f64,

    // ── FS category (cap 20) ──
    pub fs_older_file_bonus: f64,
    pub fs_copy_mtime_penalty: f64,
}

impl Default for KeeperWeights {
    fn default() -> Self {
        Self {
            content_raw_bonus: 40.0,
            content_resolution_bonus: 10.0,
            content_jpeg_truncated_penalty: -50.0,
            exif_makernote_bonus: 30.0,
            exif_make_model_bonus: 20.0,
            exif_software_editor_penalty: -35.0,
            exif_xmp_history_penalty: -30.0,
            exif_double_compression_penalty: -25.0,
            filename_camera_pattern_bonus: 25.0,
            filename_whatsapp_penalty: -30.0,
            filename_copy_marker_penalty: -20.0,
            path_dcim_bonus: 20.0,
            path_dump_folder_penalty: -25.0,
            fs_older_file_bonus: 10.0,
            fs_copy_mtime_penalty: -25.0,
        }
    }
}
