//! Categorización de archivos por tipo según su extensión.
//!
//! Clasifica archivos en categorías de alto nivel (Imágenes, Videos, Documentos,
//! Audio, Archivos, Otros) inspeccionando únicamente la extensión del nombre de
//! archivo. No realiza lectura de contenido ni detección de magic bytes.
//!
//! Usado por la GUI para agrupar resultados y por el scorer de keepers en
//! `zerodupe_policy` para priorizar ciertos tipos de archivo sobre otros.

use camino::Utf8Path;
use serde::{Deserialize, Serialize};

/// Categoría de archivo determinada por su extensión.
///
/// La clasificación es puramente sintáctica (basada en la extensión del nombre)
/// y no inspecciona el contenido del archivo. Extensiones no reconocidas caen
/// en `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileCategory {
    /// Imágenes: jpg, png, gif, webp, heic, raw, tiff, bmp, ico, etc.
    Images,
    /// Videos: mp4, mov, avi, mkv, webm, m4v, wmv, flv.
    Videos,
    /// Documentos: pdf, doc(x), xls(x), ppt(x), txt, md, csv, json, html, epub, etc.
    Documents,
    /// Audio: mp3, flac, wav, m4a, ogg, opus, aac, wma, aiff.
    Audio,
    /// Archivos comprimidos: zip, tar, gz, bz2, 7z, rar, xz, zst, lz4.
    Archives,
    /// Cualquier otra extensión no reconocida.
    Other,
}

impl FileCategory {
    pub fn from_path(path: &Utf8Path) -> Self {
        let ext = path.extension().unwrap_or("").to_lowercase();
        match ext.as_str() {
            "jpg" | "jpeg" | "png" | "gif" | "webp" | "heic" | "heif" | "raw" | "cr2" | "nef"
            | "dng" | "tiff" | "tif" | "bmp" | "ico" => Self::Images,
            "mp4" | "mov" | "avi" | "mkv" | "webm" | "m4v" | "wmv" | "flv" => Self::Videos,
            "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "txt" | "md" | "rtf"
            | "odt" | "epub" | "csv" | "json" | "xml" | "html" => Self::Documents,
            "mp3" | "flac" | "wav" | "m4a" | "ogg" | "opus" | "aac" | "wma" | "aiff" => Self::Audio,
            "zip" | "tar" | "gz" | "bz2" | "7z" | "rar" | "xz" | "zst" | "lz4" => Self::Archives,
            _ => Self::Other,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Images => "Images",
            Self::Videos => "Videos",
            Self::Documents => "Documents",
            Self::Audio => "Audio",
            Self::Archives => "Archives",
            Self::Other => "Other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8Path;

    #[test]
    fn categorizes_images() {
        assert_eq!(
            FileCategory::from_path(Utf8Path::new("photo.jpg")),
            FileCategory::Images
        );
        assert_eq!(
            FileCategory::from_path(Utf8Path::new("photo.PNG")),
            FileCategory::Images
        );
        assert_eq!(
            FileCategory::from_path(Utf8Path::new("photo.heic")),
            FileCategory::Images
        );
    }

    #[test]
    fn categorizes_videos() {
        assert_eq!(
            FileCategory::from_path(Utf8Path::new("video.mp4")),
            FileCategory::Videos
        );
        assert_eq!(
            FileCategory::from_path(Utf8Path::new("video.MOV")),
            FileCategory::Videos
        );
    }

    #[test]
    fn categorizes_documents() {
        assert_eq!(
            FileCategory::from_path(Utf8Path::new("doc.pdf")),
            FileCategory::Documents
        );
        assert_eq!(
            FileCategory::from_path(Utf8Path::new("data.csv")),
            FileCategory::Documents
        );
    }

    #[test]
    fn categorizes_audio() {
        assert_eq!(
            FileCategory::from_path(Utf8Path::new("song.mp3")),
            FileCategory::Audio
        );
        assert_eq!(
            FileCategory::from_path(Utf8Path::new("song.FLAC")),
            FileCategory::Audio
        );
    }

    #[test]
    fn categorizes_archives() {
        assert_eq!(
            FileCategory::from_path(Utf8Path::new("archive.zip")),
            FileCategory::Archives
        );
        assert_eq!(
            FileCategory::from_path(Utf8Path::new("archive.tar.gz")),
            FileCategory::Archives
        );
    }

    #[test]
    fn unknown_extension_is_other() {
        assert_eq!(
            FileCategory::from_path(Utf8Path::new("file.xyz")),
            FileCategory::Other
        );
        assert_eq!(
            FileCategory::from_path(Utf8Path::new("Makefile")),
            FileCategory::Other
        );
    }
}
