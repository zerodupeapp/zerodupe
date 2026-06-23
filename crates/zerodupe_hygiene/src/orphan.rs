//! Detector de sidecars huérfanos.
//!
//! Identifica archivos "compañeros" (sidecars) que quedaron sin su archivo principal
//! tras eliminar o mover el contenido original. Los sidecars por sí solos no tienen
//! valor y ocupan espacio innecesario.
//!
//! ## Tipos detectados
//!
//! | Sidecar | Archivo principal | Contexto |
//! |---------|-------------------|----------|
//! | `.AAE` | `.HEIC` / `.heic` | Ediciones de Fotos de Apple (iOS/macOS) |
//! | `.XMP` | `.CR2`, `.NEF`, `.ARW`, `.DNG`, `.CR3` (RAW) | Metadatos de Adobe Camera Raw |
//! | `.THM` | `.CR2`, `.NEF`, `.JPG`, `.MP4` | Thumbnails de cámaras/video |
//! | `.json` | `.jpg`, `.mp4`, etc. | Metadatos de Google Takeout |
//! | `.supplemental-metadata.json` | mismo nombre sin sufijo | Metadatos extra de Google Takeout |
//!
//! **Tier:** 🟠 Medium — los sidecars pueden contener ediciones no guardadas (`.AAE`)
//! o metadatos valiosos (`.XMP`). Se pueden limpiar, pero con confirmación.
//! `can_clean: true`.

use camino::Utf8Path;
use zerodupe_core::DiscoveredEntry;
use zerodupe_platform::PlatformProfile;

use crate::types::{JunkCategory, JunkItem, RiskLevel};

fn file_stem(path: &Utf8Path) -> &str {
    path.file_stem().unwrap_or("")
}

fn has_uppercase_ext(path: &Utf8Path, ext: &str) -> bool {
    let path_str = path.as_str();
    path_str.ends_with(ext)
}

fn has_lowercase_ext(path: &Utf8Path, ext: &str) -> bool {
    let path_str = path.as_str();
    path_str.ends_with(ext)
}

/// Detecta sidecars huérfanos: archivos complementarios cuyo archivo principal
/// ya no existe en el sistema de archivos.
///
/// Para cada extensión de sidecar conocida, verifica si existe el archivo principal
/// correspondiente. Si no existe ninguno de los formatos principales posibles,
/// el sidecar se reporta como huérfano.
///
/// Los sidecars de Google Takeout (`.jpg.json`, `.supplemental-metadata.json`)
/// reciben tratamiento especial: se deriva la ruta del archivo multimedia original
/// y se verifica su existencia.
pub fn detect_orphans(
    entries: &[DiscoveredEntry],
    _scan_root: &Utf8Path,
    _profile: &dyn PlatformProfile,
) -> Vec<JunkItem> {
    let mut orphans = Vec::new();

    for entry in entries {
        let path = &entry.path;
        let stem = file_stem(path);

        if has_uppercase_ext(path, ".AAE") {
            let heic_upper = path.with_extension("HEIC");
            let heic_lower = path.with_extension("heic");
            if !heic_upper.exists() && !heic_lower.exists() {
                orphans.push(JunkItem {
                    path: path.clone(),
                    category: JunkCategory::OrphanSidecar,
                    risk: RiskLevel::Medium,
                    size_bytes: entry.size_bytes.unwrap_or(0),
                    explanation: format!("Orphan sidecar: {} companion HEIC was deleted", stem),
                    can_clean: true,
                });
            }
            continue;
        }

        if has_lowercase_ext(path, ".xmp") {
            for raw_ext in &[
                "CR2", "NEF", "ARW", "DNG", "CR3", "cr2", "nef", "arw", "dng", "cr3",
            ] {
                let main = path.with_extension(raw_ext);
                if main.exists() {
                    break;
                }
            }
            let any_raw = || {
                for raw_ext in &[
                    "CR2", "NEF", "ARW", "DNG", "CR3", "cr2", "nef", "arw", "dng", "cr3",
                ] {
                    let main = path.with_extension(raw_ext);
                    if main.exists() {
                        return true;
                    }
                }
                false
            };
            if !any_raw() {
                orphans.push(JunkItem {
                    path: path.clone(),
                    category: JunkCategory::OrphanSidecar,
                    risk: RiskLevel::Medium,
                    size_bytes: entry.size_bytes.unwrap_or(0),
                    explanation: format!("Orphan sidecar: {} companion RAW file was deleted", stem),
                    can_clean: true,
                });
            }
            continue;
        }

        if has_lowercase_ext(path, ".thm") {
            let any_media = || {
                for media_ext in &["CR2", "NEF", "JPG", "MP4", "cr2", "nef", "jpg", "mp4"] {
                    let main = path.with_extension(media_ext);
                    if main.exists() {
                        return true;
                    }
                }
                false
            };
            if !any_media() {
                orphans.push(JunkItem {
                    path: path.clone(),
                    category: JunkCategory::OrphanSidecar,
                    risk: RiskLevel::Medium,
                    size_bytes: entry.size_bytes.unwrap_or(0),
                    explanation: format!(
                        "Orphan sidecar: {} companion media file was deleted",
                        stem
                    ),
                    can_clean: true,
                });
            }
            continue;
        }

        if has_lowercase_ext(path, ".json") && path_str_ends_with_google_takeout(path) {
            let media_path = derive_takeout_media_path(path);
            if let Some(mp) = media_path
                && !mp.exists()
            {
                orphans.push(JunkItem {
                        path: path.clone(),
                        category: JunkCategory::OrphanSidecar,
                        risk: RiskLevel::Medium,
                        size_bytes: entry.size_bytes.unwrap_or(0),
                        explanation: format!(
                            "Orphan sidecar: {} companion media file was deleted (Google Takeout metadata)",
                            stem
                        ),
                        can_clean: true,
                    });
            }
        }
    }

    orphans
}

fn path_str_ends_with_google_takeout(path: &Utf8Path) -> bool {
    let s = path.as_str();
    if s.ends_with(".supplemental-metadata.json") {
        return true;
    }
    for ext in &[
        ".jpg", ".JPG", ".jpeg", ".JPEG", ".png", ".PNG", ".gif", ".GIF", ".mp4", ".MP4", ".mov",
        ".MOV", ".heic", ".HEIC", ".tiff", ".TIFF", ".webp", ".WEBP",
    ] {
        let pattern = format!("{}.json", ext);
        if s.ends_with(&pattern) {
            return true;
        }
    }
    false
}

fn derive_takeout_media_path(json_path: &Utf8Path) -> Option<camino::Utf8PathBuf> {
    let s = json_path.as_str();

    if let Some(base) = s.strip_suffix(".supplemental-metadata.json") {
        return Some(camino::Utf8PathBuf::from(base));
    }

    for ext in &[
        ".jpg", ".JPG", ".jpeg", ".JPEG", ".png", ".PNG", ".gif", ".GIF", ".mp4", ".MP4", ".mov",
        ".MOV", ".heic", ".HEIC", ".tiff", ".TIFF", ".webp", ".WEBP",
    ] {
        let suffix = format!("{}.json", ext);
        if s.ends_with(&suffix) {
            let base = &s[..s.len() - ".json".len()];
            return Some(camino::Utf8PathBuf::from(base));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerodupe_core::{DiscoveredEntry, DiscoveredKind, FileTimestamps, RootId};
    use zerodupe_platform::mock::MockProfile;

    fn make_entry(path: &camino::Utf8Path) -> DiscoveredEntry {
        DiscoveredEntry {
            root_id: RootId(0),
            path: path.to_path_buf(),
            kind: DiscoveredKind::File,
            depth: 0,
            size_bytes: Some(0),
            readonly: false,
            timestamps: FileTimestamps::default(),
            physical_key: None,
        }
    }

    #[test]
    fn detects_orphan_aae_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let aae_path = root.join("photo.AAE");
        std::fs::write(aae_path.as_std_path(), b"AAE sidecar").unwrap();
        let aae_utf8 = camino::Utf8PathBuf::from(aae_path.as_std_path().to_str().unwrap());

        let entries = vec![make_entry(&aae_utf8)];
        let profile = MockProfile::linux_like();

        let orphans = detect_orphans(&entries, &root, &profile);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].category, JunkCategory::OrphanSidecar);
        assert!(orphans[0].explanation.contains("photo"));
    }

    #[test]
    fn does_not_detect_orphan_with_media() {
        let dir = tempfile::tempdir().unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let aae_path = root.join("photo.AAE");
        let heic_path = root.join("photo.heic");
        std::fs::write(aae_path.as_std_path(), b"AAE sidecar").unwrap();
        std::fs::write(heic_path.as_std_path(), b"heic content").unwrap();

        let aae_utf8 = camino::Utf8PathBuf::from(aae_path.as_std_path().to_str().unwrap());
        let entries = vec![make_entry(&aae_utf8)];
        let profile = MockProfile::linux_like();

        let orphans = detect_orphans(&entries, &root, &profile);
        assert!(
            orphans.is_empty(),
            "AAE should NOT be orphan when companion HEIC media exists"
        );
    }

    #[test]
    fn detects_orphan_xmp_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let xmp_path = root.join("photo.xmp");
        std::fs::write(xmp_path.as_std_path(), b"XMP sidecar").unwrap();
        let xmp_utf8 = camino::Utf8PathBuf::from(xmp_path.as_std_path().to_str().unwrap());

        let entries = vec![make_entry(&xmp_utf8)];
        let profile = MockProfile::linux_like();

        let orphans = detect_orphans(&entries, &root, &profile);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].category, JunkCategory::OrphanSidecar);
        assert!(orphans[0].explanation.contains("RAW"));
    }

    #[test]
    fn detects_takeout_json_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let json_path = root.join("photo.jpg.json");
        std::fs::write(json_path.as_std_path(), b"{}").unwrap();
        let json_utf8 = camino::Utf8PathBuf::from(json_path.as_std_path().to_str().unwrap());

        let entries = vec![make_entry(&json_utf8)];
        let profile = MockProfile::linux_like();

        let orphans = detect_orphans(&entries, &root, &profile);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].category, JunkCategory::OrphanSidecar);
        assert!(orphans[0].explanation.contains("Google Takeout"));
    }
}
