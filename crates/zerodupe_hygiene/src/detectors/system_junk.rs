//! Detector de archivos basura del sistema operativo.
//!
//! Identifica archivos de metadatos que los sistemas operativos generan automáticamente:
//!
//! - **macOS:** `.DS_Store`, `._*` (Apple Double), `.Spotlight-V100`, `.fseventsd`
//! - **Windows:** `Thumbs.db`, `desktop.ini`, `ehthumbs.db`
//! - **Linux:** `~*` (backups), `.directory`
//!
//! Usa las listas de exclusión definidas por plataforma en [`PlatformProfile::system_excludes`].
//! Los archivos se comparan por nombre (o ruta completa si el patrón lo requiere) respetando
//! la sensibilidad a mayúsculas del sistema de archivos.
//!
//! **Tier:** 🟢 Low — trash de SO, se puede limpiar automáticamente.

use camino::Utf8Path;
use zerodupe_core::{DiscoveredEntry, DiscoveredKind};
use zerodupe_platform::PlatformProfile;

use crate::types::{JunkCategory, JunkItem, RiskLevel};

/// Detecta archivos de metadatos del SO usando las exclusiones de plataforma.
///
/// Compara cada entrada de tipo `File` contra la lista `PlatformProfile::system_excludes()`,
/// aplicando comparación case-sensitive o case-insensitive según el sistema de archivos.
pub fn detect(
    entries: &[DiscoveredEntry],
    _scan_root: &Utf8Path,
    profile: &dyn PlatformProfile,
) -> Vec<JunkItem> {
    let excludes = profile.system_excludes();
    if excludes.is_empty() {
        return Vec::new();
    }

    entries
        .iter()
        .filter(|entry| entry.kind == DiscoveredKind::File)
        .filter(|entry| matches_system_exclude(&entry.path, excludes, profile))
        .map(|entry| {
            let file_name = entry.path.file_name().unwrap_or("unknown");
            JunkItem {
                path: entry.path.clone(),
                category: JunkCategory::SystemJunk,
                risk: RiskLevel::Low,
                size_bytes: entry.size_bytes.unwrap_or(0),
                explanation: format!("System metadata file: {file_name}"),
                can_clean: true,
            }
        })
        .collect()
}

fn matches_system_exclude(
    path: &Utf8Path,
    excludes: &[zerodupe_platform::SystemExclude],
    profile: &dyn PlatformProfile,
) -> bool {
    let normalized = profile.normalize_for_match(path);
    let name = path.file_name().unwrap_or("");
    let name_lower = if profile.fs_case_sensitive() {
        name.to_string()
    } else {
        name.to_lowercase()
    };

    excludes.iter().any(|exclude| {
        let pat_lower = if profile.fs_case_sensitive() {
            exclude.pattern.to_string()
        } else {
            exclude.pattern.to_lowercase()
        };

        if exclude.match_full_path {
            normalized.contains(&pat_lower)
        } else {
            name_lower == pat_lower || name_lower.starts_with(&pat_lower)
        }
    })
}
