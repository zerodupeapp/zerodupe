//! Detector de archivos vacíos (0 bytes).
//!
//! Identifica archivos regulares cuyo tamaño es exactamente 0 bytes. Son inofensivos
//! y nunca contienen datos útiles — ocupan solo una entrada de directorio.
//!
//! **Tier:** 🟢 Low — trash de SO, se puede limpiar automáticamente.

use camino::Utf8Path;
use zerodupe_core::{DiscoveredEntry, DiscoveredKind};
use zerodupe_platform::PlatformProfile;

use crate::blacklist;
use crate::types::{JunkCategory, JunkItem, RiskLevel};

/// Detecta archivos de 0 bytes que no estén en la lista negra.
///
/// Recorre todas las entradas del discovery y selecciona aquellas que son archivos
/// regulares (`DiscoveredKind::File`) con `size_bytes == Some(0)`. Descarta los que
/// estén protegidos por la lista negra (VCS, `.nomedia`, etc.).
pub fn detect(
    entries: &[DiscoveredEntry],
    _scan_root: &Utf8Path,
    profile: &dyn PlatformProfile,
) -> Vec<JunkItem> {
    entries
        .iter()
        .filter(|entry| {
            entry.kind == DiscoveredKind::File
                && entry.size_bytes == Some(0)
                && !blacklist::is_blacklisted(&entry.path, profile)
        })
        .map(|entry| JunkItem {
            path: entry.path.clone(),
            category: JunkCategory::EmptyFile,
            risk: RiskLevel::Low,
            size_bytes: 0,
            explanation: "Empty file (0 bytes)".into(),
            can_clean: true,
        })
        .collect()
}
