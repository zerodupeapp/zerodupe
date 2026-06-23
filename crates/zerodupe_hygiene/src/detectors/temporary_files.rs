//! Detector de archivos temporales y residuos de edición.
//!
//! Identifica archivos que son subproductos de editores y aplicaciones:
//!
//! - **Extensiones temporales:** `.tmp`, `.temp`, `.bak`, `.part`, `.crdownload`, `.partial`
//! - **Archivos de swap de Vim:** `.swp`, `.swo`, `.swn`
//! - **Backups de editor:** archivos terminados en `~` (Emacs, gedit…)
//! - **Archivos de bloqueo de Office:** prefijo `~$` (Word, Excel)
//! - **Crash dumps:** archivos `core.*` (core dumps de Unix)
//!
//! El nivel de riesgo se ajusta por antigüedad: los temporales de más de 30 días son
//! 🟢 Low (seguros de borrar), los de 7-30 días son 🟠 Medium (posiblemente en uso),
//! y los recientes también son 🟠 Medium por precaución.
//!
//! **Tier:** 🟢 Low (>30 días) / 🟠 Medium (resto).

use std::time::{SystemTime, UNIX_EPOCH};

use camino::Utf8Path;
use zerodupe_core::{DiscoveredEntry, DiscoveredKind};
use zerodupe_platform::PlatformProfile;

use crate::blacklist;
use crate::types::{JunkCategory, JunkItem, RiskLevel};

const TEMP_EXTENSIONS: &[&str] = &[
    "tmp",
    "temp",
    "bak",
    "swp",
    "swo",
    "swn",
    "part",
    "crdownload",
    "partial",
];

/// Detecta archivos temporales según extensión, nombre y antigüedad.
///
/// Aplica heurísticas de nombre de archivo (extensión `.tmp`, prefijo `~$`, sufijo `~`,
/// nombre `core.*`) y asigna el nivel de riesgo según la fecha de modificación:
/// más de 30 días → Low, entre 7 y 30 días → Medium, menos de 7 días → Medium
/// (con ajustes para swap de Vim y lock de Office según horas de inactividad).
pub fn detect(
    entries: &[DiscoveredEntry],
    _scan_root: &Utf8Path,
    profile: &dyn PlatformProfile,
) -> Vec<JunkItem> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    entries
        .iter()
        .filter(|entry| {
            entry.kind == DiscoveredKind::File
                && !blacklist::is_blacklisted(&entry.path, profile)
                && is_temp_file(entry)
        })
        .map(|entry| {
            let risk = temp_risk(entry, now);
            JunkItem {
                path: entry.path.clone(),
                category: JunkCategory::TemporaryFile,
                risk,
                size_bytes: entry.size_bytes.unwrap_or(0),
                explanation: temp_explanation(entry),
                can_clean: risk == RiskLevel::Low,
            }
        })
        .collect()
}

fn is_temp_file(entry: &DiscoveredEntry) -> bool {
    let file_name = entry.path.file_name().unwrap_or("");
    let path_str = entry.path.as_str();

    if let Some(ext) = entry.path.extension() {
        let ext_lower = ext.to_lowercase();
        if TEMP_EXTENSIONS.contains(&ext_lower.as_str()) {
            return true;
        }
    }

    if file_name.ends_with('~') {
        return true;
    }

    if file_name.starts_with("~$") {
        return true;
    }

    if let Some(name) = path_str.rsplit('/').next()
        && name.starts_with("core.")
    {
        return true;
    }

    false
}

fn temp_risk(entry: &DiscoveredEntry, now: i64) -> RiskLevel {
    let age_days = entry
        .timestamps
        .modified_unix_seconds
        .map(|mtime| (now - mtime) / 86400)
        .unwrap_or(0);

    if age_days > 30 {
        return RiskLevel::Low;
    }

    if age_days >= 7 {
        return RiskLevel::Medium;
    }

    let age_hours = entry
        .timestamps
        .modified_unix_seconds
        .map(|mtime| (now - mtime) / 3600)
        .unwrap_or(0);

    let file_name = entry.path.file_name().unwrap_or("");

    if file_name.starts_with("~$") && age_hours >= 1 {
        return RiskLevel::Medium;
    }

    let ext = entry.path.extension().unwrap_or("").to_lowercase();
    if ["swp", "swo", "swn"].contains(&ext.as_str()) && age_hours >= 1 {
        return RiskLevel::Medium;
    }

    RiskLevel::Medium
}

fn temp_explanation(entry: &DiscoveredEntry) -> String {
    let file_name = entry.path.file_name().unwrap_or("unknown");

    if file_name.starts_with("~$") {
        return format!("Office lock file: {file_name}");
    }

    if file_name.ends_with('~') {
        return format!("Editor backup file: {file_name}");
    }

    if let Some(name) = entry.path.as_str().rsplit('/').next()
        && name.starts_with("core.")
    {
        return format!("Crash dump: {file_name}");
    }

    if let Some(ext) = entry.path.extension() {
        let ext_lower = ext.to_lowercase();
        if ["swp", "swo", "swn"].contains(&ext_lower.as_str()) {
            return format!("Vim swap file: {file_name}");
        }
        return format!("Temporary file (.{ext_lower}): {file_name}");
    }

    format!("Temporary file: {file_name}")
}
