//! Detector de directorios de caché de desarrollo.
//!
//! Identifica directorios generados por toolchains y frameworks que pueden regenerarse
//! bajo demanda y suelen ocupar mucho espacio:
//!
//! - `__pycache__` — bytecode de Python (.pyc)
//! - `.venv` — entorno virtual de Python (solo si no hay `pyproject.toml` en el padre)
//! - `target` — directorio de build de Cargo/Rust
//! - `build` — directorio de build genérico (CMake, Meson, etc.)
//!
//! Si el directorio `.venv` tiene un `pyproject.toml` en su padre, se considera parte
//! de un proyecto activo y **no** se reporta.
//!
//! **Tier:** 🔴 High — solo reporte. Estos directorios pueden ser valiosos (entornos
//! configurados, builds incrementales) y nunca deben borrarse sin revisión manual.
//! `can_clean: false`.

use camino::Utf8Path;
use zerodupe_core::{DiscoveredEntry, DiscoveredKind};
use zerodupe_platform::PlatformProfile;

use crate::blacklist;
use crate::types::{JunkCategory, JunkItem, RiskLevel};

const CACHE_DIRS: &[&str] = &["__pycache__", ".venv", "target", "build"];

/// Detecta directorios de caché de desarrollo que no estén en la lista negra.
///
/// Itera las entradas de tipo `Directory` cuyo nombre coincide con `CACHE_DIRS`.
/// Para `.venv`, verifica que el directorio padre no contenga `pyproject.toml`
/// (señal de proyecto activo). El resto de directorios se reportan siempre.
pub fn detect(
    entries: &[DiscoveredEntry],
    _scan_root: &Utf8Path,
    profile: &dyn PlatformProfile,
) -> Vec<JunkItem> {
    entries
        .iter()
        .filter(|entry| entry.kind == DiscoveredKind::Directory)
        .filter(|entry| !blacklist::is_blacklisted(&entry.path, profile))
        .filter_map(|entry| {
            let dir_name = entry.path.file_name().unwrap_or("");
            if !CACHE_DIRS.contains(&dir_name) {
                return None;
            }

            if dir_name == ".venv" {
                let parent = entry.path.parent()?;
                let has_pyproject = parent.join("pyproject.toml").try_exists().is_ok_and(|e| e);
                if has_pyproject {
                    return None;
                }
            }

            Some(JunkItem {
                path: entry.path.clone(),
                category: JunkCategory::CacheFile,
                risk: RiskLevel::High,
                size_bytes: entry.size_bytes.unwrap_or(0),
                explanation: format!("Development cache directory: {dir_name}"),
                can_clean: false,
            })
        })
        .collect()
}
