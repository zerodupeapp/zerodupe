//! Detector de enlaces simbólicos rotos.
//!
//! Identifica enlaces simbólicos cuyo destino ya no existe en el sistema de archivos.
//! Son residuos comunes tras desinstalar aplicaciones, mover directorios o borrar
//! archivos manualmente sin limpiar los enlaces que apuntaban a ellos.
//!
//! **Tier:** 🟠 Medium — estos enlaces no pueden limpiarse automáticamente
//! (`can_clean: false`) porque el usuario debe confirmar que el destino faltante
//! no es temporal (ej. unidad externa desconectada). Van a cuarentena para revisión.

use std::fs;

use camino::Utf8Path;
use zerodupe_core::{DiscoveredEntry, DiscoveredKind};
use zerodupe_platform::PlatformProfile;

use crate::blacklist;
use crate::types::{JunkCategory, JunkItem, RiskLevel};

/// Detecta enlaces simbólicos rotos en el conjunto de entradas descubiertas.
///
/// Para cada entrada de tipo `Symlink`, intenta resolver el enlace con
/// [`std::fs::read_link`] y verifica si el destino existe con
/// [`Path::try_exists`]. Si el destino no existe, se reporta como roto.
/// Los enlaces en la lista negra (VCS, etc.) se omiten.
pub fn detect(
    entries: &[DiscoveredEntry],
    _scan_root: &Utf8Path,
    profile: &dyn PlatformProfile,
) -> Vec<JunkItem> {
    entries
        .iter()
        .filter(|entry| entry.kind == DiscoveredKind::Symlink)
        .filter(|entry| !blacklist::is_blacklisted(&entry.path, profile))
        .filter_map(|entry| {
            let target = match fs::read_link(&entry.path) {
                Ok(t) => t,
                Err(_) => return None,
            };

            if target.try_exists().is_ok_and(|exists| exists) {
                return None;
            }

            let target_display = target.display();
            Some(JunkItem {
                path: entry.path.clone(),
                category: JunkCategory::BrokenSymlink,
                risk: RiskLevel::Medium,
                size_bytes: entry.size_bytes.unwrap_or(0),
                explanation: format!("Broken symlink → {target_display}"),
                can_clean: false,
            })
        })
        .collect()
}
