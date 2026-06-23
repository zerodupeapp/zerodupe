//! Detector de directorios vacíos.
//!
//! Identifica directorios que no contienen archivos reales: pueden estar completamente
//! vacíos o contener únicamente subdirectorios que a su vez están vacíos (anidamiento).
//! El algoritmo recorre los directorios de más profundo a más superficial para propagar
//! correctamente el estado "vacío".
//!
//! Los archivos de sistema (`.DS_Store`, `Thumbs.db`, etc.) se ignoran al determinar si
//! un directorio tiene contenido real — es decir, un directorio que solo contiene
//! `Thumbs.db` se considera vacío.
//!
//! **Tier:** 🟢 Low — trash de SO, se puede limpiar automáticamente.

use std::collections::{HashMap, HashSet};

use camino::{Utf8Path, Utf8PathBuf};
use zerodupe_core::{DiscoveredEntry, DiscoveredKind};
use zerodupe_platform::PlatformProfile;

use crate::types::{JunkCategory, JunkItem, RiskLevel};

/// Detecta directorios vacíos (o con solo subdirectorios vacíos) en el árbol descubierto.
///
/// Construye un mapa de hijos por padre, ordena los directorios por profundidad
/// descendente, y para cada uno verifica si tiene al menos un hijo con contenido real
/// (archivo no-junk o subdirectorio no-vacío). Si no tiene contenido real, se marca
/// como vacío.
pub fn detect(
    entries: &[DiscoveredEntry],
    _scan_root: &Utf8Path,
    profile: &dyn PlatformProfile,
) -> Vec<JunkItem> {
    let dir_paths: HashSet<&Utf8Path> = entries
        .iter()
        .filter(|e| e.kind == DiscoveredKind::Directory)
        .map(|e| e.path.as_path())
        .collect();

    let mut children_by_parent: HashMap<&Utf8Path, Vec<&DiscoveredEntry>> = HashMap::new();
    for entry in entries {
        if let Some(parent) = entry.path.parent()
            && dir_paths.contains(parent)
        {
            children_by_parent.entry(parent).or_default().push(entry);
        }
    }

    let mut dirs_sorted: Vec<&Utf8Path> = dir_paths.into_iter().collect();
    dirs_sorted.sort_by_key(|d| std::cmp::Reverse(d.as_str().matches('/').count()));

    let mut empty_dirs: HashSet<Utf8PathBuf> = HashSet::new();

    for dir_path in dirs_sorted {
        let children = children_by_parent
            .get(dir_path)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let has_real_content = children.iter().any(|child| match child.kind {
            DiscoveredKind::File => !is_system_junk_file_name(&child.path, profile),
            DiscoveredKind::Directory => !empty_dirs.contains(&child.path),
            _ => false,
        });

        if !has_real_content {
            empty_dirs.insert(dir_path.to_path_buf());
        }
    }

    let mut results: Vec<JunkItem> = entries
        .iter()
        .filter(|e| empty_dirs.contains(&e.path))
        .map(|entry| {
            let has_children = children_by_parent
                .get(entry.path.as_path())
                .map(|c| !c.is_empty())
                .unwrap_or(false);
            JunkItem {
                path: entry.path.clone(),
                category: JunkCategory::EmptyDirectory,
                risk: RiskLevel::Low,
                size_bytes: entry.size_bytes.unwrap_or(0),
                explanation: if has_children {
                    "Directory contains only empty subdirectories".into()
                } else {
                    "Empty directory".into()
                },
                can_clean: true,
            }
        })
        .collect();

    results.sort_by(|a, b| a.path.cmp(&b.path));
    results.dedup_by(|a, b| a.path == b.path);
    results
}

fn is_system_junk_file_name(path: &Utf8Path, profile: &dyn PlatformProfile) -> bool {
    let file_name = path.file_name().unwrap_or("");
    let name_lower = if profile.fs_case_sensitive() {
        file_name.to_string()
    } else {
        file_name.to_lowercase()
    };

    profile.system_excludes().iter().any(|exclude| {
        if exclude.match_full_path {
            return false;
        }
        let pat_lower = if profile.fs_case_sensitive() {
            exclude.pattern.to_string()
        } else {
            exclude.pattern.to_lowercase()
        };
        name_lower == pat_lower || name_lower.starts_with(&pat_lower)
    })
}
