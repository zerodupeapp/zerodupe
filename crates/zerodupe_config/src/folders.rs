//! Detección de carpetas comunes del sistema operativo.
//!
//! Proporciona una lista de las 6 carpetas estándar del SO (Documentos,
//! Imágenes, Videos, Música, Descargas, Escritorio) con metadatos de
//! presentación para la GUI: nombre, ruta, color, icono y conteo de items.

use serde::{Deserialize, Serialize};

/// Representa una carpeta común del sistema operativo.
///
/// Cada carpeta incluye metadatos para presentación en la GUI:
/// nombre legible, ruta absoluta, color en hex, icono y conteo de items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonFolder {
    /// Nombre visible de la carpeta (ej. `"Documents"`).
    pub name: String,
    /// Ruta absoluta en el sistema de archivos.
    pub path: String,
    /// Color en formato hex para la GUI (ej. `"#059669"`).
    pub color: String,
    /// Identificador del icono asociado (ej. `"documents"`).
    pub icon: String,
    /// Descripción del tamaño/contenido (ej. `"42 items"`). Vacío si no es legible.
    #[serde(default)]
    pub size: String,
}

/// Retorna las carpetas comunes del sistema operativo actual.
///
/// Detecta hasta 6 carpetas estándar: Documentos, Imágenes, Videos,
/// Música, Descargas y Escritorio. Las carpetas que no existen en el SO
/// actual se omiten automáticamente. Incluye el conteo de items visibles
/// en cada carpeta.
pub fn list_common_folders() -> Vec<CommonFolder> {
    let mut folders = Vec::new();

    #[allow(unused_mut)]
    let mut push_folder = |name: &str, path: std::path::PathBuf, color: &str, icon: &str| {
        let size = folder_size_fast(&path);
        folders.push(CommonFolder {
            name: name.into(),
            path: path.to_string_lossy().into(),
            color: color.into(),
            icon: icon.into(),
            size,
        });
    };

    if let Some(p) = dirs::document_dir() {
        push_folder("Documents", p, "#059669", "documents");
    }
    if let Some(p) = dirs::picture_dir() {
        push_folder("Pictures", p, "#2563EB", "photos");
    }
    if let Some(p) = dirs::video_dir() {
        push_folder("Videos", p, "#7C3AED", "videos");
    }
    if let Some(p) = dirs::audio_dir() {
        push_folder("Music", p, "#DC2626", "music");
    }
    if let Some(p) = dirs::download_dir() {
        push_folder("Downloads", p, "#D97706", "downloads");
    }
    if let Some(p) = dirs::desktop_dir() {
        push_folder("Desktop", p, "#0891B2", "desktop");
    }

    folders
}

/// Quick folder size estimate (file count and total bytes visible, not recursive).
fn folder_size_fast(path: &std::path::Path) -> String {
    let Ok(entries) = std::fs::read_dir(path) else {
        return String::new();
    };
    let count = entries.filter_map(|e| e.ok()).count();
    if count > 0 {
        format!("{} items", count)
    } else {
        String::new()
    }
}
