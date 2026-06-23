//! Detectores de archivos basura — 7 categorías en 3 tiers de riesgo.
//!
//! | Detector | Qué detecta | Tier |
//! |----------|-------------|------|
//! | [`empty_files`] | Archivos de 0 bytes sin contenido | 🟢 Low — trash de SO |
//! | [`empty_dirs`] | Directorios vacíos o con solo subdirectorios vacíos | 🟢 Low — trash de SO |
//! | [`temporary_files`] | Temporales (`.tmp`, `.bak`, `.swp`, `~$`…), backups de editor, crash dumps | 🟢 Low / 🟠 Medium según antigüedad |
//! | [`broken_symlinks`] | Enlaces simbólicos cuyo destino ya no existe | 🟠 Medium — cuarentena |
//! | [`cache_files`] | Directorios de caché de desarrollo (`__pycache__`, `.venv`, `target`, `build`) | 🔴 High — solo reporte |
//! | [`system_junk`] | Archivos de metadatos del SO (`.DS_Store`, `Thumbs.db`, `desktop.ini`…) | 🟢 Low — trash de SO |
//! | [`orphan`][crate::orphan] | Sidecars huérfanos (`.AAE`, `.XMP`, `.THM`, `.json` de Google Takeout) | 🟠 Medium — cuarentena |

pub mod broken_symlinks;
pub mod cache_files;
pub mod empty_dirs;
pub mod empty_files;
pub mod system_junk;
pub mod temporary_files;
