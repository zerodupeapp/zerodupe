//! Generación de reportes HTML y resúmenes JSON para los tres pilares de ZeroDupe.
//!
//! Este crate produce:
//! - **Reportes HTML** por pilar (exactos, similares, higiene) con diseño responsivo,
//!   tablas de grupos, secciones de archivos protegidos y resúmenes en español/inglés.
//! - **Resúmenes JSON** (`ScanSummary`, `FullScanSummary`) para la CLI y automatización.
//! - **Reporte JSON completo** (`FullScanReport`) que agrega discovery, duplicados exactos,
//!   imágenes similares e higiene en un solo archivo serializable.
//!
//! El punto de entrada principal es [`write_json_report`], que escribe el reporte agregado
//! a disco. Los reportes HTML se generan desde el módulo [`html`]. Los textos traducidos
//! viven en [`i18n`].

pub mod html;
pub mod i18n;

pub use html::append_protected_section;

use serde::{Deserialize, Serialize};
use std::path::Path;
use zerodupe_core::{ByteCompareReport, DiscoveryReport};
use zerodupe_hygiene::types::HygieneReport;
use zerodupe_similar::SimilarityReport;

/// Resumen mínimo de escaneo con los dos datos esenciales: cantidad de grupos
/// de duplicados exactos confirmados y bytes recuperables si se eliminan los duplicados.
///
/// Es el contrato más pequeño que la CLI, GUI y automatización usan para mostrar
/// resultados sin exponer la estructura interna completa del reporte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub exact_duplicate_groups: usize,
    pub reclaimable_bytes: u64,
}

/// Serializa un [`ScanSummary`] como JSON con indentación legible.
///
/// Útil para mostrar resultados en terminal (`--json`) o guardar en archivo
/// de log sin depender del reporte completo.
pub fn to_pretty_json(summary: &ScanSummary) -> serde_json::Result<String> {
    serde_json::to_string_pretty(summary)
}

/// Resumen agregado de un escaneo completo, con conteos y bytes para los tres pilares.
///
/// Contiene:
/// - Archivos totales escaneados y bytes totales leídos.
/// - Duplicados exactos: grupos, archivos duplicados, bytes recuperables.
/// - Imágenes similares: grupos, archivos similares, bytes recuperables.
/// - Higiene: ítems de basura encontrados, bytes recuperables.
///
/// Se construye automáticamente desde [`FullScanReport::new_exact`] y
/// [`FullScanReport::new_similar`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullScanSummary {
    pub total_files_scanned: usize,
    pub total_bytes_scanned: u64,
    pub exact_duplicate_groups: usize,
    pub exact_duplicate_files: usize,
    pub exact_reclaimable_bytes: u64,
    pub similar_groups: usize,
    pub similar_files: usize,
    pub similar_reclaimable_bytes: u64,
    pub hygiene_items: usize,
    pub hygiene_reclaimable_bytes: u64,
}

/// Reporte completo de escaneo que agrega todas las etapas: discovery, duplicados
/// exactos, imágenes similares e higiene, más un resumen numérico.
///
/// Es la estructura canónica para serializar a JSON vía [`write_json_report`].
/// Las etapas opcionales (`exact_duplicates`, `similar_images`, `hygiene`) son
/// `Option` porque no todos los escaneos ejecutan los tres pilares.
///
/// Se construye con los constructores [`FullScanReport::new_exact`] o
/// [`FullScanReport::new_similar`], que calculan automáticamente el
/// [`FullScanSummary`]. Las etapas faltantes deben asignarse manualmente
/// después si se ejecutaron.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullScanReport {
    pub version: String,
    pub scan_root: String,
    pub timestamp: String,
    pub discovery: DiscoveryReport,
    pub exact_duplicates: Option<ByteCompareReport>,
    pub similar_images: Option<SimilarityReport>,
    pub hygiene: Option<HygieneReport>,
    pub summary: FullScanSummary,
}

impl FullScanReport {
    /// Construye un [`FullScanReport`] con resultados de duplicados exactos.
    ///
    /// Calcula automáticamente el [`FullScanSummary`] a partir del reporte de
    /// discovery y el de byte-compare. Las etapas de similares e higiene quedan
    /// en `None` y deben asignarse después si corresponde.
    #[must_use]
    pub fn new_exact(
        version: String,
        scan_root: String,
        timestamp: String,
        discovery: DiscoveryReport,
        exact_duplicates: ByteCompareReport,
    ) -> Self {
        let total_files_scanned = discovery.summary.files;
        let total_bytes_scanned = discovery.summary.total_file_bytes;
        let exact_duplicate_groups = exact_duplicates.confirmed_groups.len();
        let exact_duplicate_files: usize = exact_duplicates
            .confirmed_groups
            .iter()
            .map(|g| g.files.len().saturating_sub(1))
            .sum();
        let exact_reclaimable_bytes: u64 = exact_duplicates
            .confirmed_groups
            .iter()
            .map(|g| g.size_bytes * g.files.len().saturating_sub(1) as u64)
            .sum();

        Self {
            version,
            scan_root,
            timestamp,
            discovery,
            exact_duplicates: Some(exact_duplicates),
            similar_images: None,
            hygiene: None,
            summary: FullScanSummary {
                total_files_scanned,
                total_bytes_scanned,
                exact_duplicate_groups,
                exact_duplicate_files,
                exact_reclaimable_bytes,
                similar_groups: 0,
                similar_files: 0,
                similar_reclaimable_bytes: 0,
                hygiene_items: 0,
                hygiene_reclaimable_bytes: 0,
            },
        }
    }

    /// Construye un [`FullScanReport`] con resultados de imágenes similares.
    ///
    /// Calcula automáticamente el [`FullScanSummary`] a partir del reporte de
    /// discovery y el de similitud. Las etapas de exactos e higiene quedan en
    /// `None` y deben asignarse después si corresponde.
    #[must_use]
    pub fn new_similar(
        version: String,
        scan_root: String,
        timestamp: String,
        discovery: DiscoveryReport,
        similar_images: SimilarityReport,
    ) -> Self {
        let total_files_scanned = discovery.summary.files;
        let total_bytes_scanned = discovery.summary.total_file_bytes;
        let similar_groups = similar_images.groups.len();
        let similar_files: usize = similar_images
            .groups
            .iter()
            .map(|g| g.files.len().saturating_sub(1))
            .sum();
        let similar_reclaimable_bytes: u64 = similar_images
            .groups
            .iter()
            .flat_map(|g| {
                g.files
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != g.keeper_index)
                    .map(|(_, f)| f.size_bytes)
            })
            .sum();

        Self {
            version,
            scan_root,
            timestamp,
            discovery,
            exact_duplicates: None,
            similar_images: Some(similar_images),
            hygiene: None,
            summary: FullScanSummary {
                total_files_scanned,
                total_bytes_scanned,
                exact_duplicate_groups: 0,
                exact_duplicate_files: 0,
                exact_reclaimable_bytes: 0,
                similar_groups,
                similar_files,
                similar_reclaimable_bytes,
                hygiene_items: 0,
                hygiene_reclaimable_bytes: 0,
            },
        }
    }
}

/// Escribe un [`FullScanReport`] a disco como JSON con indentación legible.
///
/// Es el punto de entrada canónico para persistir el resultado completo de un
/// escaneo. El archivo resultante puede leerse luego con `serde_json` o
/// inspeccionarse manualmente.
pub fn write_json_report(report: &FullScanReport, path: &Path) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(report).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_summary() {
        let json = to_pretty_json(&ScanSummary {
            exact_duplicate_groups: 0,
            reclaimable_bytes: 0,
        })
        .expect("summary should serialize");

        assert!(json.contains("exact_duplicate_groups"));
    }
}
