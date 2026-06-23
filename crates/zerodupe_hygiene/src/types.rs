//! Tipos de datos del Pilar 3 — Higiene.
//!
//! Define las estructuras centrales para representar hallazgos de basura:
//!
//! - [`JunkCategory`] — 7 categorías de basura detectables (una por detector).
//! - [`RiskLevel`] — 3 niveles de riesgo (Low, Medium, High) que mapean a los tiers.
//! - [`JunkItem`] — un ítem individual detectado, con ruta, categoría, riesgo y explicación.
//! - [`HygieneReport`] — reporte completo con todos los ítems y resumen agregado.
//! - [`HygieneSummary`] — conteos y tamaños por categoría y nivel de riesgo.

use std::fmt;

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

/// Categoría de archivo basura detectado.
///
/// Cada variante corresponde a uno de los 7 detectores del Pilar 3.
/// Implementa `Display` para nombres legibles en reportes HTML y CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JunkCategory {
    /// Archivo regular sin contenido (0 bytes).
    EmptyFile,
    /// Directorio sin archivos reales (posiblemente con subdirectorios vacíos).
    EmptyDirectory,
    /// Archivo temporal: `.tmp`, `.bak`, `.swp`, backups de editor, crash dumps.
    TemporaryFile,
    /// Enlace simbólico que apunta a un destino inexistente.
    BrokenSymlink,
    /// Directorio de caché de desarrollo: `__pycache__`, `.venv`, `target`, `build`.
    CacheFile,
    /// Archivo de metadatos del SO: `.DS_Store`, `Thumbs.db`, `desktop.ini`, etc.
    SystemJunk,
    /// Sidecar huérfano: `.AAE`, `.XMP`, `.THM`, `.json` de Google Takeout sin su archivo principal.
    OrphanSidecar,
}

impl fmt::Display for JunkCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JunkCategory::EmptyFile => write!(f, "Empty Files"),
            JunkCategory::EmptyDirectory => write!(f, "Empty Directories"),
            JunkCategory::TemporaryFile => write!(f, "Temporary Files"),
            JunkCategory::BrokenSymlink => write!(f, "Broken Symlinks"),
            JunkCategory::CacheFile => write!(f, "Cache Files"),
            JunkCategory::SystemJunk => write!(f, "System Junk"),
            JunkCategory::OrphanSidecar => write!(f, "Orphan Sidecars"),
        }
    }
}

/// Nivel de riesgo de un ítem basura.
///
/// Determina qué acción puede tomar ZeroDupe automáticamente:
///
/// | Nivel | Tier | Acción automática |
/// |-------|------|-------------------|
/// | `Low` | 🟢 trash SO | Limpieza automática permitida |
/// | `Medium` | 🟠 cuarentena | Va a cuarentena, requiere confirmación |
/// | `High` | 🔴 solo reporte | Solo se informa, nunca se borra |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

/// Un ítem individual de basura detectado por cualquiera de los 7 detectores.
///
/// Contiene toda la información necesaria para que el usuario decida si limpiarlo:
/// ruta, categoría, nivel de riesgo, tamaño en bytes, explicación legible y si
/// puede limpiarse automáticamente.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JunkItem {
    /// Ruta completa al archivo o directorio.
    pub path: Utf8PathBuf,
    /// Categoría de basura (cuál detector lo encontró).
    pub category: JunkCategory,
    /// Nivel de riesgo (determina la acción permitida).
    pub risk: RiskLevel,
    /// Tamaño en bytes (0 para directorios y enlaces simbólicos).
    pub size_bytes: u64,
    /// Explicación legible para mostrar al usuario.
    pub explanation: String,
    /// Si el ítem puede limpiarse automáticamente (`risk == Low`).
    pub can_clean: bool,
}

/// Resumen agregado de un reporte de higiene.
///
/// Contiene conteos totales, desglose por nivel de riesgo y por categoría.
/// Se calcula automáticamente al construir un [`HygieneReport`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HygieneSummary {
    /// Número total de ítems detectados.
    pub total_items: usize,
    /// Suma de bytes de todos los ítems.
    pub total_size_bytes: u64,
    /// Cantidad de ítems con riesgo bajo (🟢 limpiables automáticamente).
    pub low_risk_count: usize,
    /// Cantidad de ítems con riesgo medio (🟠 requieren revisión).
    pub medium_risk_count: usize,
    /// Cantidad de ítems con riesgo alto (🔴 solo reporte).
    pub high_risk_count: usize,
    /// Desglose por categoría: (nombre, cantidad, bytes).
    pub by_category: Vec<(String, usize, u64)>,
}

/// Reporte completo de higiene — resultado final del pipeline de 7 detectores.
///
/// Se construye con [`HygieneReport::new`] a partir de un vector de [`JunkItem`].
/// Calcula automáticamente el resumen agregado ([`HygieneSummary`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HygieneReport {
    /// Todos los ítems detectados (sin filtrar por riesgo).
    pub items: Vec<JunkItem>,
    /// Resumen agregado con conteos y desgloses.
    pub summary: HygieneSummary,
}

impl HygieneReport {
    /// Construye un reporte a partir de los ítems detectados.
    ///
    /// Calcula automáticamente:
    /// - `total_items` y `total_size_bytes`
    /// - Conteos por nivel de riesgo (`low_risk_count`, `medium_risk_count`, `high_risk_count`)
    /// - Desglose `by_category` ordenado alfabéticamente con conteo y bytes por categoría
    pub fn new(items: Vec<JunkItem>) -> Self {
        let total_items = items.len();
        let total_size_bytes: u64 = items.iter().map(|i| i.size_bytes).sum();
        let low_risk_count = items.iter().filter(|i| i.risk == RiskLevel::Low).count();
        let medium_risk_count = items.iter().filter(|i| i.risk == RiskLevel::Medium).count();
        let high_risk_count = items.iter().filter(|i| i.risk == RiskLevel::High).count();

        use std::collections::BTreeMap;
        let mut cat_map: BTreeMap<String, (usize, u64)> = BTreeMap::new();
        for item in &items {
            let cat_name = format!("{}", item.category);
            let entry = cat_map.entry(cat_name).or_default();
            entry.0 += 1;
            entry.1 += item.size_bytes;
        }
        let by_category: Vec<(String, usize, u64)> = cat_map
            .into_iter()
            .map(|(k, (count, size))| (k, count, size))
            .collect();

        Self {
            items,
            summary: HygieneSummary {
                total_items,
                total_size_bytes,
                low_risk_count,
                medium_risk_count,
                high_risk_count,
                by_category,
            },
        }
    }
}
