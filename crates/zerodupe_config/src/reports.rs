//! Persistencia de reportes de deduplicación en formato JSON.
//!
//! Los reportes se guardan en `~/.config/zerodupe/reports/` como pares
//! JSON + HTML. Cada reporte contiene los grupos de duplicados encontrados,
//! el archivo conservado (keeper) y los archivos eliminados.
//!
//! Funciones clave:
//! - [`save_report()`]: guarda un reporte como JSON.
//! - [`list_reports()`]: lista todos los reportes existentes, limpiando huérfanos.
//! - [`get_report()`]: carga un reporte por ID.
//! - [`mark_group_verified()`]: marca un grupo como verificado por el usuario.
//! - [`build_report_from_exact()`]: construye un [`SavedReport`] desde un
//!   [`ByteCompareReport`] (Pilar 1).
//! - [`build_report_from_similar()`]: construye un [`SavedReport`] desde un
//!   [`SimilarityReport`] (Pilar 2).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use zerodupe_core::ByteCompareReport;
use zerodupe_similar::SimilarityReport;

/// Reporte de deduplicación guardado en disco (JSON).
///
/// Contiene todos los grupos de duplicados encontrados en un escaneo,
/// junto con metadatos como la fecha de generación, archivos eliminados,
/// espacio recuperado y grupos protegidos.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedReport {
    pub id: String,
    pub title: String,
    pub mode: String,
    pub source_path: String,
    pub generated_at: String,
    pub files_removed: u32,
    pub bytes_reclaimed: u64,
    pub groups_count: u32,
    #[serde(default)]
    pub verified_groups: u32,
    #[serde(default)]
    pub quarantine_path: Option<String>,
    pub status: String,
    pub groups: Vec<ReportGroup>,
    #[serde(default)]
    pub protected_groups: Vec<zerodupe_core::ProtectedGroup>,
}

/// Un grupo de archivos duplicados dentro de un reporte.
///
/// Cada grupo contiene un archivo conservado (keeper) y una lista de
/// archivos eliminados. El usuario puede marcar el grupo como verificado.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportGroup {
    /// Identificador único del grupo dentro del reporte (ej. `"group-0"`).
    pub id: String,
    /// Nombre descriptivo del grupo (nombre del archivo keeper).
    pub name: String,
    /// Algoritmo usado para detectar el duplicado (ej. `"BLAKE3"`).
    pub algo: String,
    /// Porcentaje de coincidencia (ej. `"100%"`, `"85%"`).
    pub match_pct: String,
    /// Si el usuario ha verificado manualmente este grupo.
    pub verified: bool,
    /// Snapshot del archivo conservado (keeper).
    pub keeper: FileSnapshot,
    /// Snapshots de los archivos eliminados.
    pub removed: Vec<FileSnapshot>,
}

/// Snapshot de metadatos de un archivo individual en un reporte.
///
/// No contiene el contenido del archivo, solo sus metadatos para
/// identificar y mostrar en la GUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSnapshot {
    /// Nombre del archivo (sin ruta).
    pub name: String,
    /// Ruta completa del archivo en el momento del escaneo.
    pub path: String,
    /// Tamaño en bytes.
    pub size: u64,
    /// Fecha de última modificación.
    pub modified: String,
    /// Hash del archivo (BLAKE3).
    pub hash: String,
    /// Extensión del archivo.
    pub ext: String,
}

/// Guarda un reporte como archivo JSON en el directorio de reportes.
///
/// Crea el directorio `reports_dir()` si no existe. El archivo se nombra
/// `{report.id}.json`. Retorna la ruta del archivo guardado.
pub fn save_report(report: &SavedReport) -> std::io::Result<PathBuf> {
    let dir = reports_dir()?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", report.id));
    let json = serde_json::to_string_pretty(report)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&path, json)?;
    Ok(path)
}

/// Lista todos los reportes existentes ordenados por fecha (más reciente primero).
///
/// Realiza limpieza automática de reportes huérfanos:
/// - JSON cuyo HTML no existe.
/// - Reportes cuya cuarentena fue eliminada manualmente.
/// - Cuarentenas vacías (sin archivos más allá de `journal.db`).
pub fn list_reports() -> std::io::Result<Vec<SavedReport>> {
    let dir = reports_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut reports: Vec<SavedReport> = Vec::new();
    let mut orphan_ids: Vec<String> = Vec::new();

    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json")
            && let Ok(json) = std::fs::read_to_string(&path)
            && let Ok(report) = serde_json::from_str::<SavedReport>(&json)
        {
            // Verify the HTML file exists
            let html_path = dir.join(format!("{}.html", report.id));
            if !html_path.exists() {
                orphan_ids.push(report.id.clone());
                continue;
            }
            // If quarantine_path is set, verify it still contains quarantined files
            if let Some(ref qpath) = report.quarantine_path {
                let qp = std::path::Path::new(qpath);
                if !qp.exists() {
                    // Quarantine directory was deleted manually — clean up orphan
                    let _ = std::fs::remove_file(&html_path);
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                // Check if the quarantine dir has any actual files (beyond journal.db)
                let has_entries = std::fs::read_dir(qp).is_ok_and(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .any(|e| e.file_name() != "journal.db")
                });
                if !has_entries {
                    // Quarantine was emptied — report is stale, clean up
                    let _ = std::fs::remove_file(&html_path);
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
            }
            reports.push(report);
        }
    }

    // Clean up orphan JSONs whose HTML is missing
    for id in &orphan_ids {
        let json_path = dir.join(format!("{}.json", id));
        let html_path = dir.join(format!("{}.html", id));
        let _ = std::fs::remove_file(&json_path);
        let _ = std::fs::remove_file(&html_path);
    }

    reports.sort_by(|a, b| b.generated_at.cmp(&a.generated_at));
    Ok(reports)
}

/// Carga un reporte individual por su ID.
///
/// Busca `{reports_dir()}/{id}.json` y lo deserializa.
/// Retorna `None` si el archivo no existe.
pub fn get_report(id: &str) -> std::io::Result<Option<SavedReport>> {
    let dir = reports_dir()?;
    let path = dir.join(format!("{}.json", id));
    if !path.exists() {
        return Ok(None);
    }
    let json = std::fs::read_to_string(path)?;
    let report = serde_json::from_str(&json)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(report))
}

/// Marca un grupo de duplicados como verificado (o no verificado) dentro de un reporte.
///
/// Actualiza el contador `verified_groups` del reporte y guarda los cambios.
/// Retorna error si el reporte o el grupo no existen.
pub fn mark_group_verified(report_id: &str, group_id: &str, verified: bool) -> std::io::Result<()> {
    let mut report = get_report(report_id)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "report not found"))?;

    let mut found = false;
    for group in &mut report.groups {
        if group.id == group_id {
            group.verified = verified;
            found = true;
            break;
        }
    }

    if !found {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "group not found",
        ));
    }

    report.verified_groups = report.groups.iter().filter(|g| g.verified).count() as u32;

    save_report(&report)?;
    Ok(())
}

/// Build a human-readable folder name from a path for report filenames.
fn folder_name(source_path: &str) -> String {
    if source_path.is_empty() || source_path == "/" {
        return "root".to_string();
    }
    // Take the last path component
    let p = std::path::Path::new(source_path);
    p.file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

/// Genera un ID descriptivo para un reporte nuevo.
///
/// Formato: `2026-06-07_150530_Documents_exact_a1b2c3`
/// donde el último segmento es un UUID v4 truncado a 6 caracteres
/// para garantizar unicidad.
pub fn make_report_id(source_path: &str, mode: &str) -> String {
    let now = now_local();
    let short = &uuid::Uuid::new_v4().to_string()[..6];
    format!(
        "{}_{}_{}_{}_{}",
        now.date,
        now.time,
        folder_name(source_path),
        mode,
        short
    )
}

/// Construye un [`SavedReport`] a partir de un [`ByteCompareReport`] (Pilar 1).
///
/// Convierte los grupos confirmados de duplicados exactos en grupos de
/// reporte con snapshots de archivos, calculando el total de archivos
/// eliminados y bytes recuperables. Incluye los grupos protegidos que
/// no fueron eliminados automáticamente.
pub fn build_report_from_exact(
    report: &ByteCompareReport,
    report_id: &str,
    source_path: &str,
    protected_groups: &[zerodupe_core::ProtectedGroup],
) -> SavedReport {
    let groups: Vec<ReportGroup> = report
        .confirmed_groups
        .iter()
        .enumerate()
        .map(|(i, g)| {
            let keeper_file = &g.files[g.keeper_index];
            let keeper_snapshot = FileSnapshot {
                name: keeper_file
                    .path
                    .file_name()
                    .unwrap_or("unknown")
                    .to_string(),
                path: keeper_file.path.as_str().to_string(),
                size: keeper_file.size_bytes,
                modified: "unknown".to_string(),
                hash: "BLAKE3".to_string(),
                ext: keeper_file.path.extension().unwrap_or("").to_string(),
            };

            let removed: Vec<FileSnapshot> = g
                .files
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != g.keeper_index)
                .map(|(_, f)| FileSnapshot {
                    name: f.path.file_name().unwrap_or("unknown").to_string(),
                    path: f.path.as_str().to_string(),
                    size: f.size_bytes,
                    modified: "unknown".to_string(),
                    hash: "BLAKE3".to_string(),
                    ext: f.path.extension().unwrap_or("").to_string(),
                })
                .collect();

            ReportGroup {
                id: format!("group-{i}"),
                name: keeper_file
                    .path
                    .file_name()
                    .unwrap_or("unknown")
                    .to_string(),
                algo: "BLAKE3".to_string(),
                match_pct: "100%".to_string(),
                verified: false,
                keeper: keeper_snapshot,
                removed,
            }
        })
        .collect();

    let dup_count: usize = report
        .confirmed_groups
        .iter()
        .map(|g| g.files.len().saturating_sub(1))
        .sum();
    let reclaimable: u64 = report
        .confirmed_groups
        .iter()
        .map(|g| {
            g.size_bytes
                .saturating_mul(g.files.len().saturating_sub(1) as u64)
        })
        .sum();

    let now = now_local();
    SavedReport {
        id: report_id.to_string(),
        title: format!("Exact · {} — {}", folder_name(source_path), now.date),
        mode: "exact".to_string(),
        source_path: source_path.to_string(),
        generated_at: format!("{} {}", now.date, now.time),
        files_removed: dup_count as u32,
        bytes_reclaimed: reclaimable,
        groups_count: report.confirmed_groups.len() as u32,
        verified_groups: 0,
        status: "active".to_string(),
        quarantine_path: None,
        groups,
        protected_groups: protected_groups.to_vec(),
    }
}

/// Normaliza la similitud promedio de un grupo a porcentaje entero (0–100).
fn similarity_pct(avg_similarity: f64) -> u32 {
    let pct = if avg_similarity <= 1.0 {
        avg_similarity * 100.0
    } else {
        avg_similarity
    };
    pct.round().clamp(0.0, 100.0) as u32
}

/// Construye un [`SavedReport`] a partir de un [`SimilarityReport`] (Pilar 2).
///
/// Convierte los grupos de imágenes similares en grupos de reporte con
/// snapshots de archivos. El porcentaje de coincidencia refleja la similitud
/// perceptual promedio del grupo (no es 100% como en exactos).
pub fn build_report_from_similar(
    report: &SimilarityReport,
    report_id: &str,
    source_path: &str,
    protected_groups: &[zerodupe_core::ProtectedGroup],
) -> SavedReport {
    let groups: Vec<ReportGroup> = report
        .groups
        .iter()
        .enumerate()
        .map(|(i, g)| {
            let keeper_file = &g.files[g.keeper_index];
            let snapshot = |f: &zerodupe_core::FileCandidate| FileSnapshot {
                name: f.path.file_name().unwrap_or("unknown").to_string(),
                path: f.path.as_str().to_string(),
                size: f.size_bytes,
                modified: "unknown".to_string(),
                hash: g.detector.clone(),
                ext: f.path.extension().unwrap_or("").to_string(),
            };

            let removed: Vec<FileSnapshot> = g
                .files
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != g.keeper_index)
                .map(|(_, f)| snapshot(f))
                .collect();

            ReportGroup {
                id: format!("group-{i}"),
                name: keeper_file
                    .path
                    .file_name()
                    .unwrap_or("unknown")
                    .to_string(),
                algo: g.detector.clone(),
                match_pct: format!("{}%", similarity_pct(g.avg_similarity)),
                verified: false,
                keeper: snapshot(keeper_file),
                removed,
            }
        })
        .collect();

    let dup_count: usize = report
        .groups
        .iter()
        .map(|g| g.files.len().saturating_sub(1))
        .sum();
    let reclaimable: u64 = report
        .groups
        .iter()
        .map(|g| {
            g.files
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != g.keeper_index)
                .map(|(_, f)| f.size_bytes)
                .sum::<u64>()
        })
        .sum();

    let now = now_local();
    SavedReport {
        id: report_id.to_string(),
        title: format!("Similar · {} — {}", folder_name(source_path), now.date),
        mode: "similar".to_string(),
        source_path: source_path.to_string(),
        generated_at: format!("{} {}", now.date, now.time),
        files_removed: dup_count as u32,
        bytes_reclaimed: reclaimable,
        groups_count: report.groups.len() as u32,
        verified_groups: 0,
        status: "active".to_string(),
        quarantine_path: None,
        groups,
        protected_groups: protected_groups.to_vec(),
    }
}

/// Retorna el directorio de reportes: `~/.config/zerodupe/reports/`.
pub fn reports_dir() -> std::io::Result<PathBuf> {
    let dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("zerodupe")
        .join("reports");
    Ok(dir)
}

struct LocalNow {
    date: String, // "2026-06-07"
    time: String, // "15:05:30"
}

fn now_local() -> LocalNow {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let (y, m, d) = (now.year(), now.month() as u8, now.day());
    let (h, min, s) = (now.hour(), now.minute(), now.second());
    LocalNow {
        date: format!("{y:04}-{m:02}-{d:02}"),
        time: format!("{h:02}:{min:02}:{s:02}"),
    }
}
