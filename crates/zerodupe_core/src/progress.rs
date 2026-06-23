//! Sistema de reporte de progreso para el pipeline.
//!
//! Define el trait [`ProgressReporter`] y los tipos [`ProgressEvent`] y
//! [`ScanStage`] que permiten a las etapas del pipeline emitir eventos de
//! progreso hacia la GUI o CLI. Cada evento indica en qué etapa se encuentra
//! el escaneo, cuántas unidades se han procesado y cuántas faltan.
//!
//! # Flujo
//!
//! ```text
//! ScanStage::Discovery → SizeGrouping → PartialHash → FullHash
//!                    → ByteCompare → SimilarityDetection → Hygiene → Cleaning
//! ```
//!
//! El `ProgressReporter` es un trait para permitir distintas implementaciones:
//! la GUI usa canales Tauri, la CLI imprime barras de progreso, y los tests
//! usan un reporter nulo.

use serde::{Deserialize, Serialize};

/// Receptor de eventos de progreso del pipeline.
///
/// Cada etapa del pipeline recibe una referencia a un implementador de este
/// trait y llama a `emit()` periódicamente con el estado actual. El reporter
/// puede enviar los eventos a la GUI (vía eventos Tauri), imprimirlos en la
/// terminal, o descartarlos en tests.
pub trait ProgressReporter: Send + Sync {
    /// Emite un evento de progreso al consumidor (GUI, CLI, etc.).
    fn emit(&self, event: ProgressEvent);
}

/// Evento de progreso emitido por una etapa del pipeline.
///
/// Contiene la etapa actual, el contador de unidades procesadas vs. total,
/// y opcionalmente el archivo actual y los bytes procesados/totales para
/// barras de progreso más detalladas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEvent {
    /// Etapa actual del pipeline.
    pub stage: ScanStage,
    /// Unidades procesadas hasta ahora.
    pub current: u64,
    /// Total de unidades a procesar en esta etapa.
    pub total: u64,
    /// Ruta del archivo que se está procesando actualmente, si aplica.
    pub current_file: Option<String>,
    /// Bytes procesados en esta etapa (para barras de progreso de I/O).
    pub bytes_processed: Option<u64>,
    /// Total de bytes a procesar en esta etapa.
    pub bytes_total: Option<u64>,
}

/// Etapas del pipeline de escaneo, en orden de ejecución.
///
/// Cada etapa se reporta como un [`ProgressEvent`] con su `ScanStage`
/// correspondiente. La GUI usa esta enumeración para mostrar la barra de
/// progreso con la etapa actual.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanStage {
    /// Recorriendo el sistema de archivos (descubriendo entradas).
    Discovery,
    /// Agrupando archivos por tamaño.
    SizeGrouping,
    /// Calculando hashes parciales (cabeza/cola).
    PartialHash,
    /// Calculando hashes completos (BLAKE3).
    FullHash,
    /// Comparando archivos byte a byte (verificación final).
    ByteCompare,
    /// Detectando imágenes similares (pHash + dHash + BK-tree).
    SimilarityDetection,
    /// Escaneando archivos basura (higiene).
    Hygiene,
    /// Ejecutando acciones de limpieza (eliminar/mover a cuarentena).
    Cleaning,
}
