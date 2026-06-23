//! Define `WorkflowState`, el enum que representa cada estado posible en el
//! ciclo de vida del wizard de ZeroDupe. El workflow avanza a traves de estos
//! estados segun las acciones del usuario. Cada estado se serializa a JSON para
//! comunicacion con la GUI via Tauri.

use serde::{Deserialize, Serialize};

// ── WorkflowState ────────────────────────────────────────────────────────────

/// Enum con los 11 estados del wizard de ZeroDupe.
///
/// Los estados se agrupan en 6 fases: inicial, escaneo, revision, limpieza,
/// finalizacion y error/cancelacion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowState {
    /// Estado inicial. El wizard espera que el usuario seleccione una carpeta
    /// (`SelectFolder`) o inicie el escaneo si ya hay raiz configurada
    /// (`StartScan`).
    Idle,

    /// Escaneo de duplicados exactos en progreso. `current` y `total` reflejan
    /// las 5 etapas internas: discovery, agrupacion, hash parcial, hash completo,
    /// comparacion byte a byte.
    ScanningExact { current: u64, total: u64 },

    /// Escaneo exacto completado. El usuario debe decidir si continuar con
    /// similares (`AcceptExact`), saltar a higiene (`SkipSimilar`), o limpiar
    /// los duplicados encontrados.
    ReviewingExact {
        /// Bytes recuperables (espacio que se liberaria al eliminar duplicados).
        reclaimable_bytes: u64,
    },

    /// Escaneo de archivos similares (imagenes) en progreso. Internamente avanza
    /// por 3 etapas: filtrado de candidatos, fingerprinting perceptual, y
    /// deteccion BK-tree + Union-Find.
    ScanningSimilar { current: u64, total: u64 },

    /// Escaneo de similares completado. El usuario decide si continuar con
    /// higiene (`SkipSimilar`), limpiar similares, o saltar tambien higiene
    /// (`SkipHygiene`) para ir directo a resumen.
    ReviewingSimilar { reclaimable_bytes: u64 },

    /// Escaneo de higiene (archivos basura) en progreso. Evalua los 7 detectores
    /// sobre el arbol de directorios.
    ScanningHygiene { current: u64, total: u64 },

    /// Escaneo de higiene completado. El usuario decide si limpiar los archivos
    /// basura (`AcceptHygiene`) o ir directo al resumen final (`SkipHygiene`).
    ReviewingHygiene { reclaimable_bytes: u64 },

    /// Limpieza en progreso. Se mueven duplicados y basura a cuarentena. Los
    /// contadores se actualizan en tiempo real para la barra de progreso.
    Cleaning {
        /// Archivos procesados hasta el momento.
        files_done: u64,
        /// Total de archivos a procesar.
        files_total: u64,
        /// Bytes movidos a cuarentena hasta el momento.
        bytes_done: u64,
    },

    /// Wizard finalizado exitosamente. Contiene el resumen completo de los 3
    /// pilares con grupos encontrados, espacio recuperado y archivos protegidos.
    Complete {
        exact_groups: usize,
        exact_reclaimable: u64,
        exact_files: usize,
        similar_groups: usize,
        similar_reclaimable: u64,
        similar_files: usize,
        hygiene_items: usize,
        hygiene_reclaimable: u64,
        /// Grupos con archivos protegidos (no eliminados por proteccion del SO).
        /// Serializado como JSON para la GUI.
        protected_groups: Option<serde_json::Value>,
        /// Total de archivos protegidos que no se pudieron limpiar.
        protected_file_count: usize,
        /// Archivos que fallaron al intentar mover a cuarentena.
        skipped_file_count: usize,
    },

    /// El usuario cancelo la operacion. Se preservan los reportes generados
    /// hasta el momento de la cancelacion.
    Cancelled,

    /// Ocurrio un error irrecuperable durante el escaneo o limpieza.
    Error {
        /// Mensaje descriptivo del error.
        message: String,
    },
}
