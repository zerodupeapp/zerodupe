//! Define `WorkflowError`, los tipos de error que puede producir la state
//! machine del workflow. Todos los errores son recuperables (el usuario puede
//! reintentar o cancelar).

// ── WorkflowError ────────────────────────────────────────────────────────────

/// Errores que puede retornar el metodo `Workflow::advance`.
///
/// Cubren transiciones invalidas, falta de configuracion, fallos en el pipeline
/// de escaneo y errores de I/O.
#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    /// Se intento ejecutar una accion no permitida desde el estado actual.
    /// Por ejemplo, `StartScan` desde `ReviewingExact`.
    #[error("Transicion de estado invalida")]
    InvalidTransition,

    /// Se intento iniciar un escaneo sin haber seleccionado una carpeta raiz.
    /// Ejecutar `SelectFolder` antes de `StartScan`.
    #[error("No se ha seleccionado una carpeta raiz")]
    NoScanRoot,

    /// Error interno en uno de los pipelines (exactos, similares o higiene).
    /// El mensaje describe la causa especifica.
    #[error("Error en el pipeline: {0}")]
    Pipeline(String),

    /// Error de entrada/salida del sistema de archivos. Se convierte
    /// automaticamente desde `std::io::Error`.
    #[error("Error de I/O: {0}")]
    Io(#[from] std::io::Error),
}
