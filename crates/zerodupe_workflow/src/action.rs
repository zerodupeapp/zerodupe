//! Define `WorkflowAction`, el enum con las acciones que el usuario (o la GUI)
//! puede disparar para hacer avanzar la state machine. Cada accion es valida
//! solo desde ciertos estados; dispararla desde un estado incorrecto produce
//! `WorkflowError::InvalidTransition`.

// ── WorkflowAction ───────────────────────────────────────────────────────────

/// Acciones que el usuario puede ejecutar sobre el workflow.
///
/// Representan decisiones del usuario en cada pantalla del wizard: seleccionar
/// carpeta, iniciar/aceptar/saltar escaneos, limpiar, cancelar o reiniciar.
#[derive(Debug, Clone)]
pub enum WorkflowAction {
    /// Selecciona la carpeta raiz a escanear. Solo valido desde `Idle`.
    SelectFolder {
        /// Ruta absoluta a la carpeta.
        path: String,
    },

    /// Inicia el pipeline completo de escaneo (exactos → similares → higiene).
    /// Requiere que `SelectFolder` se haya ejecutado antes. Solo valido desde `Idle`.
    StartScan,

    /// Inicia un escaneo solo de imagenes similares, sin pasar por la fase de
    /// duplicados exactos. Requiere `SelectFolder` previo. Solo valido desde `Idle`.
    StartSimilarScan,

    /// El usuario acepta los resultados de duplicados exactos y quiere continuar
    /// con el escaneo de similares. Solo valido desde `ReviewingExact`.
    AcceptExact,

    /// El usuario quiere saltar el escaneo de similares y pasar directo a higiene.
    /// Valido desde `ReviewingExact` o `ReviewingSimilar`.
    SkipSimilar,

    /// El usuario quiere saltar el escaneo de higiene e ir directo al resumen final.
    /// Valido desde `ReviewingSimilar` o `ReviewingHygiene`.
    SkipHygiene,

    /// El usuario acepta los resultados de higiene y quiere proceder a limpiar.
    /// Solo valido desde `ReviewingHygiene`.
    AcceptHygiene,

    /// Limpieza automatica con regla predefinida (ej. "newest", "largest").
    /// Valido desde `ReviewingExact`.
    AutoClean {
        /// Regla de seleccion de keeper (archivo a conservar).
        rule: String,
    },

    /// Limpieza manual donde el usuario elige explicitamente que archivo conservar
    /// en cada grupo. Valido desde `ReviewingExact` o `ReviewingSimilar`.
    ConfirmClean {
        /// Indices de los archivos keeper por grupo.
        keepers: Vec<usize>,
    },

    /// Cancela la operacion en curso. Valido desde cualquier estado.
    Cancel,

    /// Reinicia el workflow al estado `Idle`, limpiando todos los reportes.
    /// Valido desde cualquier estado.
    Reset,
}
