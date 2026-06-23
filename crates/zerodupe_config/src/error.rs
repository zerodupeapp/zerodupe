//! Tipos de error del crate `zerodupe_config`.
//!
//! Centraliza los errores de E/S y de serialización/deserialización
//! TOML que pueden ocurrir al leer o escribir la configuración.

use thiserror::Error;

/// Errores unificados del módulo de configuración.
///
/// Cubre tres categorías: errores de I/O del sistema de archivos,
/// errores de parseo de TOML (lectura de configuración corrupta),
/// y errores de serialización de TOML (escritura fallida).
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Error de entrada/salida del sistema de archivos.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Error al deserializar TOML (archivo de configuración corrupto).
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
    /// Error al serializar TOML (fallo al escribir configuración).
    #[error("TOML serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),
}
