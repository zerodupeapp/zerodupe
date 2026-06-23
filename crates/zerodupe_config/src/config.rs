//! Definición de la configuración TOML de ZeroDupe.
//!
//! [`ZerodupeConfig`] es el struct raíz que agrupa toda la configuración
//! persistente del usuario: preferencias generales, parámetros de escaneo,
//! directorio de cuarentena, y estrategia del keeper.
//!
//! Todos los structs derivan `Serialize`/`Deserialize` para lectura/escritura
//! en `~/.config/zerodupe/config.toml`.

use serde::{Deserialize, Serialize};
use zerodupe_core::DiscoveryOptions;
use zerodupe_policy::{KeeperStrategy, KeeperWeights};

/// Configuración raíz de ZeroDupe, serializable a TOML.
///
/// Agrupa todas las secciones de configuración: general, escaneo,
/// cuarentena y keeper. Se carga con [`crate::load()`] y se guarda
/// con [`crate::save()`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZerodupeConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub quarantine: QuarantineConfig,
    #[serde(default)]
    pub keeper: KeeperConfig,
}

/// Preferencias generales del usuario.
///
/// Incluye el idioma de la interfaz y el tema visual de la GUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Código de idioma (ISO 639-1). Por defecto `"en"`.
    #[serde(default = "default_language")]
    pub language: String,
    /// Tema visual: `System`, `Light` o `Dark`.
    #[serde(default)]
    pub theme: Theme,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            language: default_language(),
            theme: Theme::default(),
        }
    }
}

/// Tema visual de la GUI.
///
/// - `System`: sigue el tema del sistema operativo (por defecto).
/// - `Light`: tema claro.
/// - `Dark`: tema oscuro.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Theme {
    /// Sigue el tema del sistema operativo.
    #[default]
    System,
    /// Tema claro.
    Light,
    /// Tema oscuro.
    Dark,
}

/// Configuración de escaneo.
///
/// Define el modo de escaneo por defecto, el último directorio escaneado
/// y las opciones de descubrimiento de archivos (exclusiones, profundidad, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanConfig {
    /// Modo de escaneo por defecto: `Exact`, `Similar` o `Full`.
    #[serde(default)]
    pub default_mode: ScanMode,
    /// Último directorio escaneado, para reabrir en la GUI.
    #[serde(default)]
    pub last_directory: Option<String>,
    /// Opciones de descubrimiento: exclusiones, profundidad máxima, etc.
    #[serde(default)]
    pub discovery: DiscoveryOptions,
}

/// Modo de escaneo de la CLI/GUI.
///
/// - `Exact`: solo duplicados exactos (hash BLAKE3 + byte compare).
/// - `Similar`: imágenes similares (pHash + dHash + BK-tree).
/// - `Full`: ambos modos combinados (exactos + similares + higiene).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ScanMode {
    /// Solo duplicados exactos (Pilar 1).
    #[default]
    Exact,
    /// Solo imágenes similares (Pilar 2).
    Similar,
    /// Escaneo completo: exactos + similares + higiene (Pilares 1+2+3).
    Full,
}

/// Configuración del directorio de cuarentena.
///
/// Los archivos duplicados eliminados se mueven aquí en lugar de
/// borrarse definitivamente, permitiendo recuperación manual.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    /// Nombre del directorio de cuarentena. Por defecto `"zerodupe_quarantine"`.
    #[serde(default = "default_quarantine_dir")]
    pub directory: String,
    /// Días tras los cuales se sugiere purgar la cuarentena. Por defecto 30.
    #[serde(default = "default_purge_days")]
    pub default_purge_days: u32,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            directory: default_quarantine_dir(),
            default_purge_days: default_purge_days(),
        }
    }
}

/// Configuración del algoritmo Keeper.
///
/// El Keeper elige qué archivo conservar en cada grupo de duplicados/similares.
/// La estrategia y los pesos determinan cómo se puntúan los archivos candidatos.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeeperConfig {
    /// Estrategia de selección del archivo a conservar.
    #[serde(default)]
    pub strategy: KeeperStrategy,
    /// Pesos de las 5 categorías de puntuación del keeper.
    #[serde(default)]
    pub weights: KeeperWeights,
}

fn default_language() -> String {
    "en".into()
}

fn default_quarantine_dir() -> String {
    "zerodupe_quarantine".into()
}

fn default_purge_days() -> u32 {
    30
}
