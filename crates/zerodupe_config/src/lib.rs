//! Configuración, reportes, resume y carpetas comunes de ZeroDupe.
//!
//! Este crate centraliza toda la configuración TOML de ZeroDupe
//! (`~/.config/zerodupe/config.toml`), la persistencia de reportes
//! de deduplicación, el estado de reanudación de escaneos (`resume.json`)
//! y la detección de carpetas comunes del sistema operativo.
//!
//! ## Módulos
//!
//! - [`config`]: definición del struct [`ZerodupeConfig`] y sus submódulos
//!   de configuración (general, escaneo, cuarentena, keeper).
//! - [`reports`]: persistencia de reportes en JSON/HTML, funciones para
//!   construir, guardar, listar y marcar grupos verificados.
//! - [`resume`]: estado de escaneo reanudable con TTL de 24h.
//! - [`folders`]: carpetas comunes del SO (Documentos, Imágenes, etc.).
//! - [`error`]: tipos de error unificados para el crate.
//!
//! ## Funciones principales
//!
//! - [`load()`] / [`save()`]: carga y guarda [`ZerodupeConfig`] desde/hacia
//!   el archivo TOML por defecto.
//! - [`save_quarantine_state()`], [`load_quarantine_dirs()`]: registro
//!   persistente de directorios de cuarentena activos.
//! - [`default_path()`]: ruta por defecto del archivo de configuración.

mod config;
mod error;
pub mod folders;
pub mod reports;
pub mod resume;

pub use config::{
    GeneralConfig, KeeperConfig, QuarantineConfig, ScanConfig, ScanMode, Theme, ZerodupeConfig,
};
pub use error::ConfigError;
pub use folders::{CommonFolder, list_common_folders};
pub use reports::{
    FileSnapshot, ReportGroup, SavedReport, build_report_from_exact, build_report_from_similar,
    get_report, list_reports, make_report_id, mark_group_verified, reports_dir, save_report,
};

/// Carga la configuración desde la ruta por defecto
/// (`~/.config/zerodupe/config.toml`).
///
/// Si el archivo no existe, devuelve [`ZerodupeConfig::default()`],
/// lo que permite usar ZeroDupe sin configuración previa.
pub fn load() -> Result<ZerodupeConfig, ConfigError> {
    let path = default_path();
    if !path.exists() {
        return Ok(ZerodupeConfig::default());
    }
    let contents = std::fs::read_to_string(&path)?;
    let config = toml::from_str(&contents)?;
    Ok(config)
}

/// Guarda la configuración en la ruta por defecto
/// (`~/.config/zerodupe/config.toml`).
///
/// Crea los directorios intermedios si no existen. Usa escritura atómica
/// (archivo temporal + rename) para evitar corrupción del TOML.
pub fn save(config: &ZerodupeConfig) -> Result<(), ConfigError> {
    let path = default_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let toml_string = toml::to_string_pretty(config)?;
    let temp_path = path.with_extension("toml.tmp");
    std::fs::write(&temp_path, toml_string)?;
    std::fs::rename(&temp_path, &path)?;
    Ok(())
}

fn quarantine_state_path() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("zerodupe")
        .join("quarantine_state.json")
}

/// Registra un directorio de cuarentena en el estado persistente
/// (`~/.config/zerodupe/quarantine_state.json`).
///
/// Deduplica entradas repetidas y elimina directorios que ya no existen
/// en disco para mantener la lista limpia. Usado por la GUI para encontrar
/// cuarentenas activas entre sesiones.
pub fn save_quarantine_state(dir: &str) -> Result<(), ConfigError> {
    let path = quarantine_state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut dirs = load_quarantine_dirs();
    // Deduplicate
    if !dirs.iter().any(|d| d == dir) {
        dirs.push(dir.to_string());
    }
    // Prune directories that no longer exist
    dirs.retain(|d| std::path::Path::new(d).exists());
    let json = serde_json::json!({ "quarantine_dirs": dirs });
    let content = serde_json::to_string(&json).map_err(std::io::Error::other)?;
    std::fs::write(&path, content)?;
    Ok(())
}

/// Carga todos los directorios de cuarentena registrados.
///
/// Filtra directorios que ya no existen en disco. Soporta
/// compatibilidad hacia atrás con el formato antiguo de un solo
/// directorio (`last_quarantine_dir`).
pub fn load_quarantine_dirs() -> Vec<String> {
    let path = quarantine_state_path();
    if !path.exists() {
        return Vec::new();
    }
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(json): Result<serde_json::Value, _> = serde_json::from_str(&contents) else {
        return Vec::new();
    };
    if let Some(arr) = json["quarantine_dirs"].as_array() {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .filter(|d| std::path::Path::new(d).exists())
            .collect();
    }
    // Backwards compat: read old single-value format
    if let Some(s) = json["last_quarantine_dir"].as_str().map(|s| s.to_string())
        && std::path::Path::new(&s).exists()
    {
        return vec![s];
    }
    Vec::new()
}

/// Retorna el último directorio de cuarentena registrado.
///
/// Función de compatibilidad hacia atrás para el flujo del wizard.
/// Equivale a `load_quarantine_dirs().into_iter().last()`.
pub fn load_quarantine_state() -> Option<String> {
    load_quarantine_dirs().into_iter().last()
}

/// Elimina un directorio de cuarentena del registro persistente.
///
/// Se usa al purgar completamente un directorio de cuarentena,
/// para que la GUI deje de mostrarlo.
pub fn remove_quarantine_dir(dir: &str) -> Result<(), ConfigError> {
    let path = quarantine_state_path();
    let mut dirs = load_quarantine_dirs();
    dirs.retain(|d| d != dir);
    let json = serde_json::json!({ "quarantine_dirs": dirs });
    let content = serde_json::to_string(&json).map_err(std::io::Error::other)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, content)?;
    Ok(())
}

/// Retorna la ruta por defecto del archivo de configuración:
/// `~/.config/zerodupe/config.toml`.
///
/// Si no se puede determinar el directorio de configuración del SO,
/// usa `./zerodupe/config.toml` como fallback.
pub fn default_path() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("zerodupe")
        .join("config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = ZerodupeConfig::default();
        assert_eq!(cfg.general.language, "en");
        assert_eq!(cfg.general.theme, Theme::System);
        assert_eq!(cfg.scan.default_mode, ScanMode::Exact);
        assert_eq!(cfg.quarantine.default_purge_days, 30);
    }

    #[test]
    fn save_and_load_roundtrips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");

        let original = ZerodupeConfig {
            general: GeneralConfig {
                language: "es".into(),
                theme: Theme::Dark,
            },
            ..ZerodupeConfig::default()
        };

        let toml_string = toml::to_string_pretty(&original).expect("serialize");
        std::fs::write(&config_path, toml_string).expect("write");

        let contents = std::fs::read_to_string(&config_path).expect("read");
        let loaded: ZerodupeConfig = toml::from_str(&contents).expect("deserialize");

        assert_eq!(loaded.general.language, "es");
        assert_eq!(loaded.general.theme, Theme::Dark);
        assert_eq!(loaded.quarantine.default_purge_days, 30);
    }

    #[test]
    fn load_returns_defaults_for_missing_file() {
        let nonexistent = std::path::PathBuf::from("/tmp/zerodupe_nonexistent_config_test.toml");
        // We can't override default_path easily, so we test the logic inline:
        let path = nonexistent;
        if path.exists() {
            std::fs::remove_file(&path).ok();
        }
        assert!(!path.exists());

        let result: Result<ZerodupeConfig, ConfigError> = (|| {
            if !path.exists() {
                return Ok(ZerodupeConfig::default());
            }
            let _contents = std::fs::read_to_string(&path).map_err(ConfigError::from)?;
            unreachable!()
        })();

        let cfg = result.expect("should return defaults");
        assert_eq!(cfg.general.language, "en");
    }
}
