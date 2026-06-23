//! Estado de reanudación de escaneos (`resume.json`).
//!
//! Permite reanudar un escaneo interrumpido guardando el progreso
//! en `~/.cache/zerodupe/resume.json`. El estado tiene una validez
//! de 24 horas (TTL) y requiere que la raíz del escaneo aún exista en disco.
//!
//! ## Funciones principales
//!
//! - [`save_resume_state()`]: guarda el estado actual del escaneo.
//! - [`load_resume_state()`]: carga el estado anterior si es válido.
//! - [`clear_resume_state()`]: elimina el estado persistido.
//! - [`ResumeState::is_valid()`]: verifica TTL y existencia de la raíz.

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::path::PathBuf;

thread_local! {
    static MOCKED_RESUME_PATH: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Establece una ruta alternativa para tests (no usar en producción).
#[doc(hidden)]
pub fn set_resume_path(path: PathBuf) {
    MOCKED_RESUME_PATH.with(|p| *p.borrow_mut() = Some(path));
}

/// Limpia la ruta mock de resume (no usar en producción).
#[doc(hidden)]
pub fn clear_mocked_resume_path() {
    MOCKED_RESUME_PATH.with(|p| *p.borrow_mut() = None);
}

/// Estado de un escaneo en progreso, guardado para posible reanudación.
///
/// Contiene la raíz del escaneo, el modo, el progreso actual
/// y la marca de tiempo de inicio (ISO 8601). Válido por 24 horas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeState {
    /// Ruta raíz del escaneo.
    pub scan_root: String,
    /// Modo de escaneo (`"exact"`, `"similar"`, `"full"`).
    pub mode: String,
    /// Archivos procesados hasta el momento.
    pub files_processed: u64,
    /// Total de archivos a procesar.
    pub total_files: u64,
    /// Marca de tiempo ISO 8601 del inicio del escaneo.
    pub started_at: String,
}

impl ResumeState {
    /// Verifica si el estado de reanudación sigue siendo válido.
    ///
    /// Un estado es válido si:
    /// - Han pasado menos de 24 horas desde `started_at`.
    /// - La raíz del escaneo (`scan_root`) aún existe en disco.
    pub fn is_valid(&self) -> bool {
        if let Ok(started) = parse_iso8601(&self.started_at) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let age = now.saturating_sub(started);
            if age.as_secs() > 24 * 3600 {
                return false;
            }
        } else {
            return false;
        }
        std::path::Path::new(&self.scan_root).exists()
    }
}

fn parse_iso8601(s: &str) -> Result<std::time::Duration, ()> {
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 {
        return Err(());
    }
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    if date_parts.len() != 3 {
        return Err(());
    }
    let year: i64 = date_parts[0].parse().map_err(|_| ())?;
    let month: u64 = date_parts[1].parse().map_err(|_| ())?;
    let day: u64 = date_parts[2].parse().map_err(|_| ())?;
    let time_part = if let Some(t) = parts[1].strip_suffix('Z') {
        t
    } else {
        parts[1]
    };
    let time_parts: Vec<&str> = time_part.split(':').collect();
    let hour: u64 = time_parts.first().ok_or(())?.parse().map_err(|_| ())?;
    let min: u64 = time_parts.get(1).ok_or(())?.parse().map_err(|_| ())?;
    let sec: u64 = time_parts
        .get(2)
        .unwrap_or(&"0")
        .split('.')
        .next()
        .unwrap_or("0")
        .parse()
        .map_err(|_| ())?;

    let days = days_since_epoch(year, month, day);
    let total = days * 86400 + hour * 3600 + min * 60 + sec;
    Ok(std::time::Duration::from_secs(total))
}

fn days_since_epoch(y: i64, m: u64, d: u64) -> u64 {
    let mut days = 0u64;
    for year in 1970..y {
        days += if is_leap(year) { 366 } else { 365 };
    }
    let month_days = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    for mi in 1..m {
        days += month_days[mi as usize - 1];
    }
    days + d - 1
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

/// Retorna la ruta del archivo de estado de reanudación.
///
/// En producción: `~/.cache/zerodupe/resume.json`.
/// En tests: la ruta configurada vía [`set_resume_path()`].
pub fn resume_path() -> PathBuf {
    let mocked = MOCKED_RESUME_PATH.with(|p| p.borrow().clone());
    if let Some(custom) = mocked {
        return custom;
    }
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("zerodupe")
        .join("resume.json")
}

/// Guarda el estado de reanudación en disco.
///
/// Usa escritura atómica (archivo temporal + rename) para evitar
/// corrupción. Si el directorio padre no existe, lo crea.
pub fn save_resume_state(state: &ResumeState) -> std::io::Result<()> {
    let path = resume_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(state)?;
    let temp_path = path.with_extension("json.tmp");
    std::fs::write(&temp_path, &json)?;
    std::fs::rename(&temp_path, &path)?;
    eprintln!(
        "[resume] State saved: root={} mode={} files={}/{}",
        state.scan_root, state.mode, state.files_processed, state.total_files
    );
    Ok(())
}

/// Carga el estado de reanudación desde disco.
///
/// Si el archivo no existe o el estado expiró (más de 24h),
/// retorna `None` y elimina el archivo obsoleto.
pub fn load_resume_state() -> Option<ResumeState> {
    let path = resume_path();
    if !path.exists() {
        return None;
    }
    let data = std::fs::read_to_string(&path).ok()?;
    let state: ResumeState = serde_json::from_str(&data).ok()?;
    if !state.is_valid() {
        eprintln!(
            "[resume] State expired or root missing: {} (started {})",
            state.scan_root, state.started_at
        );
        let _ = std::fs::remove_file(&path);
        return None;
    }
    eprintln!(
        "[resume] State loaded: root={} mode={} files={}/{}",
        state.scan_root, state.mode, state.files_processed, state.total_files
    );
    Some(state)
}

/// Elimina el archivo de estado de reanudación del disco.
pub fn clear_resume_state() {
    let path = resume_path();
    if path.exists() {
        let _ = std::fs::remove_file(&path);
        eprintln!("[resume] State cleared");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Returns an ISO 8601 timestamp that is guaranteed to be within the TTL
    /// window (24h from now). Uses the current system time minus 1 hour so
    /// the state is slightly aged but still valid.
    fn recent_iso8601() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Subtract 1 hour so the state appears slightly aged, but still valid.
        let t = now.saturating_sub(3600);
        let days = t / 86400;
        let secs = t % 86400;

        // Convert days since epoch to Gregorian date (portable, no crate needed).
        let (year, month, day) = gregorian_from_epoch_days(days);
        let hour = secs / 3600;
        let min = (secs % 3600) / 60;
        let sec = secs % 60;

        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
    }

    /// Convert days since 1970-01-01 to (year, month, day).
    /// Uses the same epoch logic as `days_since_epoch` above.
    fn gregorian_from_epoch_days(mut remaining: u64) -> (i64, u64, u64) {
        let mut year: i64 = 1970;
        loop {
            let days_in_year = if is_leap(year) { 366 } else { 365 };
            if remaining < days_in_year {
                break;
            }
            remaining -= days_in_year;
            year += 1;
        }
        let month_days: [u64; 12] = if is_leap(year) {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };
        let mut month: u64 = 1;
        for &md in &month_days {
            if remaining < md {
                break;
            }
            remaining -= md;
            month += 1;
        }
        (year, month, remaining + 1)
    }

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("zerodupe_resume_test_{}_{id}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        set_resume_path(dir.join("resume.json"));
        dir
    }

    #[test]
    fn save_and_load_resume_state() {
        let dir = make_test_dir();
        let state = ResumeState {
            scan_root: "/tmp".into(),
            mode: "exact".into(),
            files_processed: 42,
            total_files: 100,
            // Use a timestamp relative to now so the TTL (24h) never expires.
            started_at: recent_iso8601(),
        };
        save_resume_state(&state).expect("save");
        let loaded = load_resume_state().expect("load");
        assert_eq!(loaded.scan_root, "/tmp");
        assert_eq!(loaded.mode, "exact");
        assert_eq!(loaded.files_processed, 42);
        assert_eq!(loaded.total_files, 100);
        clear_resume_state();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_resume_state_removes_file() {
        let dir = make_test_dir();
        let state = ResumeState {
            scan_root: "/tmp".into(),
            mode: "exact".into(),
            files_processed: 0,
            total_files: 0,
            started_at: recent_iso8601(),
        };
        save_resume_state(&state).expect("save");
        assert!(resume_path().exists());
        clear_resume_state();
        assert!(!resume_path().exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_state_is_invalid() {
        let old = ResumeState {
            scan_root: "/tmp".into(),
            mode: "exact".into(),
            files_processed: 0,
            total_files: 0,
            started_at: "2020-01-01T00:00:00Z".into(),
        };
        assert!(!old.is_valid());
        let recent = ResumeState {
            scan_root: "/tmp".into(),
            mode: "exact".into(),
            files_processed: 0,
            total_files: 0,
            started_at: recent_iso8601(),
        };
        assert!(recent.is_valid());
    }

    #[test]
    fn missing_root_is_invalid() {
        let state = ResumeState {
            scan_root: "/nonexistent/path/for/testing".into(),
            mode: "exact".into(),
            files_processed: 0,
            total_files: 0,
            started_at: recent_iso8601(),
        };
        assert!(!state.is_valid());
    }
}
