//! # Pilar 3 — Higiene
//!
//! Este crate implementa el **tercer pilar de ZeroDupe**: la detección de archivos basura
//! y residuos del sistema que no son duplicados pero ocupan espacio innecesario.
//!
//! ## Arquitectura
//!
//! El servicio central es [`HygieneService`], que ejecuta un pipeline de 3 etapas:
//!
//! 1. **Discovery** — escanea el sistema de archivos para encontrar todos los archivos y
//!    directorios bajo la raíz indicada, aplicando exclusiones de SO.
//! 2. **7 detectores en secuencia** — cada uno inspecciona una categoría específica de
//!    basura (archivos vacíos, temporales, enlaces rotos, etc.).
//! 3. **Filtrado y reporte** — se descartan ítems en la lista negra (VCS, `.nomedia`,
//!    `node_modules` vivos) y se genera un [`HygieneReport`] con resumen por categoría.
//!
//! ## 3 Tiers de riesgo
//!
//! Cada ítem detectado se clasifica en uno de tres niveles:
//!
//! | Tier | Riesgo | Significado | Acción |
//! |------|--------|-------------|--------|
//! | 🟢 | `Low` | Basura inocua del SO | Se puede limpiar automáticamente |
//! | 🟠 | `Medium` | Posiblemente útil (swap, sidecars) | Va a cuarentena, revisión manual |
//! | 🔴 | `High` | Potencialmente valioso (caché, builds) | Solo reporte, nunca se borra |
//!
//! ## Relación con otros pilares
//!
//! - **Pilar 1 (exactos):** encuentra duplicados byte a byte. El manifiesto de eliminación
//!   ([`EliminationManifest`]) permite que la higiene detecte sidecars huérfanos
//!   (`.AAE`, `.XMP`) cuyo archivo principal fue eliminado por P1.
//! - **Pilar 2 (similares):** encuentra imágenes similares. Misma relación vía manifiesto.
//! - **Cuarentena:** los ítems de riesgo medio se mueven a `zerodupe_quarantine/` (crate
//!   `zerodupe_safety`) para revisión antes de eliminación definitiva.
//!
//! ## Pipeline de escaneo
//!
//! ```text
//! HygieneService::new(scan_root)
//!   .with_exclude_dirs(["zerodupe_quarantine"])
//!   .scan(progress, cancel)
//!     → discover_roots()
//!     → empty_files::detect()
//!     → empty_dirs::detect()
//!     → temporary_files::detect()
//!     → broken_symlinks::detect()
//!     → cache_files::detect()
//!     → system_junk::detect()
//!     → orphan::detect_orphans()
//!     → blacklist::is_blacklisted() (filtro final)
//!     → HygieneReport::new(items)
//! ```

pub mod blacklist;
pub mod detectors;
pub mod manifest;
pub mod orphan;
pub mod report;
pub mod takeout;
pub mod types;

use camino::Utf8PathBuf;
use zerodupe_core::{CancelFlag, DiscoveryOptions, ProgressEvent, ProgressReporter, ScanStage};
use zerodupe_fs::discover_roots;
use zerodupe_platform::{self, PlatformProfile};

use crate::types::{HygieneReport, JunkItem};

/// Servicio principal del Pilar 3 — Higiene.
///
/// Coordina el discovery de archivos y la ejecución secuencial de los 7 detectores
/// de basura. Soporta cancelación granular entre detector y detector, reporte de
/// progreso, y exclusión de directorios (útil para no re-escanear la cuarentena).
///
/// ## Uso típico
///
/// ```ignore
/// let report = HygieneService::new(scan_root)
///     .with_exclude_dirs(vec!["zerodupe_quarantine".into()])
///     .scan(Some(&progress), Some(&cancel));
/// ```
pub struct HygieneService {
    scan_root: Utf8PathBuf,
    profile: &'static dyn PlatformProfile,
    exclude_dirs: Vec<String>,
}

impl HygieneService {
    /// Crea un nuevo servicio de higiene para la raíz indicada.
    ///
    /// Usa el perfil de plataforma actual (Linux, macOS o Windows) para aplicar
    /// las exclusiones de sistema correspondientes.
    pub fn new(scan_root: Utf8PathBuf) -> Self {
        Self {
            scan_root,
            profile: zerodupe_platform::current(),
            exclude_dirs: Vec::new(),
        }
    }

    /// Excluye directorios por nombre (no ruta completa) del escaneo de higiene.
    ///
    /// Útil para evitar que el detector re-escanee `zerodupe_quarantine/` u otros
    /// directorios generados por ZeroDupe durante la misma sesión.
    pub fn with_exclude_dirs(mut self, dirs: Vec<String>) -> Self {
        self.exclude_dirs = dirs;
        self
    }

    /// Ejecuta el pipeline completo de higiene.
    ///
    /// ## Pipeline (3 etapas)
    ///
    /// 1. **Discovery** — `discover_roots()` escanea recursivamente la raíz,
    ///    aplicando exclusiones de SO y los `exclude_dirs` configurados.
    /// 2. **7 detectores** — se ejecutan en secuencia, cada uno produciendo
    ///    `Vec<JunkItem>` para su categoría. Entre detector y detector se
    ///    consulta el flag de cancelación para permitir aborto rápido.
    /// 3. **Filtrado y reporte** — se aplica la lista negra (`blacklist`) para
    ///    proteger VCS, `.nomedia` y `node_modules` vivos, y se construye el
    ///    [`HygieneReport`] con resúmenes agregados.
    ///
    /// ## Parámetros
    ///
    /// - `progress`: reporter opcional para emitir eventos de progreso (7 pasos).
    /// - `cancel`: flag opcional para abortar el escaneo entre detectores.
    ///
    /// ## Retorno
    ///
    /// Un [`HygieneReport`] que contiene todos los ítems detectados (si se canceló,
    /// solo los acumulados hasta el momento) junto con un resumen por categoría y
    /// nivel de riesgo.
    pub fn scan(
        &self,
        progress: Option<&dyn ProgressReporter>,
        cancel: Option<&CancelFlag>,
    ) -> HygieneReport {
        if let Some(p) = progress {
            p.emit(ProgressEvent {
                stage: ScanStage::Discovery,
                current: 0,
                total: 1,
                current_file: None,
                bytes_processed: None,
                bytes_total: None,
            });
        }

        let options = DiscoveryOptions {
            exclude_prefixes: self
                .exclude_dirs
                .iter()
                .map(|d| format!("{}/", d))
                .collect(),
            ..Default::default()
        };

        let discovery = discover_roots(vec![self.scan_root.clone()], &options, None, None);

        if let Some(c) = cancel
            && c.is_cancelled()
        {
            return HygieneReport::new(Vec::new());
        }

        let mut items: Vec<JunkItem> = Vec::new();

        items.extend(detectors::empty_files::detect(
            &discovery.entries,
            &self.scan_root,
            self.profile,
        ));
        if let Some(c) = cancel
            && c.is_cancelled()
        {
            return HygieneReport::new(items);
        }
        if let Some(p) = progress {
            p.emit(ProgressEvent {
                stage: ScanStage::Hygiene,
                current: 1,
                total: 7,
                current_file: None,
                bytes_processed: None,
                bytes_total: None,
            });
        }

        items.extend(detectors::empty_dirs::detect(
            &discovery.entries,
            &self.scan_root,
            self.profile,
        ));
        if let Some(c) = cancel
            && c.is_cancelled()
        {
            return HygieneReport::new(items);
        }
        if let Some(p) = progress {
            p.emit(ProgressEvent {
                stage: ScanStage::Hygiene,
                current: 2,
                total: 7,
                current_file: None,
                bytes_processed: None,
                bytes_total: None,
            });
        }

        items.extend(detectors::temporary_files::detect(
            &discovery.entries,
            &self.scan_root,
            self.profile,
        ));
        if let Some(c) = cancel
            && c.is_cancelled()
        {
            return HygieneReport::new(items);
        }
        if let Some(p) = progress {
            p.emit(ProgressEvent {
                stage: ScanStage::Hygiene,
                current: 3,
                total: 7,
                current_file: None,
                bytes_processed: None,
                bytes_total: None,
            });
        }

        items.extend(detectors::broken_symlinks::detect(
            &discovery.entries,
            &self.scan_root,
            self.profile,
        ));
        if let Some(c) = cancel
            && c.is_cancelled()
        {
            return HygieneReport::new(items);
        }
        if let Some(p) = progress {
            p.emit(ProgressEvent {
                stage: ScanStage::Hygiene,
                current: 4,
                total: 7,
                current_file: None,
                bytes_processed: None,
                bytes_total: None,
            });
        }

        items.extend(detectors::cache_files::detect(
            &discovery.entries,
            &self.scan_root,
            self.profile,
        ));
        if let Some(c) = cancel
            && c.is_cancelled()
        {
            return HygieneReport::new(items);
        }
        if let Some(p) = progress {
            p.emit(ProgressEvent {
                stage: ScanStage::Hygiene,
                current: 5,
                total: 7,
                current_file: None,
                bytes_processed: None,
                bytes_total: None,
            });
        }

        items.extend(detectors::system_junk::detect(
            &discovery.entries,
            &self.scan_root,
            self.profile,
        ));
        if let Some(c) = cancel
            && c.is_cancelled()
        {
            return HygieneReport::new(items);
        }
        if let Some(p) = progress {
            p.emit(ProgressEvent {
                stage: ScanStage::Hygiene,
                current: 6,
                total: 7,
                current_file: None,
                bytes_processed: None,
                bytes_total: None,
            });
        }

        items.extend(orphan::detect_orphans(
            &discovery.entries,
            &self.scan_root,
            self.profile,
        ));

        // Filter out blacklisted items (VCS, .nomedia, live node_modules, etc.)
        items.retain(|item| !blacklist::is_blacklisted(&item.path, self.profile));

        HygieneReport::new(items)
    }
}
