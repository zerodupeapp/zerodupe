//! Arquitectura del `Workflow`: la state machine central que orquesta los 3
//! pilares de ZeroDupe.
//!
//! # Ciclo de vida del escaneo
//!
//! ```text
//! Discovery ──> Exactos ──> Similares ──> Higiene ──> Limpieza ──> Complete
//!               (5 etapas)  (3 etapas)   (2 etapas)
//! ```
//!
//! Cada pilar produce un reporte (`DiscoveryReport`, `ByteCompareReport`,
//! `SimilarityReport`, `HygieneReport`) que se acumula en el struct `Workflow`.
//! El usuario puede saltar similares y/o higiene con las acciones `SkipSimilar`
//! y `SkipHygiene`.
//!
//! # Sistema de cancelacion
//!
//! `CancelFlag` se comparte con todos los pipelines. Al llamar `cancel()`, cada
//! etapa interna verifica `is_cancelled()` y aborta limpiamente. El estado
//! transiciona a `Cancelled`.
//!
//! # Progreso
//!
//! `ProgressReporter` emite eventos `ProgressEvent` con etapa, archivo actual
//! y bytes procesados. La GUI y CLI usan este trait para mostrar barras de
//! progreso.
//!
//! # Resume state
//!
//! Durante el escaneo, el workflow persiste `ResumeState` en disco cada ~2
//! segundos. Si el proceso se interrumpe, la CLI puede retomar desde la ultima
//! etapa guardada. Al entrar en `Cleaning` o `Complete`, el resume state se
//! borra (la limpieza no se puede des-hacer).
//!
//! # Notificacion de cambios de estado
//!
//! `StateChangeNotifier` permite a la GUI Tauri recibir callbacks cada vez que
//! el estado del workflow cambia, enviando el estado anterior y el nuevo como
//! JSON.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use camino::Utf8PathBuf;
use zerodupe_config::reports::{build_report_from_exact, reports_dir};
use zerodupe_config::resume::{ResumeState, clear_resume_state, save_resume_state};
use zerodupe_core::{
    ByteCompareReport, CancelFlag, DiscoveryOptions, DiscoveryReport, FileCandidate,
    HashingOptions, ProgressEvent, ProgressReporter, ScanStage, VerifyMode,
};
use zerodupe_fs::discover_roots;
use zerodupe_hygiene::HygieneService;
use zerodupe_hygiene::types::{HygieneReport, JunkCategory};
use zerodupe_report::html;
use zerodupe_scan::{
    build_candidate_groups, byte_compare_groups, full_hash_groups, partial_hash_groups,
};
use zerodupe_similar::SimilarityReport;
use zerodupe_similar::detect_similars;
use zerodupe_similar_image::ImagePHashDetector;

use crate::action::WorkflowAction;
use crate::error::WorkflowError;
use crate::notifier::StateChangeNotifier;
use crate::state::WorkflowState;

// ── Workflow ─────────────────────────────────────────────────────────────────

/// Struct principal de la state machine de ZeroDupe.
///
/// Orquesta el ciclo de vida completo: discovery de archivos, deteccion de
/// duplicados exactos, deteccion de similares, higiene de archivos basura,
/// limpieza con cuarentena y generacion de reportes HTML.
///
/// # Uso tipico
///
/// ```ignore
/// let mut wf = Workflow::new();
/// wf.advance(WorkflowAction::SelectFolder { path: "/home/user".into() })?;
/// wf.advance(WorkflowAction::StartScan)?;
/// // ... el usuario navega por los estados ...
/// ```
pub struct Workflow {
    /// Estado actual del wizard.
    state: WorkflowState,

    /// Ruta raiz del escaneo, establecida via `SelectFolder`.
    scan_root: Option<Utf8PathBuf>,

    /// Flag de cancelacion compartido con todos los pipelines internos.
    cancel: CancelFlag,

    /// Reporte de discovery (archivos encontrados en el arbol).
    discovery: Option<DiscoveryReport>,

    /// Reporte de duplicados exactos (confirmados byte a byte).
    exact_report: Option<ByteCompareReport>,

    /// Reporte de archivos similares (imagenes con pHash/dHash).
    similar_report: Option<SimilarityReport>,

    /// Reporte de higiene (archivos basura detectados).
    hygiene_report: Option<HygieneReport>,

    /// Contador interno de items de higiene procesados.
    hygiene_items: u64,

    /// Bytes recuperables de higiene acumulados.
    hygiene_reclaimable: u64,

    /// Ultimo directorio de cuarentena usado. Se persiste entre sesiones.
    last_quarantine_dir: Option<Utf8PathBuf>,

    /// Reporter de progreso opcional para emitir eventos a la GUI/CLI.
    progress: Option<Box<dyn ProgressReporter>>,

    /// Notificador de cambios de estado opcional (usado por la GUI Tauri).
    state_notifier: Option<Box<dyn StateChangeNotifier>>,

    /// Ruta al ultimo reporte HTML generado.
    last_report_path: Option<std::path::PathBuf>,

    /// Instante en que se inicio el escaneo (para calcular elapsed en reportes).
    started_at: Option<std::time::Instant>,

    /// Overrides de keeper por grupo (seleccion manual del usuario).
    keeper_overrides: Option<Vec<usize>>,

    /// Ruta raiz usada para resume state (string, para serializacion).
    resume_root: Option<String>,

    /// Ultimo instante en que se guardo resume state (throttle a ~2s).
    last_resume_save: Option<Instant>,

    /// Grupos con archivos protegidos (no se pudieron limpiar por proteccion del SO).
    protected_groups: Vec<zerodupe_core::ProtectedGroup>,
}

impl Default for Workflow {
    fn default() -> Self {
        Self::new()
    }
}

impl Workflow {
    /// Crea un nuevo workflow en estado `Idle`.
    ///
    /// Carga el directorio de cuarentena de la sesion anterior si existe.
    /// Los reporters de progreso y notificadores se configuran despues con
    /// `set_progress` y `set_state_notifier`.
    pub fn new() -> Self {
        Self {
            state: WorkflowState::Idle,
            scan_root: None,
            cancel: CancelFlag::new(),
            discovery: None,
            exact_report: None,
            similar_report: None,
            hygiene_report: None,
            hygiene_items: 0,
            hygiene_reclaimable: 0,
            last_quarantine_dir: zerodupe_config::load_quarantine_state()
                .map(camino::Utf8PathBuf::from),
            progress: None,
            state_notifier: None,
            last_report_path: None,
            started_at: None,
            keeper_overrides: None,
            resume_root: None,
            last_resume_save: None,
            protected_groups: Vec::new(),
        }
    }

    /// Retorna el estado actual del workflow.
    pub fn state(&self) -> &WorkflowState {
        &self.state
    }

    /// Activa la bandera de cancelacion. Los pipelines internos verifican
    /// `is_cancelled()` periodicamente y abortan limpiamente.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Retorna una referencia al flag de cancelacion para pasarlo a sistemas
    /// externos que necesiten verificarlo.
    pub fn cancel_flag(&self) -> &CancelFlag {
        &self.cancel
    }

    /// Reporte de duplicados exactos, si el escaneo exacto ya finalizo.
    pub fn exact_report(&self) -> Option<&ByteCompareReport> {
        self.exact_report.as_ref()
    }

    /// Reporte de archivos similares, si el escaneo de similares ya finalizo.
    pub fn similar_report(&self) -> Option<&SimilarityReport> {
        self.similar_report.as_ref()
    }

    /// Reporte de higiene (archivos basura), si el escaneo de higiene ya finalizo.
    pub fn hygiene_report(&self) -> Option<&HygieneReport> {
        self.hygiene_report.as_ref()
    }

    /// Reporte de discovery (archivos encontrados en el arbol), si ya se ejecuto.
    pub fn discovery(&self) -> Option<&DiscoveryReport> {
        self.discovery.as_ref()
    }

    /// Ruta raiz del escaneo, si ya fue configurada con `SelectFolder`.
    pub fn scan_root_path(&self) -> Option<&Utf8PathBuf> {
        self.scan_root.as_ref()
    }

    /// Configura el reporter de progreso. La CLI y GUI inyectan su propia
    /// implementacion para recibir eventos de avance durante el escaneo.
    pub fn set_progress(&mut self, reporter: Option<Box<dyn ProgressReporter>>) {
        self.progress = reporter;
    }

    /// Configura el notificador de cambios de estado. La GUI Tauri lo usa para
    /// reaccionar a transiciones de estado en tiempo real.
    pub fn set_state_notifier(&mut self, notifier: Option<Box<dyn StateChangeNotifier>>) {
        self.state_notifier = notifier;
    }

    fn notify_state(&self, from: &WorkflowState, to: &WorkflowState) {
        if let Some(ref n) = self.state_notifier {
            let from_str = serde_json::to_string(from).unwrap_or_default();
            let to_str = serde_json::to_string(to).unwrap_or_default();
            n.notify_state_changed(&from_str, &to_str);
        }
    }

    /// Directorio de cuarentena activo. Los archivos limpiados se mueven aqui
    /// en lugar de eliminarse permanentemente.
    pub fn quarantine_dir(&self) -> Option<&Utf8PathBuf> {
        self.last_quarantine_dir.as_ref()
    }

    fn save_resume_progress(&mut self, mode: &str, files_processed: u64, total_files: u64) {
        let Some(ref root) = self.resume_root else {
            return;
        };
        let now = Instant::now();
        if let Some(ref last) = self.last_resume_save
            && last.elapsed().as_secs() < 2
        {
            return;
        }
        self.last_resume_save = Some(now);
        let started_at = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => {
                let secs = d.as_secs();
                let day = secs / 86400;
                let time = secs % 86400;
                let h = time / 3600;
                let m = (time % 3600) / 60;
                let s = time % 60;
                let (year, month, dom) = unix_day_to_date(day);
                format!("{year:04}-{month:02}-{dom:02}T{h:02}:{m:02}:{s:02}Z")
            }
            Err(_) => "2026-01-01T00:00:00Z".to_string(),
        };
        let state = ResumeState {
            scan_root: root.clone(),
            mode: mode.into(),
            files_processed,
            total_files,
            started_at,
        };
        let _ = save_resume_state(&state);
    }

    /// Ruta al ultimo reporte HTML generado. Util para abrirlo en el navegador
    /// tras finalizar el escaneo.
    pub fn last_report_path(&self) -> Option<&std::path::PathBuf> {
        self.last_report_path.as_ref()
    }

    fn merge_takeout_for_keeper(
        keeper_path: &camino::Utf8PathBuf,
        junk_dir: &std::path::Path,
        quarantine: &zerodupe_safety::Quarantine,
        session_id: &str,
    ) {
        if let Some(json_path) =
            zerodupe_hygiene::takeout::takeout_json_for_image(keeper_path.as_std_path())
            && let Ok(metadata) = zerodupe_hygiene::takeout::parse_takeout_json(&json_path)
        {
            let _ = zerodupe_hygiene::takeout::merge_takeout_metadata(
                keeper_path.as_std_path(),
                &metadata,
            );
            let name = json_path.file_name().unwrap_or_default();
            let dest = junk_dir.join(name);
            if std::fs::rename(&json_path, &dest).is_ok()
                && let (Ok(src_utf8), Ok(dest_utf8)) = (
                    camino::Utf8PathBuf::from_path_buf(json_path.clone()),
                    camino::Utf8PathBuf::from_path_buf(dest.clone()),
                )
            {
                let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
                let _ = quarantine.record_entry(
                    &src_utf8,
                    &dest_utf8,
                    size,
                    "takeout-json",
                    session_id,
                    Some(30),
                );
            }
        }
    }

    /// Retorna la etapa de escaneo en curso, si el workflow esta en un estado
    /// de escaneo o limpieza. Util para determinar que se estaba haciendo al
    /// momento de una cancelacion.
    pub fn cancelled_stage(&self) -> Option<ScanStage> {
        match &self.state {
            WorkflowState::ScanningExact { .. } => Some(ScanStage::FullHash),
            WorkflowState::ScanningSimilar { .. } => Some(ScanStage::SimilarityDetection),
            WorkflowState::ScanningHygiene { .. } => Some(ScanStage::Hygiene),
            WorkflowState::Cleaning { .. } => Some(ScanStage::Cleaning),
            _ => None,
        }
    }

    /// Ejecuta una accion del usuario y avanza la state machine al estado
    /// correspondiente.
    ///
    /// Este es el metodo principal de interaccion con el workflow. Recibe una
    /// `WorkflowAction` y:
    ///
    /// - Valida que la transicion sea legal desde el estado actual.
    /// - Ejecuta el pipeline correspondiente (exacto, similar, higiene, limpieza).
    /// - Actualiza el estado interno.
    /// - Notifica el cambio de estado via `StateChangeNotifier` si esta configurado.
    /// - Persiste resume state durante escaneos largos.
    ///
    /// Retorna `WorkflowError::InvalidTransition` si la accion no es valida
    /// desde el estado actual. Retorna `WorkflowError::NoScanRoot` si se intenta
    /// escanear sin haber seleccionado carpeta.
    pub fn advance(&mut self, action: WorkflowAction) -> Result<&WorkflowState, WorkflowError> {
        match (&self.state, action.clone()) {
            (WorkflowState::Idle, WorkflowAction::SelectFolder { path }) => {
                let old = self.state.clone();
                self.scan_root = Some(Utf8PathBuf::from(path));
                self.notify_state(&old, &self.state);
                Ok(&self.state)
            }
            (WorkflowState::Idle, WorkflowAction::StartScan) => {
                if self.scan_root.is_none() {
                    return Err(WorkflowError::NoScanRoot);
                }
                let old = self.state.clone();
                self.state = WorkflowState::ScanningExact {
                    current: 0,
                    total: 5,
                };
                self.notify_state(&old, &self.state);
                self.started_at = Some(std::time::Instant::now());
                self.resume_root = self.scan_root.as_ref().map(|p| p.as_str().to_string());
                self.save_resume_progress("exact", 0, 5);
                self.run_exact_scan()?;
                Ok(&self.state)
            }
            (WorkflowState::Idle, WorkflowAction::StartSimilarScan) => {
                if self.scan_root.is_none() {
                    return Err(WorkflowError::NoScanRoot);
                }
                let old = self.state.clone();
                self.state = WorkflowState::ScanningSimilar {
                    current: 0,
                    total: 3,
                };
                self.notify_state(&old, &self.state);
                self.started_at = Some(std::time::Instant::now());
                self.resume_root = self.scan_root.as_ref().map(|p| p.as_str().to_string());
                self.save_resume_progress("similar", 0, 3);
                self.run_similar_scan()?;
                Ok(&self.state)
            }
            (
                WorkflowState::ReviewingExact { .. },
                WorkflowAction::ConfirmClean { ref keepers },
            )
            | (
                WorkflowState::ReviewingSimilar { .. },
                WorkflowAction::ConfirmClean { ref keepers },
            ) => {
                self.keeper_overrides = Some(keepers.clone());
                let old = self.state.clone();
                let cleaning = WorkflowState::Cleaning {
                    files_done: 0,
                    files_total: 0,
                    bytes_done: 0,
                };
                self.state = cleaning.clone();
                self.notify_state(&old, &self.state);
                self.apply_cleanup()?;
                self.notify_state(&cleaning, &self.state);
                Ok(&self.state)
            }
            (WorkflowState::ReviewingExact { .. }, WorkflowAction::AutoClean { .. }) => {
                let old = self.state.clone();
                let cleaning = WorkflowState::Cleaning {
                    files_done: 0,
                    files_total: 0,
                    bytes_done: 0,
                };
                self.state = cleaning.clone();
                self.notify_state(&old, &self.state);
                self.apply_cleanup()?;
                self.notify_state(&cleaning, &self.state);
                Ok(&self.state)
            }
            (WorkflowState::ReviewingExact { .. }, WorkflowAction::AcceptExact) => {
                let old = self.state.clone();
                self.run_similar_scan()?;
                self.notify_state(&old, &self.state);
                Ok(&self.state)
            }
            (WorkflowState::ReviewingExact { .. }, WorkflowAction::SkipSimilar) => {
                let old = self.state.clone();
                self.run_hygiene_scan()?;
                self.notify_state(&old, &self.state);
                Ok(&self.state)
            }
            (WorkflowState::ReviewingSimilar { .. }, WorkflowAction::SkipSimilar) => {
                let old = self.state.clone();
                self.run_hygiene_scan()?;
                self.notify_state(&old, &self.state);
                Ok(&self.state)
            }
            (WorkflowState::ReviewingSimilar { .. }, WorkflowAction::SkipHygiene) => {
                let old = self.state.clone();
                self.build_complete();
                self.notify_state(&old, &self.state);
                Ok(&self.state)
            }
            (WorkflowState::ReviewingHygiene { .. }, WorkflowAction::AcceptHygiene) => {
                let old = self.state.clone();
                self.state = WorkflowState::Cleaning {
                    files_done: 0,
                    files_total: 0,
                    bytes_done: 0,
                };
                self.notify_state(&old, &self.state);
                self.apply_cleanup()?;
                Ok(&self.state)
            }
            (WorkflowState::ReviewingHygiene { .. }, WorkflowAction::SkipHygiene) => {
                let old = self.state.clone();
                self.build_complete();
                self.notify_state(&old, &self.state);
                Ok(&self.state)
            }
            (_, WorkflowAction::Cancel) => {
                let old = self.state.clone();
                self.cancel.cancel();
                self.state = WorkflowState::Cancelled;
                self.notify_state(&old, &self.state);
                clear_resume_state();
                Ok(&self.state)
            }
            (_, WorkflowAction::Reset) => {
                let old = self.state.clone();
                self.cancel = CancelFlag::new();
                self.state = WorkflowState::Idle;
                self.scan_root = None;
                self.discovery = None;
                self.exact_report = None;
                self.similar_report = None;
                self.hygiene_report = None;
                self.keeper_overrides = None;
                self.last_report_path = None;
                self.resume_root = None;
                self.last_resume_save = None;
                self.protected_groups.clear();
                self.notify_state(&old, &self.state);
                clear_resume_state();
                Ok(&self.state)
            }
            _ => Err(WorkflowError::InvalidTransition),
        }
    }

    fn run_exact_scan(&mut self) -> Result<(), WorkflowError> {
        let root = self.scan_root.clone().ok_or(WorkflowError::NoScanRoot)?;

        self.state = WorkflowState::ScanningExact {
            current: 0,
            total: 5,
        };

        let mut options = DiscoveryOptions::default();
        let profile = zerodupe_platform::current();
        for path in profile.protected_paths() {
            options.exclude_prefixes.push(path.clone());
        }
        // Nunca re-escanear la cuarentena de una limpieza anterior: sus
        // archivos volverían a aparecer como duplicados/similares.
        options
            .exclude_prefixes
            .push("zerodupe_quarantine".to_string());
        let report = discover_roots(
            vec![root],
            &options,
            self.progress.as_deref(),
            Some(&self.cancel),
        );
        self.save_resume_progress("exact", 1, 5);

        if self.cancel.is_cancelled() {
            self.state = WorkflowState::Cancelled;
            return Ok(());
        }

        let (phys, cand) = build_candidate_groups(
            &report.entries,
            self.progress.as_deref(),
            Some(&self.cancel),
        );
        self.save_resume_progress("exact", 2, 5);

        if self.cancel.is_cancelled() {
            self.state = WorkflowState::Cancelled;
            return Ok(());
        }

        let hashing = HashingOptions::default();
        // Persistent hash cache: re-scans only hash files that changed.
        // On any open failure the scan silently runs uncached.
        let cache = zerodupe_cache::HashCache::open(&zerodupe_cache::default_cache_path()).ok();
        let partial = partial_hash_groups(
            &phys.physical_files,
            &cand,
            &hashing,
            cache.as_ref(),
            self.progress.as_deref(),
            Some(&self.cancel),
        );
        self.save_resume_progress("exact", 3, 5);

        if self.cancel.is_cancelled() {
            self.state = WorkflowState::Cancelled;
            return Ok(());
        }

        let full = full_hash_groups(
            &phys.physical_files,
            &partial,
            &hashing,
            cache.as_ref(),
            self.progress.as_deref(),
            Some(&self.cancel),
        );
        self.save_resume_progress("exact", 4, 5);

        if self.cancel.is_cancelled() {
            self.state = WorkflowState::Cancelled;
            return Ok(());
        }

        let compare = byte_compare_groups(
            &full,
            &report.entries,
            &phys.physical_files,
            VerifyMode::default(),
            self.progress.as_deref(),
            Some(&self.cancel),
        );

        // Byte comparison proved these cached hashes wrong (file changed
        // without its witnesses changing): purge them so the next scan
        // re-hashes those files instead of trusting the cache again.
        if let Some(cache) = cache.as_ref() {
            for key in &compare.stale_cache_keys {
                let _ = cache.invalidate(key);
            }
        }

        let reclaimable: u64 = compare
            .confirmed_groups
            .iter()
            .map(|g| g.size_bytes * (g.files.len() as u64 - 1))
            .sum();

        let old = self.state.clone();
        // Move (not clone) the discovery report: with a million entries the
        // clone duplicated hundreds of MB for an instant.
        self.discovery = Some(report);
        self.exact_report = Some(compare);
        self.state = WorkflowState::ReviewingExact {
            reclaimable_bytes: reclaimable,
        };
        self.notify_state(&old, &self.state);

        Ok(())
    }

    fn run_similar_scan(&mut self) -> Result<(), WorkflowError> {
        let root = self.scan_root.clone().ok_or(WorkflowError::NoScanRoot)?;

        self.state = WorkflowState::ScanningSimilar {
            current: 0,
            total: 3,
        };

        // Reusar el discovery del escaneo exacto si existe; si no (modo
        // similares directo), correr discovery fresco y almacenarlo para que
        // la GUI pueda consultar file_count y categorías.
        if self.discovery.is_none() {
            let mut options = DiscoveryOptions::default();
            let profile = zerodupe_platform::current();
            for path in profile.protected_paths() {
                options.exclude_prefixes.push(path.clone());
            }
            // Nunca re-escanear la cuarentena de una limpieza anterior.
            options
                .exclude_prefixes
                .push("zerodupe_quarantine".to_string());
            self.discovery = Some(discover_roots(
                vec![root.clone()],
                &options,
                self.progress.as_deref(),
                Some(&self.cancel),
            ));
        }
        let entries = &self
            .discovery
            .as_ref()
            .expect("discovery just ensured above")
            .entries;

        let files: Vec<FileCandidate> = entries
            .iter()
            .filter(|e| {
                let ext = e.path.extension().unwrap_or("").to_lowercase();
                e.size_bytes.unwrap_or(0) > 0
                    && zerodupe_similar_image::supported_extensions().contains(&ext.as_str())
            })
            .map(|e| FileCandidate {
                path: e.path.clone(),
                size_bytes: e.size_bytes.unwrap_or(0),
            })
            .collect();

        self.save_resume_progress("similar", 1, 3);

        let progress = Arc::new(AtomicUsize::new(0));

        // Invarianza Full (grupo diedral D4): cubre espejos Y rotaciones de
        // 90°/180°/270°. En la validación 2026-06-12 el default `mirror` dejó
        // pasar 26 rotaciones duras; el costo extra es solo en la consulta
        // del BK-tree (variantes en query, no en el índice). Cláusula del
        // plan: si suben los falsos positivos, revertir a opt-in.
        let detectors: Vec<Box<dyn zerodupe_similar::SimilarityDetector>> = vec![Box::new(
            ImagePHashDetector::new()
                .with_invariance(zerodupe_similar_image::GeometricInvariance::Full),
        )];
        let detector_refs: Vec<&dyn zerodupe_similar::SimilarityDetector> =
            detectors.iter().map(|d| d.as_ref()).collect();

        // Persistent fingerprint cache: re-scans only fingerprint files that
        // changed. On any open failure the scan silently runs uncached.
        let cache = zerodupe_cache::HashCache::open(&zerodupe_cache::default_cache_path()).ok();

        // detect_similars solo expone un contador atómico; un watcher con
        // scoped thread lo convierte en ProgressEvents para la GUI.
        let total_files = files.len() as u64;
        let done = AtomicBool::new(false);
        let mut similar_report = std::thread::scope(|s| {
            if let Some(reporter) = self.progress.as_deref() {
                let counter = Arc::clone(&progress);
                let done = &done;
                s.spawn(move || {
                    while !done.load(Ordering::Relaxed) {
                        reporter.emit(ProgressEvent {
                            stage: ScanStage::SimilarityDetection,
                            current: counter.load(Ordering::Relaxed) as u64,
                            total: total_files,
                            current_file: None,
                            bytes_processed: None,
                            bytes_total: None,
                        });
                        std::thread::sleep(std::time::Duration::from_millis(250));
                    }
                });
            }
            let report = detect_similars(
                &files,
                &detector_refs,
                cache.as_ref(),
                Some(Arc::clone(&progress)),
                Some(&self.cancel),
            );
            done.store(true, Ordering::Relaxed);
            report
        });

        self.save_resume_progress("similar", 2, 3);

        // Keepers de limpiezas anteriores (journal de la cuarentena) y de la
        // pasada exacta de esta misma corrida: cada uno es el único
        // superviviente en disco de su grupo, así que la pasada de similares
        // los fija como keeper y nunca los ofrece para remoción.
        let mut prior_keepers: std::collections::HashSet<String> = std::collections::HashSet::new();
        let quarantine_dir = root.join("zerodupe_quarantine");
        if quarantine_dir.join("journal.db").exists()
            && let Ok(quarantine) = zerodupe_safety::Quarantine::open(quarantine_dir.as_std_path())
            && let Ok(kept) = quarantine.kept_files()
        {
            prior_keepers.extend(kept.into_iter().map(camino::Utf8PathBuf::into_string));
        }
        if let Some(ref exact) = self.exact_report {
            for group in &exact.confirmed_groups {
                if group.files.len() > 1 {
                    prior_keepers.insert(group.files[group.keeper_index].path.as_str().to_string());
                }
            }
        }
        zerodupe_similar::protect_prior_keepers(&mut similar_report, &prior_keepers);

        let reclaimable: u64 = similar_report
            .groups
            .iter()
            .flat_map(|g| {
                g.files
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != g.keeper_index)
                    .map(|(_, f)| f.size_bytes)
            })
            .sum();

        let old = self.state.clone();
        self.similar_report = Some(similar_report);
        self.state = WorkflowState::ReviewingSimilar {
            reclaimable_bytes: reclaimable,
        };
        self.notify_state(&old, &self.state);

        Ok(())
    }

    fn run_hygiene_scan(&mut self) -> Result<(), WorkflowError> {
        let root = self.scan_root.clone().ok_or(WorkflowError::NoScanRoot)?;

        let old = self.state.clone();
        self.state = WorkflowState::ScanningHygiene {
            current: 0,
            total: 2,
        };
        self.notify_state(&old, &self.state);

        let service = HygieneService::new(root);
        let report = service.scan(None, Some(&self.cancel));

        let reclaimable: u64 = report.summary.total_size_bytes;

        let old2 = self.state.clone();
        self.hygiene_report = Some(report);
        self.state = WorkflowState::ReviewingHygiene {
            reclaimable_bytes: reclaimable,
        };
        self.notify_state(&old2, &self.state);

        Ok(())
    }

    fn build_complete(&mut self) {
        clear_resume_state();
        let exact_groups = self
            .exact_report
            .as_ref()
            .map(|r| r.confirmed_groups.len())
            .unwrap_or(0);
        let exact_reclaimable = self
            .exact_report
            .as_ref()
            .map(|r| {
                r.confirmed_groups
                    .iter()
                    .map(|g| g.size_bytes * (g.files.len() as u64 - 1))
                    .sum()
            })
            .unwrap_or(0);
        let exact_files = self
            .exact_report
            .as_ref()
            .map(|r| {
                r.confirmed_groups
                    .iter()
                    .map(|g| g.files.len().saturating_sub(1))
                    .sum()
            })
            .unwrap_or(0);
        let similar_groups = self
            .similar_report
            .as_ref()
            .map(|r| r.groups.len())
            .unwrap_or(0);
        let similar_reclaimable = self
            .similar_report
            .as_ref()
            .map(|r| {
                r.groups
                    .iter()
                    .flat_map(|g| {
                        g.files
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| *i != g.keeper_index)
                            .map(|(_, f)| f.size_bytes)
                    })
                    .sum()
            })
            .unwrap_or(0);
        let similar_files = self
            .similar_report
            .as_ref()
            .map(|r| {
                r.groups
                    .iter()
                    .map(|g| g.files.len().saturating_sub(1))
                    .sum()
            })
            .unwrap_or(0);
        let hygiene_items = self
            .hygiene_report
            .as_ref()
            .map(|r| r.items.iter().filter(|i| i.can_clean).count())
            .unwrap_or(0);
        let hygiene_reclaimable = self
            .hygiene_report
            .as_ref()
            .map(|r| {
                r.items
                    .iter()
                    .filter(|i| i.can_clean)
                    .map(|i| i.size_bytes)
                    .sum()
            })
            .unwrap_or(0);

        let protected_data = if !self.protected_groups.is_empty() {
            serde_json::to_value(&self.protected_groups).ok()
        } else {
            None
        };

        self.state = WorkflowState::Complete {
            exact_groups,
            exact_reclaimable,
            exact_files,
            similar_groups,
            similar_reclaimable,
            similar_files,
            hygiene_items,
            hygiene_reclaimable,
            protected_groups: protected_data,
            protected_file_count: 0,
            skipped_file_count: 0,
        };
    }

    fn apply_cleanup(&mut self) -> Result<(), WorkflowError> {
        let scan_root = self.scan_root.clone().ok_or(WorkflowError::NoScanRoot)?;

        let progress = self.progress.as_deref();

        let quarantine_dir = scan_root.join("zerodupe_quarantine");
        let junk_dir = quarantine_dir.as_std_path().join("junk");
        let takeout_dir = quarantine_dir.as_std_path().join("takeout");
        std::fs::create_dir_all(&junk_dir).map_err(WorkflowError::Io)?;
        std::fs::create_dir_all(&takeout_dir).map_err(WorkflowError::Io)?;

        self.last_quarantine_dir = Some(quarantine_dir.clone());
        let _ = zerodupe_config::save_quarantine_state(quarantine_dir.as_str());

        // Commit to cleanup — no going back via resume
        clear_resume_state();

        let quarantine = zerodupe_safety::Quarantine::open(quarantine_dir.as_std_path())
            .map_err(|e| WorkflowError::Pipeline(e.to_string()))?;

        let session_id = uuid::Uuid::new_v4().to_string();
        let mut quarantine_paths: HashMap<String, String> = HashMap::new();

        // Keepers de limpiezas anteriores + keepers exactos de esta corrida:
        // únicos supervivientes de su grupo, la pasada de similares no puede
        // mandarlos a cuarentena (backstop de protect_prior_keepers, que ya
        // los fijó en el reporte; aquí se cubren también los overrides).
        let mut prior_keepers: std::collections::HashSet<String> = quarantine
            .kept_files()
            .unwrap_or_default()
            .into_iter()
            .map(camino::Utf8PathBuf::into_string)
            .collect();

        let mut local_protected: Vec<zerodupe_core::ProtectedGroup> = Vec::new();

        let mut files_done = 0u64;
        let mut bytes_done = 0u64;
        let mut total_files = 0u64;
        let mut total_bytes = 0u64;

        let mut cancelled = false;
        let mut skipped_files = 0usize;
        let mut exact_cleaned_groups = 0usize;
        let mut exact_cleaned_bytes: u64 = 0;
        let mut exact_cleaned_files = 0usize;
        let mut similar_cleaned_groups = 0usize;
        let mut similar_cleaned_bytes: u64 = 0;
        let mut similar_cleaned_files = 0usize;

        if let Some(ref report) = self.exact_report {
            for (gi, group) in report.confirmed_groups.iter().enumerate() {
                if group.files.len() <= 1 {
                    continue;
                }

                let keeper_idx = self
                    .keeper_overrides
                    .as_ref()
                    .and_then(|overrides| overrides.get(gi).copied())
                    .unwrap_or(group.keeper_index);

                Self::merge_takeout_for_keeper(
                    &group.files[keeper_idx].path,
                    &takeout_dir,
                    &quarantine,
                    &session_id,
                );

                prior_keepers.insert(group.files[keeper_idx].path.as_str().to_string());
                let group_cleaned_before = exact_cleaned_files;

                total_files += (group.files.len() - 1) as u64;
                total_bytes += group.size_bytes * (group.files.len() as u64 - 1);

                for (i, file) in group.files.iter().enumerate() {
                    if i == keeper_idx {
                        continue;
                    }

                    if self.cancel.is_cancelled() {
                        cancelled = true;
                        break;
                    }

                    let file_meta = std::fs::symlink_metadata(file.path.as_std_path());
                    let protection = if let Ok(ref meta) = file_meta {
                        zerodupe_platform::protection::classify_file(&file.path, meta)
                    } else {
                        zerodupe_platform::ProtectionLevel::NeverDelete
                    };
                    if protection == zerodupe_platform::ProtectionLevel::NeverDelete {
                        let reason = protection_reason(&file.path, &file_meta.ok());
                        let protected_file = zerodupe_core::ProtectedFileInfo {
                            path: file.path.as_str().to_string(),
                            size_bytes: file.size_bytes,
                            reason,
                        };
                        accumulate_protected_inner(
                            &mut local_protected,
                            gi,
                            group.files.len(),
                            protected_file,
                            None,
                        );
                        continue;
                    }

                    // TOCTTOU guard: re-verify the file hasn't changed since the
                    // scan (size witness propagated via the group entry) right
                    // before the destructive move. A file edited, truncated or
                    // replaced between scan and clean is refused, not quarantined.
                    let toctou_ok = zerodupe_safety::verify_safe_to_act(
                        file.path.as_path(),
                        &zerodupe_safety::FileSnapshot {
                            size_bytes: file.size_bytes,
                            modified_unix_seconds: None,
                            physical_key: None,
                        },
                        zerodupe_platform::current(),
                    )
                    .is_ok();
                    let quarantine_result = if toctou_ok {
                        quarantine.quarantine_file(
                            file.path.as_std_path(),
                            "user-cleaned",
                            &session_id,
                            Some(30),
                        )
                    } else {
                        Err(std::io::Error::other(
                            "file changed since scan (TOCTTOU guard)",
                        ))
                    };
                    match quarantine_result {
                        Ok(entry) => {
                            quarantine_paths.insert(
                                file.path.as_str().to_string(),
                                entry.quarantined_path.as_str().to_string(),
                            );

                            files_done += 1;
                            bytes_done += file.size_bytes;
                            exact_cleaned_bytes += file.size_bytes;
                            exact_cleaned_files += 1;
                        }
                        Err(_e) => {
                            skipped_files += 1;
                        }
                    }

                    self.state = WorkflowState::Cleaning {
                        files_done,
                        files_total: total_files,
                        bytes_done,
                    };

                    if let Some(p) = progress {
                        p.emit(ProgressEvent {
                            stage: ScanStage::Cleaning,
                            current: files_done,
                            total: total_files,
                            current_file: Some(file.path.as_str().to_string()),
                            bytes_processed: Some(bytes_done),
                            bytes_total: Some(total_bytes),
                        });
                    }
                }
                // El keeper queda como único superviviente de su grupo:
                // se registra para que ninguna pasada futura lo remueva.
                if exact_cleaned_files > group_cleaned_before {
                    let _ = quarantine
                        .record_kept_file(group.files[keeper_idx].path.as_path(), &session_id);
                }
                if cancelled {
                    break;
                }
                exact_cleaned_groups += 1;
            }
        }

        // Sesión separada para similares: permite que la cuarentena etiquete
        // y filtre cada tipo de limpieza (exact/similar) de forma independiente.
        let similar_session_id = format!("{session_id}-similar");

        if !cancelled && let Some(ref report) = self.similar_report {
            for (gi, group) in report.groups.iter().enumerate() {
                if group.files.len() <= 1 {
                    continue;
                }

                let keeper_idx = self
                    .keeper_overrides
                    .as_ref()
                    .and_then(|overrides| {
                        overrides
                            .get(
                                gi + self
                                    .exact_report
                                    .as_ref()
                                    .map(|r| r.confirmed_groups.len())
                                    .unwrap_or(0),
                            )
                            .copied()
                    })
                    .unwrap_or(group.keeper_index);

                Self::merge_takeout_for_keeper(
                    &group.files[keeper_idx].path,
                    &takeout_dir,
                    &quarantine,
                    &similar_session_id,
                );

                let group_cleaned_before = similar_cleaned_files;

                total_files += (group.files.len() - 1) as u64;
                total_bytes += group
                    .files
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != keeper_idx)
                    .map(|(_, f)| f.size_bytes)
                    .sum::<u64>();

                for (i, file) in group.files.iter().enumerate() {
                    if i == keeper_idx {
                        continue;
                    }

                    if self.cancel.is_cancelled() {
                        cancelled = true;
                        break;
                    }

                    // Backstop: keeper de una limpieza anterior — único
                    // superviviente de su grupo, jamás se manda a cuarentena.
                    if prior_keepers.contains(file.path.as_str()) {
                        let gi_offset = self
                            .exact_report
                            .as_ref()
                            .map(|r| r.confirmed_groups.len())
                            .unwrap_or(0);
                        accumulate_protected_inner(
                            &mut local_protected,
                            gi_offset + gi,
                            group.files.len(),
                            zerodupe_core::ProtectedFileInfo {
                                path: file.path.as_str().to_string(),
                                size_bytes: file.size_bytes,
                                reason: format!(
                                    "Keeper of a previous cleanup — sole surviving copy of its group: {}",
                                    file.path.as_str()
                                ),
                            },
                            None,
                        );
                        continue;
                    }

                    let file_meta = std::fs::symlink_metadata(file.path.as_std_path());
                    let protection = if let Ok(ref meta) = file_meta {
                        zerodupe_platform::protection::classify_file(&file.path, meta)
                    } else {
                        zerodupe_platform::ProtectionLevel::NeverDelete
                    };
                    if protection == zerodupe_platform::ProtectionLevel::NeverDelete {
                        let reason = protection_reason(&file.path, &file_meta.ok());
                        let gi_offset = self
                            .exact_report
                            .as_ref()
                            .map(|r| r.confirmed_groups.len())
                            .unwrap_or(0);
                        let protected_file = zerodupe_core::ProtectedFileInfo {
                            path: file.path.as_str().to_string(),
                            size_bytes: file.size_bytes,
                            reason,
                        };
                        accumulate_protected_inner(
                            &mut local_protected,
                            gi_offset + gi,
                            group.files.len(),
                            protected_file,
                            None,
                        );
                        continue;
                    }

                    // TOCTTOU guard (see exact-duplicate path above): refuse to
                    // quarantine a file whose size changed since the scan.
                    let toctou_ok = zerodupe_safety::verify_safe_to_act(
                        file.path.as_path(),
                        &zerodupe_safety::FileSnapshot {
                            size_bytes: file.size_bytes,
                            modified_unix_seconds: None,
                            physical_key: None,
                        },
                        zerodupe_platform::current(),
                    )
                    .is_ok();
                    let quarantine_result = if toctou_ok {
                        quarantine.quarantine_file(
                            file.path.as_std_path(),
                            "user-cleaned-similar",
                            &similar_session_id,
                            Some(30),
                        )
                    } else {
                        Err(std::io::Error::other(
                            "file changed since scan (TOCTTOU guard)",
                        ))
                    };
                    match quarantine_result {
                        Ok(entry) => {
                            quarantine_paths.insert(
                                file.path.as_str().to_string(),
                                entry.quarantined_path.as_str().to_string(),
                            );

                            files_done += 1;
                            bytes_done += file.size_bytes;
                            similar_cleaned_bytes += file.size_bytes;
                            similar_cleaned_files += 1;
                        }
                        Err(_e) => {
                            skipped_files += 1;
                        }
                    }

                    self.state = WorkflowState::Cleaning {
                        files_done,
                        files_total: total_files,
                        bytes_done,
                    };

                    if let Some(p) = progress {
                        p.emit(ProgressEvent {
                            stage: ScanStage::Cleaning,
                            current: files_done,
                            total: total_files,
                            current_file: Some(file.path.as_str().to_string()),
                            bytes_processed: Some(bytes_done),
                            bytes_total: Some(total_bytes),
                        });
                    }
                }
                if similar_cleaned_files > group_cleaned_before {
                    let _ = quarantine.record_kept_file(
                        group.files[keeper_idx].path.as_path(),
                        &similar_session_id,
                    );
                }
                if cancelled {
                    break;
                }
                similar_cleaned_groups += 1;
            }
        }

        self.protected_groups = local_protected;
        let protected_file_count: usize = self
            .protected_groups
            .iter()
            .map(|g| g.protected_files.len())
            .sum();

        let mut hygiene_items_cleaned = 0usize;
        let mut hygiene_bytes_cleaned: u64 = 0;

        if !cancelled {
            let service = HygieneService::new(scan_root.clone())
                .with_exclude_dirs(vec!["zerodupe_quarantine".to_string()]);
            let hygiene_report = service.scan(progress, Some(&self.cancel));

            for item in &hygiene_report.items {
                if self.cancel.is_cancelled() {
                    break;
                }

                if !item.can_clean {
                    continue;
                }

                match item.category {
                    JunkCategory::EmptyFile | JunkCategory::BrokenSymlink => {
                        let _ = std::fs::remove_file(item.path.as_std_path());
                        if let Ok(canonical) = item.path.canonicalize_utf8() {
                            quarantine_paths.insert(
                                item.path.as_str().to_string(),
                                canonical.as_str().to_string(),
                            );
                        }
                        hygiene_items_cleaned += 1;
                        hygiene_bytes_cleaned += item.size_bytes;
                    }
                    JunkCategory::EmptyDirectory => {
                        let _ = std::fs::remove_dir_all(item.path.as_std_path());
                        hygiene_items_cleaned += 1;
                        hygiene_bytes_cleaned += item.size_bytes;
                    }
                    _ => {
                        let file_name = item.path.file_name().unwrap_or("junk_file");
                        let dest_path = junk_dir.join(file_name);

                        if std::fs::rename(item.path.as_std_path(), &dest_path).is_ok()
                            && let Ok(dest_utf8) =
                                camino::Utf8PathBuf::from_path_buf(dest_path.clone())
                        {
                            let _ = quarantine.record_entry(
                                &item.path,
                                &dest_utf8,
                                item.size_bytes,
                                &format!("{}", item.category),
                                &session_id,
                                Some(30),
                            );
                            quarantine_paths.insert(
                                item.path.as_str().to_string(),
                                dest_utf8.as_str().to_string(),
                            );
                            hygiene_items_cleaned += 1;
                            hygiene_bytes_cleaned += item.size_bytes;
                        }
                    }
                }

                if let Some(p) = progress {
                    p.emit(ProgressEvent {
                        stage: ScanStage::Hygiene,
                        current: hygiene_items_cleaned as u64,
                        total: hygiene_report.items.iter().filter(|i| i.can_clean).count() as u64,
                        current_file: Some(item.path.as_str().to_string()),
                        bytes_processed: Some(hygiene_bytes_cleaned),
                        bytes_total: Some(
                            hygiene_report
                                .items
                                .iter()
                                .filter(|i| i.can_clean)
                                .map(|i| i.size_bytes)
                                .sum(),
                        ),
                    });
                }
            }

            self.hygiene_items = hygiene_items_cleaned as u64;
            self.hygiene_reclaimable = hygiene_bytes_cleaned;
            self.hygiene_report = Some(hygiene_report);
        } // if !cancelled

        if let Err(_e) = self.generate_html_reports(&quarantine_paths) {}

        let protected_data = if !self.protected_groups.is_empty() {
            serde_json::to_value(&self.protected_groups).ok()
        } else {
            None
        };

        self.state = WorkflowState::Complete {
            exact_groups: exact_cleaned_groups,
            exact_reclaimable: exact_cleaned_bytes,
            exact_files: exact_cleaned_files,
            similar_groups: similar_cleaned_groups,
            similar_reclaimable: similar_cleaned_bytes,
            similar_files: similar_cleaned_files,
            hygiene_items: hygiene_items_cleaned,
            hygiene_reclaimable: hygiene_bytes_cleaned,
            protected_groups: protected_data,
            protected_file_count,
            skipped_file_count: skipped_files,
        };

        Ok(())
    }

    fn generate_html_reports(
        &mut self,
        quarantine_paths: &HashMap<String, String>,
    ) -> Result<(), WorkflowError> {
        let reports_dir = reports_dir().map_err(WorkflowError::Io)?;
        std::fs::create_dir_all(&reports_dir).map_err(WorkflowError::Io)?;

        let scan_root = self
            .scan_root
            .as_ref()
            .map(|p| p.as_str())
            .unwrap_or("unknown");

        let elapsed = self
            .started_at
            .map(|start| start.elapsed())
            .unwrap_or_default();

        let lang = zerodupe_report::i18n::detect_lang();
        let mut report_id: Option<String> = None;

        if let Some(ref exact_report) = self.exact_report {
            let rid = zerodupe_config::reports::make_report_id(scan_root, "exact");
            let html_path: std::path::PathBuf = reports_dir.join(format!("{rid}.html"));

            let generated_path = html::generate_exact_html_report(
                lang,
                std::path::Path::new(scan_root),
                &html_path,
                exact_report,
                quarantine_paths,
                elapsed,
            )
            .map_err(WorkflowError::Io)?;

            let mut saved =
                build_report_from_exact(exact_report, &rid, scan_root, &self.protected_groups);
            saved.quarantine_path = self
                .last_quarantine_dir
                .as_ref()
                .map(|p| p.as_str().to_string());

            let json_path = reports_dir.join(format!("{rid}.json"));
            let json = serde_json::to_string_pretty(&saved)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            std::fs::write(&json_path, json).map_err(WorkflowError::Io)?;

            report_id = Some(rid);
            self.last_report_path = Some(generated_path);
        }

        if let Some(ref similar_report) = self.similar_report {
            let rid = report_id
                .clone()
                .unwrap_or_else(|| zerodupe_config::reports::make_report_id(scan_root, "similar"));
            let html_path: std::path::PathBuf = reports_dir.join(format!("{rid}.html"));

            let _ = html::generate_similar_html_report(
                lang,
                std::path::Path::new(scan_root),
                &html_path,
                similar_report,
                quarantine_paths,
                elapsed,
            );

            // Guardar el SavedReport JSON solo en flujo similar-only: si hubo
            // exactos, el rid es compartido y el JSON de exactos ya existe.
            if report_id.is_none() {
                let mut saved = zerodupe_config::build_report_from_similar(
                    similar_report,
                    &rid,
                    scan_root,
                    &self.protected_groups,
                );
                saved.quarantine_path = self
                    .last_quarantine_dir
                    .as_ref()
                    .map(|p| p.as_str().to_string());

                let json_path = reports_dir.join(format!("{rid}.json"));
                if let Ok(json) = serde_json::to_string_pretty(&saved) {
                    let _ = std::fs::write(&json_path, json);
                }
            }

            self.last_report_path = Some(html_path);
        }

        if let Some(ref report_path) = self.last_report_path
            && let Some(ref hygiene_report) = self.hygiene_report
        {
            html::append_hygiene_section(lang, report_path, hygiene_report)
                .map_err(WorkflowError::Io)?;
        }

        if let Some(ref report_path) = self.last_report_path
            && !self.protected_groups.is_empty()
        {
            let _ = html::append_protected_section(lang, report_path, &self.protected_groups);
        }

        Ok(())
    }
}

fn unix_day_to_date(day: u64) -> (u64, u64, u64) {
    let mut remaining = day as i64;
    let mut year = 1970u64;
    loop {
        let year_days = if is_leap_year(year) { 366 } else { 365 };
        if remaining < year_days {
            break;
        }
        remaining -= year_days;
        year += 1;
    }
    let month_days = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u64;
    for &md in &month_days {
        if remaining < md {
            break;
        }
        remaining -= md;
        month += 1;
    }
    let dom = (remaining + 1) as u64;
    (year, month, dom)
}

fn is_leap_year(y: u64) -> bool {
    y.is_multiple_of(400) || (y.is_multiple_of(4) && !y.is_multiple_of(100))
}

fn protection_reason(path: &camino::Utf8PathBuf, metadata: &Option<std::fs::Metadata>) -> String {
    let path_str = path.as_str().to_lowercase().replace('\\', "/");

    if let Some(meta) = metadata {
        let file_type = meta.file_type();
        if file_type.is_symlink() {
            return format!("Symlink — cannot safely modify: {}", path.as_str());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            if mode & 0o4000 != 0 {
                return format!("Setuid binary — system critical: {}", path.as_str());
            }
            if mode & 0o2000 != 0 {
                return format!("Setgid binary — system critical: {}", path.as_str());
            }
        }
    }

    let has_system_ext = {
        let ext = path.extension().unwrap_or("").to_lowercase();
        matches!(
            ext.as_str(),
            "exe"
                | "dll"
                | "sys"
                | "drv"
                | "ocx"
                | "msi"
                | "so"
                | "ko"
                | "a"
                | "dylib"
                | "bundle"
                | "kext"
                | "app"
                | "wasm"
        )
    };

    if has_system_ext {
        if path_str.contains("/windows/")
            || path_str.contains("/program files/")
            || path_str.contains("/program files (x86)/")
        {
            return format!("System directory on Windows: {}", path.as_str());
        }
        if path_str.contains("/system/")
            || path_str.contains("/library/")
            || path_str.contains("/usr/lib")
            || path_str.contains("/usr/bin")
            || path_str.contains("/usr/sbin")
            || path_str.contains("/bin/")
            || path_str.contains("/sbin/")
            || path_str.contains("/boot/")
            || path_str.contains("/lib/")
            || path_str.contains("/lib64/")
        {
            return format!("System directory on Unix: {}", path.as_str());
        }
        return format!("Executable file — system critical: {}", path.as_str());
    }

    format!("Protected file: {}", path.as_str())
}

fn accumulate_protected_inner(
    protected_groups: &mut Vec<zerodupe_core::ProtectedGroup>,
    group_index: usize,
    total_files: usize,
    protected_file: zerodupe_core::ProtectedFileInfo,
    cleaned_file: Option<zerodupe_core::ProtectedFileInfo>,
) {
    let protected_bytes = protected_file.size_bytes;
    if let Some(group) = protected_groups
        .iter_mut()
        .find(|g| g.group_index == group_index)
    {
        group.protected_files.push(protected_file);
        group.protected_bytes += protected_bytes;
        if let Some(cf) = cleaned_file {
            group.cleaned_files.push(cf);
        }
    } else {
        let mut cleaned = Vec::new();
        if let Some(cf) = cleaned_file {
            cleaned.push(cf);
        }
        protected_groups.push(zerodupe_core::ProtectedGroup {
            group_index,
            total_files,
            protected_files: vec![protected_file],
            cleaned_files: cleaned,
            protected_bytes,
        });
    }
}
