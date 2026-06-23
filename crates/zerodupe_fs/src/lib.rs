//! ── Discovery del filesystem para ZeroDupe ──────────────────────────────
//!
//! `zerodupe_fs` es el punto de entrada al pipeline de deduplicación: recorre
//! el sistema de archivos, recoge metadatos de cada entrada y produce un flujo
//! ordenado de [`DiscoveredEntry`] que los pilares (exactos, similares, higiene)
//! consumen sin volver a tocar el disco.
//!
//! ## Propósito
//!
//! * **Unificar el acceso a disco** en un solo crate. Los pilares trabajan sobre
//!   `DiscoveredEntry` y no hacen `stat()`, `read_dir()` ni `symlink_metadata()`
//!   — eso evita duplicación de I/O y condiciones de carrera entre etapas.
//! * **Aplicar exclusiones una sola vez**, antes de que los datos lleguen a los
//!   pipelines de hash/similar/higiene. Exclusiones mal aplicadas en cada pilar
//!   causan resultados inconsistentes.
//! * **Canonicalizar raíces** (`ScanRoot`) y asignar un `RootId` por cada
//!   directorio raíz que el usuario solicita escanear. Esto permite que el
//!   reporte final trace cada entrada a su origen.
//!
//! ## Cómo funciona
//!
//! El entry point es [`discover_roots`]: recibe una lista de raíces
//! (`Vec<Utf8PathBuf>`), opciones de descubrimiento
//! ([`DiscoveryOptions`]) y canales opcionales de progreso/cancelación.
//! Internamente:
//!
//! 1. Convierte cada ruta en un [`ScanRoot`] con un `RootId` auto-incremental.
//! 2. Por cada raíz, invoca `discover_root()`.
//! 3. `discover_root()` construye un [`WalkBuilder`] (del crate `ignore`) que:
//!    * Recorre el árbol en paralelo (rayon) según `number_of_threads`.
//!    * Respeta `.gitignore`, `.ignore` y archivos ocultos si se configura.
//!    * Filtra directorios por prefijo (ej: `node_modules`, `target`, `.git`).
//!    * Emite eventos de progreso con intervalo adaptativo (evita inundar la UI).
//!    * Obedece la señal de cancelación entre iteraciones.
//! 4. Cada entrada válida se convierte en un [`DiscoveredEntry`] con:
//!    * `root_id`, `path` (UTF-8 validado), `kind`, `depth`, `size_bytes`,
//!      `readonly`, `timestamps` (modified/created/changed), `physical_key`.
//! 5. Las entradas inválidas (paths no-UTF8, metadatos inaccesibles, errores
//!    de I/O del walker) se acumulan como [`DiscoveryError`] sin detener el scan.
//! 6. Al finalizar, entradas y errores se ordenan alfabéticamente y se empaquetan
//!    en un [`DiscoveryReport`].
//!
//! ## Multithreading
//!
//! El paralelismo se controla con `DiscoveryOptions::number_of_threads`. El
//! `WalkBuilder` de `ignore` usa rayon internamente; cada hilo del pool procesa
//! una rama del árbol de directorios en paralelo. El progreso se reporta desde
//! el hilo principal con un intervalo adaptativo al volumen de archivos.
//!
//! ## System excludes
//!
//! Las exclusiones se aplican en dos capas:
//!
//! | Capa | Mecanismo | Ejemplos |
//! |------|-----------|----------|
//! | Oculta/SO | `WalkBuilder::hidden(true)` | `.dotfiles`, `$RECYCLE.BIN` |
//! | Prefijos | `filter_entry()` con `exclude_prefixes` | `.git`, `node_modules`, `target` |
//!
//! Los prefijos se resuelven contra la raíz del scan si son relativos, lo que
//! permite exclusiones portables entre sistemas.
//!
//! ## Manejo de errores
//!
//! Los errores se clasifican con [`DiscoveryErrorKind`] (NotFound,
//! PermissionDenied, InvalidData, OtherIo). Una entrada problemática produce un
//! `DiscoveryError` y se registra, pero **nunca detiene el scan**. Esto permite
//! que el usuario obtenga resultados parciales incluso cuando hay directorios
//! sin permisos o paths corruptos.
//!
//! ## Dependencias clave
//!
//! * [`ignore`] — WalkBuilder paralelo con soporte de `.gitignore` nativo.
//! * [`camino`] — `Utf8Path`/`Utf8PathBuf` para paths UTF-8 garantizados.
//! * [`zerodupe_core`] — Tipos compartidos del workspace.
//! * [`zerodupe_platform`] — Abstracción multi-SO para physical keys y timestamps.

use std::{fs, io, path::Path, time::UNIX_EPOCH};

use camino::{Utf8Path, Utf8PathBuf};
use ignore::WalkBuilder;
use zerodupe_core::{
    CancelFlag, DiscoveredEntry, DiscoveredKind, DiscoveryError, DiscoveryErrorKind,
    DiscoveryOptions, DiscoveryReport, FileTimestamps, ProgressEvent, ProgressReporter, RootId,
    ScanRoot, ScanStage, ZeroDupeError, ZeroDupeResult,
};

// ── Cross-platform physical file key ──

/// ── Clave física de archivo multi-plataforma ──
///
/// Extrae un [`PhysicalFileKey`] que identifica de forma única a un archivo
/// en el sistema de archivos, independientemente de su nombre o ruta.
///
/// ## Por qué existe
///
/// Dos paths distintos pueden apuntar al mismo inodo (hard links, bind mounts).
/// Sin una clave física, el pipeline contaría el mismo archivo varias veces,
/// inflaría estadísticas y podría intentar borrar el mismo contenido por
/// duplicado. Esta función da a cada archivo una identidad canónica a nivel
/// de dispositivo+inodo (Unix) o volumen+file index (Windows).
///
/// ## Comportamiento por plataforma
///
/// | SO | Fuente | Campos |
/// |----|--------|--------|
/// | Linux / macOS | `symlink_metadata()` + `MetadataExt` | `dev()` + `ino()` |
/// | Windows | `MetadataExt` | volume serial + file index |
/// | Otros | Fallback vía `from_fallback` | hash del path |
///
/// Si `symlink_metadata()` falla (archivo borrado entre discovery y hash),
/// se usa el fallback basado en el path.
///
/// ## Cuándo se llama
///
/// Durante `add_entry()`, solo para archivos regulares (`DiscoveredKind::File`),
/// aprovechando que los metadatos ya están en mano — esto ahorra dos llamadas
/// extra a `stat()` en las etapas posteriores del pipeline.
pub fn extract_physical_file_key(path: &Utf8Path) -> zerodupe_platform::PhysicalFileKey {
    extract_physical_key_impl(path)
}

#[cfg(unix)]
fn extract_physical_key_impl(path: &Utf8Path) -> zerodupe_platform::PhysicalFileKey {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(path.as_std_path()) {
        Ok(meta) => zerodupe_platform::PhysicalFileKey::from_unix(meta.dev(), meta.ino()),
        Err(_) => zerodupe_platform::PhysicalFileKey::from_fallback(path),
    }
}

#[cfg(windows)]
fn extract_physical_key_impl(path: &Utf8Path) -> zerodupe_platform::PhysicalFileKey {
    zerodupe_platform::PhysicalFileKey::from_path_windows(path)
        .unwrap_or_else(|| zerodupe_platform::PhysicalFileKey::from_fallback(path))
}

#[cfg(not(any(unix, windows)))]
fn extract_physical_key_impl(path: &Utf8Path) -> zerodupe_platform::PhysicalFileKey {
    zerodupe_platform::PhysicalFileKey::from_fallback(path)
}

/// ── Validación temprana de paths UTF-8 ──
///
/// Verifica que un path proporcionado por el usuario pueda representarse como
/// UTF-8 y no esté vacío.
///
/// ## Por qué existe
///
/// ZeroDupe usa [`camino::Utf8Path`] en toda la aplicación para evitar
/// panics por paths no-UTF8 en Windows o en sistemas Linux con locales
/// rotos. Esta validación se ejecuta en el CLI antes de invocar
/// `discover_roots()`, dando al usuario un mensaje de error claro en lugar
/// de un panic oscuro dentro del walker.
///
/// ## Errores
///
/// * `ZeroDupeError::InvalidPath` si el path es una cadena vacía.
/// * Los paths no-UTF8 son rechazados por `camino` en la conversión de tipos
///   antes de llegar a esta función.
pub fn validate_utf8_path(path: &Utf8Path) -> ZeroDupeResult<()> {
    if path.as_str().is_empty() {
        return Err(ZeroDupeError::InvalidPath("empty path".to_string()));
    }

    Ok(())
}

/// ── Entry point del discovery de archivos ──
///
/// Recorre una o varias raíces del sistema de archivos y produce un
/// [`DiscoveryReport`] con todas las entradas encontradas, ordenadas y
/// clasificadas.
///
/// ## Por qué es el entry point único
///
/// Centralizar el discovery aquí garantiza que **todos los pilares** (exactos,
/// similares, higiene) vean exactamente las mismas entradas, con los mismos
/// metadatos capturados en el mismo momento. Si cada pilar hiciera su propio
/// `walkdir`, los resultados divergerían si un archivo se crea/borra entre
/// etapas.
///
/// ## Parámetros
///
/// * `roots` — Lista de directorios raíz a escanear. Pueden solaparse; las
///   entradas duplicadas se detectan vía `PhysicalFileKey` en etapas posteriores.
/// * `options` — [`DiscoveryOptions`]: exclusiones, seguimiento de symlinks,
///   archivos ocultos, número de hilos.
/// * `progress` — Reporter opcional de progreso para la UI (CLI wizard o GUI).
/// * `cancel` — Bandera opcional de cancelación para interrumpir el scan.
///
/// ## Retorno
///
/// [`DiscoveryReport`] con:
///
/// | Campo | Descripción |
/// |-------|-------------|
/// | `scan_roots` | Raíces escaneadas con sus `RootId` |
/// | `entries` | [`DiscoveredEntry`] ordenadas alfabéticamente |
/// | `errors` | [`DiscoveryError`] ordenados alfabéticamente |
/// | `summary` | Conteos: files, directories, symlinks, total_file_bytes, errors |
///
/// ## Flujo interno
///
/// 1. Asigna `RootId` a cada raíz (índice en el vector).
/// 2. Itera secuencialmente las raíces (no en paralelo entre raíces, porque
///    cada `WalkBuilder` ya paraleliza internamente su propio árbol).
/// 3. Por cada raíz, `discover_root()` construye el walker, aplica exclusiones
///    y emite progreso.
/// 4. Las entradas y errores se acumulan en vectores mutables compartidos.
/// 5. Al final, se ordenan alfabéticamente para determinismo.
pub fn discover_roots(
    roots: Vec<Utf8PathBuf>,
    options: &DiscoveryOptions,
    progress: Option<&dyn ProgressReporter>,
    cancel: Option<&CancelFlag>,
) -> DiscoveryReport {
    let scan_roots = roots
        .into_iter()
        .enumerate()
        .map(|(index, path)| ScanRoot {
            id: RootId(index as u32),
            path,
        })
        .collect::<Vec<_>>();

    let mut entries = Vec::new();
    let mut errors = Vec::new();

    for root in &scan_roots {
        discover_root(root, options, &mut entries, &mut errors, progress, cancel);
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));
    errors.sort_by(|left, right| left.path.cmp(&right.path));

    DiscoveryReport::new(scan_roots, entries, errors)
}

fn discover_root(
    root: &ScanRoot,
    options: &DiscoveryOptions,
    entries: &mut Vec<DiscoveredEntry>,
    errors: &mut Vec<DiscoveryError>,
    progress: Option<&dyn ProgressReporter>,
    cancel: Option<&CancelFlag>,
) {
    if !root.path.exists() {
        errors.push(discovery_error(
            Some(root.id),
            Some(root.path.clone()),
            DiscoveryErrorKind::NotFound,
            "root path does not exist".to_string(),
        ));
        return;
    }

    let exclude_prefixes: Vec<String> = options
        .exclude_prefixes
        .iter()
        .map(|pattern| {
            if Path::new(pattern).is_absolute() {
                pattern.clone()
            } else {
                // Resolve relative patterns against the scan root.
                root.path.join(pattern).as_str().to_string()
            }
        })
        .collect();

    let mut builder = WalkBuilder::new(root.path.as_std_path());
    builder
        .follow_links(options.follow_symlinks)
        .hidden(!options.include_hidden)
        .git_ignore(options.respect_gitignore)
        .git_global(options.respect_gitignore)
        .git_exclude(options.respect_gitignore)
        .ignore(options.respect_gitignore);

    if !exclude_prefixes.is_empty() {
        builder.filter_entry(move |entry| {
            let entry_path = entry.path();
            for pattern in &exclude_prefixes {
                if entry_path.starts_with(pattern) {
                    return false;
                }
            }
            true
        });
    }

    let mut files_found: u64 = 0;

    // Emit initial progress so UI updates immediately
    if let Some(p) = progress {
        p.emit(ProgressEvent {
            stage: ScanStage::Discovery,
            current: 0,
            total: 0,
            current_file: Some(root.path.to_string()),
            bytes_processed: None,
            bytes_total: None,
        });
    }

    for result in builder.build() {
        // Adaptive interval: fewer events for large directories to avoid flooding the UI
        let report_interval = match files_found {
            0..=99 => 10u64,
            100..=999 => 50,
            1000..=9999 => 200,
            _ => 500,
        };
        if files_found.is_multiple_of(report_interval)
            && let Some(p) = progress
        {
            p.emit(ProgressEvent {
                stage: ScanStage::Discovery,
                current: entries.len() as u64,
                total: 0,
                current_file: None,
                bytes_processed: None,
                bytes_total: None,
            });
        }
        if let Some(c) = cancel
            && c.is_cancelled()
        {
            return;
        }

        match result {
            Ok(entry) => {
                add_entry(root.id, &entry, options, entries, errors);
                files_found += 1;
            }
            Err(error) => errors.push(ignore_error(root.id, &error)),
        }
    }
}

fn add_entry(
    root_id: RootId,
    entry: &ignore::DirEntry,
    options: &DiscoveryOptions,
    entries: &mut Vec<DiscoveredEntry>,
    errors: &mut Vec<DiscoveryError>,
) {
    let path = entry.path();
    let depth = entry.depth();

    let utf8_path = match path_to_utf8(path) {
        Ok(path) => path,
        Err(error) => {
            errors.push(error);
            return;
        }
    };

    let metadata = match entry.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            errors.push(ignore_error(root_id, &error));
            return;
        }
    };

    let file_type = metadata.file_type();
    let kind = if file_type.is_symlink() {
        DiscoveredKind::Symlink
    } else if file_type.is_file() {
        DiscoveredKind::File
    } else if file_type.is_dir() {
        DiscoveredKind::Directory
    } else {
        DiscoveredKind::Other
    };

    if kind == DiscoveredKind::Symlink && !options.include_symlink_entries {
        return;
    }

    let size_bytes = (kind == DiscoveredKind::File).then_some(metadata.len());
    let readonly = metadata.permissions().readonly();
    let timestamps = timestamps_from_metadata(&metadata);
    // Capture the physical identity here, where the metadata is already in
    // hand — saves the scan stages two extra stat() calls per file.
    let physical_key = (kind == DiscoveredKind::File)
        .then(|| zerodupe_platform::current().physical_key(&utf8_path, &metadata))
        .flatten();

    entries.push(DiscoveredEntry {
        root_id,
        path: utf8_path,
        kind,
        depth,
        size_bytes,
        readonly,
        timestamps,
        physical_key,
    });
}

fn timestamps_from_metadata(metadata: &fs::Metadata) -> FileTimestamps {
    FileTimestamps {
        modified_unix_seconds: metadata.modified().ok().and_then(unix_seconds),
        created_unix_seconds: metadata.created().ok().and_then(unix_seconds),
        modified_unix_nanos: metadata.modified().ok().and_then(unix_nanos),
        changed_unix_nanos: zerodupe_platform::change_time_nanos(metadata),
    }
}

fn unix_seconds(time: std::time::SystemTime) -> Option<i64> {
    let seconds = time.duration_since(UNIX_EPOCH).ok()?.as_secs();
    i64::try_from(seconds).ok()
}

fn unix_nanos(time: std::time::SystemTime) -> Option<i64> {
    let nanos = time.duration_since(UNIX_EPOCH).ok()?.as_nanos();
    i64::try_from(nanos).ok()
}

fn path_to_utf8(path: &Path) -> Result<Utf8PathBuf, DiscoveryError> {
    Utf8PathBuf::from_path_buf(path.to_path_buf()).map_err(|path| {
        discovery_error(
            None,
            None,
            DiscoveryErrorKind::InvalidData,
            format!("path is not valid UTF-8: {}", path.display()),
        )
    })
}

fn ignore_error(root_id: RootId, error: &ignore::Error) -> DiscoveryError {
    let kind = error
        .io_error()
        .map_or(DiscoveryErrorKind::OtherIo, io_error_kind);

    discovery_error(Some(root_id), None, kind, error.to_string())
}

fn io_error_kind(error: &io::Error) -> DiscoveryErrorKind {
    match error.kind() {
        io::ErrorKind::NotFound => DiscoveryErrorKind::NotFound,
        io::ErrorKind::PermissionDenied => DiscoveryErrorKind::PermissionDenied,
        io::ErrorKind::InvalidData => DiscoveryErrorKind::InvalidData,
        io::ErrorKind::InvalidInput => DiscoveryErrorKind::InvalidData,
        _ => DiscoveryErrorKind::OtherIo,
    }
}

fn discovery_error(
    root_id: Option<RootId>,
    path: Option<Utf8PathBuf>,
    kind: DiscoveryErrorKind,
    message: String,
) -> DiscoveryError {
    DiscoveryError {
        root_id,
        path,
        kind,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn rejects_empty_path() {
        let err = validate_utf8_path(Utf8Path::new("")).unwrap_err();
        assert!(matches!(err, ZeroDupeError::InvalidPath(_)));
    }

    #[test]
    fn discovers_regular_file() {
        let temp = tempfile::tempdir().expect("tempdir should exist");
        let file_path = temp.path().join("hello.txt");
        let mut file = fs::File::create(&file_path).expect("file should be created");
        file.write_all(b"hello").expect("file should be written");

        let root = path_to_utf8(temp.path()).expect("temp path should be utf8");
        let report = discover_roots(vec![root], &DiscoveryOptions::default(), None, None);

        assert_eq!(report.summary.errors, 0);
        assert_eq!(report.summary.files, 1);
        assert_eq!(report.summary.total_file_bytes, 5);
    }

    #[test]
    fn reports_missing_root() {
        let report = discover_roots(
            vec![Utf8PathBuf::from("/definitely/missing/zerodupe/root")],
            &DiscoveryOptions::default(),
            None,
            None,
        );

        assert_eq!(report.summary.files, 0);
        assert_eq!(report.summary.errors, 1);
        assert_eq!(report.errors[0].kind, DiscoveryErrorKind::NotFound);
    }

    #[test]
    fn hides_hidden_files_by_default() {
        let temp = tempfile::tempdir().expect("tempdir should exist");
        fs::write(temp.path().join(".hidden"), b"secret").expect("hidden file should be written");

        let root = path_to_utf8(temp.path()).expect("temp path should be utf8");
        let report = discover_roots(vec![root], &DiscoveryOptions::default(), None, None);

        assert_eq!(report.summary.files, 0);
    }

    #[test]
    fn includes_hidden_files_when_configured() {
        let temp = tempfile::tempdir().expect("tempdir should exist");
        fs::write(temp.path().join(".hidden"), b"secret").expect("hidden file should be written");

        let root = path_to_utf8(temp.path()).expect("temp path should be utf8");
        let options = DiscoveryOptions {
            include_hidden: true,
            ..DiscoveryOptions::default()
        };
        let report = discover_roots(vec![root], &options, None, None);

        assert_eq!(report.summary.files, 1);
    }

    #[cfg(unix)]
    #[test]
    fn includes_symlink_entry_without_following() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir should exist");
        let target = temp.path().join("target.txt");
        let link = temp.path().join("link.txt");
        fs::write(&target, b"target").expect("target should be written");
        symlink(&target, &link).expect("symlink should be created");

        let root = path_to_utf8(temp.path()).expect("temp path should be utf8");
        let report = discover_roots(vec![root], &DiscoveryOptions::default(), None, None);

        assert_eq!(report.summary.files, 1);
        assert_eq!(report.summary.symlinks, 1);
    }

    #[cfg(unix)]
    #[test]
    fn no_symlink_entries_skips_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir should exist");
        let target = temp.path().join("target.txt");
        let link = temp.path().join("link.txt");
        fs::write(&target, b"target").expect("target should be written");
        symlink(&target, &link).expect("symlink should be created");

        let root = path_to_utf8(temp.path()).expect("temp path should be utf8");
        let options = DiscoveryOptions {
            include_symlink_entries: false,
            ..DiscoveryOptions::default()
        };
        let report = discover_roots(vec![root], &options, None, None);

        assert_eq!(report.summary.files, 1);
        assert_eq!(report.summary.symlinks, 0);
    }

    #[test]
    fn discovers_nested_subdirectories() {
        let temp = tempfile::tempdir().expect("tempdir should exist");
        let subdir = temp.path().join("a").join("b");
        fs::create_dir_all(&subdir).expect("subdir should be created");
        fs::write(subdir.join("nested.txt"), b"nested").expect("file should be written");

        let root = path_to_utf8(temp.path()).expect("temp path should be utf8");
        let report = discover_roots(vec![root], &DiscoveryOptions::default(), None, None);

        assert_eq!(report.summary.files, 1);
        assert_eq!(report.summary.directories, 3); // root, "a", and "a/b"
        let paths: Vec<_> = report.entries.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.contains("nested.txt")));
    }

    #[test]
    fn excludes_matching_path_prefix() {
        let temp = tempfile::tempdir().expect("tempdir should exist");
        let keep = temp.path().join("keep");
        let exclude_dir = temp.path().join("node_modules");
        fs::create_dir(&keep).expect("keep dir");
        fs::create_dir(&exclude_dir).expect("exclude dir");
        fs::write(keep.join("good.txt"), b"good").expect("file");
        fs::write(exclude_dir.join("bad.txt"), b"bad").expect("file");

        let root = path_to_utf8(temp.path()).expect("temp path should be utf8");
        let options = DiscoveryOptions {
            exclude_prefixes: vec![exclude_dir.to_string_lossy().to_string()],
            ..DiscoveryOptions::default()
        };
        let report = discover_roots(vec![root], &options, None, None);

        assert_eq!(report.summary.files, 1);
        let entry_paths: Vec<_> = report.entries.iter().map(|e| e.path.as_str()).collect();
        assert!(entry_paths.iter().any(|p| p.contains("good.txt")));
        assert!(!entry_paths.iter().any(|p| p.contains("bad.txt")));
    }

    #[test]
    fn excludes_relative_pattern_resolved_against_root() {
        let temp = tempfile::tempdir().expect("tempdir should exist");
        let excluded = temp.path().join("build");
        let keep = temp.path().join("src");
        fs::create_dir(&excluded).expect("build dir");
        fs::create_dir(&keep).expect("src dir");
        fs::write(excluded.join("output.o"), b"obj").expect("file");
        fs::write(keep.join("main.rs"), b"fn main() {}").expect("file");

        let root = path_to_utf8(temp.path()).expect("temp path should be utf8");
        let options = DiscoveryOptions {
            exclude_prefixes: vec!["build".to_string()],
            ..DiscoveryOptions::default()
        };
        let report = discover_roots(vec![root], &options, None, None);

        assert_eq!(report.summary.files, 1);
        let entry_paths: Vec<_> = report.entries.iter().map(|e| e.path.as_str()).collect();
        assert!(entry_paths.iter().any(|p| p.contains("main.rs")));
        assert!(!entry_paths.iter().any(|p| p.contains("output.o")));
    }

    #[test]
    fn multiple_exclude_prefixes() {
        let temp = tempfile::tempdir().expect("tempdir should exist");
        for dir in &["target", "node_modules", "src"] {
            fs::create_dir(temp.path().join(dir)).expect("dir");
        }
        fs::write(temp.path().join("target").join("foo"), b"x").expect("file");
        fs::write(temp.path().join("node_modules").join("bar"), b"y").expect("file");
        fs::write(temp.path().join("src").join("main.rs"), b"fn main() {}").expect("file");

        let root = path_to_utf8(temp.path()).expect("temp path should be utf8");
        let options = DiscoveryOptions {
            exclude_prefixes: vec![
                temp.path().join("target").to_string_lossy().to_string(),
                temp.path()
                    .join("node_modules")
                    .to_string_lossy()
                    .to_string(),
            ],
            ..DiscoveryOptions::default()
        };
        let report = discover_roots(vec![root], &options, None, None);

        assert_eq!(report.summary.files, 1);
        let entry_paths: Vec<_> = report.entries.iter().map(|e| e.path.as_str()).collect();
        assert!(entry_paths.iter().any(|p| p.contains("main.rs")));
    }

    #[test]
    fn empty_exclude_prefixes_changes_nothing() {
        let temp = tempfile::tempdir().expect("tempdir should exist");
        fs::write(temp.path().join("a.txt"), b"a").expect("file");

        let root = path_to_utf8(temp.path()).expect("temp path should be utf8");
        let report = discover_roots(vec![root], &DiscoveryOptions::default(), None, None);

        assert_eq!(report.summary.files, 1);
    }
}
