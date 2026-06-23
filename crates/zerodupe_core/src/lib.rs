//! Tipos de dominio compartidos por todos los crates del workspace ZeroDupe.
//!
//! # Propósito
//!
//! Este crate define los tipos de datos que fluyen entre los 3 pilares del sistema:
//!
//! 1. **Pilar 1 — Duplicados exactos**: `FileCandidate` → `DiscoveredEntry` →
//!    `PhysicalFile` → `SizeGroup` → `HashGroup` → `ExactDuplicateGroup` →
//!    `ByteCompareGroup` → `ByteCompareReport`.
//!
//! 2. **Pilar 2 — Imágenes similares**: los tipos de discovery y hashing se reutilizan;
//!    la detección de similitud se orquesta con `zerodupe_similar` y
//!    `zerodupe_similar_image`.
//!
//! 3. **Pilar 3 — Higiene**: `QuarantineEntry`, `QuarantineReport` y
//!    `QuarantineSession` modelan el ciclo de cuarentena de archivos basura.
//!
//! # Jerarquía de tipos
//!
//! El pipeline de exactos sigue una cadena de refinamiento progresivo:
//!
//! ```text
//! Discovery
//!   ├─ DiscoveryOptions  →  configura qué y cómo descubrir
//!   ├─ ScanRoot          →  raíz de escaneo con identificador estable
//!   ├─ DiscoveredEntry   →  entrada del sistema de archivos con metadatos
//!   ├─ DiscoveredKind    →  tipo grueso: File, Directory, Symlink
//!   ├─ DiscoveryError    →  error no fatal durante el recorrido
//!   └─ DiscoveryReport   →  reporte agregado de discovery
//!
//! Normalización física
//!   ├─ PhysicalFile      →  archivo físico único (desduplica hardlinks)
//!   ├─ HardlinkCluster   →  cluster de entradas que comparten inodo
//!   ├─ EmptyFileGroup    →  grupo de archivos de 0 bytes (sin contenido que comparar)
//!   └─ PhysicalFileReport → resultado de normalización
//!
//! Agrupación por tamaño
//!   ├─ SizeGroup         →  grupo de archivos del mismo tamaño
//!   └─ CandidateReport   →  reporte de agrupación por tamaño
//!
//! Hashing parcial
//!   ├─ HashingOptions    →  estrategia de hashing parcial (chunk size, HeadOnly/HeadTail)
//!   ├─ HashRegion        →  región del archivo a hashear (Full, Prefix, Suffix, HeadTail, Sampled)
//!   ├─ HashAlgorithm     →  algoritmo de hash (Blake3)
//!   ├─ PartialStrategy   →  estrategia de hashing parcial
//!   ├─ HashGroup         →  subgrupo que comparte tamaño + hash parcial
//!   └─ PartialHashReport →  resultado del hashing parcial
//!
//! Hashing completo
//!   ├─ ExactDuplicateGroup → grupo confirmado por hash completo (BLAKE3)
//!   └─ FullHashReport      → resultado del hashing completo (cache hits/misses)
//!
//! Verificación byte a byte
//!   ├─ VerifyMode        →  cuándo verificar (CachedOnly por defecto, Always, Never)
//!   ├─ ByteCompareGroup  →  grupo verificado byte a byte con keeper recomendado
//!   └─ ByteCompareReport →  reporte final de duplicados exactos
//!
//! Cuarentena (Pilar 3 — Higiene)
//!   ├─ QuarantineEntry   →  entrada individual en cuarentena
//!   ├─ QuarantineSession →  sesión de cuarentena agrupando entradas relacionadas
//!   └─ QuarantineReport  →  resultado de una operación de cuarentena
//! ```
//!
//! # Identificadores
//!
//! | Tipo     | Propósito                                      |
//! |----------|------------------------------------------------|
//! | `RootId` | Identificador estable de raíz de escaneo       |
//! | `ScanId` | Identificador único de ejecución de escaneo    |
//! | `GroupId`| Identificador de grupo de duplicados exactos   |
//!
//! # Submódulos
//!
//! - [`cancellation`] — Bandera de cancelación thread-safe ([`CancelFlag`])
//! - [`categorizer`] — Categorización de archivos por extensión ([`FileCategory`])
//! - [`progress`] — Sistema de reporte de progreso ([`ProgressEvent`], [`ScanStage`])
//!
//! # Dependencias
//!
//! Este crate es el único del workspace sin dependencia interna a otros crates
//! del proyecto (excepto `zerodupe_platform` para `PhysicalFileKey`). Todos los
//! demás crates del workspace dependen de él.

pub mod cancellation;
pub use cancellation::CancelFlag;

pub mod categorizer;
pub use categorizer::FileCategory;

pub mod progress;
pub use progress::{ProgressEvent, ProgressReporter, ScanStage};

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

// ── Identificadores ──────────────────────────────────────────────────────────

/// Identificador estable de una raíz de escaneo proporcionada por el usuario.
///
/// Cada `ScanRoot` recibe un `RootId` único que persiste a lo largo de todo
/// el pipeline, permitiendo rastrear a qué raíz pertenece cada entrada
/// descubierta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RootId(pub u32);

/// Identificador único de una ejecución de escaneo.
///
/// Generado con UUID v4 al iniciar cada sesión. Permite correlacionar
/// reportes, entradas de caché y sesiones de cuarentena con el escaneo
/// que las produjo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScanId(Uuid);

impl ScanId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ScanId {
    fn default() -> Self {
        Self::new()
    }
}

/// Identificador estable de un grupo de duplicados exactos.
///
/// Asignado a cada [`ExactDuplicateGroup`] al confirmarse por hash completo.
/// Se usa en reportes y en la UI para que el usuario pueda referenciar grupos
/// específicos al decidir qué archivos conservar o eliminar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(Uuid);

impl GroupId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for GroupId {
    fn default() -> Self {
        Self::new()
    }
}

// ── Discovery ───────────────────────────────────────────────────────────────

/// Candidato básico del sistema de archivos descubierto durante el escaneo.
///
/// Es la unidad más elemental del pipeline: una tupla `(ruta, tamaño)`. Aparece
/// en [`ByteCompareGroup`], [`ExactDuplicateGroup`] y en los reportes finales.
/// A diferencia de [`DiscoveredEntry`], no incluye metadatos extendidos ni
/// identificador de raíz; es el tipo «terminal» que ve el usuario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCandidate {
    /// Ruta canónica del archivo en el sistema.
    pub path: Utf8PathBuf,
    /// Tamaño en bytes según metadatos del sistema de archivos.
    pub size_bytes: u64,
}

/// Raíz de escaneo seleccionada por el usuario para discovery.
///
/// Cada invocación del pipeline acepta una o más raíces. El `id` permite
/// rastrear a qué raíz pertenece cada [`DiscoveredEntry`] y detectar
/// solapamientos entre raíces durante la normalización física.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRoot {
    /// Identificador estable asignado en el momento del discovery.
    pub id: RootId,
    /// Ruta absoluta del directorio raíz a escanear.
    pub path: Utf8PathBuf,
}

/// Configuración del recorrido de discovery del sistema de archivos.
///
/// Controla qué entradas se incluyen o excluyen durante el walk. Los valores
/// por defecto son conservadores: no seguir symlinks, no incluir ocultos,
/// no respetar `.gitignore`.
///
/// Usado por `zerodupe_fs` para construir el walker que produce
/// [`DiscoveredEntry`]s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryOptions {
    /// Si `true`, sigue symlinks a directorios (peligroso: puede causar ciclos).
    pub follow_symlinks: bool,
    /// Si `true`, incluye las entradas symlink en el resultado (aunque no se sigan).
    pub include_symlink_entries: bool,
    /// Si `true`, incluye archivos y directorios ocultos (los que empiezan con `.`).
    pub include_hidden: bool,
    /// Si `true`, excluye patrones listados en `.gitignore`.
    pub respect_gitignore: bool,
    /// Prefijos de ruta a omitir (comparación `starts_with`, no globs).
    /// Los prefijos relativos se resuelven contra la raíz de escaneo.
    #[serde(alias = "exclude_patterns")]
    pub exclude_prefixes: Vec<String>,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            follow_symlinks: false,
            include_symlink_entries: true,
            include_hidden: false,
            respect_gitignore: false,
            exclude_prefixes: Vec::new(),
        }
    }
}

/// Tipo de archivo observado durante el recorrido del sistema de archivos.
///
/// Clasificación gruesa que determina el tratamiento posterior:
/// - `File` → entra al pipeline de hashing y comparación.
/// - `Directory` → solo se recorre; no se hashea.
/// - `Symlink` → se reporta pero no se sigue (a menos que `follow_symlinks` esté activo).
/// - `Other` → sockets, FIFOs, dispositivos; se ignoran en hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveredKind {
    File,
    Directory,
    Symlink,
    Other,
}

/// Timestamps normalizados a segundos Unix (con precisión de nanosegundos).
///
/// Capturados durante el discovery para alimentar [`FileVersion`] y habilitar
/// la validación de caché de hashes por testigos temporales (mtime + ctime).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTimestamps {
    /// Fecha de última modificación en segundos Unix.
    pub modified_unix_seconds: Option<i64>,
    /// Fecha de creación en segundos Unix. `None` en sistemas que no la exponen.
    pub created_unix_seconds: Option<i64>,
    /// mtime con precisión de nanosegundos — cierra el agujero de invalidación
    /// de caché cuando dos modificaciones ocurren dentro del mismo segundo.
    #[serde(default)]
    pub modified_unix_nanos: Option<i64>,
    /// ctime (tiempo de cambio de inodo) en nanosegundos. Mantenido por el
    /// kernel, no falsificable desde userspace; `None` en Windows.
    #[serde(default)]
    pub changed_unix_nanos: Option<i64>,
}

/// Testigos de versión de archivo usados para validar entradas de caché de hash.
///
/// Un hash cacheado solo se considera válido si los testigos actuales coinciden
/// con los almacenados al calcular el hash. `ctime_nanos` solo se compara cuando
/// ambos lados tienen valor (Windows carece de ctime).
///
/// Se construye desde [`FileTimestamps`] (via discovery) o directamente desde
/// `std::fs::Metadata` (via `from_metadata`) para pipelines que hacen stat
/// fuera del discovery, como el orquestador de similitud.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileVersion {
    /// mtime en nanosegundos Unix.
    pub mtime_nanos: Option<i64>,
    /// ctime en nanosegundos Unix. `None` en Windows.
    pub ctime_nanos: Option<i64>,
}

impl FileVersion {
    /// Extracts the version witnesses directly from filesystem metadata.
    ///
    /// Used by pipelines that stat files outside of discovery (e.g. the
    /// similarity orchestrator). Same semantics as the witnesses captured
    /// in `FileTimestamps` during discovery.
    #[must_use]
    pub fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        let mtime_nanos = metadata.modified().ok().and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|d| i64::try_from(d.as_nanos()).ok())
        });
        Self {
            mtime_nanos,
            ctime_nanos: zerodupe_platform::change_time_nanos(metadata),
        }
    }

    #[must_use]
    pub fn from_timestamps(timestamps: &FileTimestamps) -> Self {
        Self {
            // Fall back to second precision when the filesystem (or an old
            // serialized report) doesn't provide nanoseconds.
            mtime_nanos: timestamps.modified_unix_nanos.or_else(|| {
                timestamps
                    .modified_unix_seconds
                    .and_then(|s| s.checked_mul(1_000_000_000))
            }),
            ctime_nanos: timestamps.changed_unix_nanos,
        }
    }
}

/// Entrada del sistema de archivos observada durante el discovery.
///
/// Es la versión «rica» de [`FileCandidate`]: incluye metadatos completos
/// (tipo, profundidad, timestamps, key física) y el `root_id` que la originó.
/// Tras la normalización física, las entradas se reducen a [`PhysicalFile`]s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredEntry {
    /// Raíz de escaneo a la que pertenece esta entrada.
    pub root_id: RootId,
    /// Ruta absoluta de la entrada en el sistema de archivos.
    pub path: Utf8PathBuf,
    /// Tipo de entrada (archivo, directorio, symlink, otro).
    pub kind: DiscoveredKind,
    /// Profundidad relativa a la raíz de escaneo (0 = la raíz misma).
    pub depth: usize,
    /// Tamaño en bytes. `None` para entradas que no son archivos regulares.
    pub size_bytes: Option<u64>,
    /// Si el archivo tiene el flag de solo-lectura.
    pub readonly: bool,
    /// Timestamps normalizados capturados en el momento del discovery.
    pub timestamps: FileTimestamps,
    /// Identidad física capturada durante el discovery (inodo + dispositivo en
    /// Unix; clave de volumen + índice en Windows). Evita un `stat()` extra en
    /// etapas posteriores. `None` para no-archivos o si no se pudo determinar.
    #[serde(default)]
    pub physical_key: Option<zerodupe_platform::PhysicalFileKey>,
}

/// Categoría estructurada de error de discovery.
///
/// Permite a las capas superiores decidir si un error es recuperable o no,
/// y generar mensajes de usuario apropiados según el tipo de fallo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryErrorKind {
    /// Permisos insuficientes para leer el directorio o archivo.
    PermissionDenied,
    /// La entrada desapareció entre el listado y el stat.
    NotFound,
    /// Datos corruptos o inconsistentes del sistema de archivos.
    InvalidData,
    /// Bucle de symlinks detectado (solo con `follow_symlinks` activo).
    SymlinkLoop,
    /// Symlink roto (el destino no existe).
    BrokenSymlink,
    /// Ruta excede la longitud máxima del sistema operativo.
    PathTooLong,
    /// Se esperaba un directorio pero se encontró otra cosa.
    NotDirectory,
    /// Otro error de I/O no categorizado.
    OtherIo,
}

/// Error no fatal durante el discovery del sistema de archivos.
///
/// Un error de discovery no aborta el escaneo completo; la entrada problemática
/// se omite y se registra para el reporte final.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryError {
    /// Raíz donde ocurrió el error, si se pudo determinar.
    pub root_id: Option<RootId>,
    /// Ruta donde ocurrió el error, si se pudo determinar.
    pub path: Option<Utf8PathBuf>,
    /// Categoría del error.
    pub kind: DiscoveryErrorKind,
    /// Mensaje descriptivo legible por humanos.
    pub message: String,
}

/// Contadores agregados del discovery.
///
/// Proporciona un resumen rápido para la UI: cuántos archivos, directorios,
/// symlinks y errores se encontraron, más el total de bytes.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoverySummary {
    /// Número de raíces de escaneo.
    pub roots: usize,
    /// Total de entradas descubiertas (archivos + directorios + symlinks + otros).
    pub entries: usize,
    /// Solo archivos regulares.
    pub files: usize,
    /// Solo directorios.
    pub directories: usize,
    /// Solo symlinks.
    pub symlinks: usize,
    /// Otras entradas (sockets, FIFOs, dispositivos).
    pub other: usize,
    /// Errores no fatales encontrados.
    pub errors: usize,
    /// Suma de tamaños de todos los archivos regulares.
    pub total_file_bytes: u64,
}

/// Resultado completo del discovery del sistema de archivos.
///
/// Es el producto de salida de `zerodupe_fs` y el punto de entrada para
/// `zerodupe_scan` (pipeline de exactos) y `zerodupe_similar` (pipeline
/// de similares). Contiene todas las entradas descubiertas, los errores
/// encontrados y un resumen agregado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryReport {
    /// Raíces de escaneo usadas.
    pub roots: Vec<ScanRoot>,
    /// Todas las entradas descubiertas.
    pub entries: Vec<DiscoveredEntry>,
    /// Errores no fatales encontrados durante el recorrido.
    pub errors: Vec<DiscoveryError>,
    /// Resumen agregado con contadores.
    pub summary: DiscoverySummary,
}

impl DiscoveryReport {
    #[must_use]
    pub fn new(
        roots: Vec<ScanRoot>,
        entries: Vec<DiscoveredEntry>,
        errors: Vec<DiscoveryError>,
    ) -> Self {
        let summary = DiscoverySummary::from_parts(roots.len(), &entries, errors.len());
        Self {
            roots,
            entries,
            errors,
            summary,
        }
    }
}

impl DiscoverySummary {
    #[must_use]
    fn from_parts(roots: usize, entries: &[DiscoveredEntry], errors: usize) -> Self {
        let mut summary = Self {
            roots,
            entries: entries.len(),
            errors,
            ..Self::default()
        };
        for entry in entries {
            match entry.kind {
                DiscoveredKind::File => {
                    summary.files += 1;
                    summary.total_file_bytes += entry.size_bytes.unwrap_or(0);
                }
                DiscoveredKind::Directory => summary.directories += 1,
                DiscoveredKind::Symlink => summary.symlinks += 1,
                DiscoveredKind::Other => summary.other += 1,
            }
        }
        summary
    }
}

pub use zerodupe_platform::PhysicalFileKey;

/// Snapshot de metadatos de archivo tomado antes del hashing.
///
/// Usado para verificación TOCTTOU (Time-Of-Check-To-Time-Of-Use):
/// después de leer y hashear un archivo, se compara este snapshot con
/// los metadatos actuales para detectar si el archivo fue modificado
/// durante la lectura. Es la base del sistema de seguridad de
/// `zerodupe_safety`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSnapshot {
    /// Ruta canónica del archivo.
    pub path: Utf8PathBuf,
    /// Tamaño en bytes en el momento del snapshot.
    pub size_bytes: u64,
    /// mtime en segundos Unix en el momento del snapshot.
    pub modified_unix_seconds: Option<i64>,
    /// Identidad física (inodo/dispositivo) en el momento del snapshot.
    pub physical_key: Option<zerodupe_platform::PhysicalFileKey>,
    /// Testigos de versión para validación de caché de hash.
    #[serde(default)]
    pub version: FileVersion,
}

/// Archivo físico único en disco, con todas sus rutas linkadas (hardlinks).
///
/// Durante la normalización, múltiples [`DiscoveredEntry`]s que apuntan al
/// mismo inodo (misma `PhysicalFileKey`) se colapsan en un solo
/// `PhysicalFile`. Esto evita comparar un archivo consigo mismo y permite
/// detectar clusters de hardlinks.
///
/// El `representative_index` apunta a una de las entradas originales cuya
/// ruta se usa como `canonical_path` para hashing y comparación.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalFile {
    /// Índice en la lista original de `DiscoveredEntry` para la ruta representativa.
    pub representative_index: usize,
    /// Todos los índices de entrada que apuntan al mismo archivo físico
    /// (incluyendo el representativo).
    pub linked_entry_indices: Vec<usize>,
    /// Tamaño en bytes del archivo.
    pub size_bytes: u64,
    /// Clave de identidad física (inodo + dispositivo, o equivalente).
    pub physical_key: Option<zerodupe_platform::PhysicalFileKey>,
    /// Ruta canónica usada para leer el archivo durante el hashing.
    pub canonical_path: Utf8PathBuf,
    /// Snapshot de metadatos para verificación TOCTTOU.
    pub snapshot: FileSnapshot,
}

/// Grupo de archivos de cero bytes.
///
/// Los archivos vacíos no tienen contenido que comparar, por lo que se agrupan
/// aparte. Técnicamente son «idénticos» (todos tienen hash vacío), pero el
/// pipeline los separa para que el usuario decida sin pasar por hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmptyFileGroup {
    /// Índices en la lista de `DiscoveredEntry` de todos los archivos vacíos.
    pub entry_indices: Vec<usize>,
}

/// Resultado de normalizar entradas descubiertas en archivos físicos únicos.
///
/// Producido por la etapa de normalización de `zerodupe_scan`: colapsa
/// hardlinks, detecta rutas duplicadas y raíces solapadas, y separa archivos
/// vacíos. Es la entrada para la etapa de agrupación por tamaño.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalFileReport {
    /// Archivos físicos únicos (cada uno representa uno o más hardlinks).
    pub physical_files: Vec<PhysicalFile>,
    /// Clusters de hardlinks detectados.
    pub hardlink_clusters: Vec<HardlinkCluster>,
    /// Archivos de cero bytes agrupados aparte.
    pub empty_files: EmptyFileGroup,
    /// Número de rutas duplicadas eliminadas durante la normalización.
    pub duplicate_paths_removed: usize,
    /// `true` si se detectaron y resolvieron raíces de escaneo solapadas.
    pub overlapping_roots_resolved: bool,
}

// ── Agrupación por tamaño ───────────────────────────────────────────────────

/// Grupo de archivos físicos que comparten el mismo tamaño en bytes.
///
/// Es la primera etapa de filtrado: solo los grupos con `entry_count >= 2`
/// avanzan al hashing parcial. Los grupos de tamaño único («solos») se
/// descartan porque no pueden tener duplicados.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeGroup {
    /// Tamaño compartido por todos los archivos del grupo.
    pub size_bytes: u64,
    /// Número de archivos en este grupo.
    pub entry_count: usize,
    /// Índices en la lista de `PhysicalFile`.
    pub physical_file_indices: Vec<usize>,
}

/// Cluster de entradas que comparten el mismo archivo físico (hardlinks).
///
/// Detectado durante la normalización física comparando `PhysicalFileKey`s.
/// Cada cluster agrupa todas las rutas que apuntan al mismo inodo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardlinkCluster {
    /// Identificador numérico del cluster dentro del reporte.
    pub cluster_id: usize,
    /// Índices de todas las `DiscoveredEntry` en este cluster.
    pub entry_indices: Vec<usize>,
    /// Ruta canónica representativa del cluster.
    pub canonical_path: Utf8PathBuf,
}

/// Resultado agregado de la etapa de agrupación por tamaño.
///
/// Producido tras clasificar los [`PhysicalFile`]s por tamaño. Los grupos
/// con un solo miembro se descartan (`skipped_solo`). Los grupos con 2+
/// miembros pasan a la etapa de hashing parcial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateReport {
    /// Grupos de archivos del mismo tamaño con 2+ miembros.
    pub size_groups: Vec<SizeGroup>,
    /// Clusters de hardlinks detectados durante la normalización.
    pub hardlink_clusters: Vec<HardlinkCluster>,
    /// Número de archivos de cero bytes.
    pub empty_file_count: usize,
    /// Grupos de tamaño único descartados (no pueden tener duplicados).
    pub skipped_solo: usize,
}

impl CandidateReport {
    #[must_use]
    pub fn total_candidates(&self) -> usize {
        self.size_groups.iter().map(|g| g.entry_count).sum()
    }

    #[must_use]
    pub fn multi_entry_groups(&self) -> usize {
        self.size_groups
            .iter()
            .filter(|g| g.entry_count >= 2)
            .count()
    }
}

// ── Hashing parcial ─────────────────────────────────────────────────────────

/// Región de un archivo a hashear.
///
/// Controla qué bytes se leen y se pasan al hasher. Las estrategias más
/// comunes son `HeadTail` (primeros + últimos N bytes) y `Full` (archivo
/// completo). `Sampled` permite estrategias adaptativas avanzadas.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashRegion {
    /// Hashear el archivo completo.
    Full,
    /// Hashear los primeros `bytes` bytes.
    Prefix { bytes: usize },
    /// Hashear los últimos `bytes` bytes.
    Suffix { bytes: usize },
    /// Hashear los primeros `head_bytes` y últimos `tail_bytes` en una sola
    /// pasada del hasher (eficiente: una sola lectura con seek).
    HeadTail {
        head_bytes: usize,
        tail_bytes: usize,
    },
    /// Hashear múltiples regiones no solapantes (para estrategias adaptativas).
    Sampled { samples: Vec<FileSample> },
}

/// Especificación de una región para [`HashRegion::Sampled`].
///
/// Define un segmento contiguo del archivo a hashear, identificado por
/// su offset de inicio y su longitud en bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileSample {
    /// Offset desde el inicio del archivo donde comienza la región.
    pub offset: u64,
    /// Longitud de la región en bytes.
    pub length: usize,
}

/// Algoritmos de hash soportados.
///
/// Actualmente solo BLAKE3, seleccionado por su velocidad (aprovecha SIMD
/// y paralelismo interno) y resistencia a colisiones (~2⁻¹²⁸).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Blake3,
}

/// Estrategia de hashing parcial.
///
/// Controla qué partes del archivo se hashean en la primera pasada para
/// descartar rápidamente archivos distintos sin leer el contenido completo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartialStrategy {
    /// Solo hashear los primeros N bytes (rápido, menor capacidad de filtrado).
    HeadOnly,
    /// Hashear cabeza + cola en una sola pasada (mejor filtrado, mismo costo de I/O).
    HeadTail,
}

/// Configuración del paso de hashing parcial.
///
/// Controla cuántos bytes leer, con qué estrategia y algoritmo, y si se
/// debe verificar TOCTTOU después de cada lectura. El valor por defecto
/// usa HeadTail con 4 KiB en cada extremo y BLAKE3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashingOptions {
    /// Tamaño del chunk para hashing parcial (bytes a leer de cabeza y cola).
    pub partial_chunk_size: usize,
    /// Estrategia de hashing parcial (HeadOnly o HeadTail).
    pub partial_strategy: PartialStrategy,
    /// Algoritmo de hash a usar (por ahora solo BLAKE3).
    pub hash_algorithm: HashAlgorithm,
    /// Verificación TOCTTOU en tiempo de escaneo (size + mtime vs snapshot).
    /// **Desactivado por defecto**: la verificación crítica de seguridad la
    /// hace `zerodupe_safety::verify_safe_to_act` antes de cualquier acción
    /// destructiva, independientemente de este flag.
    pub verify_after_read: bool,
    /// Hashear archivos en paralelo. `None` (por defecto) decide según el
    /// tipo de almacenamiento: SSD → paralelo, HDD → secuencial en orden de
    /// inodo (donde los seeks paralelos causarían thrashing). `Some(_)` fuerza
    /// el modo — usado por tests para probar que ambas rutas producen
    /// resultados idénticos.
    #[serde(default)]
    pub parallel_hashing: Option<bool>,
}

impl Default for HashingOptions {
    fn default() -> Self {
        Self {
            partial_chunk_size: 4096,
            partial_strategy: PartialStrategy::HeadTail,
            hash_algorithm: HashAlgorithm::Blake3,
            verify_after_read: false,
            parallel_hashing: None,
        }
    }
}

/// Modo de verificación byte a byte para la etapa 5.
///
/// Una colisión BLAKE3 no es un riesgo práctico (~2⁻¹²⁸); el riesgo real es
/// un hash obsoleto servido por la caché. `CachedOnly` (por defecto) verifica
/// solo los grupos expuestos a ese riesgo y confía en el resto.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyMode {
    /// Verificar solo los grupos donde algún hash provino de la caché (por defecto).
    #[default]
    CachedOnly,
    /// Verificar todos los grupos — modo paranoico.
    Always,
    /// Confiar en el hash completo, nunca comparar bytes.
    Never,
}

/// Subgrupo de archivos que comparten tamaño y hash parcial idénticos.
///
/// Producido por la etapa de hashing parcial: archivos del mismo tamaño
/// que produjeron el mismo hash parcial se agrupan para avanzar al hashing
/// completo. Si algún miembro obtuvo su hash parcial de la caché, el grupo
/// se marca con `any_cached` para que `VerifyMode::CachedOnly` lo verifique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashGroup {
    /// Tamaño compartido por todos los archivos del grupo.
    pub size_bytes: u64,
    /// Hash parcial (hex) compartido por todos los miembros.
    pub partial_hash: String,
    /// Índices en la lista de `PhysicalFile`.
    pub physical_file_indices: Vec<usize>,
    /// `true` si al menos un miembro obtuvo su hash parcial de la caché.
    /// Relevante cuando la región parcial cubre todo el archivo (size ≤
    /// head+tail) y la etapa 4 promueve el grupo sin re-hashear: la
    /// procedencia del parcial se convierte en la procedencia del grupo.
    #[serde(default)]
    pub any_cached: bool,
}

/// Categoría de error no fatal durante el hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashErrorKind {
    /// El archivo ya no existe (eliminado entre discovery y hashing).
    NotFound,
    /// Permisos insuficientes para leer el archivo.
    PermissionDenied,
    /// El archivo cambió (tamaño o mtime) entre el snapshot y la lectura.
    FileChanged,
    /// La entrada ya no es un archivo regular (ej. se convirtió en symlink).
    NotRegularFile,
    /// Otro error de I/O no categorizado.
    Io,
}

/// Error no fatal encontrado durante el hashing de un archivo.
///
/// Un error de hashing no aborta el pipeline; el archivo problemático se
/// excluye del grupo y se registra para el reporte final.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashError {
    /// Índice del `DiscoveredEntry` o `PhysicalFile` que falló.
    pub entry_index: usize,
    /// Ruta del archivo que falló.
    pub path: String,
    /// Categoría del error.
    pub kind: HashErrorKind,
    /// Mensaje descriptivo.
    pub message: String,
}

/// Resultado agregado del paso de hashing parcial.
///
/// Contiene los grupos que sobrevivieron al filtro de hash parcial y avanzan
/// al hashing completo. Los archivos con hash parcial único se eliminan
/// (`eliminated_by_partial`). Los archivos cuyo tamaño es menor o igual que
/// la región parcial se promueven directamente (`promoted_to_full`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialHashReport {
    /// Grupos de archivos que comparten tamaño + hash parcial.
    pub groups: Vec<HashGroup>,
    /// Archivos eliminados por tener hash parcial único.
    pub eliminated_by_partial: usize,
    /// Archivos promovidos a hash completo sin re-leer (size ≤ región parcial).
    pub promoted_to_full: usize,
    /// Errores encontrados durante el hashing parcial.
    pub hash_errors: Vec<HashError>,
}

impl PartialHashReport {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    #[must_use]
    pub fn total_remaining(&self) -> usize {
        self.groups
            .iter()
            .map(|g| g.physical_file_indices.len())
            .sum()
    }
}

/// Clave para una entrada en la caché persistente de hashes.
///
/// Combina la identidad física del archivo, su tamaño, testigos de versión,
/// algoritmo y región hasheada. Una entrada cacheada solo es válida si todos
/// estos campos coinciden con el estado actual del archivo.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashCacheKey {
    /// Identidad física del archivo (inodo + dispositivo o equivalente).
    pub physical_key: Option<zerodupe_platform::PhysicalFileKey>,
    /// Tamaño del archivo en bytes.
    pub size_bytes: u64,
    /// Testigos de versión actuales; la entrada cacheada es válida solo si coinciden.
    pub version: FileVersion,
    /// Algoritmo de hash usado.
    pub hash_algorithm: HashAlgorithm,
    /// Región del archivo que fue hasheada.
    pub region: HashRegion,
}

// ── Cuarentena (Pilar 3 — Higiene) ─────────────────────────────────────────

/// Entrada individual en el diario de cuarentena.
///
/// Representa un archivo que fue movido a cuarentena (renombrado y trasladado
/// a un directorio seguro). Mantiene la ruta original para poder restaurarlo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineEntry {
    /// Identificador único de la entrada en la BD de cuarentena.
    pub id: u64,
    /// Ruta original del archivo antes de ser puesto en cuarentena.
    pub original_path: Utf8PathBuf,
    /// Ruta donde reside el archivo dentro del directorio de cuarentena.
    pub quarantined_path: Utf8PathBuf,
    /// Tamaño del archivo en bytes.
    #[serde(rename = "bytes")]
    pub size_bytes: u64,
    /// Razón por la que fue puesto en cuarentena (ej. "archivo temporal").
    pub reason: String,
    /// Fecha/hora en que fue movido a cuarentena (ISO 8601).
    #[serde(rename = "modified")]
    pub moved_at: String,
    /// `true` si el archivo ya fue restaurado a su ubicación original.
    pub restored: bool,
    /// ID de la sesión de cuarentena a la que pertenece.
    pub session_id: String,
    /// Fecha de purga automática, si está configurada (ISO 8601).
    pub purge_at: Option<String>,
}

/// Agrupa entradas de cuarentena por sesión de limpieza.
///
/// Cada sesión representa una ejecución del detector de higiene que movió
/// archivos a cuarentena. Permite restaurar o purgar todas las entradas
/// de una sesión de forma atómica.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineSession {
    /// Identificador único de la sesión.
    pub id: String,
    /// Modo de operación (ej. "higiene", "manual").
    pub mode: String,
    /// Etiqueta descriptiva de la sesión.
    pub label: String,
    /// Ruta raíz donde se ejecutó la limpieza.
    pub source_path: String,
    /// Fecha/hora de la limpieza (ISO 8601).
    pub cleaned_at: String,
    /// Días tras los cuales las entradas se purgan automáticamente.
    pub purge_in_days: u32,
    /// Archivos puestos en cuarentena en esta sesión.
    pub files: Vec<QuarantineEntry>,
}

/// Resultado de una operación de cuarentena.
///
/// Resume cuántos archivos se pusieron en cuarentena o se restauraron,
/// el total de bytes afectados, y cualquier error encontrado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineReport {
    /// Número de archivos puestos en cuarentena en esta operación.
    pub files_quarantined: usize,
    /// Número de archivos restaurados desde cuarentena.
    pub files_restored: usize,
    /// Total de bytes afectados (suma de tamaños).
    pub bytes_affected: u64,
    /// Entradas individuales de cuarentena generadas.
    pub entries: Vec<QuarantineEntry>,
    /// Errores encontrados durante la operación.
    pub errors: Vec<String>,
}

// ── Verificación byte a byte (etapa 5) ──────────────────────────────────────

/// Resultado de la comparación byte a byte de un grupo de duplicados.
///
/// Es el veredicto final del pipeline de exactos: archivos con hash completo
/// idéntico se comparan byte a byte para descartar colisiones de hash o
/// entradas de caché obsoletas. Incluye la recomendación de ZeroDupe sobre
/// qué archivo conservar (`keeper_index`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteCompareGroup {
    /// Tamaño compartido por todos los archivos del grupo.
    pub size_bytes: u64,
    /// Archivos confirmados como duplicados exactos.
    pub files: Vec<FileCandidate>,
    /// Archivos que fallaron la comparación (falsos positivos por hash).
    pub false_positives: Vec<FileCandidate>,
    /// Índice en `files` del archivo recomendado como keeper.
    pub keeper_index: usize,
    /// Ruta del archivo recomendado como keeper.
    pub keeper_path: Utf8PathBuf,
}

/// Resultado agregado de la verificación byte a byte.
///
/// Es el producto final del pipeline de duplicados exactos. Contiene los
/// grupos confirmados, los falsos positivos detectados, las claves de caché
/// que resultaron obsoletas y los grupos en los que se confió sin verificar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteCompareReport {
    /// Grupos confirmados como duplicados exactos.
    pub confirmed_groups: Vec<ByteCompareGroup>,
    /// Archivos eliminados por no coincidir byte a byte.
    pub eliminated_by_compare: usize,
    /// Número de grupos que resultaron ser falsos positivos.
    pub false_positive_groups: usize,
    /// Errores encontrados durante la comparación.
    pub compare_errors: Vec<HashError>,
    /// Grupos confirmados sin comparación byte a byte porque todos los hashes
    /// se calcularon en esta sesión (`VerifyMode::CachedOnly`) o porque la
    /// verificación se desactivó (`VerifyMode::Never`).
    #[serde(default)]
    pub groups_trusted: usize,
    /// Claves físicas cuyos hashes cacheados resultaron ser incorrectos tras
    /// la comparación byte a byte. El llamador debe invalidarlas en la caché.
    #[serde(default)]
    pub stale_cache_keys: Vec<zerodupe_platform::PhysicalFileKey>,
}

impl ByteCompareReport {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.confirmed_groups.is_empty()
    }

    #[must_use]
    pub fn total_confirmed_files(&self) -> usize {
        self.confirmed_groups.iter().map(|g| g.files.len()).sum()
    }
}

// ── Hashing completo (etapa 4) ──────────────────────────────────────────────

/// Resultado agregado del paso de hashing completo.
///
/// Producido tras calcular el hash BLAKE3 completo de cada archivo en los
/// grupos que sobrevivieron al hashing parcial. Los archivos cuyo tamaño es
/// ≤ que la región parcial se promueven sin re-leer (`covered_by_partial`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullHashReport {
    /// Grupos de duplicados exactos confirmados por hash completo.
    pub groups: Vec<ExactDuplicateGroup>,
    /// Archivos eliminados por tener hash completo único.
    pub eliminated_by_full: usize,
    /// Total de archivos en grupos de 2+ miembros (duplicados confirmados).
    pub confirmed_duplicates: usize,
    /// Errores encontrados durante el hashing completo.
    pub hash_errors: Vec<HashError>,
    /// Hashes servidos desde la caché (no fue necesario re-leer el archivo).
    pub cache_hits: usize,
    /// Hashes calculados desde cero (archivo leído y hasheado).
    pub cache_misses: usize,
    /// Archivos cuyo hash parcial ya cubría cada byte (size ≤ head+tail),
    /// promovidos a duplicados exactos sin una segunda lectura.
    #[serde(default)]
    pub covered_by_partial: usize,
}

impl FullHashReport {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    #[must_use]
    pub fn total_files(&self) -> usize {
        self.groups.iter().map(|g| g.files.len()).sum()
    }
}

/// Grupo final de duplicados exactos confirmado por el pipeline backend.
///
/// Producido por la etapa de hashing completo (BLAKE3). Si algún miembro
/// obtuvo su hash de la caché, el grupo se marca con `any_cached` para que
/// `VerifyMode::CachedOnly` active la verificación byte a byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactDuplicateGroup {
    /// Identificador único del grupo.
    pub id: GroupId,
    /// Tamaño compartido por todos los archivos del grupo.
    pub size_bytes: u64,
    /// Archivos que componen el grupo (todos con el mismo hash BLAKE3).
    pub files: Vec<FileCandidate>,
    /// `true` si al menos un miembro obtuvo su hash completo de la caché en
    /// lugar de calcularse en esta sesión. Solo estos grupos conllevan riesgo
    /// de hash obsoleto y necesitan verificación byte a byte con
    /// `VerifyMode::CachedOnly`.
    #[serde(default)]
    pub any_cached: bool,
}

// ── Errores de dominio ──────────────────────────────────────────────────────

/// Información sobre un archivo protegido contra eliminación.
///
/// Cuando el usuario marca archivos como protegidos (keepers), el sistema
/// registra qué archivos se preservaron y por qué.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedFileInfo {
    /// Ruta del archivo protegido.
    pub path: String,
    /// Tamaño en bytes del archivo protegido.
    pub size_bytes: u64,
    /// Razón por la que fue protegido (ej. "marcado como keeper por el usuario").
    pub reason: String,
}

/// Grupo de duplicados donde al menos un archivo fue protegido contra eliminación.
///
/// Reporta qué archivos se conservaron (protegidos) y cuáles se limpiaron
/// (eliminados o movidos a cuarentena), junto con el total de bytes protegidos.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedGroup {
    /// Índice del grupo en el reporte original.
    pub group_index: usize,
    /// Total de archivos en el grupo.
    pub total_files: usize,
    /// Archivos que fueron protegidos (no eliminados).
    pub protected_files: Vec<ProtectedFileInfo>,
    /// Archivos que sí fueron eliminados/puestos en cuarentena.
    pub cleaned_files: Vec<ProtectedFileInfo>,
    /// Total de bytes protegidos en este grupo.
    pub protected_bytes: u64,
}

#[derive(Debug, Error)]
pub enum ZeroDupeError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("operation is not yet implemented: {0}")]
    NotImplemented(&'static str),
}

pub type ZeroDupeResult<T> = Result<T, ZeroDupeError>;

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_ids_are_unique() {
        assert_ne!(ScanId::new(), ScanId::new());
    }

    #[test]
    fn discovery_report_summarizes_entries() {
        let root_id = RootId(0);
        let report = DiscoveryReport::new(
            vec![ScanRoot {
                id: root_id,
                path: Utf8PathBuf::from("/tmp"),
            }],
            vec![DiscoveredEntry {
                root_id,
                path: Utf8PathBuf::from("/tmp/file.txt"),
                kind: DiscoveredKind::File,
                depth: 1,
                size_bytes: Some(5),
                readonly: false,
                timestamps: FileTimestamps::default(),
                physical_key: None,
            }],
            Vec::new(),
        );
        assert_eq!(report.summary.files, 1);
        assert_eq!(report.summary.total_file_bytes, 5);
    }

    #[test]
    fn physical_file_key_unix_serializes() {
        let key = zerodupe_platform::PhysicalFileKey::from_unix(2049, 12345);
        let json = serde_json::to_string(&key).expect("serialize");
        let deser: zerodupe_platform::PhysicalFileKey =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(key, deser);
        assert_eq!(key.discriminant, 0);
    }

    #[test]
    fn physical_file_key_fallback_serializes() {
        let key = zerodupe_platform::PhysicalFileKey::from_fallback(camino::Utf8Path::new(
            "/tmp/test.txt",
        ));
        let json = serde_json::to_string(&key).expect("serialize");
        let deser: zerodupe_platform::PhysicalFileKey =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(key, deser);
        assert_eq!(key.discriminant, 2);
    }

    #[test]
    fn hashing_options_default_is_head_tail_4k() {
        let opts = HashingOptions::default();
        assert_eq!(opts.partial_chunk_size, 4096);
        assert_eq!(opts.partial_strategy, PartialStrategy::HeadTail);
        assert_eq!(opts.hash_algorithm, HashAlgorithm::Blake3);
    }

    #[test]
    fn hash_region_serializes_all_variants() {
        for region in &[
            HashRegion::Full,
            HashRegion::Prefix { bytes: 1024 },
            HashRegion::Suffix { bytes: 2048 },
            HashRegion::HeadTail {
                head_bytes: 4096,
                tail_bytes: 4096,
            },
        ] {
            let json = serde_json::to_string(region).expect("serialize");
            let _deser: HashRegion = serde_json::from_str(&json).expect("deserialize");
        }
    }

    #[test]
    fn hash_cache_key_is_constructible() {
        let _key = HashCacheKey {
            physical_key: Some(zerodupe_platform::PhysicalFileKey::from_unix(1, 2)),
            size_bytes: 100,
            version: FileVersion {
                mtime_nanos: Some(1_700_000_000_000_000_000),
                ctime_nanos: None,
            },
            hash_algorithm: HashAlgorithm::Blake3,
            region: HashRegion::HeadTail {
                head_bytes: 4096,
                tail_bytes: 4096,
            },
        };
    }
}
