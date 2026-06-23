//! Manifiesto de eliminación — puente entre los pilares.
//!
//! Define [`EliminationManifest`], una lista de rutas que fueron eliminadas por los
//! pilares de duplicados (P1 — exactos, P2 — similares). El Pilar 3 (higiene) consume
//! este manifiesto para detectar sidecars huérfanos: si un archivo `.AAE` o `.XMP`
//! aparece en el manifiesto, su sidecar compañero puede marcarse como basura.
//!
//! Actualmente el manifiesto se construye de forma vacía; la integración con P1/P2
//! está planificada para una fase futura.

use camino::Utf8PathBuf;

/// Archivos que fueron eliminados por P1 (duplicados exactos) o P2 (imágenes similares).
///
/// En el futuro, P1/P2 escribirán este manifiesto y P3 lo consumirá para detectar
/// sidecars huérfanos cuyo archivo principal fue deduplicado.
#[derive(Debug, Clone, Default)]
pub struct EliminationManifest {
    /// Rutas de archivos eliminados por los pilares de duplicados.
    pub eliminated_paths: Vec<Utf8PathBuf>,
}

impl EliminationManifest {
    /// Crea un manifiesto vacío (sin eliminaciones registradas).
    pub fn empty() -> Self {
        Self {
            eliminated_paths: Vec::new(),
        }
    }
}
