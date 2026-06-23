//! Bandera de cancelación ligera para código síncrono.
//!
//! Proporciona [`CancelFlag`], un token de cancelación thread-safe compatible
//! con Rayon. Permite que el usuario (vía GUI o CLI) interrumpa un escaneo en
//! curso sin esperar a que termine. El flag se consulta periódicamente en los
//! bucles de procesamiento; cuando está activo, el pipeline aborta limpiamente.
//!
//! Usa `Arc<AtomicBool>` internamente: el clon es barato y todas las copias
//! comparten el mismo estado.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Token de cancelación ligero, thread-safe y compatible con Rayon.
///
/// Cada etapa del pipeline recibe un clon y consulta `is_cancelled()` en cada
/// iteración. La GUI o el CLI llaman a `cancel()` cuando el usuario pulsa
/// "Cancelar". Cero dependencias externas.
///
/// # Ejemplo
///
/// ```ignore
/// let flag = CancelFlag::new();
/// rayon::scope(|s| {
///     for item in items {
///         let flag = flag.clone();
///         s.spawn(move |_| {
///             if flag.is_cancelled() { return; }
///             // ... procesar item
///         });
///     }
/// });
/// ```
#[derive(Clone, Default)]
pub struct CancelFlag(Arc<AtomicBool>);

impl CancelFlag {
    pub fn new() -> Self {
        Self::default()
    }

    /// Signal cancellation.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Check if cancellation has been requested.
    /// Safe to call from any thread, including Rayon workers.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_not_cancelled() {
        let flag = CancelFlag::new();
        assert!(!flag.is_cancelled());
    }

    #[test]
    fn cancel_sets_flag() {
        let flag = CancelFlag::new();
        flag.cancel();
        assert!(flag.is_cancelled());
    }

    #[test]
    fn clone_shares_state() {
        let a = CancelFlag::new();
        let b = a.clone();
        b.cancel();
        assert!(a.is_cancelled());
    }
}
