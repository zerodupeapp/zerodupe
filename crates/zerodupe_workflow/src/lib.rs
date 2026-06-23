//! Crate `zerodupe_workflow` — Maquina de estados central de ZeroDupe.
//!
//! Este crate orquesta los 3 pilares del deduplicador (exactos, similares, higiene)
//! a traves de una state machine con 11 estados y 9 acciones. Es usado por la
//! CLI interactiva (`zerodupe_cli`).
//!
//! # Modulos exportados
//!
//! | Modulo       | Proposito                                            |
//! |-------------|------------------------------------------------------|
//! | `Workflow`  | Struct principal que conecta discovery → exactos → similares → higiene |
//! | `WorkflowState` | Enum con los 11 estados del wizard               |
//! | `WorkflowAction` | Enum con las 9 acciones que disparan transiciones |
//! | `WorkflowError`  | Tipos de error de la state machine               |
//! | `StateChangeNotifier` | Trait para notificar cambios de estado (GUI) |
//! | `TopGroup` / `build_top_*` | Resumenes agrupados para mostrar al usuario |
//!
//! # Ciclo de vida tipico
//!
//! ```text
//! Idle → SelectFolder → StartScan → ScanningExact → ReviewingExact
//!   → (AcceptExact) → ScanningSimilar → ReviewingSimilar
//!     → (SkipSimilar) → ScanningHygiene → ReviewingHygiene
//!       → (AcceptHygiene) → Cleaning → Complete
//! ```
//!
//! El usuario puede saltar similares o higiene, cancelar en cualquier momento,
//! o ir directo a limpieza desde cualquier estado de revision.

mod action;
mod error;
mod notifier;
mod state;
mod summary;
mod workflow;

pub use action::WorkflowAction;
pub use error::WorkflowError;
pub use notifier::StateChangeNotifier;
pub use state::WorkflowState;
pub use summary::{TopGroup, build_top_groups, build_top_similar_groups};
pub use workflow::Workflow;
pub use zerodupe_config::ZerodupeConfig;
