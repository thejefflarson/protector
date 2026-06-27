//! The diagnostics PANEL components (ADR-0019, the PRESENTATION layer): the readiness /
//! coverage panel, the instructional first-run checklist, the behavioral-bake panel, the
//! recent-reversions panel, and the attack-vectors ("what an attacker could reach") table.
//!
//! Each is a pure `maud` renderer (`Props -> Markup`) that imports ONLY its `Props` (from
//! the `view_model`), the shared `chips` primitives, and maud — NO `engine::` domain type.
//! That boundary is the whole point of the component split; the per-component
//! `*_imports_no_engine_domain_type` tests document it. Migrated from the transitional
//! `legacy::panels` / `legacy::readiness` string-concat helpers (JEF-206).

pub mod attack_vectors;
pub mod bake;
pub mod first_run;
pub mod readiness;
pub mod reversions;

pub use attack_vectors::attack_vectors;
pub use bake::bake;
pub use first_run::first_run;
pub use readiness::readiness;
pub use reversions::reversions;
