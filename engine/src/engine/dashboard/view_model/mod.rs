//! The dashboard's DATA layer (ADR-0019): pure functions that shape engine domain state
//! into the plain `Props` structs the `components` renderers consume. No maud, no markup —
//! just the mapping from `Finding`s / readiness / arm-state into component-shaped data.
//!
//! This ticket (JEF-204) migrates the status banner and the nav (`status`); the findings
//! table, cards, report, and judgements view-models land in tickets 3–6.

pub mod attack_vectors;
pub mod bake;
pub mod findings;
pub mod reversions;
pub mod status;
// The readiness / first-run view-model (JEF-206 panel migration).
pub mod readiness;

pub use attack_vectors::{AttackVectorRow, AttackVectorsProps, attack_vectors_props};
pub use bake::{BakeProps, BakeVariantRow, bake_props};
pub use readiness::{
    FirstRunItemProps, FirstRunProps, ReadinessProps, ReadinessRowProps, first_run_props,
    readiness_props,
};
pub use reversions::{ReversionRow, ReversionsProps, reversions_props};
pub use status::{
    BannerProps, ClusterStatus, NavItem, NavProps, banner_props, cluster_status, nav_props,
};
