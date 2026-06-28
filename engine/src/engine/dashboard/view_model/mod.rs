//! The dashboard's DATA layer (ADR-0019): pure functions that shape engine domain state
//! into the plain `Props` structs the `components` renderers consume. No maud, no markup —
//! just the mapping from `Finding`s / readiness / arm-state into component-shaped data.
//!
//! Two of its submodules hold the aggregations the JSON routes serialize directly — the
//! readiness snapshot ([`readiness_data`]: `/readiness`) and the would-have-acted report
//! ([`report_data`]: `/report.json`). They are pure data with no rendering; the `_props`
//! mappers turn them into the component `Props`.

pub mod attack_vectors;
pub mod bake;
pub mod findings;
pub mod judgements;
pub mod policy;
pub mod readiness;
pub mod readiness_data;
pub mod report;
pub mod report_data;
pub mod reversions;
pub mod status;

pub use attack_vectors::{AttackVectorRow, AttackVectorsProps, attack_vectors_props};
pub use bake::{BakeProps, BakeVariantRow, bake_props};
pub use judgements::{JudgementCardProps, JudgementLead, JudgementsProps, judgements_props};
pub use policy::{PolicyDecisionRow, PolicyProps, policy_props};
pub use readiness::{
    FirstRunItemProps, FirstRunProps, ReadinessProps, ReadinessRowProps, first_run_props,
    readiness_props,
};
pub use report::{
    LeftAloneRow, Lifetime, ReportBody, ReportDiff, ReportProps, WouldActRow, report_props,
};
pub use reversions::{ReversionRow, ReversionsProps, reversions_props};
pub use status::{
    BannerProps, ClusterStatus, NavItem, NavProps, banner_props, cluster_status, nav_props,
};
