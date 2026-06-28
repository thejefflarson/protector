//! The dashboard's PRESENTATION layer (ADR-0019): pure `maud` renderers, each
//! `Props -> Markup`. A component in this module **must not import an `engine::` domain
//! type** — it receives only its `Props` (from `view_model`), the shared `chips`
//! primitives, and maud. That boundary keeps the markup auto-escaped and the domain out of
//! the view; the per-component `*_imports_no_engine_domain_type` tests document it.
//!
//! JEF-204 migrates the nav + status banner as the proof-of-pattern and stands up the
//! shared `chips` primitives; tickets 3–6 migrate the findings table, cards, report, and
//! judgements onto these.

pub mod banner;
pub mod chips;
pub mod findings;
pub mod graph;
pub mod judgements;
pub mod nav;
pub mod panels;
pub mod policy;
pub mod report;

pub use banner::banner;
pub use judgements::judgements;
pub use nav::nav;
pub use policy::policy;
pub use report::report;
