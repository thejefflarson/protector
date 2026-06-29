//! The engine's **output-state** domain layer: the shared types the engine core
//! writes each pass and the metrics mirror reads — the proven-chain [`Finding`] row and its
//! evidence, the single per-entry [`VerdictStore`], the [`Findings`] / [`JudgementLog`] /
//! [`ReversionLog`] handles, the [`BakeStats`] / [`ModelHealth`] / [`ReadinessConfig`] coverage
//! shapes, the per-entry recency / Δ facts, and the would-have-acted [`Report`] +
//! [`Readiness`] aggregations that feed the OTLP mirror.
//!
//! This is pure DATA: it holds no rendering and no HTTP serving. The engine core, journal,
//! metrics, and adjudicator write and read these handles; nothing here knows how the state is
//! presented. Untrusted free-text (CVE titles, verdict prose, model prompts) is carried
//! verbatim and is the consumer's responsibility to escape wherever it is later spliced into a
//! sink (the zero-egress invariant: this state never leaves the cluster).

mod evidence;
mod findings;
mod judgement;
mod readiness;
mod recency;
mod report;
mod reversion;
mod verdict_store;

pub use evidence::{CveEvidence, EntryEvidence, FindingEvidence};
pub use findings::{Finding, Findings, PathStep};
pub use judgement::{Judgement, JudgementLog};
pub use readiness::Readiness;
pub use recency::{Delta, RecencyInfo, StoredPosture};
pub use report::{Report, default_window_report};
pub use reversion::{ReversionLog, ReversionRecord};
pub use verdict_store::{BakeStats, ModelHealth, ReadinessConfig, VerdictEntry, VerdictStore};
