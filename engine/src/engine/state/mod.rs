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

mod agent_liveness;
mod evidence;
mod findings;
mod judgement;
mod parity;
mod readiness;
mod recency;
mod report;
mod reversion;
mod signing_baseline;
mod verdict_store;

pub use agent_liveness::{
    AgentLivenessStore, BlindReason, NodeCoverage, NodeState, RuntimeCoverage,
    derive_runtime_coverage, expected_agent_nodes,
};
pub use evidence::{CveEvidence, EntryEvidence, FindingEvidence};
pub use findings::{Finding, Findings, PathStep};
pub use judgement::{Judgement, JudgementLog};
pub use parity::{CorroborationParity, ParityReadiness};
// The corroboration-parity fold (JEF-310) — read-only measurement over the pass's chains.
pub(crate) use parity::derive_parity;
pub use readiness::{
    InputState, NodeCoverageRow, NodeCoverageState, ParityReport, ParityState, Readiness,
    ReadinessRow,
};
// The dashboard view_model (ADR-0019) derives the live readiness snapshot from the engine's
// config + per-pass health, the same pure aggregation the OTLP mirror reads.
pub(crate) use readiness::derive_readiness;
pub use recency::{Delta, RecencyInfo, StoredPosture};
pub use report::{LeftAloneEntry, Report, WouldActEntry, default_window_report};
pub use reversion::{ReversionLog, ReversionRecord};
pub use signing_baseline::{
    DEFAULT_MAX_REPOS, SharedSigningBaseline, SigningBaseline, SigningBaselineStore,
};
pub use verdict_store::{BakeStats, ModelHealth, ReadinessConfig, VerdictEntry, VerdictStore};
