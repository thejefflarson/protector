//! [`McpState`] — the read-only engine handles the four MCP tools read from (JEF-488). It is the
//! SAME `state::` handles the dashboard renders (findings, the judgement ring, the admission-decision
//! log), never a new data path (ADR-0031 §1: "back them with the existing view-model builders /
//! `state::` handles"). Cheaply cloneable (all `Arc`), and it mutates nothing — the MCP server is
//! strictly observational, exactly like the dashboard (ADR-0016).

use std::sync::Arc;

use crate::engine::policy_log::PolicyDecisionLog;
use crate::engine::state::{
    Finding, Findings, Judgement, JudgementLog, Readiness, derive_readiness,
};

/// The read-only handles the MCP tools snapshot from, plus the cluster label. Built by `run_loop`
/// from the same `Arc`s it hands the dashboard, so the two surfaces can never show divergent state.
#[derive(Clone)]
pub struct McpState {
    /// The proven-chain findings snapshot (verdicts resolved at read time) + the per-pass coverage /
    /// freshness the readiness derivation reads.
    pub findings: Arc<Findings>,
    /// The bounded judgement ring (prompt + reply per judgement) for `explain_verdict`'s forensic
    /// disclosure.
    pub judgements: Arc<JudgementLog>,
    /// The webhook's admission-decision log — the source the signing inventory is derived from.
    pub policy_log: Arc<PolicyDecisionLog>,
    /// The cluster label (surfaced verbatim after sanitizing, like the dashboard strip).
    pub cluster: String,
}

impl McpState {
    /// The breach-relevant findings snapshot the tools list/explain over (verdicts resolved).
    pub fn findings(&self) -> Vec<Finding> {
        self.findings.snapshot()
    }

    /// The newest-first judgement ring (the verbatim prompt/reply behind each entry's verdict).
    pub fn judgements(&self) -> Vec<Judgement> {
        self.judgements.snapshot()
    }

    /// The live readiness/coverage snapshot — derived EXACTLY as the dashboard derives it
    /// (`derive_readiness` over the handle's config/health/last-pass/runtime, with the cross-pass
    /// coverage-stall register overlaid). Pure read; makes no decision (ADR-0016).
    pub fn readiness(&self) -> Readiness {
        let config = self.findings.readiness_config();
        let health = self.findings.model_health();
        let last_pass = self.findings.last_pass();
        let runtime = self.findings.runtime_coverage();
        derive_readiness(&config, health, last_pass, &runtime)
            .with_coverage_stall(&self.findings.coverage_state())
    }

    /// The freshness stamp — the last completed pass, if any.
    pub fn last_pass(&self) -> Option<std::time::SystemTime> {
        self.findings.last_pass()
    }
}
