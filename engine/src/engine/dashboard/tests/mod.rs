//! The v2 dashboard's page-composition + render tests (JEF-255, ADR-0019): the single-page
//! `render_html` / `render_fragment` composition over the model + view_model data — the status
//! line, the BREACH queue, the dense endpoints table and its expand-to-detail, the admission
//! strip, the internals disclosure — plus the ported structural guard tests and the
//! untrusted-text escaping checks. Shared fixtures live here; each group is a small submodule
//! split to keep every file under the 1,000-line cap (CLAUDE.md).
#![allow(unused_imports)]

use std::collections::BTreeMap;
use std::time::SystemTime;

use super::page::{LiveInputs, render_fragment, render_html};
use super::{DASHBOARD_CSS, DASHBOARD_JS, default_window_report};
use crate::engine::dashboard::model::{
    BakeStats, EntryEvidence, Finding, Findings, Judgement, JudgementLog, ModelHealth, PathStep,
    ReadinessConfig, ReversionLog, ReversionRecord, VerdictStore,
};
use crate::engine::dashboard::recency::{Delta, RecencyInfo};
use crate::engine::dashboard::view_model::posture::Posture;
use crate::engine::dashboard::view_model::readiness_data::{Readiness, derive_readiness};
use crate::engine::policy_log::{DecisionTallies, PolicyDecisionLog, PolicyDecisionRecord};
use crate::engine::reason::adjudicate::Verdict;

mod escaping;
mod guards;
mod render;

/// A breach-relevant finding for one entry with a TYPED verdict already resolved (the shape the
/// page sees after `Findings::snapshot` resolves the verdict from the store).
pub(super) fn finding(entry: &str, objective: &str, verdict: Option<Verdict>) -> Finding {
    Finding {
        entry: entry.into(),
        objective: objective.into(),
        foothold: true,
        corroborated: false,
        disposition: "auto-eligible".into(),
        cut: Some(format!("{entry} -[reaches/Tcp]-> {objective}")),
        breach_relevant: true,
        verdict,
        path: vec![PathStep {
            from: entry.into(),
            relation: "reaches/Tcp".into(),
            to: objective.into(),
        }],
        evidence: EntryEvidence::default(),
        recency: None,
    }
}

/// A fully-covered, model-judging readiness snapshot (every input met, last call ok).
pub(super) fn covered() -> Readiness {
    let mut bake = BakeStats::default();
    bake.signals_by_variant.insert("alert".into(), 1);
    bake.signals_by_variant.insert("connection".into(), 1);
    derive_readiness(
        &ReadinessConfig {
            model_attached: true,
            kev_count: 5,
            epss_count: 5,
            journal_durable: true,
            armed: false,
        },
        ModelHealth::Ok,
        &bake,
        Some(SystemTime::now()),
    )
}

/// A readiness snapshot with the model attached but its last call timed out — the blind state.
pub(super) fn model_down() -> Readiness {
    derive_readiness(
        &ReadinessConfig {
            model_attached: true,
            kev_count: 5,
            epss_count: 5,
            journal_durable: true,
            armed: false,
        },
        ModelHealth::Timeout,
        &BakeStats::default(),
        Some(SystemTime::now()),
    )
}

/// Render the full page over a fixture bundle.
pub(super) fn page(
    findings: &[Finding],
    readiness: &Readiness,
    admission: &[PolicyDecisionRecord],
    tallies: DecisionTallies,
    reversions: &[ReversionRecord],
    bake: &BakeStats,
    prompts: &BTreeMap<String, String>,
) -> String {
    render_html(&LiveInputs {
        findings,
        last_pass: Some(SystemTime::now()),
        readiness,
        admission_records: admission,
        admission_tallies: tallies,
        reversions,
        bake,
        prompts,
    })
}

/// Render the `/fragment` live region over a fixture bundle.
pub(super) fn fragment(
    findings: &[Finding],
    readiness: &Readiness,
    admission: &[PolicyDecisionRecord],
    tallies: DecisionTallies,
    reversions: &[ReversionRecord],
    bake: &BakeStats,
    prompts: &BTreeMap<String, String>,
) -> String {
    render_fragment(&LiveInputs {
        findings,
        last_pass: Some(SystemTime::now()),
        readiness,
        admission_records: admission,
        admission_tallies: tallies,
        reversions,
        bake,
        prompts,
    })
}

/// Assert a rendered surface never prints an `ADR-` or `JEF-` token (the rendered-output
/// invariant — code comments keep their refs).
pub(super) fn assert_no_internal_refs(label: &str, rendered: &str) {
    assert!(
        !rendered.contains("ADR-"),
        "{label}: leaked an ADR- ref into operator-facing output"
    );
    assert!(
        !rendered.contains("JEF-"),
        "{label}: leaked a JEF- ref into operator-facing output"
    );
}
