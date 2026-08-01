//! `blind` scenario: model down / warming → the blind/warming banner. Findings exist but no
//! model is answering, so nothing can be judged.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use protector::engine::dashboard::DashboardState;
use protector::engine::policy_log::PolicyDecisionLog;
use protector::engine::state::{Finding, ModelHealth, StoredPosture};

use crate::fixtures::{breach_finding, simple_finding};
use crate::sample_data::{covered_bake, covered_config, fresh_handles};

/// `blind` — model down / warming → the blind/warming banner. Findings exist but no model is
/// answering, so nothing can be judged.
pub(super) fn build_blind() -> DashboardState {
    // The blind scenario keeps the journal DISABLED so the Trust tab shows its honest
    // "no decisions journaled yet" empty state (the empty case the brief asks for).
    let (findings, judgements, reversions, journal) = fresh_handles();
    let now = Instant::now();
    let verdicts = findings.verdicts();

    let mut rows: Vec<Finding> = vec![
        breach_finding(),
        simple_finding(
            "deployment/edge/auth-proxy",
            "secret/identity/oidc-signing-key",
        ),
        simple_finding("deployment/web/storefront", "secret/web/session-key"),
    ];
    for i in 0..6 {
        rows.push(simple_finding(
            "deployment/cd/argocd-server",
            &format!("secret/team-{i:02}/repo-creds"),
        ));
    }
    findings.replace(rows);

    // No decisive verdicts land while the model is down — seed recency so rows read as fresh
    // awaiting entries rather than render-clock artifacts.
    for entry in [
        "deployment/edge/api-gateway",
        "deployment/edge/auth-proxy",
        "deployment/web/storefront",
        "deployment/cd/argocd-server",
    ] {
        verdicts.record_recency(entry, StoredPosture::Awaiting, now);
    }

    findings.set_bake(covered_bake());
    // Model attached but NOT answering (warming / down) → the blind banner.
    findings.set_readiness_config(covered_config(true));
    findings.set_model_health(ModelHealth::Timeout);
    findings.mark_pass(SystemTime::now());

    DashboardState {
        findings,
        judgements,
        reversions,
        decision_journal: journal,
        // The blind scenario keeps the admission log EMPTY so the Admission tab shows its honest
        // "no admission decisions recorded yet" empty state (the empty case the brief asks for).
        policy_log: Arc::new(PolicyDecisionLog::new()),
        cluster: "prod-us-east-1 (PREVIEW — blind)".into(),
        auth_mode: protector::engine::dashboard::AuthMode::EdgeOnly,
        mcp_audit: Arc::new(protector::engine::mcp::AccessAuditSink::in_memory()),
        divergence: Arc::new(protector::engine::state::DivergenceLog::new()),
    }
}
