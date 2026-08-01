//! `clear` scenario: all findings Refuted, model judging, fully covered → the green all-clear.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use protector::engine::dashboard::DashboardState;
use protector::engine::reason::adjudicate::Verdict;
use protector::engine::state::{Finding, Judgement, ModelHealth, StoredPosture};

use crate::fixtures::simple_finding;
use crate::sample_data::{
    covered_bake, covered_config, fresh_handles, sample_journal, sample_policy_log,
};
use crate::samples::SAMPLE_PROMPT;

/// `clear` — all findings Refuted, model judging, fully covered → the green all-clear.
pub(super) fn build_clear() -> DashboardState {
    let (findings, judgements, reversions, _journal) = fresh_handles();
    let now = Instant::now();
    let verdicts = findings.verdicts();

    // A handful of breach-relevant entries, every one of which the model refuted.
    let entries: &[(&str, &str, &str)] = &[
        (
            "deployment/edge/api-gateway",
            "secret/payments/stripe-live-key",
            "single Tcp/5432 edge is mTLS-gated and the gateway holds no decrypt key — \
             no unauthenticated path to the mounted secret",
        ),
        (
            "deployment/web/marketing-site",
            "configmap/web/feature-flags",
            "no reachable secret objective; the only edge is a public CDN origin",
        ),
        (
            "daemonset/obs/node-exporter",
            "secret/obs/scrape-token",
            "scrape token is read-only metrics scope; no privilege or lateral path",
        ),
        (
            "deployment/internal/wiki",
            "secret/internal/wiki-db",
            "not internet-facing in the proven topology; entry is mesh-internal only",
        ),
    ];
    let mut rows: Vec<Finding> = entries
        .iter()
        .map(|(e, o, _)| simple_finding(e, o))
        .collect();
    // A cleared fan-out, so the `→ ×N` collapse is exercised in the all-clear too.
    for i in 0..18 {
        rows.push(simple_finding(
            "deployment/cd/argocd-server",
            &format!("secret/team-{i:02}/repo-creds"),
        ));
    }
    findings.replace(rows);

    for (entry, _obj, why) in entries {
        verdicts.set_display(entry, Verdict::Refuted((*why).into()));
        verdicts.record_recency(entry, StoredPosture::Safe, now);
    }
    verdicts.set_display(
        "deployment/cd/argocd-server",
        Verdict::Refuted(
            "reaches many repo-cred secrets but all edges are gated by an authenticated, \
             RBAC-scoped API — no unauthenticated breach path"
                .into(),
        ),
    );
    verdicts.record_recency("deployment/cd/argocd-server", StoredPosture::Safe, now);

    // A judgement so "show model prompt" works on a cleared row.
    judgements.record(Judgement {
        entry: "deployment/edge/api-gateway".into(),
        objectives: 1,
        verdict: "Refuted(\"no unauthenticated path\")".into(),
        prompt: Some(SAMPLE_PROMPT.into()),
        reply: Some(
            "refuted — the single Tcp/5432 edge is mTLS-gated and the gateway holds no \
             decrypt key, so the mounted Stripe key is not reachable unauthenticated."
                .into(),
        ),
    });

    findings.set_bake(covered_bake());
    findings.set_readiness_config(covered_config(true));
    findings.set_model_health(ModelHealth::Ok);
    findings.mark_pass(SystemTime::now());

    DashboardState {
        findings,
        judgements,
        reversions,
        // The clear scenario still has would-have-acted history to calibrate trust against.
        decision_journal: sample_journal(),
        // The webhook floor: a populated admission log (admits + an audited + an enforced deny).
        policy_log: sample_policy_log(),
        cluster: "prod-us-east-1 (PREVIEW — clear)".into(),
        auth_mode: protector::engine::dashboard::AuthMode::EdgeOnly,
        mcp_audit: Arc::new(protector::engine::mcp::AccessAuditSink::in_memory()),
        divergence: Arc::new(protector::engine::state::DivergenceLog::new()),
    }
}
