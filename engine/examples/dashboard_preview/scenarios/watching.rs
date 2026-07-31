//! `watching` scenario: no breach, but ≥1 awaiting + a degraded feed → the elevated ochre
//! "watching" state.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use protector::engine::dashboard::DashboardState;
use protector::engine::reason::adjudicate::Verdict;
use protector::engine::state::{Finding, ModelHealth, ReadinessConfig, StoredPosture};

use crate::fixtures::simple_finding;
use crate::sample_data::{covered_bake, fresh_handles, sample_journal, sample_policy_log};

/// `watching` — no breach, but ≥1 awaiting + a degraded feed → the elevated ochre "watching".
pub(super) fn build_watching() -> DashboardState {
    let (findings, judgements, reversions, _journal) = fresh_handles();
    let now = Instant::now();
    let verdicts = findings.verdicts();

    let mut rows: Vec<Finding> = vec![
        // AWAITING — a breach-relevant entry the model has not yet reached (no verdict).
        simple_finding(
            "deployment/edge/auth-proxy",
            "secret/identity/oidc-signing-key",
        ),
        // CLEARED — a couple the model refuted.
        simple_finding(
            "deployment/web/marketing-site",
            "configmap/web/feature-flags",
        ),
        simple_finding("daemonset/obs/node-exporter", "secret/obs/scrape-token"),
    ];
    for i in 0..6 {
        rows.push(simple_finding(
            "deployment/cd/argocd-server",
            &format!("secret/team-{i:02}/repo-creds"),
        ));
    }
    findings.replace(rows);

    // AWAITING: deliberately leave NO verdict so the row renders the ochre awaiting treatment.
    verdicts.record_recency("deployment/edge/auth-proxy", StoredPosture::Awaiting, now);

    let cleared: &[(&str, &str)] = &[
        (
            "deployment/web/marketing-site",
            "no reachable secret objective; the only edge is a public CDN origin",
        ),
        (
            "daemonset/obs/node-exporter",
            "scrape token is read-only metrics scope; no privilege or lateral path",
        ),
        (
            "deployment/cd/argocd-server",
            "reaches many repo-cred secrets but all edges are gated by an authenticated, \
             RBAC-scoped API — no unauthenticated breach path",
        ),
    ];
    for (entry, why) in cleared {
        verdicts.set_display(entry, Verdict::Refuted((*why).into()));
        verdicts.record_recency(entry, StoredPosture::Safe, now);
    }

    // A DEGRADED feed: KEV present, but the EPSS feed didn't load (0) — coverage is partial,
    // which (with the awaiting row) keeps the strip in the elevated "watching" state.
    findings.set_bake(covered_bake());
    findings.set_readiness_config(ReadinessConfig {
        model_attached: true,
        kev_count: 1342,
        epss_count: 0, // degraded — EPSS feed absent.
        journal_durable: true,
        armed: false,
        tuf_cache_age_secs: Some(3 * 60 * 60),
        unverifiable_spike: false,
        checking_images: 2, // degraded — two images stuck 'checking'.
    });
    findings.set_model_health(ModelHealth::Ok);
    findings.mark_pass(SystemTime::now());

    DashboardState {
        findings,
        judgements,
        reversions,
        decision_journal: sample_journal(),
        policy_log: sample_policy_log(),
        cluster: "prod-us-east-1 (PREVIEW — watching)".into(),
        auth_mode: protector::engine::dashboard::AuthMode::EdgeOnly,
        mcp_audit: Arc::new(protector::engine::mcp::AccessAuditSink::in_memory()),
    }
}
