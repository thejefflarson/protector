//! `breach` scenario: the rich breach sample (the default) — a breach with
//! CVE/KEV/path/cut/judgement, plus awaiting/uncertain/cleared rows and an argocd fan-out.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use protector::engine::dashboard::DashboardState;
use protector::engine::reason::adjudicate::Verdict;
use protector::engine::state::{
    Finding, Judgement, ModelHealth, ReversionRecord, ScopePreviewStore, StoredPosture,
};

use crate::fixtures::{breach_finding, redundant_finding, simple_finding};
use crate::sample_data::{
    covered_bake, covered_config, fresh_handles, sample_journal, sample_policy_log,
};
use crate::samples::{SAMPLE_PROMPT, SAMPLE_REPLY};

/// `breach` — the rich breach sample (the default): a breach with CVE/KEV/path/cut/judgement,
/// plus awaiting/uncertain/cleared rows and an argocd fan-out.
pub(super) fn build_breach() -> DashboardState {
    let (findings, judgements, reversions, _journal) = fresh_handles();
    let now = Instant::now();
    let verdicts = findings.verdicts();

    let mut rows: Vec<Finding> = vec![
        // BREACH — internet-facing, proven multi-hop, KEV CVE, runtime alert, proposed cut.
        breach_finding(),
        // NO-CUT — one secret reachable via two redundant backends (JEF-281 multi-path view).
        redundant_finding(),
        // AWAITING — a breach-relevant entry the model has not yet reached (no verdict).
        simple_finding(
            "deployment/edge/auth-proxy",
            "secret/identity/oidc-signing-key",
        ),
        // UNCERTAIN — the model timed out judging this one.
        simple_finding("deployment/web/storefront", "secret/web/session-key"),
        // CLEARED — a few entries the model refuted.
        simple_finding(
            "deployment/web/marketing-site",
            "configmap/web/feature-flags",
        ),
        simple_finding("daemonset/obs/node-exporter", "secret/obs/scrape-token"),
        simple_finding("deployment/internal/wiki", "secret/internal/wiki-db"),
    ];
    // COLLAPSED REPLICAS — three StatefulSet pod replicas of one workload (item 5). They fold to a
    // single `×3` row labeled with the workload, carrying the worst posture among the replicas.
    for ordinal in 0..3 {
        rows.push(simple_finding(
            &format!("workload/analytics/Pod/murmurify-aggregator-{ordinal}"),
            "secret/analytics/warehouse-creds",
        ));
    }
    // CLEARED fan-out — one argocd entry reaching MANY objectives collapses to a `→ ×N` row.
    for i in 0..18 {
        rows.push(simple_finding(
            "deployment/cd/argocd-server",
            &format!("secret/team-{i:02}/repo-creds"),
        ));
    }
    findings.replace(rows);

    // BREACH: an Exploitable verdict (the strongest "this is a live, reachable breach" call).
    let breach = "deployment/edge/api-gateway";
    let breach_verdict = Verdict::Exploitable(
        "KEV-listed RCE (CVE-2024-3094, EPSS 94%) is loaded at runtime and a reverse shell \
         already fired; the single Tcp/5432 edge reaches the live payments key."
            .into(),
    );
    verdicts.set_display(breach, breach_verdict.clone());
    verdicts.record_recency(breach, StoredPosture::Breach, now);

    // AWAITING: deliberately leave NO verdict so the row renders the ochre awaiting treatment.
    verdicts.record_recency("deployment/edge/auth-proxy", StoredPosture::Awaiting, now);

    // COLLAPSED REPLICAS: one replica is a live breach (the worst posture), the rest cleared —
    // the merged `×3` row must carry the breach posture (item 5).
    verdicts.set_display(
        "workload/analytics/Pod/murmurify-aggregator-1",
        Verdict::Confirmed,
    );
    verdicts.record_recency(
        "workload/analytics/Pod/murmurify-aggregator-1",
        StoredPosture::Breach,
        now,
    );
    for ordinal in [0, 2] {
        verdicts.set_display(
            &format!("workload/analytics/Pod/murmurify-aggregator-{ordinal}"),
            Verdict::Refuted("replica reaches the same warehouse creds; not exploitable".into()),
        );
        verdicts.record_recency(
            &format!("workload/analytics/Pod/murmurify-aggregator-{ordinal}"),
            StoredPosture::Safe,
            now,
        );
    }

    // UNCERTAIN: a model-timeout verdict. Its posture is `Unknown`, never `Safe` — an
    // inconclusive read is never green (JEF-302 honesty).
    let uncertain = "deployment/web/storefront";
    verdicts.set_display(
        uncertain,
        Verdict::Uncertain("model unavailable — adjudication timed out (CPU model)".into()),
    );
    verdicts.record_recency(uncertain, StoredPosture::Unknown, now);

    // CLEARED: Refuted verdicts for the remaining single entries + the argocd fan-out.
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
            "deployment/internal/wiki",
            "not internet-facing in the proven topology; entry is mesh-internal only",
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

    // Record judgements so "show model prompt" works (breach + the timed-out uncertain).
    judgements.record(Judgement {
        entry: breach.into(),
        objectives: 1,
        verdict: format!("{breach_verdict:?}"),
        prompt: Some(SAMPLE_PROMPT.into()),
        reply: Some(SAMPLE_REPLY.into()),
    });
    judgements.record(Judgement {
        entry: uncertain.into(),
        objectives: 1,
        verdict: "Uncertain(\"model unavailable\")".into(),
        prompt: Some(
            "DECISION PROCEDURE: judge whether deployment/web/storefront is exploitable …".into(),
        ),
        reply: None, // the model timed out — honest "no reply".
    });

    findings.set_bake(covered_bake());
    findings.set_readiness_config(covered_config(true));
    findings.set_model_health(ModelHealth::Ok);
    findings.mark_pass(SystemTime::now());

    // A self-reverted cut, for the Activity tab's safety story.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    reversions.record(ReversionRecord {
        cut: "deployment/edge/legacy-admin -[reaches/Tcp/8080]-> service/internal/admin-api".into(),
        reason: "breach condition cleared — entry no longer internet-facing after ingress change"
            .into(),
        at_ms: now_ms.saturating_sub(90_000),
    });

    DashboardState {
        findings,
        judgements,
        reversions,
        decision_journal: sample_journal(),
        policy_log: sample_policy_log(),
        cluster: "prod-us-east-1 (PREVIEW — breach)".into(),
        auth_mode: protector::engine::dashboard::AuthMode::EdgeOnly,
        mcp_audit: Arc::new(protector::engine::mcp::AccessAuditSink::in_memory()),
        divergence: Arc::new(protector::engine::state::DivergenceLog::new()),
        // No standing cuts in the preview scenarios — the panel's own empty state.
        scope_preview: Arc::new(ScopePreviewStore::new()),
    }
}
