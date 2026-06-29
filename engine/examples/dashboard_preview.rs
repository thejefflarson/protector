//! THROWAWAY local preview of the v3 dashboard — a dev artifact, NOT part of the product.
//!
//! It boots the real dashboard (`serve_dashboard`) over the real `state::` handles
//! (`Findings` / `JudgementLog` / `ReversionLog`), populated with representative sample data
//! through the same write/publish API the engine run loop uses, so a human can open a browser
//! and see every visual state at once:
//!
//! - one BREACH (internet-facing, multi-hop proven path, KEV+CVSS+EPSS CVE, runtime alert,
//!   proposed cut, and a recorded Judgement so "show model prompt" works);
//! - one AWAITING entry (no verdict yet — the ochre/elevated treatment);
//! - one UNCERTAIN entry;
//! - several CLEARED (Refuted) entries, including an argocd-style fan-out reaching many
//!   objectives (the `→ ×N` collapse);
//! - readiness stamped so the status strip reads "watching" (model judging + covered, but
//!   awaiting/uncertain present → not green) with a recent last-pass.
//!
//! Run it with:  `cargo run --example dashboard_preview`  (from the `engine/` dir, or pass
//! `-p protector` from the workspace root), then open http://127.0.0.1:8787/.

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use protector::engine::dashboard::{DashboardState, serve_dashboard};
use protector::engine::reason::adjudicate::Verdict;
use protector::engine::state::{
    BakeStats, CveEvidence, EntryEvidence, Finding, Findings, Judgement, JudgementLog, ModelHealth,
    PathStep, ReadinessConfig, ReversionLog, ReversionRecord, StoredPosture,
};
use protector_behavior::Behavior;

/// A single proven-chain hop, terse to build.
fn hop(from: &str, relation: &str, to: &str) -> PathStep {
    PathStep {
        from: from.into(),
        relation: relation.into(),
        to: to.into(),
    }
}

/// Build the BREACH finding: an internet-facing front door with a multi-hop proven path, a
/// KEV + CVSS + EPSS CVE, a runtime alert, and a proposed cut. The verdict is set on the
/// verdict store (not the row) so it resolves exactly like the engine resolves it at snapshot.
fn breach_finding() -> Finding {
    let evidence = EntryEvidence {
        cves: vec![CveEvidence {
            id: "CVE-2024-3094".into(),
            severity: "critical".into(),
            score: Some("10.0".into()),
            kev: true,
            epss: Some("94%".into()),
            reachability: "loaded-at-runtime".into(),
            fix: "fix available: 5.6.0 to 5.6.1".into(),
            title: Some("xz/liblzma backdoor — pre-auth RCE via sshd".into()),
        }],
        runtime: vec![
            Behavior::Alert {
                rule: "Reverse shell spawned in container".into(),
            },
            Behavior::ProcessExec {
                path: "/bin/sh".into(),
            },
            Behavior::NetworkConnection {
                peer: "185.220.101.4:9001".into(),
                internet: true,
            },
        ],
        exposed_secrets: vec![],
        misconfigs: vec![],
        rbac_findings: vec![],
    };
    Finding {
        entry: "deployment/edge/api-gateway".into(),
        objective: "secret/payments/stripe-live-key".into(),
        foothold: true,
        corroborated: true,
        disposition: "auto-eligible".into(),
        cut: Some(
            "deployment/edge/api-gateway -[reaches/Tcp/5432]-> statefulset/payments/ledger-db"
                .into(),
        ),
        breach_relevant: true,
        // Resolved from the verdict store at snapshot — left None on the row.
        verdict: None,
        path: vec![
            hop(
                "deployment/edge/api-gateway",
                "reaches/Tcp/5432",
                "statefulset/payments/ledger-db",
            ),
            hop(
                "statefulset/payments/ledger-db",
                "mounts",
                "secret/payments/stripe-live-key",
            ),
        ],
        evidence,
        recency: None,
    }
}

/// A plain breach-relevant finding skeleton (single hop) used for the awaiting / uncertain /
/// cleared rows. Evidence is left empty for these (the row renders an honest "no evidence").
fn simple_finding(entry: &str, objective: &str) -> Finding {
    Finding {
        entry: entry.into(),
        objective: objective.into(),
        foothold: entry.contains("edge") || entry.contains("ingress"),
        corroborated: false,
        disposition: "structural — propose".into(),
        cut: Some(format!("{entry} -[reaches/Tcp/443]-> {objective}")),
        breach_relevant: true,
        verdict: None,
        path: vec![hop(entry, "reaches/Tcp/443", objective)],
        evidence: EntryEvidence::default(),
        recency: None,
    }
}

#[tokio::main]
async fn main() {
    // The real shared handles the engine writes each pass.
    let findings = Arc::new(Findings::new());
    let judgements = Arc::new(JudgementLog::new());
    let reversions = Arc::new(ReversionLog::new());

    // A single pass clock — recency is tracked against this, like the engine's per-pass Instant.
    let now = Instant::now();
    let verdicts = findings.verdicts();

    // ---- 1. Assemble this pass's findings rows. ----
    let mut rows: Vec<Finding> = vec![
        // BREACH — internet-facing, proven multi-hop, KEV CVE, runtime alert, proposed cut.
        breach_finding(),
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

    // CLEARED fan-out — one argocd entry reaching MANY objectives collapses to a `→ ×N` row.
    for i in 0..18 {
        rows.push(simple_finding(
            "deployment/cd/argocd-server",
            &format!("secret/team-{i:02}/repo-creds"),
        ));
    }

    // Publish the rows once — verdicts/recency resolve from the store at snapshot time.
    findings.replace(rows);

    // ---- 2. Stamp each entry's verdict + recency in the shared store. ----
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
    // (We still seed first-seen so it reads as a fresh row, not a render-clock artifact.)
    verdicts.record_recency("deployment/edge/auth-proxy", StoredPosture::Awaiting, now);

    // UNCERTAIN: a model-timeout verdict.
    let uncertain = "deployment/web/storefront";
    verdicts.set_display(
        uncertain,
        Verdict::Uncertain("model unavailable — adjudication timed out (CPU model)".into()),
    );
    verdicts.record_recency(uncertain, StoredPosture::Safe, now);

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

    // ---- 3. Record judgements so "show model prompt" works (at minimum for the breach). ----
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

    // ---- 4. Per-pass freshness / bake / readiness config / model health. ----
    let mut bake = BakeStats::default();
    bake.signals_by_variant.insert("alert".into(), 3);
    bake.signals_by_variant.insert("exec".into(), 41);
    bake.signals_by_variant.insert("connection".into(), 162);
    bake.signals_by_variant.insert("secret-read".into(), 7);
    bake.resolved = 198;
    bake.unresolved = 15;
    bake.runtime_store = 213;
    bake.corroborations = 1;
    findings.set_bake(bake);

    // Fully-covered, actively-judging config → with the awaiting/uncertain rows present this
    // lands the strip in the "watching" state (covered + judging, but not all-clear/green).
    findings.set_readiness_config(ReadinessConfig {
        model_attached: true,
        kev_count: 1342,
        epss_count: 241_000,
        journal_durable: true,
        armed: false, // shadow — the safe default (ADR-0016).
    });
    findings.set_model_health(ModelHealth::Ok);
    findings.mark_pass(SystemTime::now());

    // ---- 5. A self-reverted cut, for the Activity tab's safety story. ----
    let now_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    reversions.record(ReversionRecord {
        cut: "deployment/edge/legacy-admin -[reaches/Tcp/8080]-> service/internal/admin-api".into(),
        reason: "breach condition cleared — entry no longer internet-facing after ingress change"
            .into(),
        at_ms: now_ms.saturating_sub(90_000),
    });

    // ---- 6. Serve it. ----
    let state = DashboardState {
        findings,
        judgements,
        reversions,
        cluster: "prod-us-east-1 (PREVIEW — sample data)".into(),
    };

    let addr = "127.0.0.1:8787".parse().unwrap();
    println!("dashboard preview on http://{addr}/  (Ctrl-C to stop)");
    serve_dashboard(addr, state).await;
}

/// A representative model prompt, so the "show model prompt" disclosure has real content.
const SAMPLE_PROMPT: &str = "\
DECISION PROCEDURE — adjudicate whether the proven attack path is EXPLOITABLE.

ENTRY: deployment/edge/api-gateway  (internet-facing front door: yes)
OBJECTIVE: secret/payments/stripe-live-key
PROVEN PATH:
  deployment/edge/api-gateway -[reaches/Tcp/5432]-> statefulset/payments/ledger-db
  statefulset/payments/ledger-db -[mounts]-> secret/payments/stripe-live-key

CVE EVIDENCE (severity/reachability input — not on its own the breach call):
  - CVE-2024-3094  critical  cvss 10.0  KEV: yes  EPSS 94%  reachability: loaded-at-runtime
    fix available: 5.6.0 to 5.6.1
    title: xz/liblzma backdoor — pre-auth RCE via sshd

RUNTIME EVIDENCE (live corroboration):
  - ALERT: Reverse shell spawned in container
  - exec: /bin/sh
  - connection: 185.220.101.4:9001 (internet)

Answer with one of: confirmed | exploitable | refuted | uncertain, then a one-line reason.";

/// The matching model reply.
const SAMPLE_REPLY: &str = "\
exploitable — the KEV-listed, runtime-loaded RCE plus the already-fired reverse shell make this \
a live path; the single Tcp/5432 edge to the ledger DB reaches the mounted live Stripe key. \
Propose the network cut.";
