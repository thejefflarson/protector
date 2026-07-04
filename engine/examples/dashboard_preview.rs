//! DEV-ONLY hot-reload preview of the v3 dashboard — a dev artifact, NOT part of the product.
//!
//! Unlike the shipped `serve_dashboard` (which bakes the CSS/JS into the binary via
//! `include_str!`, so every visual tweak forces a full Rust rebuild), this example mounts its
//! OWN axum router that:
//!
//! - serves `/assets/dashboard.css` and `/assets/dashboard.js` by reading
//!   `engine/web/dist/*` FROM DISK on every request (path resolved relative to
//!   `CARGO_MANIFEST_DIR`), so a CSS/JS edit shows on the next browser refresh — no rebuild;
//! - renders `/` and `/fragment` through the dashboard's PUBLIC render path
//!   (`view_model::build_findings_view` / `build_status_strip` + `page::*`), over the real
//!   `state::` handles, exactly as `serve_dashboard` does — so the preview can't drift from
//!   production rendering;
//! - selects which sample state to build via `?scenario=clear|watching|breach|blind`, so every
//!   honesty state is one URL away with no code edit (default `breach`);
//! - appends a tiny dev-livereload IIFE to the served JS (kept ONLY here, never written to the
//!   repo's `dashboard.js`) that polls `/dev/reload` and calls `location.reload()` when the
//!   token changes — so a CSS/JS save (mtime change) OR a cargo-watch restart (nonce change)
//!   auto-refreshes the browser.
//!
//! Run it under cargo-watch for the full loop:
//!   `cargo watch -x 'run --example dashboard_preview'`
//! or once:
//!   `cargo run --example dashboard_preview`
//! then open http://127.0.0.1:8787/ (try `?scenario=clear|watching|breach|blind`).
//!
//! This changes NOTHING about the shipped `serve_dashboard` or the repo's `dashboard.js`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::Query;
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;

use protector::engine::dashboard::view_model::props::Tab;
use protector::engine::dashboard::{DashboardState, page, view_model};
use protector::engine::journal::{Decision, DecisionJournal, EnrichmentCoverage};
use protector::engine::policy_log::{PolicyDecisionLog, PolicyDecisionRecord};
use protector::engine::reason::adjudicate::Verdict;
use protector::engine::state::{
    BakeStats, CveEvidence, EntryEvidence, Finding, Findings, Judgement, JudgementLog, ModelHealth,
    PathStep, ReadinessConfig, ReversionLog, ReversionRecord, StoredPosture,
};
use protector_behavior::Behavior;

// ---------------------------------------------------------------------------------------------
// Finding skeletons (shared across scenarios).
// ---------------------------------------------------------------------------------------------

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
        paths: vec![],
        paths_truncated: false,
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
        paths: vec![],
        paths_truncated: false,
        evidence: EntryEvidence::default(),
        recency: None,
    }
}

/// A wide, NO-CUT finding (JEF-281): an internet-facing front door reaching one secret via TWO
/// redundant backends, so no single edge severs the objective. Showcases the multi-path detail —
/// both proven paths stacked, and the "reachable via N redundant paths" reason line.
fn redundant_finding() -> Finding {
    let entry = "deployment/edge/webhook-router";
    let objective = "secret/app/shared-creds";
    let path_via_db = vec![
        hop(entry, "reaches/Tcp/5432", "statefulset/app/ledger-db"),
        hop("statefulset/app/ledger-db", "mounts", objective),
    ];
    let path_via_cache = vec![
        hop(entry, "reaches/Tcp/6379", "deployment/app/cache"),
        hop("deployment/app/cache", "mounts", objective),
    ];
    Finding {
        entry: entry.into(),
        objective: objective.into(),
        foothold: true,
        corroborated: false,
        disposition: "no-cut".into(),
        // No single edge severs the chain — the redundant paths ARE the reason.
        cut: None,
        breach_relevant: true,
        verdict: None,
        path: path_via_db.clone(),
        paths: vec![path_via_db, path_via_cache],
        paths_truncated: false,
        evidence: EntryEvidence::default(),
        recency: None,
    }
}

// ---------------------------------------------------------------------------------------------
// Per-scenario sample-state builders.
//
// Each returns a fully-populated `DashboardState` for one honesty state, so the rendered page
// reads exactly as the engine would render that state. All four share the same finding
// skeletons above; they differ in which verdicts/health/readiness they stamp.
// ---------------------------------------------------------------------------------------------

/// The selectable preview scenarios. `?scenario=` maps onto these; default is `Breach`.
#[derive(Clone, Copy)]
enum Scenario {
    Clear,
    Watching,
    Breach,
    Blind,
}

impl Scenario {
    fn parse(s: Option<&str>) -> Scenario {
        match s {
            Some("clear") => Scenario::Clear,
            Some("watching") => Scenario::Watching,
            Some("blind") => Scenario::Blind,
            _ => Scenario::Breach,
        }
    }

    fn build(self) -> DashboardState {
        match self {
            Scenario::Clear => build_clear(),
            Scenario::Watching => build_watching(),
            Scenario::Breach => build_breach(),
            Scenario::Blind => build_blind(),
        }
    }
}

/// Fresh shared handles for one scenario render. Cheap; rebuilt per request so each scenario
/// renders from clean state. The decision journal is disabled by default (empty Trust report);
/// scenarios that want a populated would-have-acted diff swap in a [`sample_journal`].
fn fresh_handles() -> (
    Arc<Findings>,
    Arc<JudgementLog>,
    Arc<ReversionLog>,
    Arc<DecisionJournal>,
) {
    (
        Arc::new(Findings::new()),
        Arc::new(JudgementLog::new()),
        Arc::new(ReversionLog::new()),
        Arc::new(DecisionJournal::disabled()),
    )
}

/// A file-backed decision journal seeded with a representative would-have-acted mix, so the Trust
/// tab shows real would-cut + left-alone rows in the covered scenarios. Records (most recent
/// "now"): an OPEN would-act (still standing), a SHORT-LIVED would-act (opened then cleared), a
/// COVERAGE-GAP would-act (affirmed with no CVE/behavioral backing), and two LEFT-ALONE clears.
/// Written under a unique temp path per build so a `?scenario=` switch never collides.
fn sample_journal() -> Arc<DecisionJournal> {
    let path = std::env::temp_dir().join(format!(
        "protector-preview-journal-{}.jsonl",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    // Start clean so a re-render doesn't accumulate episodes.
    let _ = std::fs::remove_file(&path);
    let journal = DecisionJournal::open(&path);

    let backed = || {
        Some(EnrichmentCoverage {
            cves: vec!["CVE-2024-3094".into()],
            behavioral: true,
        })
    };
    let unbacked = || {
        Some(EnrichmentCoverage {
            cves: vec![],
            behavioral: false,
        })
    };

    // OPEN would-act — still the latest verdict, so the cut would still be standing now.
    journal.record(Decision::Breach {
        entry: "deployment/edge/api-gateway".into(),
        objectives: 1,
        verdict: "exploitable — KEV-listed RCE loaded at runtime; reaches the live payments key"
            .into(),
        coverage: backed(),
        fingerprint: None,
        verdict_typed: None,
    });
    // SHORT-LIVED would-act — opened then immediately cleared (the likely-FP signature).
    journal.record(Decision::Breach {
        entry: "deployment/web/storefront".into(),
        objectives: 1,
        verdict: "exploitable — transient: session key briefly reachable during a rollout".into(),
        coverage: backed(),
        fingerprint: None,
        verdict_typed: None,
    });
    journal.record(Decision::Breach {
        entry: "deployment/web/storefront".into(),
        objectives: 1,
        verdict: "not exploitable — rollout completed; the edge is mTLS-gated again".into(),
        coverage: backed(),
        fingerprint: None,
        verdict_typed: None,
    });
    // COVERAGE-GAP would-act — affirmed with NO CVE/behavioral backing (scrutinise first).
    journal.record(Decision::Breach {
        entry: "deployment/cd/argocd-server".into(),
        objectives: 7,
        verdict: "exploitable — broad reach to repo-cred secrets (no CVE/runtime backing)".into(),
        coverage: unbacked(),
        fingerprint: None,
        verdict_typed: None,
    });
    // LEFT-ALONE clears — proven paths the model deliberately cleared (the trust half).
    journal.record(Decision::Breach {
        entry: "deployment/web/marketing-site".into(),
        objectives: 1,
        verdict: "not exploitable — no reachable secret objective; only a public CDN origin".into(),
        coverage: backed(),
        fingerprint: None,
        verdict_typed: None,
    });
    journal.record(Decision::Breach {
        entry: "daemonset/obs/node-exporter".into(),
        objectives: 1,
        verdict: "not exploitable — scrape token is read-only metrics scope; no lateral path"
            .into(),
        coverage: backed(),
        fingerprint: None,
        verdict_typed: None,
    });

    Arc::new(journal)
}

/// A populated admission-decision log for the Admission tab (the webhook floor): a representative
/// mix of clean admits, an audited would-deny-but-allowed, and an enforced deny — including at
/// least one `would-fail` shadow gate so the "if enforced" what-if shows a would-deny. Deduped
/// counts mirror replica churn (an `allow` seen across N replicas folds to one counted row).
fn sample_policy_log() -> Arc<PolicyDecisionLog> {
    let log = PolicyDecisionLog::new();
    // A clean admit, signed + meshed — seen across 12 replicas (folds to one counted row).
    for _ in 0..12 {
        log.record(
            PolicyDecisionRecord::now(
                "admission",
                "allow",
                "Deployment/edge/api-gateway",
                "ghcr.io/acme/api-gateway:1.8.2",
                "verified",
                "verified",
                "edge",
                "",
            )
            .with_would_admit(true),
        );
    }
    // Another clean admit, signature verified, mesh out-of-scope but would-pass (a Job pod).
    log.record(
        PolicyDecisionRecord::now(
            "admission",
            "allow",
            "Job/data/nightly-export",
            "ghcr.io/acme/export:3.0.0",
            "verified",
            "would-pass",
            "data",
            "",
        )
        .with_would_admit(true),
    );
    // An AUDITED would-deny-but-allowed: the signature gate would fail (unsigned image), but the
    // webhook is in shadow so the request is allowed — the "if enforced" what-if is would-deny.
    log.record(
        PolicyDecisionRecord::now(
            "admission",
            "audit",
            "Deployment/web/legacy-storefront",
            "docker.io/library/storefront:latest",
            "would-fail",
            "verified",
            "web",
            "unsigned or untrusted image(s): docker.io/library/storefront:latest",
        )
        .with_would_admit(false),
    );
    // An enforced DENY: a out-of-mesh pod whose mesh gate would fail AND is enforced here.
    log.record(
        PolicyDecisionRecord::now(
            "mesh-injection",
            "deny",
            "Pod/payments/debug-shell",
            "alpine:3.19",
            "would-pass",
            "would-fail",
            "payments",
            "pod not sidecar-injected and namespace requires the mesh",
        )
        .with_would_admit(false),
    );
    record_signing_inventory(&log);
    Arc::new(log)
}

/// Seed the signing sweep's per-image observation rows (JEF-261 shape) so the Admission tab's
/// signing inventory (JEF-262) renders every posture: a GitHub Actions keyless signature, a
/// human/Google-issued signature, an invalid signature (loud), a plain not-signed (calm), and a
/// transient checking. Keyed `Image/<ref>` with the posture in the `signature` word + `reason`
/// prose, exactly as `engine::signing_sweep` records them.
fn record_signing_inventory(log: &PolicyDecisionLog) {
    let sweep = |image: &str, status: &str, reason: &str| {
        log.record(PolicyDecisionRecord::now(
            "image-signature",
            "allow",
            format!("Image/{image}"),
            image,
            status,
            "",
            "",
            reason,
        ));
    };
    sweep(
        "ghcr.io/acme/api-gateway@sha256:1a2b3c4d5e6f70819293a4b5c6d7e8f90112233445566778899aabbccddeeff0",
        "signed",
        "signed by https://github.com/acme/api-gateway/.github/workflows/release.yaml@refs/tags/v1.8.2 \
         via https://token.actions.githubusercontent.com",
    );
    sweep(
        "ghcr.io/acme/export:3.0.0",
        "signed",
        "signed by releng@acme.example via https://accounts.google.com",
    );
    sweep(
        "docker.io/library/storefront:latest",
        "invalid-signature",
        "signature present but does not verify (untrusted/tampered chain)",
    );
    sweep("docker.io/library/postgres:16", "not-signed", "");
    sweep(
        "registry.k8s.io/pause:3.9",
        "checking",
        "signing posture not yet known (registry/log unreachable)",
    );
    // A signing-regression finding (JEF-264): the api-gateway repo — with an established signed
    // history — is now signed by a NEW identity (the push-access-compromise signal). Audit-only:
    // the image is still admitted; the loud banner surfaces before→after in full.
    log.record(PolicyDecisionRecord::now(
        "signing-regression",
        "allow",
        "SigningRegression/ghcr.io/acme/api-gateway",
        "ghcr.io/acme/api-gateway:v1.9.0",
        "regression-identity-established",
        "",
        "",
        "signed by https://github.com/acme-forks/api-gateway/.github/workflows/build.yaml@refs/heads/main \
         via https://token.actions.githubusercontent.com | before: \
         https://github.com/acme/api-gateway/.github/workflows/release.yaml@refs/tags/v1.8.2",
    ));
    // An "exception accepted" (JEF-265): the export repo legitimately rotated its signer, and the
    // operator opted THAT drift out via a scoped, recorded exception. Rendered CALM + distinctly
    // labelled "exception accepted" (never green-cleared), kept visible, never counted as breach.
    sweep(
        "ghcr.io/acme/export:3.1.0",
        "signed",
        "signed by releng-ci@acme.example via https://accounts.google.com",
    );
    log.record(PolicyDecisionRecord::now(
        "signing-exception",
        "allow",
        "SigningException/ghcr.io/acme/export",
        "ghcr.io/acme/export:3.1.0",
        "exception-identity-established",
        "",
        "",
        "signed by releng-ci@acme.example via https://accounts.google.com | before: \
         releng@acme.example",
    ));
}

/// A representative bake/coverage summary used by the covered scenarios.
fn covered_bake() -> BakeStats {
    let mut bake = BakeStats::default();
    bake.signals_by_variant.insert("alert".into(), 3);
    bake.signals_by_variant.insert("exec".into(), 41);
    bake.signals_by_variant.insert("connection".into(), 162);
    bake.signals_by_variant.insert("secret-read".into(), 7);
    bake.resolved = 198;
    bake.unresolved = 15;
    bake.runtime_store = 213;
    bake.corroborations = 1;
    bake
}

/// A fully-wired readiness config (model attached, catalogues loaded, shadow/unarmed).
fn covered_config(model_attached: bool) -> ReadinessConfig {
    ReadinessConfig {
        model_attached,
        kev_count: 1342,
        epss_count: 241_000,
        journal_durable: true,
        armed: false,                          // shadow — the safe default (ADR-0016).
        tuf_cache_age_secs: Some(3 * 60 * 60), // a fresh trust root (3h old).
        unverifiable_spike: false,
    }
}

/// `clear` — all findings Refuted, model judging, fully covered → the green all-clear.
fn build_clear() -> DashboardState {
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
    }
}

/// `watching` — no breach, but ≥1 awaiting + a degraded feed → the elevated ochre "watching".
fn build_watching() -> DashboardState {
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
    }
}

/// `breach` — the rich breach sample (the default): a breach with CVE/KEV/path/cut/judgement,
/// plus awaiting/uncertain/cleared rows and an argocd fan-out.
fn build_breach() -> DashboardState {
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
    }
}

/// `blind` — model down / warming → the blind/warming banner. Findings exist but no model is
/// answering, so nothing can be judged.
fn build_blind() -> DashboardState {
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
    }
}

// ---------------------------------------------------------------------------------------------
// The example's own axum router: disk-served assets + public render path + dev livereload.
// ---------------------------------------------------------------------------------------------

/// Process-start nonce: a fresh value each launch, so a cargo-watch restart (new process)
/// changes the `/dev/reload` token and the browser refreshes onto the rebuilt binary.
static START_NONCE: std::sync::OnceLock<u128> = std::sync::OnceLock::new();

fn start_nonce() -> u128 {
    *START_NONCE.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    })
}

/// Absolute path to a `web/dist/<name>` asset, resolved from `CARGO_MANIFEST_DIR` so it works
/// from `cargo run` regardless of the shell's cwd.
fn dist_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("web")
        .join("dist")
        .join(name)
}

/// Read an asset from disk per request. On a read error, return the error text so a missing
/// file is obvious in the browser rather than silently empty.
fn read_asset(name: &str) -> String {
    let path = dist_path(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| format!("/* dashboard_preview: failed to read {path:?}: {e} */"))
}

/// The `?scenario=` query.
#[derive(serde::Deserialize, Default)]
struct PreviewQuery {
    scenario: Option<String>,
    tab: Option<String>,
}

fn resolve_tab(tab: Option<&str>) -> Tab {
    match tab {
        // The merged Action tab + its legacy soft-aliases (trust/activity), matching production.
        Some("action") | Some("trust") | Some("activity") => Tab::Action,
        Some("readiness") => Tab::Readiness,
        Some("admission") => Tab::Admission,
        _ => Tab::Findings,
    }
}

/// Build the persistent status strip the same way production does — from the live findings +
/// judgement snapshots, so its honesty reading reflects the real cluster posture on every tab.
fn preview_strip(state: &DashboardState) -> view_model::props::StatusStripProps {
    view_model::build_status_strip(
        state.cluster.clone(),
        &state.findings.snapshot(),
        &state.judgements.snapshot(),
        &state.readiness(),
        state.findings.last_pass(),
    )
}

/// Build the Findings view props through the public render path.
fn preview_findings(state: &DashboardState) -> view_model::props::FindingsViewProps {
    view_model::build_findings_view(
        state.cluster.clone(),
        &state.findings.snapshot(),
        &state.judgements.snapshot(),
        &state.readiness(),
        state.findings.last_pass(),
    )
}

/// Build the merged Action view props through the public render path (the would-have-acted report
/// from the decision journal + the self-reverted-cuts ring + the judgement ring).
fn preview_action(state: &DashboardState) -> view_model::props::ActionViewProps {
    use protector::engine::state::default_window_report;
    let report = default_window_report(&state.decision_journal);
    view_model::build_action_view(
        preview_strip(state),
        &report,
        &state.reversions.snapshot(),
        &state.judgements.snapshot(),
    )
}

/// Build the Readiness view props through the public render path.
fn preview_readiness(state: &DashboardState) -> view_model::props::ReadinessViewProps {
    view_model::build_readiness_view(preview_strip(state), &state.readiness())
}

/// Build the Admission view props through the public render path.
fn preview_admission(state: &DashboardState) -> view_model::props::AdmissionViewProps {
    view_model::build_admission_view(preview_strip(state), &state.policy_log.snapshot())
}

/// Render the full page for a tab through the dashboard's PUBLIC render path (all four real).
fn render_page(state: &DashboardState, tab: Tab) -> String {
    let markup = match tab {
        Tab::Findings => page::findings_page(&preview_findings(state)),
        Tab::Action => page::action_page(&preview_action(state)),
        Tab::Readiness => page::readiness_page(&preview_readiness(state)),
        Tab::Admission => page::admission_page(&preview_admission(state)),
    };
    markup.into_string()
}

/// Render the `/fragment` live-region inner content through the public render path.
fn render_fragment(state: &DashboardState, tab: Tab) -> String {
    let markup = match tab {
        Tab::Findings => page::findings_fragment(&preview_findings(state)),
        Tab::Action => page::action_fragment(&preview_action(state)),
        Tab::Readiness => page::readiness_fragment(&preview_readiness(state)),
        Tab::Admission => page::admission_fragment(&preview_admission(state)),
    };
    markup.into_string()
}

async fn index(Query(q): Query<PreviewQuery>) -> Html<String> {
    let state = Scenario::parse(q.scenario.as_deref()).build();
    Html(render_page(&state, resolve_tab(q.tab.as_deref())))
}

async fn fragment(Query(q): Query<PreviewQuery>) -> Html<String> {
    let state = Scenario::parse(q.scenario.as_deref()).build();
    Html(render_fragment(&state, resolve_tab(q.tab.as_deref())))
}

/// `GET /assets/dashboard.css` — read from disk, per request (the hot-reload point).
async fn dashboard_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        read_asset("dashboard.css"),
    )
        .into_response()
}

/// `GET /assets/dashboard.js` — read from disk, per request, with the dev-livereload IIFE
/// APPENDED. The IIFE is kept ONLY here; it is never written to the repo's `dashboard.js`.
async fn dashboard_js() -> Response {
    let body = format!("{}\n{}", read_asset("dashboard.js"), DEV_LIVERELOAD_JS);
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        body,
    )
        .into_response()
}

/// `GET /dev/reload` — a token = the process-start nonce combined with the mtimes of the two
/// assets. Changes on a CSS/JS save (mtime) OR a cargo-watch restart (nonce).
async fn dev_reload() -> Response {
    let token = format!(
        "{}-{}-{}",
        start_nonce(),
        asset_mtime("dashboard.css"),
        asset_mtime("dashboard.js"),
    );
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], token).into_response()
}

/// The asset's mtime as nanos-since-epoch, or 0 if it can't be read.
fn asset_mtime(name: &str) -> u128 {
    std::fs::metadata(dist_path(name))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(index))
        .route("/fragment", get(fragment))
        .route("/assets/dashboard.css", get(dashboard_css))
        .route("/assets/dashboard.js", get(dashboard_js))
        .route("/dev/reload", get(dev_reload));

    let addr = "127.0.0.1:8787";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("dashboard preview (hot-reload) on http://{addr}/  (Ctrl-C to stop)");
    println!("  scenarios: /?scenario=clear | watching | breach | blind  (default: breach)");
    println!("  tabs:      /?tab=findings | action | readiness | admission  (default: findings)");
    println!(
        "  assets served from disk: {:?}",
        dist_path("dashboard.css")
    );
    axum::serve(listener, app).await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// Sample model prompt/reply + the dev-livereload client (example-only).
// ---------------------------------------------------------------------------------------------

/// The dev-only livereload client, appended to the served `dashboard.js`. It polls
/// `/dev/reload` ~once a second and reloads the page when the token changes. NEVER written to
/// the repo's `dashboard.js` — it lives only in the example's served response.
const DEV_LIVERELOAD_JS: &str = r#"
/* dashboard_preview dev-livereload — example-only, not part of dashboard.js */
(function () {
  var last = null;
  function poll() {
    fetch('/dev/reload', { cache: 'no-store' })
      .then(function (r) { return r.text(); })
      .then(function (token) {
        if (last === null) { last = token; return; }
        if (token !== last) { location.reload(); }
      })
      .catch(function () { /* server restarting — keep polling */ });
  }
  setInterval(poll, 1000);
  poll();
})();
"#;

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
