//! Shared sample handles, journal/policy-log seeding, and bake/readiness fixtures reused across
//! preview scenarios.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use protector::engine::journal::{Decision, DecisionJournal, EnrichmentCoverage};
use protector::engine::policy_log::{PolicyDecisionLog, PolicyDecisionRecord};
use protector::engine::state::{BakeStats, Findings, JudgementLog, ReadinessConfig, ReversionLog};

/// Fresh shared handles for one scenario render. Cheap; rebuilt per request so each scenario
/// renders from clean state. The decision journal is disabled by default (empty Trust report);
/// scenarios that want a populated would-have-acted diff swap in a [`sample_journal`].
pub(crate) fn fresh_handles() -> (
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
pub(crate) fn sample_journal() -> Arc<DecisionJournal> {
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
pub(crate) fn sample_policy_log() -> Arc<PolicyDecisionLog> {
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
pub(crate) fn covered_bake() -> BakeStats {
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
pub(crate) fn covered_config(model_attached: bool) -> ReadinessConfig {
    ReadinessConfig {
        model_attached,
        kev_count: 1342,
        epss_count: 241_000,
        journal_durable: true,
        armed: false,                          // shadow — the safe default (ADR-0016).
        tuf_cache_age_secs: Some(3 * 60 * 60), // a fresh trust root (3h old).
        unverifiable_spike: false,
        checking_images: 0, // verification completing — nothing stuck checking.
    }
}
