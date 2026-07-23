//! Tests for the read-only MCP server (ADR-0031 / JEF-488): the tier clamp, the per-entry tiered
//! redaction (redacted/forensic/raw), the withheld-not-omitted contract, the audit seam, the
//! exactly-four tool surface, and the rmcp-behind-the-verifier compose spike (unauthenticated →
//! 401 on the same path as `/api`; a verified identity reaches the handler via a request extension).

use std::sync::Arc;

use serde_json::{Map, Value};

use crate::engine::dashboard::auth::claims::Tier;
use crate::engine::graph::attack::CREDENTIAL_ACCESS;
use crate::engine::policy_log::PolicyDecisionLog;
use crate::engine::reason::adjudicate::Verdict;
use crate::engine::state::{
    CveEvidence, EntryEvidence, Finding, Findings, Judgement, JudgementLog, PathStep,
};

use super::audit::RecordingAuditSink;
use super::dispatch::dispatch;
use super::render::{self, EntryData};
use super::server::ProtectorMcp;
use super::state::McpState;
use super::tiering::{EffectiveTier, parse_requested_tier};
use super::tools;

// ---- fixtures -------------------------------------------------------------------------------

const ENTRY: &str = "workload/shop/Deployment/storefront";
const SECRET_OBJECTIVE: &str = "secret/shop/db-password";
const SECRET_NAME: &str = "db-password";
const CVE: &str = "CVE-2021-44228";

/// A breach-relevant finding whose objective is a SECRET (the crown-jewel name), whose evidence
/// carries a CVE, and whose verdict prose names both — so a redaction test can assert each tier's
/// disclosure precisely.
fn secret_finding() -> Finding {
    Finding {
        entry: ENTRY.to_string(),
        objective: SECRET_OBJECTIVE.to_string(),
        attack: CREDENTIAL_ACCESS,
        foothold: true,
        corroborated: false,
        disposition: "auto-eligible".into(),
        cut: None,
        breach_relevant: true,
        verdict: Some(Verdict::Exploitable(format!(
            "the storefront reaches {SECRET_NAME} via {CVE}"
        ))),
        path: vec![PathStep {
            from: ENTRY.to_string(),
            relation: "reaches/Tcp/5432".into(),
            to: SECRET_OBJECTIVE.to_string(),
        }],
        paths: vec![],
        paths_truncated: false,
        evidence: EntryEvidence {
            cves: vec![CveEvidence {
                id: CVE.to_string(),
                severity: "critical".into(),
                score: Some("10.0".into()),
                kev: true,
                epss: Some("97%".into()),
                reachability: "loaded-at-runtime".into(),
                fix: "fix available: 2.17.0".into(),
                title: Some("Log4Shell".into()),
            }],
            ..EntryEvidence::default()
        },
        recency: None,
        node: None,
    }
}

/// The verbatim judgement for the entry, naming the secret + the CVE in its prompt/reply.
fn secret_judgement() -> Judgement {
    Judgement {
        entry: ENTRY.to_string(),
        objectives: 1,
        verdict: "exploitable".into(),
        prompt: Some(format!(
            "does storefront reach {SECRET_NAME}? evidence: {CVE}"
        )),
        reply: Some(format!("yes — {SECRET_NAME} is reachable")),
    }
}

/// An [`McpState`] over one secret-bearing finding + its judgement (empty admission log).
fn state_with_secret() -> McpState {
    let findings = Findings::new();
    findings.replace(vec![secret_finding()]);
    let judgements = JudgementLog::new();
    judgements.record(secret_judgement());
    McpState {
        findings: Arc::new(findings),
        judgements: Arc::new(judgements),
        policy_log: Arc::new(PolicyDecisionLog::new()),
        cluster: "prod-eu".into(),
    }
}

/// Render one entry's finding at a tier and return the response as a flat JSON string (so `contains`
/// assertions cover every nested field).
fn rendered(tier: EffectiveTier) -> String {
    let f = secret_finding();
    let group = [&f];
    let j = secret_judgement();
    let data = EntryData::from_group(ENTRY, &group, Some(&j), false);
    data.render(tier).to_string()
}

// ---- tier clamp -----------------------------------------------------------------------------

#[test]
fn clamp_never_widens_past_the_ceiling() {
    // A redacted-ceiling token CANNOT get forensic/raw by asking — the arg only narrows.
    assert_eq!(
        EffectiveTier::clamp(Some(Tier::Raw), Tier::Redacted),
        EffectiveTier::Redacted
    );
    assert_eq!(
        EffectiveTier::clamp(Some(Tier::Forensic), Tier::Redacted),
        EffectiveTier::Redacted
    );
    // A forensic-ceiling token can be narrowed to redacted, but not widened to raw.
    assert_eq!(
        EffectiveTier::clamp(Some(Tier::Redacted), Tier::Forensic),
        EffectiveTier::Redacted
    );
    assert_eq!(
        EffectiveTier::clamp(Some(Tier::Raw), Tier::Forensic),
        EffectiveTier::Forensic
    );
    // Absent request → served exactly the granted ceiling.
    assert_eq!(EffectiveTier::clamp(None, Tier::Raw), EffectiveTier::Raw);
    assert_eq!(
        EffectiveTier::clamp(None, Tier::Redacted),
        EffectiveTier::Redacted
    );
}

#[test]
fn bulk_tools_cap_at_forensic_even_with_a_raw_ceiling() {
    // The per-tool cap: a raw-ceiling token clamped to raw is still capped to forensic for a BULK
    // listing — secret names are never emitted in bulk (per-entry only, ADR-0031 acceptance).
    let raw = EffectiveTier::clamp(None, Tier::Raw);
    assert_eq!(
        raw.capped_at(EffectiveTier::Forensic),
        EffectiveTier::Forensic
    );
}

#[test]
fn parse_requested_tier_reads_the_three_tiers_and_floors_garbage() {
    assert_eq!(parse_requested_tier(Some("raw")), Some(Tier::Raw));
    assert_eq!(parse_requested_tier(Some("Forensic")), Some(Tier::Forensic));
    assert_eq!(parse_requested_tier(Some("  ")), None);
    assert_eq!(parse_requested_tier(None), None);
    // A garbage label floors to Redacted (it can never widen past the ceiling anyway).
    assert_eq!(parse_requested_tier(Some("root")), Some(Tier::Redacted));
}

// ---- per-entry tiered redaction -------------------------------------------------------------

#[test]
fn redacted_tier_leaks_no_secret_name_cve_or_path() {
    let out = rendered(EffectiveTier::Redacted);
    assert!(
        !out.contains(SECRET_NAME),
        "redacted must not leak a secret name: {out}"
    );
    assert!(!out.contains(CVE), "redacted must not leak a CVE id: {out}");
    assert!(
        !out.contains(ENTRY),
        "redacted must not leak the entry path: {out}"
    );
    assert!(
        !out.contains("shop"),
        "redacted must not leak topology/namespace: {out}"
    );
    assert!(
        !out.contains("storefront"),
        "redacted must not leak the workload name the verdict prose echoes: {out}"
    );
    // But it is NOT an empty shape: the verdict label, an objective COUNT, the technique ID, and the
    // sentinels are all present (withheld ≠ omitted).
    assert!(out.contains("exploitable"), "verdict label present: {out}");
    assert!(
        out.contains("\"objective_count\":1"),
        "objective count present: {out}"
    );
    assert!(
        out.contains(CREDENTIAL_ACCESS.technique_id),
        "technique id present: {out}"
    );
    assert!(
        out.contains("forensic tier required"),
        "sentinels present: {out}"
    );
}

#[test]
fn redacted_tier_withholds_the_free_text_verdict_reason_topology() {
    // The judge model's free-text `why` routinely echoes the entry/namespace/peer/path it reasoned
    // over — topology the shared scrubbers CANNOT strip (they only remove SECRET names + CVE
    // tokens). So the reason is WITHHELD below forensic; only the static label survives at redacted.
    let mut f = secret_finding();
    f.objective = "secret/edge/vault-token".into();
    f.verdict = Some(Verdict::Exploitable(
        "the argocd-server pod in edge is internet-facing and reaches secret/edge/vault-token"
            .into(),
    ));
    let group = [&f];
    let redacted = EntryData::from_group(ENTRY, &group, None, false)
        .render(EffectiveTier::Redacted)
        .to_string();
    // None of the model-echoed topology leaks at the default tier.
    for topology in [
        "argocd-server",
        "vault-token",
        "secret/edge",
        "internet-facing",
    ] {
        assert!(
            !redacted.contains(topology),
            "redacted must not leak model-echoed topology `{topology}`: {redacted}"
        );
    }
    // `edge` only appears inside the withheld path/entry sentinels here, never the reason — the
    // reason itself is a sentinel, and the static label still rides along.
    assert!(
        redacted.contains("verdict reason; forensic tier required"),
        "the reason is a typed sentinel: {redacted}"
    );
    assert!(
        redacted.contains("exploitable"),
        "the static label survives: {redacted}"
    );

    // At forensic (where paths/topology are already disclosed) the reason text IS present — only the
    // secret NAME within it is scrubbed.
    let forensic = EntryData::from_group(ENTRY, &group, None, false)
        .render(EffectiveTier::Forensic)
        .to_string();
    assert!(
        forensic.contains("argocd-server pod in edge is internet-facing"),
        "forensic reveals the reason prose: {forensic}"
    );
    assert!(
        !forensic.contains("vault-token"),
        "forensic still scrubs the secret name inside the reason: {forensic}"
    );
}

#[test]
fn forensic_tier_adds_cve_paths_and_prompt_but_still_scrubs_secret_names() {
    let out = rendered(EffectiveTier::Forensic);
    // Forensic unlocks the CVE id, the entry/path topology, and the judgement prompt+reply...
    assert!(out.contains(CVE), "forensic reveals the CVE id: {out}");
    assert!(
        out.contains(ENTRY) || out.contains("storefront"),
        "forensic reveals the path: {out}"
    );
    assert!(
        out.contains("does storefront reach"),
        "forensic reveals the prompt: {out}"
    );
    // ...but the SECRET NAME is still scrubbed at forensic.
    assert!(
        !out.contains(SECRET_NAME),
        "forensic must STILL scrub the secret name: {out}"
    );
    assert!(
        out.contains("[redacted]"),
        "the scrubbed secret leaves a marker: {out}"
    );
}

#[test]
fn raw_tier_adds_secret_names_but_never_a_value() {
    let out = rendered(EffectiveTier::Raw);
    assert!(
        out.contains(SECRET_NAME),
        "raw reveals the secret NAME: {out}"
    );
    assert!(out.contains(CVE), "raw still carries the CVE id: {out}");
    // There is no secret VALUE anywhere — the fixture never carries one, and no field reads one.
    // The top-level manifest records that values are never disclosed (no unlock tier).
    let f = secret_finding();
    let group = [&f];
    let data = EntryData::from_group(ENTRY, &group, None, false);
    let withheld = render::withheld_for(std::slice::from_ref(&data), EffectiveTier::Raw);
    let manifest = render::manifest(EffectiveTier::Raw, &withheld).to_string();
    assert!(
        manifest.contains("\"secret_values\""),
        "manifest names secret_values: {manifest}"
    );
    assert!(
        manifest.contains("\"unlock\":\"never\""),
        "values have no unlock tier: {manifest}"
    );
}

#[test]
fn every_response_carries_a_redaction_manifest() {
    let f = secret_finding();
    let group = [&f];
    let data = EntryData::from_group(ENTRY, &group, None, false);
    for tier in [
        EffectiveTier::Redacted,
        EffectiveTier::Forensic,
        EffectiveTier::Raw,
    ] {
        let withheld = render::withheld_for(std::slice::from_ref(&data), tier);
        let manifest = render::manifest(tier, &withheld);
        assert_eq!(manifest["tier"], tier.as_str());
        assert!(manifest["withheld"].is_array(), "withheld is a typed list");
    }
}

// ---- dispatch: clamp + audit through the trust core -----------------------------------------

#[test]
fn list_findings_redacted_ceiling_never_dumps_secret_names() {
    let state = state_with_secret();
    let sink = RecordingAuditSink::default();
    let out = dispatch(
        &state,
        &sink,
        "user@example.com",
        tools::LIST_FINDINGS,
        None,
        Tier::Redacted,
    )
    .expect("list_findings");
    let text = out.to_string();
    assert!(
        !text.contains(SECRET_NAME),
        "redacted list leaks no secret name: {text}"
    );
    assert!(!text.contains(CVE), "redacted list leaks no CVE: {text}");
    // A redacted response discloses nothing cluster-specific → no audit line.
    assert!(
        sink.records().is_empty(),
        "redacted access is NOT journaled"
    );
}

#[test]
fn list_findings_with_raw_ceiling_is_still_capped_to_forensic() {
    // The "no dump-all-at-raw" guarantee: even a raw-granted token gets at most forensic detail from
    // the BULK list — the secret name never appears there.
    let state = state_with_secret();
    let sink = RecordingAuditSink::default();
    let out = dispatch(
        &state,
        &sink,
        "root@example.com",
        tools::LIST_FINDINGS,
        None,
        Tier::Raw,
    )
    .expect("list_findings");
    let text = out.to_string();
    assert!(
        !text.contains(SECRET_NAME),
        "bulk list must never emit a secret name: {text}"
    );
    // Forensic-level disclosure (CVE/paths) IS journaled.
    let records = sink.records();
    assert_eq!(
        records.len(),
        1,
        "a forensic bulk disclosure is journaled once"
    );
    assert_eq!(records[0].tier, EffectiveTier::Forensic);
    assert_eq!(records[0].tool, tools::LIST_FINDINGS);
}

#[test]
fn explain_verdict_raw_reveals_the_secret_name_and_journals_the_access() {
    let state = state_with_secret();
    let sink = RecordingAuditSink::default();
    let mut args = Map::new();
    args.insert("entry".into(), Value::String(ENTRY.into()));
    args.insert("tier".into(), Value::String("raw".into()));
    let out = dispatch(
        &state,
        &sink,
        "alice@corp.example",
        tools::EXPLAIN_VERDICT,
        Some(&args),
        Tier::Raw,
    )
    .expect("explain_verdict");
    let text = out.to_string();
    assert!(
        text.contains(SECRET_NAME),
        "raw explain reveals the secret name: {text}"
    );

    // The access emits an audit record: subject · entry · tool · tier · time.
    let records = sink.records();
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r.subject, "alice@corp.example");
    assert_eq!(r.entry, ENTRY);
    assert_eq!(r.tool, tools::EXPLAIN_VERDICT);
    assert_eq!(r.tier, EffectiveTier::Raw);
    assert!(r.time_unix_secs > 0);
}

#[test]
fn explain_verdict_clamps_a_redacted_token_that_asks_for_raw() {
    // A redacted-ceiling token requesting raw is clamped — the secret name stays withheld, and the
    // access is NOT journaled (redacted discloses nothing cluster-specific).
    let state = state_with_secret();
    let sink = RecordingAuditSink::default();
    let mut args = Map::new();
    args.insert("entry".into(), Value::String(ENTRY.into()));
    args.insert("tier".into(), Value::String("raw".into()));
    let out = dispatch(
        &state,
        &sink,
        "eve@corp.example",
        tools::EXPLAIN_VERDICT,
        Some(&args),
        Tier::Redacted,
    )
    .expect("explain_verdict");
    let text = out.to_string();
    assert!(
        !text.contains(SECRET_NAME),
        "a clamped redacted token gets no secret name: {text}"
    );
    assert!(
        sink.records().is_empty(),
        "a clamped-to-redacted access is not journaled"
    );
}

#[test]
fn the_durable_access_sink_records_exactly_one_line_for_a_raw_pull_and_none_for_redacted() {
    // JEF-490: the same subject·entry·tool·tier·time contract, proven through the DURABLE sink the
    // "Access" tab reads (not just the test RecordingAuditSink) — a raw pull appends one line, a
    // redacted pull appends none.
    use crate::engine::mcp::access_audit::AccessAuditSink;

    let state = state_with_secret();

    // A redacted pull discloses nothing cluster-specific → NO audit line.
    let redacted_sink = AccessAuditSink::in_memory();
    dispatch(
        &state,
        &redacted_sink,
        "eve@corp.example",
        tools::LIST_FINDINGS,
        None,
        Tier::Redacted,
    )
    .expect("list_findings");
    assert!(
        redacted_sink.records().is_empty(),
        "a redacted pull is NOT audited by the durable sink"
    );

    // A raw explain_verdict IS audited — exactly one line, carrying the verified subject + entry.
    let raw_sink = AccessAuditSink::in_memory();
    let mut args = Map::new();
    args.insert("entry".into(), Value::String(ENTRY.into()));
    args.insert("tier".into(), Value::String("raw".into()));
    dispatch(
        &state,
        &raw_sink,
        "alice@corp.example",
        tools::EXPLAIN_VERDICT,
        Some(&args),
        Tier::Raw,
    )
    .expect("explain_verdict");
    let records = raw_sink.records();
    assert_eq!(records.len(), 1, "a raw pull appends exactly one line");
    assert_eq!(records[0].subject, "alice@corp.example");
    assert_eq!(records[0].entry, ENTRY);
    assert_eq!(records[0].tool, tools::EXPLAIN_VERDICT);
    assert_eq!(records[0].tier, EffectiveTier::Raw);
}

#[test]
fn explain_verdict_accepts_the_opaque_ref_and_rejects_an_unknown_entry() {
    let state = state_with_secret();
    let sink = RecordingAuditSink::default();
    // The opaque ref from list_findings resolves to the same entry (never an index into arbitrary
    // state).
    let mut by_ref = Map::new();
    by_ref.insert("entry".into(), Value::String(render::entry_ref(ENTRY)));
    assert!(
        dispatch(
            &state,
            &sink,
            "s",
            tools::EXPLAIN_VERDICT,
            Some(&by_ref),
            Tier::Redacted
        )
        .is_ok(),
        "the opaque ref is a valid handle"
    );
    // An unknown entry is rejected, never served.
    let mut bad = Map::new();
    bad.insert(
        "entry".into(),
        Value::String("workload/evil/../etc/passwd".into()),
    );
    assert_eq!(
        dispatch(
            &state,
            &sink,
            "s",
            tools::EXPLAIN_VERDICT,
            Some(&bad),
            Tier::Raw
        ),
        Err(tools::ToolError::UnknownEntry)
    );
}

#[test]
fn get_coverage_and_signing_inventory_are_read_only_and_tier_aware() {
    let state = state_with_secret();
    let sink = RecordingAuditSink::default();
    let cov = dispatch(
        &state,
        &sink,
        "s",
        tools::GET_COVERAGE,
        None,
        Tier::Redacted,
    )
    .expect("coverage");
    assert!(cov["redaction"]["tier"] == "redacted");
    let sign = dispatch(
        &state,
        &sink,
        "s",
        tools::SIGNING_INVENTORY,
        None,
        Tier::Redacted,
    )
    .expect("signing");
    assert!(
        sign["images"].is_string(),
        "redacted signing hides image refs behind a sentinel"
    );
}

// ---- the four-tool surface (no actuation) ---------------------------------------------------

#[test]
fn the_tool_surface_is_exactly_the_four_reads_with_no_actuation_tool() {
    let names: Vec<String> = ProtectorMcp::tool_descriptors()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(
        names,
        vec![
            tools::LIST_FINDINGS,
            tools::EXPLAIN_VERDICT,
            tools::GET_COVERAGE,
            tools::SIGNING_INVENTORY,
        ],
        "the surface is EXACTLY the four reads"
    );
    assert_eq!(names.len(), tools::TOOL_NAMES.len());
    // No actuation verb is present by construction — there is no mutate/actuate tool to withhold.
    for forbidden in [
        "isolate",
        "arm",
        "quarantine",
        "patch",
        "apply",
        "revert",
        "cut",
        "delete",
    ] {
        assert!(
            !names.iter().any(|n| n.contains(forbidden)),
            "no actuation tool `{forbidden}` may exist"
        );
    }
    // An unknown tool name is rejected by the dispatcher (fail-closed routing).
    let state = state_with_secret();
    let sink = RecordingAuditSink::default();
    assert_eq!(
        dispatch(&state, &sink, "s", "isolate", None, Tier::Raw),
        Err(tools::ToolError::UnknownTool)
    );
}

// ---- rmcp behind the verifier: the compose spike --------------------------------------------

mod transport {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::extract::Extension;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use tower::ServiceExt; // oneshot

    use crate::engine::dashboard::auth::Identity;
    use crate::engine::dashboard::auth::test_support::{
        KEY_A_PEM, KID_A, base_claims, sign, verifier_with_key_a,
    };
    use crate::engine::mcp::audit::TracingAuditSink;
    use crate::engine::mcp::transport::{MCP_PATH, WELL_KNOWN_PATH, mcp_auth};

    fn valid_token() -> String {
        sign(KEY_A_PEM, KID_A, &base_claims())
    }

    #[tokio::test]
    async fn an_unauthenticated_mcp_call_is_401_on_the_same_path_as_api() {
        let (verifier, _fetcher) = verifier_with_key_a();
        let router = crate::engine::mcp::transport::router(
            super::state_with_secret(),
            Arc::new(verifier),
            Arc::new(TracingAuditSink),
        );
        let request = Request::builder()
            .method("POST")
            .uri(MCP_PATH)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            ))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        // Rejected by OUR verifier layer before rmcp is ever reached — the same fail-closed 401 as
        // `/api`, with the ID-JAG WWW-Authenticate challenge.
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            response.headers().contains_key(header::WWW_AUTHENTICATE),
            "the 401 carries the ID-JAG challenge"
        );
    }

    #[tokio::test]
    async fn an_oversize_request_body_is_rejected_before_auth_or_parse() {
        // The DoS/OOM guard: the body-limit layer is OUTERMOST, so a multi-GB body is rejected with
        // 413 before it is ever verified or parsed — a token-holder (even redacted tier) cannot OOM
        // the engine process. (Timeout + concurrency bounds are wired alongside; see `router`.)
        let (verifier, _fetcher) = verifier_with_key_a();
        let router = crate::engine::mcp::transport::router(
            super::state_with_secret(),
            Arc::new(verifier),
            Arc::new(TracingAuditSink),
        );
        let oversize = vec![b'x'; 512 * 1024]; // > the 256 KiB cap
        let request = Request::builder()
            .method("POST")
            .uri(MCP_PATH)
            .header(header::AUTHORIZATION, format!("Bearer {}", valid_token()))
            .header(header::CONTENT_TYPE, "application/json")
            // A real large POST advertises its length; the limit layer rejects it up front (413).
            .header(header::CONTENT_LENGTH, oversize.len())
            .body(Body::from(oversize))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // A normal small body still passes the limit (and reaches rmcp — not a 413).
        let ok = crate::engine::mcp::transport::router(
            super::state_with_secret(),
            Arc::new(verifier_with_key_a().0),
            Arc::new(TracingAuditSink),
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(MCP_PATH)
                .header(header::AUTHORIZATION, format!("Bearer {}", valid_token()))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_ne!(ok.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn a_valid_token_passes_the_verifier_and_reaches_rmcp() {
        let (verifier, _fetcher) = verifier_with_key_a();
        let router = crate::engine::mcp::transport::router(
            super::state_with_secret(),
            Arc::new(verifier),
            Arc::new(TracingAuditSink),
        );
        let request = Request::builder()
            .method("POST")
            .uri(MCP_PATH)
            .header(header::AUTHORIZATION, format!("Bearer {}", valid_token()))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
            ))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        // The verifier passed it through to rmcp: whatever rmcp answers, it is NOT our 401/403.
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn well_known_discovery_is_unauthenticated_and_names_the_issuer() {
        let (verifier, _fetcher) = verifier_with_key_a();
        let issuer = verifier.config().issuer.clone();
        let router = crate::engine::mcp::transport::router(
            super::state_with_secret(),
            Arc::new(verifier),
            Arc::new(TracingAuditSink),
        );
        let request = Request::builder()
            .method("GET")
            .uri(WELL_KNOWN_PATH)
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            text.contains(&issuer),
            "discovery advertises the authorization server: {text}"
        );
    }

    /// The identity the auth layer sets on a verified request reaches the downstream handler through
    /// a request extension — exactly the mechanism rmcp reads (`Parts.extensions`). A probe handler
    /// behind [`mcp_auth`] reads the [`Identity`] extension and echoes the resolved tier.
    #[tokio::test]
    async fn a_verified_identity_reaches_the_handler_via_a_request_extension() {
        async fn probe(Extension(identity): Extension<Identity>) -> String {
            format!("{:?}", identity.tier)
        }
        let (verifier, _fetcher) = verifier_with_key_a();
        let app =
            Router::new()
                .route("/probe", get(probe))
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(verifier),
                    mcp_auth,
                ));
        let request = Request::builder()
            .method("GET")
            .uri("/probe")
            .header(header::AUTHORIZATION, format!("Bearer {}", valid_token()))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        // `base_claims()` grants the `forensic` tier — the handler saw the verified identity.
        assert_eq!(String::from_utf8(body.to_vec()).unwrap(), "Forensic");
    }
}
