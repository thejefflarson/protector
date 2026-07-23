//! Integration tests for the LIVE-router OIDC enforcement (JEF-487 / ADR-0030 §6). They drive the
//! REAL `dashboard::router` with a configured [`Enforcer`] built over an in-memory JWKS (no egress,
//! via the JEF-485 `test_support` seam), and assert the content-negotiated fail-closed contract:
//! `/api/*.json` denials are `401` JSON and are NEVER `302`'d; a document `GET /` denial is a `302`
//! to login; a below-tier identity is `403`; JWKS-down is `503`; every rejection still carries the
//! strict CSP + `no-store`; and the unconfigured router (no enforcer) serves without rejecting.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use super::Verifier;
use super::claims::Tier;
use super::enforce::Enforcer;
use super::test_support::{
    KEY_A_N, KEY_A_PEM, KID_A, TestFetcher, base_claims, jwk_set, now, sign, test_config,
};
use crate::engine::dashboard::{AuthMode, DashboardState, router};
use crate::engine::journal::DecisionJournal;
use crate::engine::policy_log::PolicyDecisionLog;
use crate::engine::state::{Findings, JudgementLog, ReversionLog};

const LOGIN_URL: &str = "https://login.example/authorize";

/// A minimal, empty-but-honest dashboard state — enough to exercise the routes end-to-end.
fn empty_state(auth_mode: AuthMode) -> DashboardState {
    DashboardState {
        findings: Arc::new(Findings::new()),
        judgements: Arc::new(JudgementLog::new()),
        reversions: Arc::new(ReversionLog::new()),
        decision_journal: Arc::new(DecisionJournal::disabled()),
        policy_log: Arc::new(PolicyDecisionLog::new()),
        cluster: "prod-test".into(),
        auth_mode,
    }
}

/// An enforcer over an in-memory JWKS serving key-A, with the given minimum tier and a fixed login
/// redirect. Zero egress — the verifier fetches from the injected [`TestFetcher`].
fn enforcer(min_tier: Tier) -> Arc<Enforcer> {
    let fetcher = Arc::new(TestFetcher::new(jwk_set(&[(KID_A, KEY_A_N)])));
    let verifier = Verifier::with_fetcher(test_config(), fetcher);
    Arc::new(Enforcer::from_parts(verifier, LOGIN_URL.into(), min_tier))
}

/// An enforcer whose JWKS fetch always fails — the unreachable-IdP condition.
fn enforcer_jwks_down() -> Arc<Enforcer> {
    let verifier = Verifier::with_fetcher(test_config(), Arc::new(TestFetcher::failing()));
    Arc::new(Enforcer::from_parts(
        verifier,
        LOGIN_URL.into(),
        Tier::Redacted,
    ))
}

/// Send a request through the configured router and return the response.
async fn send(auth: Option<Arc<Enforcer>>, request: Request<Body>) -> axum::response::Response {
    router(empty_state(AuthMode::Oidc), auth)
        .oneshot(request)
        .await
        .unwrap()
}

/// A `GET` request with an optional bearer token and Accept header.
fn get(uri: &str, token: Option<&str>, accept: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(accept) = accept {
        builder = builder.header(header::ACCEPT, accept);
    }
    builder.body(Body::empty()).unwrap()
}

fn valid_token() -> String {
    sign(KEY_A_PEM, KID_A, &base_claims())
}

async fn body_string(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// -------------------------------------------------------------------------------------------------
// /api/*.json — 401 JSON, never a redirect. No token / tampered / expired.
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn api_findings_with_no_token_is_401_tiny_json_never_302() {
    let response = send(
        Some(enforcer(Tier::Redacted)),
        get("/api/findings.json", None, Some("application/json")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response.headers().get(header::LOCATION).is_none(),
        "an /api route is NEVER 302'd (a redirected fetch dies on connect-src 'self')"
    );
    // No graph data — a tiny body only (no strip, no findings, no stack).
    let body = body_string(response).await;
    assert_eq!(body, r#"{"error":"unauthenticated"}"#);
    assert!(
        !body.contains("strip"),
        "the 401 body carries no view-model"
    );
}

#[tokio::test]
async fn api_findings_with_tampered_token_is_401() {
    // Flip the first char of the signature segment — a deterministic signature mismatch.
    let token = valid_token();
    let mut segments: Vec<String> = token.split('.').map(String::from).collect();
    let sig = &segments[2];
    let first = sig.chars().next().unwrap();
    let replacement = if first == 'A' { 'B' } else { 'A' };
    segments[2] = format!("{replacement}{}", &sig[1..]);
    let tampered = segments.join(".");

    let response = send(
        Some(enforcer(Tier::Redacted)),
        get(
            "/api/findings.json",
            Some(&tampered),
            Some("application/json"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::LOCATION).is_none());
}

#[tokio::test]
async fn api_findings_with_expired_token_is_401() {
    let mut claims = base_claims();
    claims["nbf"] = serde_json::json!(now() - 7200);
    claims["exp"] = serde_json::json!(now() - 3600);
    let token = sign(KEY_A_PEM, KID_A, &claims);

    let response = send(
        Some(enforcer(Tier::Redacted)),
        get("/api/findings.json", Some(&token), Some("application/json")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_route_is_never_302_even_without_a_json_accept_header() {
    // The path prefix is authoritative: even with NO Accept header the `/api/` route is the JSON
    // class and a missing token is a 401, never a redirect.
    let response = send(
        Some(enforcer(Tier::Redacted)),
        get("/api/findings.json", None, None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::LOCATION).is_none());
}

// -------------------------------------------------------------------------------------------------
// Valid token — 200 with the view-model, and the honest server-derived auth-mode pill.
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn api_findings_with_valid_token_is_200_with_the_view_model_and_oidc_auth_mode() {
    let response = send(
        Some(enforcer(Tier::Redacted)),
        get(
            "/api/findings.json",
            Some(&valid_token()),
            Some("application/json"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body_string(response).await).unwrap();
    assert!(value.get("strip").is_some(), "a 200 serves the view-model");
    assert_eq!(
        value["strip"]["auth-mode"],
        serde_json::json!("oidc"),
        "the enforcing dashboard reports the honest oidc pill"
    );
}

// -------------------------------------------------------------------------------------------------
// Document GET / — 302 to login, never for /api.
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn document_root_with_no_token_is_302_to_login() {
    let response = send(
        Some(enforcer(Tier::Redacted)),
        get("/", None, Some("text/html,application/xhtml+xml")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        LOGIN_URL,
        "an unauthenticated browser navigation is redirected to login"
    );
}

// -------------------------------------------------------------------------------------------------
// 403 below the minimum tier; 503 JWKS-down.
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn valid_token_below_the_minimum_tier_is_403() {
    // The base token is tier `forensic`; require `raw` → the identity is verified but forbidden.
    let response = send(
        Some(enforcer(Tier::Raw)),
        get(
            "/api/findings.json",
            Some(&valid_token()),
            Some("application/json"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_string(response).await, r#"{"error":"forbidden"}"#);
}

#[tokio::test]
async fn jwks_unreachable_is_503_never_a_bypass() {
    let response = send(
        Some(enforcer_jwks_down()),
        get(
            "/api/findings.json",
            Some(&valid_token()),
            Some("application/json"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response.headers().get(header::LOCATION).is_none(),
        "a 503 is never a redirect and never serves the graph"
    );
}

// -------------------------------------------------------------------------------------------------
// The honesty guards compose WITH auth: CSP + no-store ride every rejection.
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_401_still_carries_the_strict_csp_and_no_store() {
    let response = send(
        Some(enforcer(Tier::Redacted)),
        get("/api/findings.json", None, Some("application/json")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let csp = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .expect("the CSP layer wraps the auth rejection too");
    assert!(
        csp.contains("connect-src 'self'"),
        "CSP rides the 401: {csp}"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store",
        "a cached 401/302 is the JEF-283 edge bug — every rejection is no-store"
    );
}

#[tokio::test]
async fn a_302_login_redirect_is_no_store() {
    let response = send(
        Some(enforcer(Tier::Redacted)),
        get("/", None, Some("text/html")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store",
        "a cached 302->login is exactly the Cloudflare edge bug (JEF-283)"
    );
}

// -------------------------------------------------------------------------------------------------
// Unconfigured (no enforcer) — serves without rejecting; the loud-WARN passthrough is in run_loop.
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn unconfigured_router_serves_without_rejecting() {
    // The config-absent path (None) must NOT reject — an unauthenticated request is served as today
    // (edge-trust only). This is the escape hatch that keeps an existing deploy from being locked
    // out on upgrade (ADR-0030 §6).
    let response = router(empty_state(AuthMode::EdgeOnly), None)
        .oneshot(get("/api/findings.json", None, Some("application/json")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body_string(response).await).unwrap();
    assert_eq!(
        value["strip"]["auth-mode"],
        serde_json::json!("edge-only"),
        "an unconfigured dashboard honestly reports edge-only"
    );
}
