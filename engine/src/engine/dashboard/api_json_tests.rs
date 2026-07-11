//! HTTP-level tests for the read-only per-view JSON endpoints (ADR-0025, JEF-395):
//! `GET /api/{findings,action,readiness,admission,alerts}.json`. They assert that each endpoint
//! serves the SAME view-model its tab renders (byte-for-byte the serialized props — no drift, no
//! second DTO), that it is GET-only (a write verb 405s — the view is never a gate), and that it
//! carries `Cache-Control: no-store` (the per-session-gated, zero-egress snapshot must never sit
//! in a shared edge cache — JEF-283). They drive the real axum router via `tower::oneshot`.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use tower::ServiceExt;

use super::DashboardState;
use crate::engine::journal::DecisionJournal;
use crate::engine::policy_log::PolicyDecisionLog;
use crate::engine::state::{Findings, JudgementLog, ReversionLog};

/// A minimal, empty-but-honest dashboard state — enough to exercise the routes end-to-end. The
/// findings handle has no completed pass, so the strip reads warming/blind (never a false green),
/// which is exactly the honest resting state to serve from an empty engine.
fn empty_state() -> DashboardState {
    DashboardState {
        findings: Arc::new(Findings::new()),
        judgements: Arc::new(JudgementLog::new()),
        reversions: Arc::new(ReversionLog::new()),
        decision_journal: Arc::new(DecisionJournal::disabled()),
        policy_log: Arc::new(PolicyDecisionLog::new()),
        cluster: "prod-test".into(),
    }
}

/// GET a route and return `(status, no_store, body_bytes)`.
async fn get(path: &str) -> (StatusCode, bool, Vec<u8>) {
    let router = super::router(empty_state());
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let no_store = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("no-store"))
        .unwrap_or(false);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();
    assert!(
        content_type.starts_with("application/json"),
        "{path} must be served as JSON, got {content_type:?}"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, no_store, body.to_vec())
}

#[tokio::test]
async fn every_endpoint_is_get_only_json_and_no_store() {
    for path in [
        "/api/findings.json",
        "/api/alerts.json",
        "/api/action.json",
        "/api/readiness.json",
        "/api/admission.json",
    ] {
        let (status, no_store, body) = get(path).await;
        assert_eq!(status, StatusCode::OK, "{path} should 200");
        assert!(no_store, "{path} must carry Cache-Control: no-store");
        // A valid JSON object body (the serialized view-model).
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(value.is_object(), "{path} returns a JSON object");
        assert!(
            value.get("strip").is_some(),
            "{path} nests the persistent strip"
        );
    }
}

#[tokio::test]
async fn a_write_verb_is_rejected_the_view_is_never_a_gate() {
    // POST to a JSON endpoint must not be routed (405) — there is no write route (ADR-0016).
    let router = super::router(empty_state());
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/findings.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "a write verb has no route — the JSON is read-only"
    );
}

#[tokio::test]
async fn each_endpoint_returns_the_same_view_model_its_tab_renders() {
    // The endpoint body must equal the serialization of the SAME builder the page route uses —
    // proof there is no parallel DTO and no drift (ADR-0025 decision (a)). The props derive only
    // `Serialize` (the wire is one-directional server→client), so compare on the JSON `Value`.
    let state = empty_state();

    let cases: [(&str, serde_json::Value); 5] = [
        (
            "/api/findings.json",
            serde_json::to_value(state.findings_view()).unwrap(),
        ),
        (
            "/api/alerts.json",
            serde_json::to_value(state.alerts_view()).unwrap(),
        ),
        (
            "/api/action.json",
            serde_json::to_value(state.action_view()).unwrap(),
        ),
        (
            "/api/readiness.json",
            serde_json::to_value(state.readiness_view()).unwrap(),
        ),
        (
            "/api/admission.json",
            serde_json::to_value(state.admission_view()).unwrap(),
        ),
    ];

    for (path, expected) in cases {
        let (_, _, body) = get(path).await;
        let from_endpoint: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            from_endpoint, expected,
            "{path} must serve the same view-model the tab renders (no drift, no second DTO)"
        );
    }
}

#[tokio::test]
async fn an_empty_engine_never_serves_a_false_green() {
    // The honesty invariant at the JSON boundary: with no completed pass, the served strip is
    // never all-clear (ADR-0025 / ADR-0016 — calm-when-blind).
    let (_, _, body) = get("/api/findings.json").await;
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value["strip"]["all-clear"],
        serde_json::json!(false),
        "a warming/blind engine must not ship the green token"
    );
}
