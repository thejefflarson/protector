use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::post;
use tower::ServiceExt; // for `oneshot`

use super::*;

/// A minimal router that mirrors how the real ingest wires the bearer layer: a POST
/// handler behind `bearer_auth` carrying the configured token as state.
fn auth_router(token: IngestToken) -> Router {
    Router::new()
        .route("/behavior", post(|| async { StatusCode::OK }))
        .layer(axum::middleware::from_fn_with_state(token, bearer_auth))
}

fn post_with_auth(auth: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("POST").uri("/behavior");
    if let Some(value) = auth {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn correct_bearer_is_accepted() {
    let app = auth_router(IngestToken::from_literal("s3cr3t"));
    let resp = app
        .oneshot(post_with_auth(Some("Bearer s3cr3t")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn missing_bearer_is_rejected_401() {
    let app = auth_router(IngestToken::from_literal("s3cr3t"));
    let resp = app.oneshot(post_with_auth(None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer"
    );
}

#[tokio::test]
async fn wrong_bearer_is_rejected_401() {
    let app = auth_router(IngestToken::from_literal("s3cr3t"));
    let resp = app
        .oneshot(post_with_auth(Some("Bearer wrong")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_authorization_header_is_rejected_401() {
    let app = auth_router(IngestToken::from_literal("s3cr3t"));
    // No "Bearer " scheme prefix.
    let resp = app.oneshot(post_with_auth(Some("s3cr3t"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn matches_is_length_aware_and_value_exact() {
    let token = IngestToken::from_literal("correct-horse");
    assert!(token.matches("correct-horse"));
    assert!(!token.matches("correct-hors")); // shorter
    assert!(!token.matches("correct-horsee")); // longer
    assert!(!token.matches("incorrect-hor")); // same length, different bytes
}

#[test]
fn extract_bearer_handles_both_cases_and_whitespace() {
    let req = |h: &str| {
        Request::builder()
            .header(header::AUTHORIZATION, h)
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(extract_bearer(&req("Bearer abc")), Some("abc"));
    assert_eq!(extract_bearer(&req("bearer abc")), Some("abc"));
    assert_eq!(extract_bearer(&req("Bearer   abc  ")), Some("abc"));
    assert_eq!(extract_bearer(&req("Bearer ")), None);
    assert_eq!(extract_bearer(&req("Basic abc")), None);
}

#[test]
fn from_env_reads_file_before_inline_value() {
    // File takes precedence over the inline env var, and a trailing newline (the
    // usual secret-file artifact) is trimmed.
    let dir = std::env::temp_dir().join(format!("protector-ingest-tok-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("token");
    std::fs::write(&path, "file-token\n").unwrap();

    // SAFETY: single-threaded test; we set + clear these vars within this test only.
    unsafe {
        std::env::set_var("PROTECTOR_INGEST_TOKEN_FILE", &path);
        std::env::set_var("PROTECTOR_INGEST_TOKEN", "inline-token");
    }
    let token = IngestToken::from_env().expect("file token resolves");
    assert!(
        token.matches("file-token"),
        "file value wins and is trimmed"
    );

    unsafe {
        std::env::remove_var("PROTECTOR_INGEST_TOKEN_FILE");
    }
    let token = IngestToken::from_env().expect("inline token resolves");
    assert!(token.matches("inline-token"));

    unsafe {
        std::env::remove_var("PROTECTOR_INGEST_TOKEN");
    }
    assert!(
        IngestToken::from_env().is_none(),
        "no token configured -> None"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rate_limit_allows_burst_then_throttles_then_refills() {
    // 2 tokens of burst, refilling at 1/sec.
    let limiter = RateLimit::new(1.0, 2.0);
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let t0 = Instant::now();

    // The burst is spendable immediately.
    assert!(limiter.allow(peer, t0));
    assert!(limiter.allow(peer, t0));
    // Third request in the same instant is over the limit.
    assert!(!limiter.allow(peer, t0));

    // After 1s a single token has refilled.
    let t1 = t0 + Duration::from_secs(1);
    assert!(limiter.allow(peer, t1));
    assert!(!limiter.allow(peer, t1));
}

#[test]
fn rate_limit_is_per_peer() {
    let limiter = RateLimit::new(1.0, 1.0);
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let now = Instant::now();
    // Each peer has its own bucket — exhausting A doesn't affect B.
    assert!(limiter.allow(a, now));
    assert!(!limiter.allow(a, now));
    assert!(limiter.allow(b, now));
}

/// The rate-limit middleware rejects an over-limit peer with 429 (a burst of 1).
#[tokio::test]
async fn rate_limit_middleware_returns_429_over_limit() {
    let limiter = RateLimit::new(0.0, 1.0); // 1 token, no refill
    let app = Router::new()
        .route("/behavior", post(|| async { StatusCode::OK }))
        .layer(axum::middleware::from_fn_with_state(limiter, rate_limit));

    let peer: SocketAddr = "10.0.0.9:1234".parse().unwrap();
    let make = || {
        let mut req = Request::builder()
            .method("POST")
            .uri("/behavior")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        req
    };

    let first = app.clone().oneshot(make()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let second = app.oneshot(make()).await.unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}
