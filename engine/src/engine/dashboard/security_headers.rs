//! The dashboard's strict same-origin Content-Security-Policy (ADR-0025).
//!
//! The dashboard is a bundled Preact client that reconciles from same-origin, read-only
//! JSON. Under ADR-0025 the served bundle runs under a strict CSP that pins every fetchable
//! origin to `'self'`: no CDN, no third-party script/style/connect, and — because Preact
//! needs no `eval` — **no `'unsafe-eval'`**. This is the net-new header the v4 rewrite adds
//! (there was no CSP before); it makes the zero-egress / no-CDN invariant a browser-enforced
//! guarantee, not just a build-time property of the bundle.
//!
//! It is a single response-header middleware applied to the whole dashboard router, kept in
//! its own module so it composes cleanly with routes other work adds (e.g. the `/api/*.json`
//! snapshot endpoints) — the layer covers every route without touching their definitions.

use axum::body::Body;
use axum::http::{HeaderValue, Request, header};
use axum::middleware::Next;
use axum::response::Response;

/// The strict same-origin policy. Every fetchable directive is `'self'`; `object-src` and
/// `base-uri` are locked to `'none'`. `frame-ancestors 'none'` forbids embedding the operator
/// dashboard in any frame and `form-action 'self'` pins form targets same-origin — together
/// they close the clickjacking / UI-redress gap that `default-src` does NOT cover (framing and
/// form submission are governed by their own directives, not `default-src`). No `'unsafe-inline'`
/// (every visual is a STYLEGUIDE class, ADR-0019 §5 / ADR-0025) and no `'unsafe-eval'` (Preact
/// runs without it).
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
     style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; \
     frame-ancestors 'none'; form-action 'self'";

/// Middleware that stamps the strict CSP on every dashboard response. Applied as a router
/// `.layer(...)`, so it covers the pages, the assets, and any JSON snapshot route uniformly.
///
/// Alongside the CSP `frame-ancestors 'none'`, we also stamp the legacy `X-Frame-Options: DENY`
/// so anti-framing holds on any client that predates CSP `frame-ancestors` support.
pub async fn set_csp(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    response
        .headers_mut()
        .insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use tower::ServiceExt;

    /// Every directive the ADR-0025 strict policy names, so a future edit can't silently drop
    /// one (e.g. loosen `script-src` or add `'unsafe-eval'`) without failing this test.
    #[test]
    fn the_policy_pins_every_origin_to_self_with_no_unsafe_escape_hatch() {
        let csp = CONTENT_SECURITY_POLICY;
        for directive in [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            // Anti-clickjacking / UI-redress: `default-src` does not cover framing or form
            // submission, so these must be named explicitly (and must not silently regress).
            "frame-ancestors 'none'",
            "form-action 'self'",
        ] {
            assert!(
                csp.contains(directive),
                "CSP must contain `{directive}` — got: {csp}"
            );
        }
        // Preact needs no eval, and every visual is a class — so neither unsafe escape hatch
        // may appear (they would defeat the point of the strict policy).
        assert!(
            !csp.contains("unsafe-eval"),
            "CSP must not allow 'unsafe-eval'"
        );
        assert!(
            !csp.contains("unsafe-inline"),
            "CSP must not allow 'unsafe-inline'"
        );
        // No off-origin scheme anywhere (no CDN, no third-party origin).
        assert!(
            !csp.contains("http://") && !csp.contains("https://"),
            "CSP names no off-origin"
        );
    }

    #[tokio::test]
    async fn the_layer_stamps_the_csp_on_a_response() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(set_csp));
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let header = response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .expect("the CSP header is present on every dashboard response")
            .to_str()
            .unwrap();
        assert_eq!(header, CONTENT_SECURITY_POLICY);
        // Belt-and-suspenders anti-framing for pre-`frame-ancestors` clients.
        assert_eq!(
            response
                .headers()
                .get(header::X_FRAME_OPTIONS)
                .expect("X-Frame-Options is present")
                .to_str()
                .unwrap(),
            "DENY"
        );
    }
}
