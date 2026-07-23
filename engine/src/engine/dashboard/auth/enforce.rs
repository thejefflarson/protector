//! Content-negotiating enforcement (JEF-487, ADR-0030 §6): mounts the JEF-485 [`Verifier`] as the
//! LIVE dashboard access gate and shapes every fail-closed denial by **route class**, so the client
//! contract holds:
//!
//! - a **document** request (`GET /`, a browser navigation) with no/expired/invalid token → **302**
//!   to the IdP/login (derived from the OIDC config), so the browser can re-authenticate;
//! - an **`/api/*.json`** request (a programmatic `fetch`, `accept: application/json`) with
//!   no/expired/invalid token → **401** with a tiny `{"error":"unauthenticated"}` body. An `/api`
//!   route is **NEVER** 302'd — a redirected `fetch` dies on the strict CSP `connect-src 'self'` and
//!   the client mislabels auth as "stale" (the load-bearing reason the path-prefix rule is a hard
//!   guarantee, not a heuristic);
//! - a **valid** token whose identity is below the configured minimum tier → **403** (both classes;
//!   re-login cannot change the identity, so a document is not redirected here);
//! - a **JWKS-unreachable** condition → **503** (both classes) — we could not verify, so we do not
//!   serve; this matches the [`AuthError::status`](super::AuthError::status) mapping the verifier
//!   already defines. Never a bypass.
//!
//! Every denial carries `Cache-Control: no-store` (JEF-283: a cached `302`→login is exactly the
//! Cloudflare-edge bug), and — because this layer is mounted UNDER the CSP layer — the strict CSP
//! rides every rejection too. The gate is the ONLY thing that can turn a request into a `next.run`;
//! there is no path that serves the graph on a verification error (the fail-*open* trap ADR-0030 §6
//! names as the single highest-risk line).

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::claims::Tier;
use super::{AuthError, Identity, OidcConfig, Verifier, authenticate, non_empty_env};

/// The tiny JSON body for a `401` — no graph data, no stack, no which-check-failed detail (ADR-0030
/// §6: which check failed is not the caller's business).
const BODY_UNAUTHENTICATED: &str = r#"{"error":"unauthenticated"}"#;
/// The tiny JSON body for a `403`.
const BODY_FORBIDDEN: &str = r#"{"error":"forbidden"}"#;
/// The tiny JSON body for a `503` (JWKS unreachable — we could not verify).
const BODY_UNAVAILABLE: &str = r#"{"error":"unavailable"}"#;

/// `PROTECTOR_DASHBOARD_OIDC_LOGIN_URL` — where a browser DOCUMENT request with no/invalid token is
/// 302'd. Optional; defaults to the configured issuer (ADR-0030 §7: protector is a resource server,
/// not an OAuth client — it does not build an `authorization_code` redirect, it points the browser
/// at the login surface, which for the Cloudflare-Access reference issues the assertion itself).
const ENV_LOGIN_URL: &str = "PROTECTOR_DASHBOARD_OIDC_LOGIN_URL";
/// `PROTECTOR_DASHBOARD_OIDC_MIN_TIER` — the minimum authorization tier a verified identity must
/// hold to VIEW. Optional escape hatch; defaults to the most-restricted [`Tier::Redacted`] (every
/// verified identity passes), so configuring an issuer never, by itself, forbids a valid token.
const ENV_MIN_TIER: &str = "PROTECTOR_DASHBOARD_OIDC_MIN_TIER";

/// The live dashboard access gate: the JEF-485 [`Verifier`] plus the content-negotiation policy
/// (where to send an unauthenticated browser, and the minimum authorization tier). Built ONLY when
/// an issuer is configured — its absence is the loud edge-only bypass (ADR-0030 §6), which the
/// caller handles by simply not mounting this layer.
pub struct Enforcer {
    verifier: Verifier,
    /// Where a browser DOCUMENT request with no/expired/invalid token is 302'd.
    login_redirect: String,
    /// The minimum authorization tier a verified identity must hold to view (default `Redacted`).
    min_tier: Tier,
}

impl Enforcer {
    /// Build the production gate from a configured [`OidcConfig`]: a verifier that fetches the
    /// issuer's keys over HTTPS, the login redirect (configured URL, else the issuer), and the
    /// minimum tier (env escape hatch, else the most-restricted default).
    pub fn new(config: OidcConfig) -> Self {
        let login_redirect = login_redirect(&config);
        Self {
            verifier: Verifier::from_config(config),
            login_redirect,
            min_tier: configured_min_tier(),
        }
    }

    /// Assemble a gate from explicit parts — the seam tests use to inject a [`Verifier`] built over
    /// an in-memory JWKS (no egress) and pin the login redirect / minimum tier deterministically.
    #[cfg(test)]
    pub(crate) fn from_parts(verifier: Verifier, login_redirect: String, min_tier: Tier) -> Self {
        Self {
            verifier,
            login_redirect,
            min_tier,
        }
    }

    /// Whether a verified identity meets the minimum tier. `Tier` is ordered
    /// `Redacted < Forensic < Raw`, and the default floor is `Redacted`, so with no configured
    /// minimum every verified identity is permitted (authentication alone gates viewing).
    fn identity_permitted(&self, identity: &Identity) -> bool {
        identity.tier >= self.min_tier
    }
}

/// The axum middleware: verify the request (via the shared [`authenticate`] seam) and, on success
/// meeting the tier gate, insert the [`Identity`] and pass through; on ANY failure, DENY with a
/// route-class-negotiated response. Mounted with
/// `from_fn_with_state(Arc<Enforcer>, enforce)` UNDER the CSP layer.
pub async fn enforce(
    State(enforcer): State<Arc<Enforcer>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let class = route_class(request.uri(), request.headers());
    match authenticate(&enforcer.verifier, request.headers()).await {
        Ok(identity) if enforcer.identity_permitted(&identity) => {
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Ok(identity) => {
            tracing::warn!(
                subject = %identity.subject,
                "dashboard: verified identity is below the minimum tier (forbidden)"
            );
            deny(Denial::Forbidden, class, &enforcer.login_redirect)
        }
        Err(error) => {
            tracing::warn!(%error, ?class, "dashboard OIDC verification denied (fail-closed)");
            deny(Denial::Auth(error), class, &enforcer.login_redirect)
        }
    }
}

/// Which class of request this is — the axis the failure is negotiated on. An `/api/` path is the
/// JSON class unconditionally (the hard "never 302 an `/api` route" guarantee); otherwise a client
/// that explicitly prefers JSON is treated as the JSON class too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteClass {
    /// A browser navigation (`GET /`, `/assets/*`) — an auth failure is a `302` to login.
    Document,
    /// A programmatic `/api/*.json` (or JSON-preferring) request — an auth failure is a `401`, never
    /// a redirect.
    Api,
}

/// Distinguish the JSON API class from a browser document. The `/api/` path prefix is authoritative
/// (a redirected `fetch` breaks under CSP), and assets fall to `Document` so an unauthenticated
/// direct asset hit rides the document 302 — the browser reaches assets only after the document has
/// authenticated, so this is the honest call.
fn route_class(uri: &Uri, headers: &HeaderMap) -> RouteClass {
    if uri.path().starts_with("/api/") || prefers_json(headers) {
        RouteClass::Api
    } else {
        RouteClass::Document
    }
}

/// Whether the client explicitly asks for JSON and not HTML — a programmatic `fetch`, not a browser
/// navigation. A browser's `Accept: text/html,...` is NOT treated as JSON even if it also lists
/// `application/json`.
fn prefers_json(headers: &HeaderMap) -> bool {
    let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    accept.contains("application/json") && !accept.contains("text/html")
}

/// The two kinds of denial: a verification failure (its [`AuthError`] carries the JWKS-down vs
/// auth-failure distinction) or a tier-authorization failure on an otherwise-valid token.
enum Denial {
    Auth(AuthError),
    Forbidden,
}

/// Map a denial to the route-class-negotiated response, then stamp `no-store`. JWKS-unreachable is a
/// `503` on BOTH classes (availability, not an auth challenge — never a 302); a `Forbidden` is a
/// `403` on both (re-login cannot change the identity); every other auth failure is a `401` for the
/// JSON class and a `302`-to-login for a document.
fn deny(denial: Denial, class: RouteClass, login_redirect: &str) -> Response {
    let response = match (denial, class) {
        (Denial::Auth(AuthError::JwksUnreachable), RouteClass::Api) => {
            json(StatusCode::SERVICE_UNAVAILABLE, BODY_UNAVAILABLE)
        }
        (Denial::Auth(AuthError::JwksUnreachable), RouteClass::Document) => {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        (Denial::Forbidden, RouteClass::Api) => json(StatusCode::FORBIDDEN, BODY_FORBIDDEN),
        (Denial::Forbidden, RouteClass::Document) => StatusCode::FORBIDDEN.into_response(),
        (Denial::Auth(_), RouteClass::Api) => json(StatusCode::UNAUTHORIZED, BODY_UNAUTHENTICATED),
        (Denial::Auth(_), RouteClass::Document) => redirect(login_redirect),
    };
    no_store(response)
}

/// A tiny JSON error response with the given status — no graph data, no error detail.
fn json(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response()
}

/// A `302 Found` to the login/IdP surface. A `Location` that cannot be a header value must not
/// panic — it denies with a bare `401` (fail closed), never serves.
fn redirect(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(_) => StatusCode::UNAUTHORIZED.into_response(),
    }
}

/// Stamp `Cache-Control: no-store` on a denial so a shared edge (Cloudflare) never caches a
/// `302`→login (or any rejection) against the URL and serves it to the next caller (JEF-283).
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The browser login redirect target: the configured `PROTECTOR_DASHBOARD_OIDC_LOGIN_URL`, else the
/// issuer (ADR-0030 §7).
fn login_redirect(config: &OidcConfig) -> String {
    non_empty_env(ENV_LOGIN_URL).unwrap_or_else(|| config.issuer.clone())
}

/// The configured minimum viewing tier, or the most-restricted default (which permits every
/// verified identity). An unknown label maps to the floor (fail-safe, never permissive).
fn configured_min_tier() -> Tier {
    non_empty_env(ENV_MIN_TIER)
        .map(|value| Tier::from_claim_str(&value))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, LOCATION};

    fn uri(path: &str) -> Uri {
        path.parse().unwrap()
    }

    fn accept(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn api_path_is_always_the_json_class_even_with_an_html_accept() {
        // The path prefix is authoritative: an `/api/` route is the JSON class no matter what the
        // browser's Accept header says — the hard "never 302 an /api route" guarantee.
        assert_eq!(
            route_class(&uri("/api/findings.json"), &accept("text/html")),
            RouteClass::Api
        );
    }

    #[test]
    fn root_is_the_document_class_but_a_json_fetch_of_root_is_the_api_class() {
        // A plain browser navigation of `/` is a document (→ 302 on failure); a JSON-preferring
        // fetch of `/` is treated as the API class (→ 401, never a redirect).
        assert_eq!(
            route_class(&uri("/"), &HeaderMap::new()),
            RouteClass::Document
        );
        assert_eq!(
            route_class(&uri("/"), &accept("application/json")),
            RouteClass::Api
        );
    }

    #[test]
    fn a_browser_accept_listing_both_html_and_json_is_a_document() {
        // A real browser navigation sends `text/html,application/xhtml+xml,...,application/json;...`
        // — that must NOT be mistaken for a programmatic JSON client.
        assert!(!prefers_json(&accept(
            "text/html,application/xhtml+xml,application/json;q=0.9"
        )));
        assert!(prefers_json(&accept("application/json")));
    }

    #[test]
    fn assets_are_the_document_class() {
        assert_eq!(
            route_class(&uri("/assets/dashboard.css"), &HeaderMap::new()),
            RouteClass::Document
        );
    }

    #[test]
    fn api_auth_failure_is_a_401_json_never_a_redirect() {
        let response = deny(Denial::Auth(AuthError::MissingToken), RouteClass::Api, "x");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            response.headers().get(LOCATION).is_none(),
            "/api never 302s"
        );
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
    }

    #[test]
    fn document_auth_failure_is_a_302_to_login() {
        let response = deny(
            Denial::Auth(AuthError::Expired),
            RouteClass::Document,
            "https://login.example",
        );
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers().get(LOCATION).unwrap(),
            "https://login.example"
        );
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
    }

    #[test]
    fn jwks_unreachable_is_a_503_on_both_classes_never_a_302() {
        for class in [RouteClass::Api, RouteClass::Document] {
            let response = deny(Denial::Auth(AuthError::JwksUnreachable), class, "x");
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(
                response.headers().get(LOCATION).is_none(),
                "a 503 is never a redirect"
            );
        }
    }

    #[test]
    fn forbidden_is_a_403_on_both_classes_never_a_302() {
        for class in [RouteClass::Api, RouteClass::Document] {
            let response = deny(Denial::Forbidden, class, "x");
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(
                response.headers().get(LOCATION).is_none(),
                "a forbidden identity is not re-challenged with a redirect"
            );
        }
    }
}
