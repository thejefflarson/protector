//! Transport + mount (ADR-0031 §5/§6, JEF-488). rmcp's streamable-HTTP [`StreamableHttpService`] is
//! mounted as an axum service BEHIND our OIDC verifier layer: [`mcp_auth`] runs the SAME
//! [`authenticate`] seam the dashboard `/api` gate uses, so an unauthenticated MCP call is rejected
//! by the identical path (a `401`) BEFORE a single byte reaches rmcp. On success it inserts the
//! verified [`Identity`] into the request extensions, which rmcp propagates into the tool handler
//! (see [`super::server`]).
//!
//! For zero-touch enterprise auth (ID-JAG) the server advertises an unauthenticated
//! `.well-known/oauth-protected-resource` document and answers every denial with a
//! `WWW-Authenticate: Bearer` challenge pointing at it, so an ID-JAG-capable client runs the token
//! exchange automatically. Protector is the PROTECTED RESOURCE — it verifies tokens (§5), it never
//! mints them.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rmcp::transport::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;

use crate::engine::dashboard::auth::{Verifier, authenticate};

use super::audit::AuditSink;
use super::server::ProtectorMcp;
use super::state::McpState;

/// The single MCP endpoint path (POST for calls, GET for the SSE stream, DELETE to end a session).
pub const MCP_PATH: &str = "/mcp";
/// The RFC 9728 protected-resource metadata path (unauthenticated discovery).
pub const WELL_KNOWN_PATH: &str = "/.well-known/oauth-protected-resource";

/// `PROTECTOR_MCP_ALLOWED_HOSTS` — comma-separated `Host`/`host:port` values rmcp accepts (DNS-
/// rebinding guard). Unset keeps rmcp's loopback-only default; a real ingress deployment sets it to
/// its own host.
const ENV_ALLOWED_HOSTS: &str = "PROTECTOR_MCP_ALLOWED_HOSTS";

/// The env var carrying the externally-reachable MCP resource URL, advertised in the
/// protected-resource metadata's `resource` field. Optional.
const ENV_RESOURCE_URL: &str = "PROTECTOR_MCP_RESOURCE_URL";

/// A trimmed, non-empty environment value, or `None` if unset/blank.
fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Hard cap on a single MCP request body. A JSON-RPC tool call is tiny (a name + a couple of string
/// args); 256 KiB is generous and stops any token-holder — including the lowest `redacted` tier —
/// from OOM-ing the engine PROCESS with a multi-GB body. Enforced OUTSIDE the auth layer, so an
/// oversized body is rejected before it is verified OR parsed.
const MAX_BODY_BYTES: usize = 256 * 1024;
/// Hard cap on concurrently in-flight MCP requests. Bounds total work (incl. any long-lived
/// streamed response) so a token-holder cannot exhaust the engine by opening unbounded connections.
const MAX_CONCURRENT: usize = 64;
/// Per-request timeout. Safe because the server runs STATELESS (`json_response`, no long-lived SSE
/// session) — every request is a bounded request→response, so a slow/abandoned call cannot pin a
/// worker or accumulate a session + keep-alive task.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Build the MCP router: the rmcp streamable-HTTP service at [`MCP_PATH`] behind the resource
/// governors + the [`mcp_auth`] verifier layer, plus the UNAUTHENTICATED protected-resource metadata
/// at [`WELL_KNOWN_PATH`]. The well-known route is added AFTER the governor/auth `.layer`s, so
/// discovery stays open while every MCP call is gated AND resource-bounded.
pub fn router(state: McpState, verifier: Arc<Verifier>, audit: Arc<dyn AuditSink>) -> Router {
    let session_manager = Arc::new(LocalSessionManager::default());
    let config = server_config();
    let factory = move || Ok(ProtectorMcp::new(state.clone(), audit.clone()));
    let mcp_service = StreamableHttpService::new(factory, session_manager, config);

    let metadata = protected_resource_metadata(&verifier);

    Router::new()
        .route_service(MCP_PATH, mcp_service)
        // Layers are applied inner→outer, so a request flows through them OUTER→inner: the body
        // limit runs FIRST (reject an oversized body before verify/parse — the OOM guard), then the
        // timeout + concurrency bound, then auth, then rmcp. A token-holder cannot OOM or exhaust the
        // engine process (DoS → cluster-wide runtime-blindness).
        .layer(axum::middleware::from_fn_with_state(verifier, mcp_auth))
        .layer(tower::limit::ConcurrencyLimitLayer::new(MAX_CONCURRENT))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_BODY_BYTES,
        ))
        // Discovery is unauthenticated (it carries only the issuer, no cluster data), added after
        // the auth layer so it is NOT gated.
        .route(
            WELL_KNOWN_PATH,
            get(move || {
                let metadata = metadata.clone();
                async move { ([(header::CONTENT_TYPE, "application/json")], metadata) }
            }),
        )
}

/// Serve the MCP server over plain HTTP on `addr` until the process exits — opt-in, zero-egress,
/// in-cluster only, meant to sit behind the cluster's ingress/mesh (like the dashboard). A bind
/// failure logs and the task exits; the engine loop is unaffected.
pub async fn serve_mcp(
    addr: SocketAddr,
    state: McpState,
    verifier: Arc<Verifier>,
    audit: Arc<dyn AuditSink>,
) {
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(error) => {
            tracing::error!(%error, %addr, "mcp: failed to bind; MCP server disabled");
            return;
        }
    };
    tracing::info!(%addr, "mcp listening (read-only, tiered redaction, OIDC-gated)");
    if let Err(error) =
        axum::serve(listener, router(state, verifier, audit).into_make_service()).await
    {
        tracing::error!(%error, "mcp server stopped");
    }
}

/// The rmcp server config. STATELESS + `json_response` (every request is a bounded request→response
/// returning `application/json`), so there is NO per-session task or keep-alive SSE stream to
/// accumulate — an attacker cannot pile up idle sessions, and the per-request timeout is safe
/// (nothing is meant to stay open). Loopback-only `Host` acceptance by default (the DNS-rebinding
/// guard); an operator behind an ingress adds their host via [`ENV_ALLOWED_HOSTS`].
fn server_config() -> rmcp::transport::StreamableHttpServerConfig {
    let mut config = rmcp::transport::StreamableHttpServerConfig::default();
    // STATELESS request→response mode (the config is `#[non_exhaustive]`, so set fields on default).
    config.stateful_mode = false;
    config.json_response = true;
    if let Some(hosts) = non_empty_env(ENV_ALLOWED_HOSTS) {
        let hosts: Vec<String> = hosts
            .split(',')
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .collect();
        // Only override the loopback default with a NON-empty list — a value like "," that parses to
        // empty must not silently disable the DNS-rebinding guard (rmcp treats an empty list as
        // allow-all). Auth still gates every request regardless, but the guard stays on.
        if !hosts.is_empty() {
            config.allowed_hosts = hosts;
        }
    }
    config
}

/// The RFC 9728 protected-resource metadata document — advertises the operator's issuer as the
/// authorization server so an ID-JAG-capable client onboards zero-touch. `resource` is the optional
/// externally-reachable URL ([`ENV_RESOURCE_URL`]).
fn protected_resource_metadata(verifier: &Verifier) -> String {
    let issuer = verifier.config().issuer.clone();
    let resource = non_empty_env(ENV_RESOURCE_URL);
    let mut doc = serde_json::json!({
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
    });
    if let Some(resource) = resource {
        doc["resource"] = serde_json::json!(resource);
    }
    doc.to_string()
}

/// The MCP auth middleware: verify the presented token via the SHARED [`authenticate`] seam (the
/// same verifier the dashboard `/api` gate uses), insert the [`Identity`] on success, and DENY on
/// any failure with the AuthError's status (a `401`, or `503` for JWKS-unreachable) plus a
/// `WWW-Authenticate` challenge pointing at the discovery document. Fail-closed: there is no path
/// that reaches rmcp without a verified identity.
pub async fn mcp_auth(
    State(verifier): State<Arc<Verifier>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    match authenticate(&verifier, request.headers()).await {
        Ok(identity) => {
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(error) => {
            tracing::warn!(%error, "mcp OIDC verification denied (fail-closed)");
            let status = error.status();
            challenge(status)
        }
    }
}

/// A bare denial carrying the ID-JAG `WWW-Authenticate` challenge + `no-store`. The challenge points
/// at the protected-resource metadata so an ID-JAG client can run the exchange automatically.
fn challenge(status: StatusCode) -> Response {
    let mut response = status.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(concat!(
            "Bearer resource_metadata=\"",
            "/.well-known/oauth-protected-resource",
            "\""
        )),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
