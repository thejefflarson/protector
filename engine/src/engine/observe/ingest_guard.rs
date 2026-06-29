//! App-layer guards for the runtime/behavioral ingest (the :9999 port).
//!
//! The ingest accepts observations that flip a chain's `corroborated-now`
//! predicate — i.e. they can make a proven attack chain *actionable*. An
//! unauthenticated caller could forge those observations, so this module supplies
//! two axum layers applied ONLY to the ingest router (never the :8443 admission webhook):
//!
//!   * [`bearer_auth`] — a per-request middleware that requires
//!     `Authorization: Bearer <token>` matching a shared secret, rejecting a
//!     missing/incorrect bearer with `401` BEFORE the body is deserialized. The
//!     compare is constant-time so a wrong token leaks no timing signal. When no
//!     token is configured the layer is absent and a startup WARNING is logged, so
//!     the engine can be deployed before the Secret/agent roll out (see the chart
//!     README for the rollout ordering).
//!
//!   * [`RateLimit`] — a small in-process token bucket keyed per peer IP, so a
//!     single source can't drive unbounded ingest work even with a valid token.
//!     Kept in-process (no `tower_governor`) to keep the engine's build lean.
//!
//! Authentication (who may post) is this repo's job; authorization (which mesh
//! identities may connect) is the cluster's Linkerd mesh-authz layer — the two are
//! complementary, not redundant.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use subtle::ConstantTimeEq;

/// The shared secret the ingest requires on every request, read once at startup.
///
/// `None` means no token is configured — the ingest is left unauthenticated (with a
/// loud startup warning) so the engine can be deployed ahead of the Secret/agent.
#[derive(Clone)]
pub struct IngestToken(Arc<String>);

impl IngestToken {
    /// Resolve the ingest token from the environment, file-before-env:
    ///
    ///   * `PROTECTOR_INGEST_TOKEN_FILE` — a mounted file (takes precedence). Read
    ///     once; its trailing newline (the usual `kubectl create secret` artifact)
    ///     is trimmed.
    ///   * `PROTECTOR_INGEST_TOKEN` — an inline value.
    ///
    /// Returns `None` when neither is set or the resolved value is empty.
    pub fn from_env() -> Option<Self> {
        if let Ok(path) = std::env::var("PROTECTOR_INGEST_TOKEN_FILE") {
            match std::fs::read_to_string(&path) {
                Ok(contents) => {
                    let token = contents.trim().to_string();
                    if token.is_empty() {
                        tracing::warn!(
                            %path,
                            "PROTECTOR_INGEST_TOKEN_FILE is set but empty — ingest token unset"
                        );
                        return None;
                    }
                    return Some(Self(Arc::new(token)));
                }
                Err(error) => {
                    tracing::warn!(
                        %path, %error,
                        "PROTECTOR_INGEST_TOKEN_FILE could not be read — ingest token unset"
                    );
                    return None;
                }
            }
        }
        match std::env::var("PROTECTOR_INGEST_TOKEN") {
            Ok(value) if !value.trim().is_empty() => Some(Self(Arc::new(value.trim().to_string()))),
            _ => None,
        }
    }

    /// For tests: wrap a literal token.
    #[cfg(test)]
    pub fn from_literal(token: &str) -> Self {
        Self(Arc::new(token.to_string()))
    }

    /// Constant-time equality against a presented bearer value. Constant-time so a
    /// near-miss token can't be discovered byte-by-byte via response timing.
    fn matches(&self, presented: &str) -> bool {
        let expected = self.0.as_bytes();
        let got = presented.as_bytes();
        // `ct_eq` is only constant-time for equal-length inputs; differing lengths
        // are an immediate (and safe) mismatch — the length of the secret is not
        // itself a secret.
        if expected.len() != got.len() {
            return false;
        }
        expected.ct_eq(got).into()
    }
}

/// Pull the bearer credential out of an `Authorization: Bearer <token>` header.
fn extract_bearer(req: &Request<Body>) -> Option<&str> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    if token.is_empty() { None } else { Some(token) }
}

/// axum middleware: require a correct `Authorization: Bearer <token>`. Rejects a
/// missing/incorrect bearer with `401` BEFORE the handler (so a forged body is never
/// deserialized). Installed only when a token is configured.
pub async fn bearer_auth(
    State(token): State<IngestToken>,
    req: Request<Body>,
    next: Next,
) -> Response {
    match extract_bearer(&req) {
        Some(presented) if token.matches(presented) => next.run(req).await,
        _ => unauthorized(),
    }
}

fn unauthorized() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Bearer")
        .body(Body::empty())
        .expect("static 401 response is always valid")
}

/// A per-peer token-bucket rate limiter. Each source IP gets `burst` tokens that
/// refill at `rate` per second; a request with no token left is rejected `429`.
/// In-process and lock-guarded — adequate for the engine's single-replica ingest
/// without pulling in a heavier rate-limit dependency.
#[derive(Clone)]
pub struct RateLimit {
    inner: Arc<Mutex<RateLimitInner>>,
    rate_per_sec: f64,
    burst: f64,
}

struct RateLimitInner {
    /// Per-peer `(tokens, last_refill)`. Pruned opportunistically so a churn of
    /// short-lived peers can't grow the map without bound.
    buckets: HashMap<IpAddr, (f64, Instant)>,
}

impl RateLimit {
    /// Cap on tracked peers; beyond it, fully-refilled idle buckets are dropped.
    const MAX_PEERS: usize = 4096;

    /// `rate_per_sec` sustained requests/second per peer with a `burst` allowance.
    pub fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RateLimitInner {
                buckets: HashMap::new(),
            })),
            rate_per_sec,
            burst,
        }
    }

    /// Whether `peer` may make a request now, consuming one token if so.
    fn allow(&self, peer: IpAddr, now: Instant) -> bool {
        let mut inner = self.inner.lock().expect("rate-limit mutex poisoned");
        if inner.buckets.len() > Self::MAX_PEERS {
            let burst = self.burst;
            inner
                .buckets
                .retain(|_, (tokens, _)| *tokens < burst - f64::EPSILON);
        }
        let burst = self.burst;
        let rate = self.rate_per_sec;
        let entry = inner.buckets.entry(peer).or_insert((burst, now));
        let (tokens, last) = entry;
        let elapsed = now.saturating_duration_since(*last).as_secs_f64();
        *tokens = (*tokens + elapsed * rate).min(burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// axum middleware: enforce the per-peer [`RateLimit`]. A request over the limit is
/// rejected `429` before the handler runs.
pub async fn rate_limit(
    State(limiter): State<RateLimit>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if limiter.allow(peer.ip(), Instant::now()) {
        next.run(req).await
    } else {
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .body(Body::empty())
            .expect("static 429 response is always valid")
    }
}

/// Default sustained ingest rate per peer (requests/second). The agent batches and
/// re-reports on an interval, and Falco/falcosidekick is low-volume, so this is far
/// above legitimate traffic while still bounding a flood.
pub const DEFAULT_RATE_PER_SEC: f64 = 50.0;

/// Default burst allowance per peer — absorbs a normal flush/startup spike.
pub const DEFAULT_BURST: f64 = 100.0;

#[cfg(test)]
mod tests;
