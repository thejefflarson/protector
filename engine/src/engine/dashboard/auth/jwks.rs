//! The cached, rotation-aware, **single-flight** JWKS store (ADR-0030 §5).
//!
//! Verifying a JWT's signature needs the issuer's public signing keys. This store fetches them
//! via OIDC discovery (`<issuer>/.well-known/openid-configuration` → `jwks_uri` → keys) through a
//! **bounded-timeout** client, caches the set, and refetches on an **unknown `kid`** (key
//! rotation) or after a **TTL**. Only **one** refresh is ever in flight — a cold `kid` under load
//! coalesces onto a single fetch instead of stampeding the IdP.
//!
//! **Anti-stampede.** The `kid` is read from the token's UNSIGNED header before any signature
//! check, so an unauthenticated attacker can spray tokens each carrying a distinct random `kid`.
//! The single-flight lock alone only collapses *concurrent* misses, not *sequential* ones — so a
//! rotation-triggered refetch is additionally rate-limited to at most one network fetch per
//! [`min_refresh_interval`](JwksStore::min_refresh_interval): an unknown `kid` on an otherwise
//! fresh cache refetches only if the interval has elapsed since the last attempt, else it denies
//! immediately with no network. A genuine rotation still resolves within `min_refresh_interval`.
//!
//! **Bounded body.** The discovery and JWKS responses are read under a hard byte budget
//! ([`MAX_JWKS_BODY_BYTES`]) so a compromised / MITM / buggy issuer cannot OOM the engine with an
//! unbounded body.
//!
//! Per ADR-0030 §6 this store is **fail-closed**: a discovery/JWKS fetch failure — including an
//! over-large body or a throttled miss — is an [`AuthError`], never a bypass. The [`JwksFetcher`]
//! seam lets tests serve a set in-memory with zero egress (and leaves room for the ADR's
//! mounted-JWKS air-gap source on the same interface).

use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use serde::Deserialize;
use tokio::sync::Mutex;

use super::AuthError;

/// How long a fetched key set is served before it is proactively refetched, even for a known
/// `kid` — the rotation-freshness TTL. Bounds how stale a revoked key can linger in cache.
const DEFAULT_TTL_SECS: u64 = 300;

/// Total timeout (seconds) for a discovery / JWKS fetch, overridable via
/// `PROTECTOR_OIDC_JWKS_TIMEOUT_SECS`. Short by design: verification must fail closed fast on an
/// unreachable IdP rather than hang the request.
const DEFAULT_FETCH_TIMEOUT_SECS: u64 = 5;

/// Minimum wall-clock between rotation-triggered network refetches, overridable via
/// `PROTECTOR_OIDC_MIN_REFRESH_SECS`. Caps how fast an attacker-controlled unknown-`kid` stream
/// can drive outbound JWKS fetches: at most one per interval, regardless of concurrency or
/// sequencing. A genuine rotation still resolves within this interval.
const DEFAULT_MIN_REFRESH_SECS: u64 = 5;

/// Hard cap on the discovery / JWKS response body we will buffer (1 MiB — a JWKS is a handful of
/// public keys, kilobytes at most). An over-large body fails closed rather than risk an OOM.
const MAX_JWKS_BODY_BYTES: usize = 1024 * 1024;

/// Source of the issuer's current JWK set. Abstracted as a trait so production fetches over HTTPS
/// while tests inject an in-memory set (no egress) — and so the ADR-0030 air-gap "mounted JWKS"
/// source can slot in on the same seam later.
#[async_trait]
pub trait JwksFetcher: Send + Sync {
    /// Fetch the issuer's current JWK set. `Err` on any failure (fail-closed, ADR-0030 §6).
    async fn fetch(&self) -> Result<JwkSet, AuthError>;
}

/// The subset of the OIDC discovery document we read — only `jwks_uri`.
#[derive(Deserialize)]
struct Discovery {
    jwks_uri: String,
}

/// Fetches discovery → `jwks_uri` → keys over HTTPS with a **bounded-timeout** client (never an
/// unbounded `reqwest::Client::new()`, mirroring [`crate::engine::model::timeout_only_client`]).
/// Any failure — unreachable IdP, non-2xx, unparsable body — is [`AuthError::JwksUnreachable`],
/// so a JWKS-fetch failure denies rather than bypasses (ADR-0030 §6).
pub struct HttpJwksFetcher {
    /// `None` when even the bounded client could not be built — we fail closed rather than fall
    /// back to an unbounded client that could stall the request on a hung IdP.
    client: Option<reqwest::Client>,
    issuer: String,
}

impl HttpJwksFetcher {
    /// Build a fetcher for `issuer` with a bounded-timeout client.
    pub fn new(issuer: impl Into<String>) -> Self {
        let timeout = std::env::var("PROTECTOR_OIDC_JWKS_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(DEFAULT_FETCH_TIMEOUT_SECS);
        let client = match crate::engine::model::timeout_only_client(timeout) {
            Ok(client) => Some(client),
            Err(error) => {
                // Do NOT fall back to an unbounded client — that would reintroduce the exact hung-
                // IdP stall this store bounds against. A `None` client fails closed at fetch time.
                tracing::error!(%error, "OIDC: could not build a bounded JWKS client; JWKS fetch will fail closed");
                None
            }
        };
        Self {
            client,
            issuer: issuer.into(),
        }
    }
}

#[async_trait]
impl JwksFetcher for HttpJwksFetcher {
    async fn fetch(&self) -> Result<JwkSet, AuthError> {
        let client = self.client.as_ref().ok_or(AuthError::JwksUnreachable)?;
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        let discovery: Discovery = get_json(client, &discovery_url).await?;
        get_json(client, &discovery.jwks_uri).await
    }
}

/// GET `url` and deserialize a 2xx JSON body **under a hard byte budget**. Any failure —
/// unreachable, non-2xx, an over-large body, or an unparsable one — collapses to
/// [`AuthError::JwksUnreachable`] so a fetch failure denies, never bypasses.
async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, AuthError> {
    let mut response = client
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|_| AuthError::JwksUnreachable)?;
    // Reject an over-large ADVERTISED body up front (the cheap path).
    if response
        .content_length()
        .is_some_and(|len| len > MAX_JWKS_BODY_BYTES as u64)
    {
        return Err(AuthError::JwksUnreachable);
    }
    // Read with a running byte BUDGET so a missing or lying Content-Length can't OOM the engine:
    // a compromised / MITM / buggy issuer must not be able to stream an unbounded body at us.
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AuthError::JwksUnreachable)?
    {
        if body.len() + chunk.len() > MAX_JWKS_BODY_BYTES {
            return Err(AuthError::JwksUnreachable);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| AuthError::JwksUnreachable)
}

/// A cached key set plus when it was fetched (for the TTL check).
struct Cached {
    keys: JwkSet,
    fetched_at: Instant,
}

impl Cached {
    /// Whether this cache entry is still within the rotation-freshness TTL.
    fn fresh(&self, ttl: Duration) -> bool {
        self.fetched_at.elapsed() < ttl
    }
}

/// The cached, rotation-aware, single-flight, rate-limited JWKS store.
pub struct JwksStore {
    fetcher: Arc<dyn JwksFetcher>,
    cache: ArcSwapOption<Cached>,
    /// Serializes refreshes so only ONE fetch is in flight for a cold `kid` (no IdP stampede).
    refresh_lock: Mutex<()>,
    /// When a network refetch was last ATTEMPTED (success or failure). Only ever touched while
    /// `refresh_lock` is held; a std mutex keeps it `Sync`. Drives the anti-stampede rate limit.
    last_refresh: std::sync::Mutex<Option<Instant>>,
    ttl: Duration,
    /// The minimum wall-clock between rotation-triggered network refetches (anti-stampede).
    min_refresh_interval: Duration,
}

impl JwksStore {
    /// A store over `fetcher` with the default TTL and refresh interval (`PROTECTOR_OIDC_TTL` is
    /// fixed; the refresh interval honors `PROTECTOR_OIDC_MIN_REFRESH_SECS`).
    pub fn new(fetcher: Arc<dyn JwksFetcher>) -> Self {
        let min_refresh = std::env::var("PROTECTOR_OIDC_MIN_REFRESH_SECS")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(DEFAULT_MIN_REFRESH_SECS);
        Self::with_policy(
            fetcher,
            Duration::from_secs(DEFAULT_TTL_SECS),
            Duration::from_secs(min_refresh),
        )
    }

    /// A store with an explicit TTL and refresh interval — the seam tests use to exercise the
    /// TTL-refetch and anti-stampede rate-limit paths on short, deterministic timings.
    pub fn with_policy(
        fetcher: Arc<dyn JwksFetcher>,
        ttl: Duration,
        min_refresh_interval: Duration,
    ) -> Self {
        Self {
            fetcher,
            cache: ArcSwapOption::empty(),
            refresh_lock: Mutex::new(()),
            last_refresh: std::sync::Mutex::new(None),
            ttl,
            min_refresh_interval,
        }
    }

    /// Resolve a [`DecodingKey`] for the token's `kid`. Serves from cache when the set is fresh
    /// and already contains the `kid`; otherwise refreshes (single-flight, rate-limited) and
    /// retries. An unknown `kid` is [`AuthError::UnknownKey`]; a fetch failure (or an empty cache
    /// under throttle) is [`AuthError::JwksUnreachable`] — either way it denies (ADR-0030 §6).
    pub async fn decoding_key(&self, kid: Option<&str>) -> Result<DecodingKey, AuthError> {
        // Fast path: a fresh cache that already carries the requested key.
        if let Some(cached) = self.cache.load_full()
            && cached.fresh(self.ttl)
            && let Some(jwk) = find_key(&cached.keys, kid)
        {
            return decoding_key_from_jwk(jwk);
        }
        // Unknown `kid`, or a stale / empty cache: refresh (single-flight, rate-limited).
        let cached = self.refresh(kid).await?;
        match find_key(&cached.keys, kid) {
            Some(jwk) => decoding_key_from_jwk(jwk),
            None => Err(AuthError::UnknownKey),
        }
    }

    /// Perform a single-flight, rate-limited refresh. Concurrent callers block on `refresh_lock`;
    /// the first may fetch and swap the cache, and the rest re-check under the lock. A network
    /// fetch happens ONLY if the cache still lacks what we need AND `min_refresh_interval` has
    /// elapsed since the last attempt — otherwise we serve the current cache without egress (the
    /// caller's `find_key` then denies an absent `kid`). So an unknown-`kid` stream drives at most
    /// one fetch per interval, whether the misses arrive concurrently or in sequence.
    async fn refresh(&self, kid: Option<&str>) -> Result<Arc<Cached>, AuthError> {
        let _guard = self.refresh_lock.lock().await;
        let current = self.cache.load_full();
        // Re-check under the lock: a concurrent caller may have just refreshed what we need.
        if let Some(cached) = &current
            && cached.fresh(self.ttl)
            && find_key(&cached.keys, kid).is_some()
        {
            return Ok(cached.clone());
        }
        // Anti-stampede: throttle rotation-triggered network refetches. Within the interval,
        // serve the current cache (a present `kid` still resolves; an absent one denies) — but
        // make NO outbound call. The empty-cache-under-throttle case fails closed.
        if let Some(last) = *self.last_refresh.lock().unwrap()
            && last.elapsed() < self.min_refresh_interval
        {
            return current.ok_or(AuthError::JwksUnreachable);
        }
        // We are the single flight for this interval. Record the attempt BEFORE the await so a
        // FAILED fetch also counts against the interval (never hammer a flapping/hostile IdP).
        *self.last_refresh.lock().unwrap() = Some(Instant::now());
        let keys = self.fetcher.fetch().await?;
        let cached = Arc::new(Cached {
            keys,
            fetched_at: Instant::now(),
        });
        self.cache.store(Some(cached.clone()));
        Ok(cached)
    }
}

/// Find a key in the set. With a `kid`, match it exactly. Without one, resolve only when the set
/// is unambiguous (a single key) — never guess among several keys.
fn find_key<'a>(set: &'a JwkSet, kid: Option<&str>) -> Option<&'a Jwk> {
    match kid {
        Some(kid) => set.find(kid),
        None => match set.keys.as_slice() {
            [only] => Some(only),
            _ => None,
        },
    }
}

/// Build a [`DecodingKey`] from a JWK. A key we cannot turn into a decoding key is treated as
/// [`AuthError::UnknownKey`] — an unusable key is no key (fail closed).
fn decoding_key_from_jwk(jwk: &Jwk) -> Result<DecodingKey, AuthError> {
    DecodingKey::from_jwk(jwk).map_err(|_| AuthError::UnknownKey)
}
