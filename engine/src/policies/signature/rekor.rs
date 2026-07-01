//! The Rekor transparency-log lane (JEF-266, ADR-0020 §4 + the ADR-0015 Rekor amendment).
//!
//! This is the ONE outbound call protector adds beyond the registry pull. It is a **deliberate,
//! operator-accepted carve-out of the zero-egress posture** and therefore **opt-in, OFF by
//! default**: with `PROTECTOR_REKOR_ENABLE` unset the lane is never constructed, no query leaves
//! the cluster, and the signature *inventory* (JEF-261/262) + baseline (JEF-263) + local drift
//! (JEF-264) all keep working exactly as before (full zero-egress). Set `PROTECTOR_REKOR_URL` to a
//! self-hosted Rekor mirror to enable the history/divergence checks while still egressing nothing
//! to the public log.
//!
//! What the lane buys (both consumed by [`signing_rekor`](crate::engine::signing_rekor)):
//!
//!   * **History bootstrap / strength.** A repo whose signed image the public log already carries
//!     an entry for inherits *real provenance* — its TOFU baseline is marked **log-corroborated**
//!     (stronger than a purely local first-sight), defeating the cold-start weakness ADR-0020
//!     names.
//!   * **Registry↔log divergence.** A signature the registry serves but the log has no entry for
//!     (or the reverse — the log holds an entry the registry serves unsigned) is tampering neither
//!     source reveals alone → a divergence finding.
//!
//! ## What leaks, and what never does
//!
//! Only image identifiers/digests (already public — pulled from public registries) reach the log
//! operator. The security graph and evidence NEVER leave the cluster. This lane is distinct from —
//! and never routed through — the model-endpoint validator (that is the model's lane).
//!
//! ## Feasibility (recorded per the ticket)
//!
//! `sigstore-rs` 0.14 DOES expose a Rekor search client (`rekor::apis::index_api::search_index`,
//! query by artifact hash / email / public key, behind the `rekor` feature that `cosign` already
//! pulls in). We deliberately query Rekor's REST index (`/api/v1/index/retrieve`) directly with a
//! bounded [`reqwest`] client instead: it gives us tight control over the timeout, the
//! response-size cap, and malformed-response handling the security review requires, without pulling
//! in the heavier entry-body/cert-parsing surface. The client is abstracted behind [`RekorClient`]
//! so the lane's decision logic is exhaustively unit-testable with a fake — the thin HTTP impl is
//! validated against a live/self-hosted Rekor.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use async_trait::async_trait;
use tokio::sync::Mutex;

/// What the transparency log knows about an image's signing, as consulted for one artifact. Every
/// field is derived from UNTRUSTED third-party (the public log) data — bounded here, escaped at
/// render by any consumer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RekorHistory {
    /// The log holds at least one signing entry for this artifact/identity. This is the
    /// security-bearing fact: it corroborates a local `Signed` posture, and its ABSENCE against a
    /// local `Signed` — or its PRESENCE against a local `NotSigned` — is registry↔log divergence.
    pub signed_in_log: bool,
    /// Signer identities the log attributes to this artifact, deduped + bounded. May be empty even
    /// when [`signed_in_log`](Self::signed_in_log) — identity extraction from entry bodies is
    /// best-effort; the presence of an entry is the load-bearing signal. UNTRUSTED — escape at
    /// render.
    pub identities: Vec<String>,
}

/// Queries the transparency log for an image's signing history. Abstracted behind a trait — exactly
/// like [`SignatureObserver`](super::SignatureObserver) — so the lane's corroboration/divergence
/// logic is unit-testable with a fake, without reaching the public log.
#[async_trait]
pub trait RekorClient: Send + Sync {
    /// Look up `image` (optionally narrowed by the observed signer `identity`) in the log. `Err`
    /// only on an infrastructure failure (unreachable / timeout / malformed / no queryable key) —
    /// which the lane degrades to local-only (never a false clean, never a false divergence). A
    /// definitive "the log has no entry" is `Ok(RekorHistory { signed_in_log: false, .. })`.
    async fn lookup(&self, image: &str, identity: Option<&str>) -> Result<RekorHistory>;
}

/// Whether an env var reads as truthy (`1` / `true` / `yes` / `on`, case-insensitive). Anything
/// else — including unset — is false, so the lane stays OFF unless explicitly enabled.
fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// The Rekor lane's configuration, resolved from the environment. The lane is built ONLY when
/// [`enabled`](Self::enabled) — otherwise no client is constructed and nothing egresses.
#[derive(Debug, Clone)]
pub struct RekorConfig {
    /// Opt-in switch (`PROTECTOR_REKOR_ENABLE`). OFF by default — zero egress preserved.
    pub enabled: bool,
    /// Rekor base URL (`PROTECTOR_REKOR_URL`). Defaults to the public good log; point it at a
    /// self-hosted mirror to keep the history/divergence checks while egressing nothing public.
    pub base_url: String,
    /// Per-query wall-clock budget, so a slow/hung log can't stall the sweep.
    pub timeout: Duration,
    /// How long a looked-up history stays cached (bounds re-querying an unchanged repo/image each
    /// pass — the same TTL discipline the posture observer uses).
    pub cache_ttl: Duration,
    /// Hard cap on the log response we will read (bytes) — an untrusted third party must not be
    /// able to make us allocate unbounded memory.
    pub max_response_bytes: usize,
}

impl RekorConfig {
    /// Default public-good Rekor endpoint.
    pub const DEFAULT_URL: &'static str = "https://rekor.sigstore.dev";

    /// Resolve the lane's config from the environment. `PROTECTOR_REKOR_ENABLE` gates the whole
    /// lane OFF by default (zero egress); the rest tune it when enabled.
    pub fn from_env() -> Self {
        let base_url = std::env::var("PROTECTOR_REKOR_URL")
            .ok()
            .map(|u| u.trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| Self::DEFAULT_URL.to_string());
        Self {
            enabled: env_truthy("PROTECTOR_REKOR_ENABLE"),
            base_url,
            timeout: Duration::from_secs(env_u64("PROTECTOR_REKOR_TIMEOUT", 5)),
            cache_ttl: Duration::from_secs(env_u64("PROTECTOR_REKOR_CACHE_TTL", 3600)),
            max_response_bytes: env_u64("PROTECTOR_REKOR_MAX_BYTES", 1_048_576) as usize,
        }
    }
}

/// Parse a numeric env var, falling back to `default` if unset or unparseable.
fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The production [`RekorClient`]: a bounded HTTP query against Rekor's REST search index
/// (`/api/v1/index/retrieve`). Times out, caps the response size, and treats a malformed body as an
/// infrastructure error (degrade to local-only) rather than a fabricated "no entry" (which would be
/// a false divergence).
pub struct HttpRekorClient {
    client: reqwest::Client,
    base_url: String,
    timeout: Duration,
    max_response_bytes: usize,
}

impl HttpRekorClient {
    /// Build the client from resolved [`RekorConfig`]. The reqwest client carries the per-query
    /// timeout as a floor; each call also wraps its own `tokio::time::timeout` so a hung connect
    /// can't outlive the budget.
    pub fn new(config: &RekorConfig) -> Result<Self> {
        let client = reqwest::Client::builder().timeout(config.timeout).build()?;
        Ok(Self {
            client,
            base_url: config.base_url.clone(),
            timeout: config.timeout,
            max_response_bytes: config.max_response_bytes,
        })
    }

    /// The query key for an image: prefer the pinned `@sha256:…` digest (the artifact hash Rekor's
    /// index is keyed on); fall back to a keyless *email* signer identity. A workflow-URI identity
    /// and a tag-only ref have no index key here, so we return `None` and the lane degrades (never
    /// a false divergence on an unqueryable ref).
    fn query_key(image: &str, identity: Option<&str>) -> Option<QueryKey> {
        if let Some((_, digest)) = image.split_once('@')
            && digest.starts_with("sha256:")
        {
            return Some(QueryKey::Hash(digest.to_string()));
        }
        if let Some(id) = identity
            && id.contains('@')
            && !id.starts_with("http://")
            && !id.starts_with("https://")
        {
            return Some(QueryKey::Email(id.to_string()));
        }
        None
    }
}

/// What we can key a Rekor index search on for a given image.
enum QueryKey {
    /// The pinned artifact digest (`sha256:…`).
    Hash(String),
    /// A keyless email signer identity.
    Email(String),
}

#[async_trait]
impl RekorClient for HttpRekorClient {
    async fn lookup(&self, image: &str, identity: Option<&str>) -> Result<RekorHistory> {
        let Some(key) = Self::query_key(image, identity) else {
            bail!("no queryable rekor index key for {image}");
        };
        let body = match &key {
            QueryKey::Hash(hash) => serde_json::json!({ "hash": hash }),
            QueryKey::Email(email) => serde_json::json!({ "email": email }),
        };
        let url = format!("{}/api/v1/index/retrieve", self.base_url);
        let mut resp =
            tokio::time::timeout(self.timeout, self.client.post(&url).json(&body).send()).await??;
        let status = resp.status();
        if !status.is_success() {
            bail!("rekor index query returned {status}");
        }
        // Stream the body under a running byte cap rather than buffering it whole with
        // `resp.text()`: the response is untrusted (a hostile or compromised log endpoint), and
        // `.text()` would allocate the entire body BEFORE any size check, so a multi-GB body sent
        // within the timeout could OOM-kill the engine. Accumulate chunk-by-chunk and bail the
        // instant the cap would be exceeded — memory stays bounded by `max_response_bytes`. The
        // outer timeout bounds total read time exactly as the previous single-`.text()` timeout did.
        let max = self.max_response_bytes;
        let text = tokio::time::timeout(self.timeout, async {
            let mut buf: Vec<u8> = Vec::new();
            while let Some(chunk) = resp.chunk().await? {
                if buf.len() + chunk.len() > max {
                    bail!("rekor response exceeded {max} bytes");
                }
                buf.extend_from_slice(&chunk);
            }
            String::from_utf8(buf).map_err(|e| anyhow::anyhow!("rekor response not utf-8: {e}"))
        })
        .await??;
        // The index returns a JSON array of entry UUIDs. A malformed body is an infrastructure
        // error (degrade to local-only), NEVER an empty result — an empty result would fabricate a
        // false "not in log" divergence against a genuinely-signed image.
        let uuids: Vec<String> = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("malformed rekor index response: {e}"))?;
        Ok(RekorHistory {
            signed_in_log: !uuids.is_empty(),
            // Identity extraction from entry bodies is out of scope for the thin client; the entry
            // presence is the load-bearing signal.
            identities: Vec::new(),
        })
    }
}

/// Fronts a [`RekorClient`] with a TTL + image-keyed cache so an unchanged repo/image is NOT
/// re-queried each pass (the ticket's "bounded/cached" requirement). Only definitive `Ok` results
/// are cached; an infrastructure error is deliberately NOT cached, so an unreachable log is retried
/// next pass instead of being frozen into a degraded verdict. Built ONCE (persisting the cache
/// across passes) and only when the lane is enabled — so a disabled lane holds no client and
/// egresses nothing.
pub struct RekorLane {
    client: Arc<dyn RekorClient>,
    cache_ttl: Duration,
    cache: Mutex<HashMap<String, (RekorHistory, Instant)>>,
}

impl RekorLane {
    pub fn new(client: Arc<dyn RekorClient>, cache_ttl: Duration) -> Self {
        Self {
            client,
            cache_ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Look up `image`, serving a fresh cached history without an outbound call. An `Err`
    /// (unreachable / malformed / unqueryable) is propagated and NOT cached, so the lane degrades
    /// to local-only this pass and retries next pass.
    pub async fn lookup(&self, image: &str, identity: Option<&str>) -> Result<RekorHistory> {
        if let Some((history, cached_at)) = self.cache.lock().await.get(image).cloned()
            && cached_at.elapsed() < self.cache_ttl
        {
            return Ok(history);
        }
        let history = self.client.lookup(image, identity).await?;
        self.cache
            .lock()
            .await
            .insert(image.to_string(), (history.clone(), Instant::now()));
        Ok(history)
    }
}

#[cfg(test)]
#[path = "rekor_tests.rs"]
mod tests;
