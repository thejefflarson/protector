//! Shared client for an OpenAI-compatible chat endpoint (a local Ollama by
//! default). The adjudicator (judge) is the sole `chat` consumer — the model-backed
//! hypothesis stage was removed (JEF-363), so nothing else judges through here.
//! `keep_warm` is a bypass: a one-token keep-alive ping that never touches a verdict.
//! Local-first: point it at an in-cluster model so the graph never leaves the cluster.
//!
//! This is glue — the one network call the model layer makes. The prompt-building
//! and reply-parsing that wrap it are pure and tested in their own modules. Completion
//! reuse lives one layer up in the adjudicator's verdict cache (JEF-350), keyed on the
//! deterministic prompt hash; there is deliberately no cache here (JEF-364 removed the
//! JEF-362 completion LRU — it was redundant with the verdict cache and pinned transient
//! `Uncertain` replies, blocking the JEF-234 retry/backoff).

use std::time::Duration;

use serde_json::{Value, json};

/// Default cap on the model calls protector keeps IN FLIGHT at once during an adjudication
/// pass. Deliberately generous (never 1): this is a connection/timeout fan-out safety bound,
/// not the old serialization gate (JEF-337 removed that). See [`model_concurrency`].
pub const DEFAULT_MODEL_CONCURRENCY: usize = 8;

/// Max model calls protector dispatches concurrently within a single adjudication pass,
/// from `PROTECTOR_MODEL_CONCURRENCY` (default [`DEFAULT_MODEL_CONCURRENCY`]).
///
/// JEF-337: protector no longer serializes model calls behind a process-wide 1-permit gate.
/// Ollama owns concurrency now — `OLLAMA_NUM_PARALLEL` decides how many requests it runs at
/// once and `OLLAMA_MAX_QUEUE` bounds the rest — and it is sized for the node it runs on. That
/// is the REAL throttle; protector reinventing it (one in-flight request) only capped
/// throughput and left ollama replicas idle. This knob is NOT that gate reborn: it is a
/// generous upper bound on how many timeouts/connections protector may hold open at once (each
/// call can hold the full `PROTECTOR_ENGINE_MODEL_TIMEOUT_SECS` window), so a huge fleet can't
/// open thousands of sockets in one pass. An unset, unparseable, or `0` value falls back to the
/// default; a positive value is honoured verbatim.
pub fn model_concurrency() -> usize {
    parse_model_concurrency(std::env::var("PROTECTOR_MODEL_CONCURRENCY").ok().as_deref())
}

/// Pure parse of the `PROTECTOR_MODEL_CONCURRENCY` value, split out so it's testable without
/// process-global env: unset / unparseable / `0` → [`DEFAULT_MODEL_CONCURRENCY`] (never a
/// deadlocking `buffer_unordered(0)`); any positive value is that many concurrent calls.
fn parse_model_concurrency(raw: Option<&str>) -> usize {
    raw.and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_MODEL_CONCURRENCY)
}

/// Total request timeout in seconds, from `PROTECTOR_ENGINE_MODEL_TIMEOUT_SECS`
/// (default 120 — the buried code default now that the chart no longer sets it, ADR-0021).
/// A small local model on CPU-only hardware (a Pi cluster) can take far longer than a few
/// seconds to answer an adjudication prompt, so the default is generous; raise the env
/// further where needed. The watch loop never starves while it waits (the reflectors run
/// in their own tasks) and verdicts are cached per entry.
fn timeout_secs() -> u64 {
    std::env::var("PROTECTOR_ENGINE_MODEL_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120)
}

/// Build a client carrying ONLY the total timeout — the bounded fallback. Public to the
/// crate so the fallback path is unit-testable: whatever build path `client()` lands on,
/// the request is still bounded by `timeout_secs()`.
pub(crate) fn timeout_only_client(timeout: u64) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
}

/// A client for the model endpoint with bounded timeouts. A slow or hung endpoint
/// then degrades to the safe `None` path (callers treat that as "no verdict") rather
/// than stalling the single engine loop indefinitely.
///
/// The primary builder also sets a `connect_timeout`. If that build fails (e.g. the TLS
/// backend fails to initialize), we do NOT silently fall back to a client with no
/// timeouts — that would reintroduce the exact unbounded stall this module exists to
/// prevent (a hung Ollama blocking a judging pass indefinitely). Instead we retry with a
/// minimal builder that still carries the configured total `timeout`, so the fallback is
/// itself bounded. That fallback is loud: a `tracing::warn!` plus a
/// `protector.engine.model_client_fallback` counter so the path is observable in metrics.
/// If even the timeout-only builder fails, reqwest cannot construct any client at all, so
/// rather than degrade to an unbounded client we panic — there is no safe bounded client
/// to return, and an unbounded one would reintroduce the stall this module bounds against.
pub fn client() -> reqwest::Client {
    let timeout = timeout_secs();
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|error| {
            // Primary build failed. Retry with ONLY the total timeout — the connect
            // timeout or another option may be what the backend rejected — so the
            // fallback stays bounded rather than degrading to an unbounded client.
            tracing::warn!(%error, "model client builder failed; retrying with a timeout-only client");
            record_fallback();
            timeout_only_client(timeout).unwrap_or_else(|error| {
                // Even the minimal timeout-only builder failed — reqwest cannot
                // construct ANY client (TLS backend / runtime fundamentally broken).
                // We must NOT degrade to an unbounded default reqwest client here:
                // that would reintroduce the exact unbounded stall this module exists to
                // prevent (a hung Ollama blocking a judging pass indefinitely). There is
                // no safe bounded client to hand back, so fail loudly rather than ship a
                // client that can stall the engine loop forever.
                record_fallback();
                panic!(
                    "model client builder failed even with a timeout-only builder \
                     ({error}); refusing to fall back to an unbounded client"
                );
            })
        })
}

/// Increment the model-client fallback counter on the global meter (a no-op when no OTLP
/// endpoint is configured). Counts every time `client()` takes a fallback build path, so
/// a non-zero value means a builder failure degraded the client and warrants a look.
fn record_fallback() {
    opentelemetry::global::meter("protector.engine")
        .u64_counter("protector.engine.model_client_fallback")
        .with_description("Times the model client builder fell back to a degraded client.")
        .build()
        .add(1, &[]);
}

/// Upper bound on the completion the model may emit (`max_tokens`). A verdict is a
/// small JSON object plus a one-line reason — well under this — so the cap never
/// truncates a legitimate reply, but it stops a misbehaving or compromised endpoint
/// from streaming an unbounded completion we then buffer and log. `keep_warm` caps
/// to one token; the judging path needs room for the verdict JSON + reason.
const MAX_COMPLETION_TOKENS: u32 = 1024;

/// Hard cap on the response body we buffer before parsing (256 KiB). The reply is a
/// small verdict JSON; this bounds the memory/log-amplification a large or hostile
/// endpoint reply could cause even with `max_tokens` set (the server need not honour
/// `max_tokens`). A body over the cap is rejected as `None` (callers degrade safely)
/// rather than buffered whole via `response.json()`.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Send `prompt` as a single user message and return the assistant's text, or
/// `None` on any transport/shape error (callers degrade safely on `None`).
/// Temperature 0 for reproducible output. The completion is bounded two ways: a
/// `max_tokens` cap asks the server to stop early, and the response body is read
/// with a [`MAX_RESPONSE_BYTES`] cap so a server that ignores `max_tokens` still
/// can't make us buffer an unbounded reply.
///
/// There is no completion cache here (JEF-364): every call hits the endpoint. Reuse
/// lives in the adjudicator's verdict cache (JEF-350), which keys on the deterministic
/// prompt hash — a hit there means `chat` is never called, and a miss means the prompt
/// changed so a completion cache would miss too. A completion cache would only add a
/// live hazard: it would pin a transient `Uncertain` reply (which the verdict store
/// deliberately never caches, so JEF-234 backoff can retry) until the evidence changed.
pub async fn chat(
    client: &reqwest::Client,
    endpoint: &str,
    model: &str,
    prompt: &str,
) -> Option<String> {
    // JEF-337: no serialization gate — the call just fires. Concurrency is owned by ollama
    // (`OLLAMA_NUM_PARALLEL`/`OLLAMA_MAX_QUEUE`) and fan-out is bounded per pass by
    // `model_concurrency`. Each call is still bounded by the reqwest timeout (see `client`).
    let body = json!({
        "model": model,
        "temperature": 0,
        "max_tokens": MAX_COMPLETION_TOKENS,
        "messages": [{ "role": "user", "content": prompt }]
    });
    let response = client.post(endpoint).json(&body).send().await.ok()?;
    // JEF-301: a non-success HTTP status (the 500 Ollama returns when it OOM-crashes ingesting
    // a heavy prompt, a 502/503 while it restarts, etc.) is a FAILURE, not an answer. Return
    // `None` explicitly so the caller records it as `Uncertain` ("model unavailable") — feeding
    // the per-entry backoff and the global breaker (JEF-234) — rather than trying to parse an
    // error body as a verdict. This makes "a 500 counts as a failure" structural instead of
    // relying on the error body happening not to parse into a verdict shape.
    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            "model endpoint returned a non-success status; treating as unavailable (no verdict)"
        );
        return None;
    }
    let bytes = bounded_body(response).await?;
    let json: Value = serde_json::from_slice(&bytes).ok()?;
    let content = json["choices"][0]["message"]["content"]
        .as_str()
        .map(str::to_string)?;
    Some(content)
}

/// Read a response body with a [`MAX_RESPONSE_BYTES`] ceiling, returning `None` if it
/// would exceed the cap (or on any transport error). Streaming the chunks lets us
/// bail as soon as the accumulated size crosses the cap instead of buffering the
/// whole (possibly hostile) body via `response.json()`/`response.bytes()` first.
async fn bounded_body(mut response: reqwest::Response) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            tracing::warn!(
                cap = MAX_RESPONSE_BYTES,
                "model response exceeded the body cap; discarding (treated as no verdict)"
            );
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    Some(buf)
}

/// The model endpoint + name, read once from `PROTECTOR_ENGINE_MODEL` /
/// `PROTECTOR_ENGINE_MODEL_NAME`. `None` when no endpoint is set (deterministic-only —
/// null hypothesizer and adjudicator). The single source of truth for the model
/// endpoint and the default model name, shared by the engine's model-backed builders
/// and by [`spawn_keep_warm`] below (so keep-warm warms exactly the configured model).
///
/// Zero-egress is enforced structurally (CLAUDE.md invariant): the endpoint host must
/// resolve in-cluster (loopback, an RFC1918/private range, or a cluster service domain)
/// unless `PROTECTOR_ALLOW_EXTERNAL_MODEL=1` explicitly opts into an external endpoint.
/// An external endpoint without the opt-in **fails closed** — the model is left
/// unattached (deterministic-only) rather than POSTing the graph off-cluster.
pub fn config() -> Option<(String, String)> {
    let endpoint = std::env::var("PROTECTOR_ENGINE_MODEL")
        .ok()
        .filter(|e| !e.is_empty())?;
    let allow_external = external_opt_in("PROTECTOR_ALLOW_EXTERNAL_MODEL");
    if let Err(reason) = validate_in_cluster_endpoint(&endpoint, allow_external) {
        tracing::error!(
            endpoint = %endpoint,
            "{reason}; refusing to attach the model (set PROTECTOR_ALLOW_EXTERNAL_MODEL=1 to override). \
             Running deterministic-only."
        );
        return None;
    }
    let name =
        std::env::var("PROTECTOR_ENGINE_MODEL_NAME").unwrap_or_else(|_| "qwen2.5:3b".to_string());
    Some((endpoint, name))
}

/// Whether an external-endpoint opt-in env var is set to a truthy value (`1`/`true`/
/// `yes`/`on`, any case). Used for both `PROTECTOR_ALLOW_EXTERNAL_MODEL` and the
/// notifier's `PROTECTOR_ALLOW_EXTERNAL_NOTIFY`.
pub fn external_opt_in(var: &str) -> bool {
    std::env::var(var)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Validate that `endpoint`'s host is in-cluster, honouring an explicit external
/// opt-in. `Ok(())` when the host is loopback, an RFC1918/private range, or a cluster
/// service domain (`.svc`, `.svc.cluster.local`, `.cluster.local`, or a plain
/// single-label service name like `ollama`); `Err(reason)` for anything else unless
/// `allow_external` is set. The homelab default (Ollama at a `.svc.cluster.local`
/// address) passes unchanged.
pub fn validate_in_cluster_endpoint(endpoint: &str, allow_external: bool) -> Result<(), String> {
    if allow_external {
        return Ok(());
    }
    let host = endpoint_host(endpoint)
        .ok_or_else(|| format!("model endpoint {endpoint:?} has no parseable host"))?;
    if host_is_in_cluster(&host) {
        Ok(())
    } else {
        Err(format!(
            "model endpoint host {host:?} is not in-cluster (zero-egress invariant)"
        ))
    }
}

/// Extract the lowercased host (no scheme, userinfo, port, path, or trailing dot)
/// from an endpoint URL. A deliberately small hand parser — we only need the
/// authority's host, not a full URL crate — that tolerates a missing scheme
/// (`ollama.svc:11434`) and an IPv6 literal (`[::1]:11434`).
fn endpoint_host(endpoint: &str) -> Option<String> {
    // Drop the scheme.
    let after_scheme = endpoint
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(endpoint);
    // The authority ends at the first `/`, `?`, or `#`.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Drop any userinfo (`user:pass@`).
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, r)| r)
        .unwrap_or(authority);
    // Split host from port, handling a bracketed IPv6 literal.
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split_once(']').map(|(h, _)| h)?
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    let host = host.trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Whether a host is in-cluster: loopback, a private/RFC1918 (or ULA) IP, a cluster
/// service DNS suffix, or a bare single-label service name (no dot — a same-namespace
/// service like `ollama`). A public DNS name or a public IP is NOT in-cluster.
fn host_is_in_cluster(host: &str) -> bool {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            // is_unique_local()/is_unicast_link_local() are unstable; match ULA (fc00::/7)
            // and link-local (fe80::/10) by prefix alongside loopback.
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        };
    }
    if host == "localhost" {
        return true;
    }
    // A bare single-label name (no dot) is a same-namespace service (`ollama`).
    if !host.contains('.') {
        return true;
    }
    const CLUSTER_SUFFIXES: [&str; 3] = [".svc", ".svc.cluster.local", ".cluster.local"];
    CLUSTER_SUFFIXES.iter().any(|suffix| host.ends_with(suffix))
}

/// Default keep-warm interval (seconds). Ollama unloads an idle model after
/// `OLLAMA_KEEP_ALIVE` (5 minutes by default), so a ping every 4 minutes keeps the
/// model resident with margin to spare — that's what stops the first judging pass
/// after an engine restart from being glacial (JEF-63). Override with
/// `PROTECTOR_ENGINE_KEEPWARM_SECS`; `0` disables keep-warm entirely.
pub const DEFAULT_KEEPWARM_SECS: u64 = 240;

/// How long Ollama should hold the model resident after a keep-warm ping, sent as the
/// `keep_alive` field (Ollama-specific; a strict OpenAI gateway simply ignores the
/// extra field). Chosen comfortably longer than [`DEFAULT_KEEPWARM_SECS`] so the
/// residency window never lapses between pings even if one is delayed.
const KEEPWARM_RESIDENCY_SECS: u64 = 600;

/// The configured keep-warm interval, or `None` when keep-warm is disabled (the env
/// var is `0`). Reads `PROTECTOR_ENGINE_KEEPWARM_SECS`, defaulting to
/// [`DEFAULT_KEEPWARM_SECS`]; an unparseable value falls back to the default.
pub fn keepwarm_interval() -> Option<Duration> {
    parse_keepwarm_interval(
        std::env::var("PROTECTOR_ENGINE_KEEPWARM_SECS")
            .ok()
            .as_deref(),
    )
}

/// Pure interval-gating decision, split out from [`keepwarm_interval`] so it's testable
/// without touching process-global env: `raw` is the raw `PROTECTOR_ENGINE_KEEPWARM_SECS`
/// value (`None` when unset). Unset or unparseable → [`DEFAULT_KEEPWARM_SECS`]; `0`
/// disables keep-warm (`None`); any positive value is that many seconds.
fn parse_keepwarm_interval(raw: Option<&str>) -> Option<Duration> {
    let secs = raw
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(DEFAULT_KEEPWARM_SECS);
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// Issue a single best-effort keep-warm ping: a minimal, near-no-op chat that asks the
/// endpoint to load (or keep) the model resident without doing real judging work. The
/// output is capped to one token (the discarded completion is irrelevant — the point is
/// the resident weights), and Ollama is asked via `keep_alive` to hold the model in
/// memory for [`KEEPWARM_RESIDENCY_SECS`]. Returns `true` if the endpoint answered (the
/// model is warm), `false` on any transport/status error — callers treat this as
/// best-effort and never block on it. Does NOT touch verdicts or actuation.
pub async fn keep_warm(client: &reqwest::Client, endpoint: &str, model: &str) -> bool {
    // JEF-337: keep-warm's one-token ping fires without any gate — ollama owns concurrency,
    // so a background ping overlapping a judging/propose request is fine. Best-effort and
    // bounded by the reqwest timeout.
    let body = json!({
        "model": model,
        "temperature": 0,
        "max_tokens": 1,
        "keep_alive": KEEPWARM_RESIDENCY_SECS,
        "messages": [{ "role": "user", "content": "ping" }]
    });
    matches!(
        client.post(endpoint).json(&body).send().await,
        Ok(response) if response.status().is_success()
    )
}

/// Keep the configured model warm so the first judging pass after an engine restart
/// isn't glacial (the "no verdicts for ~20 min after restart" pain, JEF-63). A CPU-only
/// local model takes minutes to load its weights; once Ollama unloads an idle model
/// (default 5 min) the next adjudication eats that cold-load before any verdict lands.
///
/// This spawns a lightweight background task that warms the model once at startup and
/// then pings it on an interval shorter than Ollama's unload timeout, keeping the model
/// resident between judging passes. It is strictly **best-effort and shadow-safe**: the
/// ping is a one-token no-op chat (see [`keep_warm`]) that touches no verdict, enable, or
/// actuation path, and a down or slow endpoint is logged at debug and retried next tick —
/// it never blocks the engine loop or the output state.
///
/// A **no-op when no model is configured** (`PROTECTOR_ENGINE_MODEL` empty → no task is
/// spawned) and when keep-warm is disabled (`PROTECTOR_ENGINE_KEEPWARM_SECS=0`).
/// Returns the spawned task's handle (so the caller can abort it on shutdown), or `None`
/// when nothing was spawned. The engine calls this opaquely — keep-warm lives here, with
/// the client, the interval const, and the [`keep_warm`] ping it drives.
pub fn spawn_keep_warm() -> Option<tokio::task::JoinHandle<()>> {
    let (endpoint, model, interval) = keep_warm_plan(config(), keepwarm_interval())?;
    tracing::info!(
        %model,
        interval_secs = interval.as_secs(),
        "keep-warm: pinging the model to stay resident between judging passes"
    );
    Some(tokio::spawn(async move {
        let client = client();
        let mut ticker = tokio::time::interval(interval);
        // Skip missed ticks rather than bursting catch-up pings if a tick is delayed
        // (e.g. the runtime was busy) — one ping per interval is all keep-warm needs.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            // The first tick fires immediately, giving the startup warm-up; subsequent
            // ticks are the periodic keep-alive.
            ticker.tick().await;
            if keep_warm(&client, &endpoint, &model).await {
                tracing::debug!(%model, "keep-warm ping ok (model resident)");
            } else {
                tracing::debug!(%model, "keep-warm ping failed (model down?); retrying next tick");
            }
        }
    }))
}

/// The pure keep-warm gating decision, split out of [`spawn_keep_warm`] so it's testable
/// without spawning a task or reading process env. Returns `Some((endpoint, model,
/// interval))` only when BOTH a model is configured (`config`) AND keep-warm is enabled
/// (`interval`); `None` otherwise — i.e. a no-op when `PROTECTOR_ENGINE_MODEL` is empty
/// or `PROTECTOR_ENGINE_KEEPWARM_SECS=0`.
fn keep_warm_plan(
    config: Option<(String, String)>,
    interval: Option<Duration>,
) -> Option<(String, String, Duration)> {
    let (endpoint, model) = config?;
    let interval = interval?;
    Some((endpoint, model, interval))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bounded fallback builder must succeed and yield a usable client — this is the
    /// path `client()` lands on when the primary builder fails, and the whole point is
    /// that it still applies a timeout rather than degrading to an unbounded client.
    #[test]
    fn timeout_only_fallback_builds() {
        assert!(
            timeout_only_client(30).is_ok(),
            "the timeout-only fallback builder must produce a client"
        );
    }

    /// A hung endpoint must not block forever: a client built with a sub-second timeout
    /// returns an error promptly rather than hanging. This asserts the *bound* exists on
    /// the fallback shape (a reqwest `Client` with only `.timeout(..)` set), which is what
    /// keeps a builder-failure fallback safe.
    #[tokio::test]
    async fn timeout_only_client_is_bounded() {
        let client = timeout_only_client(1).expect("fallback client builds");
        // 10.255.255.1 is a reserved, unroutable address — the connect stalls, so only
        // the total timeout can end this. If the fallback were unbounded it would hang.
        let started = std::time::Instant::now();
        let result = client
            .post("http://10.255.255.1:9/v1/chat/completions")
            .json(&json!({"model": "x", "messages": []}))
            .send()
            .await;
        assert!(result.is_err(), "the request must fail, not succeed");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a 1s-timeout client must give up well under 5s, took {:?}",
            started.elapsed()
        );
    }

    /// `client()` returns a usable client regardless of which build path it takes, and
    /// the fallback counter increment is a no-op without an OTLP meter (must not panic).
    #[test]
    fn client_constructs_and_fallback_counter_is_safe() {
        let _ = client();
        record_fallback();
    }

    #[test]
    fn keepwarm_unset_uses_the_default_interval() {
        assert_eq!(
            parse_keepwarm_interval(None),
            Some(Duration::from_secs(DEFAULT_KEEPWARM_SECS)),
            "an unset PROTECTOR_ENGINE_KEEPWARM_SECS must fall back to the default"
        );
    }

    #[test]
    fn keepwarm_zero_disables() {
        assert_eq!(
            parse_keepwarm_interval(Some("0")),
            None,
            "PROTECTOR_ENGINE_KEEPWARM_SECS=0 must disable keep-warm"
        );
        assert_eq!(
            parse_keepwarm_interval(Some("  0  ")),
            None,
            "surrounding whitespace must not defeat the disable sentinel"
        );
    }

    #[test]
    fn keepwarm_positive_is_that_many_seconds() {
        assert_eq!(
            parse_keepwarm_interval(Some("90")),
            Some(Duration::from_secs(90))
        );
        assert_eq!(
            parse_keepwarm_interval(Some(" 90 ")),
            Some(Duration::from_secs(90)),
            "trimmed values must parse"
        );
    }

    #[test]
    fn keepwarm_unparseable_falls_back_to_the_default() {
        assert_eq!(
            parse_keepwarm_interval(Some("not-a-number")),
            Some(Duration::from_secs(DEFAULT_KEEPWARM_SECS)),
            "a garbage value must fall back to the default, not disable keep-warm"
        );
        assert_eq!(
            parse_keepwarm_interval(Some("")),
            Some(Duration::from_secs(DEFAULT_KEEPWARM_SECS)),
            "an empty value must fall back to the default"
        );
    }

    /// Keep-warm (JEF-107) is gated on BOTH a configured model and a non-zero interval.
    /// With no model configured it must be a no-op regardless of the interval — that's
    /// the `PROTECTOR_ENGINE_MODEL` empty case the issue requires.
    #[test]
    fn keep_warm_is_a_noop_with_no_model() {
        assert!(
            keep_warm_plan(None, Some(Duration::from_secs(240))).is_none(),
            "no model configured must mean no keep-warm, even with a valid interval"
        );
    }

    /// With keep-warm disabled (`PROTECTOR_ENGINE_KEEPWARM_SECS=0` → `None` interval) it
    /// must be a no-op even when a model IS configured.
    #[test]
    fn keep_warm_is_a_noop_when_disabled() {
        assert!(
            keep_warm_plan(Some(("http://ollama/v1".into(), "qwen2.5:3b".into())), None).is_none(),
            "a zero interval must disable keep-warm even with a model configured"
        );
    }

    /// With both a model and an interval, keep-warm carries the endpoint/model/interval
    /// through unchanged for the spawned task to use.
    #[test]
    fn keep_warm_plans_when_model_and_interval_present() {
        let plan = keep_warm_plan(
            Some(("http://ollama/v1".into(), "qwen2.5:3b".into())),
            Some(Duration::from_secs(120)),
        );
        assert_eq!(
            plan,
            Some((
                "http://ollama/v1".to_string(),
                "qwen2.5:3b".to_string(),
                Duration::from_secs(120)
            ))
        );
    }

    /// Fix 4: the chat request body must carry a `max_tokens` bound so a misbehaving or
    /// compromised endpoint can't be asked for an unbounded completion. (The body is built
    /// inline in `chat`; assert the constant feeds a request body of the expected shape.)
    #[test]
    fn chat_body_includes_a_max_tokens_bound() {
        let body = json!({
            "model": "m",
            "temperature": 0,
            "max_tokens": MAX_COMPLETION_TOKENS,
            "messages": [{ "role": "user", "content": "p" }]
        });
        assert_eq!(
            body["max_tokens"].as_u64(),
            Some(MAX_COMPLETION_TOKENS as u64),
            "the chat body must bound the completion with max_tokens"
        );
        const {
            assert!(MAX_COMPLETION_TOKENS > 0, "the bound must be positive");
            // The response body cap must be a sane, non-trivial bound.
            assert!(
                MAX_RESPONSE_BYTES >= 4 * 1024,
                "the response cap must leave room for a verdict JSON"
            );
        }
    }

    /// Fix 4: a response body over the cap is rejected (returns `None`) rather than
    /// buffered whole. Served from a localhost test server so no real model is needed.
    #[tokio::test]
    async fn oversized_response_is_rejected_not_buffered() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // A server that answers with a body just over the cap.
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Drain the request line(s) enough to respond; we don't need to parse it.
                let mut buf = [0u8; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
                let oversized = "x".repeat(MAX_RESPONSE_BYTES + 1024);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    oversized.len(),
                    oversized
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });

        let client = timeout_only_client(5).unwrap();
        let endpoint = format!("http://{addr}/v1/chat/completions");
        let out = chat(&client, &endpoint, "m", "p").await;
        assert!(
            out.is_none(),
            "an over-cap response must be rejected as None, not buffered/parsed"
        );
        let _ = server.await;
    }

    /// JEF-301: a server 500 (the status Ollama returns when it OOM-crashes ingesting a heavy
    /// prompt) must be treated as a FAILURE — `chat` returns `None` so the caller records an
    /// `Uncertain` that feeds the backoff/breaker — NOT parsed as a verdict. Served from a
    /// localhost server so no real model is needed.
    #[tokio::test]
    async fn server_500_is_treated_as_unavailable_not_a_verdict() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                // A 500 with a JSON error body — exactly what an OOM-crashing Ollama returns.
                // Even though the body IS valid JSON, it is NOT a verdict and must be rejected
                // on the status alone.
                let payload =
                    json!({ "error": "model runner has crashed (out of memory)" }).to_string();
                let resp = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });

        let client = timeout_only_client(5).unwrap();
        let endpoint = format!("http://{addr}/v1/chat/completions");
        let out = chat(&client, &endpoint, "m", "p").await;
        assert!(
            out.is_none(),
            "a 500 must be treated as unavailable (None), never parsed as a verdict"
        );
        let _ = server.await;
    }

    /// JEF-337: with the serialization gate removed, concurrent `chat` calls run in PARALLEL —
    /// protector no longer caps itself to one in-flight model request; ollama owns concurrency.
    /// A localhost server records the max number of requests open at once; each lingers briefly
    /// so overlap is observable. We fire 5 `chat` calls with a `JoinSet` and assert the server
    /// saw MORE THAN ONE in flight at once — the exact opposite of the old single-flight gate,
    /// proving the gate is truly gone (not reborn under another name).
    #[tokio::test]
    async fn chat_calls_run_concurrently_without_a_serialization_gate() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const CALLS: usize = 5;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));

        let srv_in_flight = in_flight.clone();
        let srv_max = max_in_flight.clone();
        let server = tokio::spawn(async move {
            for _ in 0..CALLS {
                let (mut sock, _) = listener.accept().await.unwrap();
                let in_flight = srv_in_flight.clone();
                let max = srv_max.clone();
                tokio::spawn(async move {
                    // Drain the request enough to respond; we don't need to parse it.
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    // Record the concurrency this request observed. With the gate gone,
                    // overlapping requests push `now` above 1.
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max.fetch_max(now, Ordering::SeqCst);
                    // Linger so the other in-flight requests overlap this one and are seen
                    // by the counter above.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    let payload = json!({
                        "choices": [{ "message": { "content": "ok" } }]
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });

        let endpoint = format!("http://{addr}/v1/chat/completions");
        let mut set = tokio::task::JoinSet::new();
        for i in 0..CALLS {
            let endpoint = endpoint.clone();
            // Distinct prompts so every one of the CALLS requests reaches the wire — this
            // test is about concurrency (the server must see all CALLS in flight).
            let prompt = format!("p{i}");
            set.spawn(async move {
                let client = timeout_only_client(5).unwrap();
                chat(&client, &endpoint, "m", &prompt).await
            });
        }
        while let Some(res) = set.join_next().await {
            assert_eq!(
                res.unwrap().as_deref(),
                Some("ok"),
                "every concurrent chat call must still complete normally"
            );
        }
        server.await.unwrap();

        assert!(
            max_in_flight.load(Ordering::SeqCst) > 1,
            "with the serialization gate removed, model calls must overlap (saw {})",
            max_in_flight.load(Ordering::SeqCst)
        );
    }

    /// JEF-337: the concurrency knob defaults to a generous [`DEFAULT_MODEL_CONCURRENCY`]
    /// (never 1), falls back to it for an unset / unparseable / `0` value (a `0` would
    /// deadlock `buffer_unordered`), and honours any positive value verbatim.
    #[test]
    fn model_concurrency_defaults_generously_and_honours_the_env() {
        assert_eq!(
            parse_model_concurrency(None),
            DEFAULT_MODEL_CONCURRENCY,
            "unset must fall back to the generous default"
        );
        assert_ne!(DEFAULT_MODEL_CONCURRENCY, 1, "the default must never be 1");
        assert_eq!(
            parse_model_concurrency(Some("0")),
            DEFAULT_MODEL_CONCURRENCY,
            "0 must fall back to the default (never a deadlocking buffer_unordered(0))"
        );
        assert_eq!(
            parse_model_concurrency(Some("not-a-number")),
            DEFAULT_MODEL_CONCURRENCY,
            "an unparseable value must fall back to the default"
        );
        assert_eq!(
            parse_model_concurrency(Some("16")),
            16,
            "a positive value is honoured verbatim"
        );
        assert_eq!(
            parse_model_concurrency(Some(" 4 ")),
            4,
            "a trimmed positive value is honoured"
        );
    }

    /// Fix 5: in-cluster endpoints pass the zero-egress check; an external one fails closed
    /// without the opt-in and passes with it. The homelab default (`.svc.cluster.local`)
    /// must pass unchanged.
    #[test]
    fn endpoint_egress_validation() {
        for in_cluster in [
            "http://localhost:11434/v1/chat/completions",
            "http://127.0.0.1:11434/v1",
            "http://10.0.0.5:11434/v1",
            "http://192.168.1.10:11434/v1",
            "http://ollama:11434/v1",
            "http://ollama.ai.svc:11434/v1",
            "http://ollama.ai.svc.cluster.local:11434/v1",
            "ollama.ai.svc.cluster.local:11434/v1", // no scheme
            "http://[::1]:11434/v1",
        ] {
            assert!(
                validate_in_cluster_endpoint(in_cluster, false).is_ok(),
                "{in_cluster} must be treated as in-cluster"
            );
        }
        // External fails closed without the opt-in, passes with it.
        assert!(validate_in_cluster_endpoint("https://evil.com/v1", false).is_err());
        assert!(validate_in_cluster_endpoint("https://8.8.8.8/v1", false).is_err());
        assert!(validate_in_cluster_endpoint("https://evil.com/v1", true).is_ok());
    }

    #[test]
    fn endpoint_host_parses_authority() {
        assert_eq!(
            endpoint_host("http://ollama.ai.svc.cluster.local:11434/v1/chat"),
            Some("ollama.ai.svc.cluster.local".to_string())
        );
        assert_eq!(
            endpoint_host("https://user:pass@HOST.example.com:443/x"),
            Some("host.example.com".to_string())
        );
        assert_eq!(endpoint_host("http://[::1]:8080/"), Some("::1".to_string()));
        // FQDN trailing dot is stripped (matches the runtime's resolution).
        assert_eq!(
            endpoint_host("http://evil.com./hook"),
            Some("evil.com".to_string())
        );
    }

    /// JEF-364: there is no completion cache, so an identical prompt is re-sent to the
    /// endpoint on every pass — a transient `Uncertain` reply must NOT stick. This is the
    /// exact hazard the JEF-362 LRU introduced: it cached any 200 (including a reply that
    /// parses to `Uncertain`, which the verdict store deliberately never caches so JEF-234
    /// backoff can retry), pinning the entry to that stale completion. A counting localhost
    /// server proves the second call re-hits the wire (two connections) rather than being
    /// served a cached completion, and the caller could get a *fresh* answer the next pass.
    #[tokio::test]
    async fn identical_prompt_is_resent_no_cached_completion_sticks() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Each connection is answered in order: first an `Uncertain`-shaped verdict (the
        // transient reply that must not be pinned), then a decided verdict on the retry.
        let uncertain = json!({ "verdict": "Uncertain", "reason": "model unsure" }).to_string();
        let decided = json!({ "verdict": "Benign", "reason": "settled" }).to_string();
        let responses = [uncertain.clone(), decided.clone()];

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let srv_count = count.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let n = srv_count.fetch_add(1, Ordering::SeqCst);
                let content = responses
                    .get(n)
                    .cloned()
                    .unwrap_or_else(|| responses[responses.len() - 1].clone());
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let payload =
                        json!({ "choices": [{ "message": { "content": content } }] }).to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });

        let client = timeout_only_client(5).unwrap();
        let endpoint = format!("http://{addr}/v1/chat/completions");

        // First pass: the transient `Uncertain` completion.
        let first = chat(&client, &endpoint, "m", "same-prompt").await;
        assert_eq!(
            first.as_deref(),
            Some(uncertain.as_str()),
            "first pass returns the transient Uncertain reply"
        );

        // Second pass, byte-identical prompt: must re-hit the wire, NOT replay a cached
        // completion — so it can pick up the endpoint's now-decided answer.
        let second = chat(&client, &endpoint, "m", "same-prompt").await;
        assert_eq!(
            second.as_deref(),
            Some(decided.as_str()),
            "the identical prompt must be re-sent and get the fresh reply — no cached Uncertain sticks"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "both passes must hit the wire — there is no completion cache to short-circuit the retry"
        );
        server.abort();
    }

    /// The keep-warm residency hint must outlast the ping interval, so the model never
    /// lapses out of memory between pings even if one tick is delayed. A `const` block
    /// makes this a compile-time guarantee rather than a runtime check.
    #[test]
    fn residency_outlasts_the_default_interval() {
        const {
            assert!(
                KEEPWARM_RESIDENCY_SECS > DEFAULT_KEEPWARM_SECS,
                "the Ollama keep_alive residency must exceed the ping interval"
            );
        }
    }
}
