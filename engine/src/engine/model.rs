//! Shared client for an OpenAI-compatible chat endpoint (a local Ollama by
//! default, a frontier gateway for escalations). Both the hypothesis source
//! (propose) and the adjudicator (judge) call through here. Local-first: point it
//! at an in-cluster model so the graph never leaves the cluster.
//!
//! This is glue — the one network call the model layers make. The prompt-building
//! and reply-parsing that wrap it are pure and tested in their own modules.

use std::time::Duration;

use serde_json::{Value, json};

/// Total request timeout in seconds, from `PROTECTOR_ENGINE_MODEL_TIMEOUT_SECS`
/// (default 30). A small local model on CPU-only hardware (a Pi cluster) can take far
/// longer than 30s to answer an adjudication prompt, so the deployment raises this; the
/// watch loop no longer starves while it waits (the reflectors run in their own tasks).
fn timeout_secs() -> u64 {
    std::env::var("PROTECTOR_ENGINE_MODEL_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
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

/// Send `prompt` as a single user message and return the assistant's text, or
/// `None` on any transport/shape error (callers degrade safely on `None`).
/// Temperature 0 for reproducible output.
pub async fn chat(
    client: &reqwest::Client,
    endpoint: &str,
    model: &str,
    prompt: &str,
) -> Option<String> {
    let body = json!({
        "model": model,
        "temperature": 0,
        "messages": [{ "role": "user", "content": prompt }]
    });
    let response = client.post(endpoint).json(&body).send().await.ok()?;
    let json: Value = response.json().await.ok()?;
    json["choices"][0]["message"]["content"]
        .as_str()
        .map(str::to_string)
}

/// The model endpoint + name, read once from `PROTECTOR_ENGINE_MODEL` /
/// `PROTECTOR_ENGINE_MODEL_NAME`. `None` when no endpoint is set (deterministic-only —
/// null hypothesizer and adjudicator). The single source of truth for the model
/// endpoint and the default model name, shared by the engine's model-backed builders
/// and by [`spawn_keep_warm`] below (so keep-warm warms exactly the configured model).
pub fn config() -> Option<(String, String)> {
    let endpoint = std::env::var("PROTECTOR_ENGINE_MODEL")
        .ok()
        .filter(|e| !e.is_empty())?;
    let name =
        std::env::var("PROTECTOR_ENGINE_MODEL_NAME").unwrap_or_else(|_| "qwen2.5:3b".to_string());
    Some((endpoint, name))
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
/// isn't glacial (the "dashboard blank ~20 min after restart" pain, JEF-63). A CPU-only
/// local model takes minutes to load its weights; once Ollama unloads an idle model
/// (default 5 min) the next adjudication eats that cold-load before any verdict lands.
///
/// This spawns a lightweight background task that warms the model once at startup and
/// then pings it on an interval shorter than Ollama's unload timeout, keeping the model
/// resident between judging passes. It is strictly **best-effort and shadow-safe**: the
/// ping is a one-token no-op chat (see [`keep_warm`]) that touches no verdict, enable, or
/// actuation path, and a down or slow endpoint is logged at debug and retried next tick —
/// it never blocks the engine loop or the dashboard.
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
