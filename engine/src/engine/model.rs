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
fn timeout_only_client(timeout: u64) -> reqwest::Result<reqwest::Client> {
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
/// itself bounded. Either fallback is loud: a `tracing::warn!` plus a
/// `protector.engine.model_client_fallback` counter so the path is observable in metrics.
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
                // Even the minimal builder failed: `Client::new()` has NO timeouts, the
                // exact stall we bound against, so this must be loud too.
                tracing::warn!(%error, "timeout-only model client builder also failed; using a default client WITHOUT timeouts");
                record_fallback();
                reqwest::Client::new()
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
}
