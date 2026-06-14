//! Shared client for an OpenAI-compatible chat endpoint (a local Ollama by
//! default, a frontier gateway for escalations). Both the hypothesis source
//! (propose) and the adjudicator (judge) call through here. Local-first: point it
//! at an in-cluster model so the graph never leaves the cluster.
//!
//! This is glue — the one network call the model layers make. The prompt-building
//! and reply-parsing that wrap it are pure and tested in their own modules.

use std::time::Duration;

use serde_json::{Value, json};

/// A client for the model endpoint with bounded timeouts. A slow or hung endpoint
/// then degrades to the safe `None` path (callers treat that as "no verdict") rather
/// than stalling the single engine loop indefinitely. Falls back to a default client
/// only if the TLS backend fails to initialize.
///
/// The total timeout is `PROTECTOR_ENGINE_MODEL_TIMEOUT_SECS` (default 30). A small
/// local model on CPU-only hardware (a Pi cluster) can take far longer than 30s to
/// answer an adjudication prompt, so the deployment raises this; the watch loop no
/// longer starves while it waits (the reflectors run in their own tasks).
pub fn client() -> reqwest::Client {
    let timeout = std::env::var("PROTECTOR_ENGINE_MODEL_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default()
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
