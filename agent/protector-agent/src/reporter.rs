//! The reporter: batches observations and POSTs them to the engine's behavioral
//! ingest (`/behavior`, ADR-0014). In-cluster, mesh-protected hop; the agent never
//! sends behavioral data anywhere else (the data is a map of the cluster — it stays
//! in-cluster, per VISION's local-first conviction).
//!
//! The POST carries an `Authorization: Bearer <token>` (Fix A) so the engine can
//! reject forged observations from any other caller that can reach :9999. The token
//! is the shared secret the engine also reads; authentication (this header) is
//! complementary to the cluster's Linkerd mesh authorization.

use std::time::Duration;

use protector_behavior::RuntimeObservation;

/// POSTs batches of [`RuntimeObservation`]s to `{base}/behavior`.
pub struct Reporter {
    client: reqwest::Client,
    url: String,
    /// Shared-secret bearer for the engine's ingest authn (Fix A). `None` = send no
    /// `Authorization` header (the engine then runs the ingest unauthenticated, which
    /// it warns about); set it once the Secret has rolled out.
    token: Option<String>,
}

/// Resolve the ingest token from the environment, file-before-env — matching the
/// engine's own resolution so the agent and engine read the same secret:
///
///   * `PROTECTOR_INGEST_TOKEN_FILE` — a mounted file (takes precedence); its trailing
///     newline (the usual secret-file artifact) is trimmed.
///   * `PROTECTOR_INGEST_TOKEN` — an inline value.
///
/// `None` when neither is set or the resolved value is empty.
fn ingest_token() -> Option<String> {
    if let Ok(path) = std::env::var("PROTECTOR_INGEST_TOKEN_FILE") {
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let token = contents.trim().to_string();
                if token.is_empty() {
                    tracing::warn!(%path, "PROTECTOR_INGEST_TOKEN_FILE is empty — ingest token unset");
                    return None;
                }
                return Some(token);
            }
            Err(error) => {
                tracing::warn!(%path, %error, "PROTECTOR_INGEST_TOKEN_FILE unreadable — ingest token unset");
                return None;
            }
        }
    }
    std::env::var("PROTECTOR_INGEST_TOKEN")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

impl Reporter {
    /// `base` is the engine's runtime-ingest URL (e.g.
    /// `http://protector.protector.svc.cluster.local:9999`). The ingest token is read
    /// once from the environment (file before env).
    pub fn new(base: &str) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        let token = ingest_token();
        if token.is_none() {
            tracing::warn!(
                "no ingest token configured (PROTECTOR_INGEST_TOKEN / \
                 PROTECTOR_INGEST_TOKEN_FILE) — posting behavioral observations \
                 without an Authorization header"
            );
        }
        Ok(Self {
            client,
            url: format!("{}/behavior", base.trim_end_matches('/')),
            token,
        })
    }

    /// Build the POST for `batch`, attaching the bearer header when a token is
    /// configured. Split out so the header wiring is unit-testable without a server.
    fn build_request(&self, batch: &[RuntimeObservation]) -> reqwest::RequestBuilder {
        let mut req = self.client.post(&self.url).json(batch);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        req
    }

    /// Send one batch; returns how many observations were accepted (0 on failure or an
    /// empty batch). Best-effort: a failed POST is logged and dropped — behavioral
    /// evidence is additive, so a lost batch costs a little freshness, never correctness,
    /// and must never wedge the agent. The caller rolls the count into an interval
    /// heartbeat; per-send detail stays at debug.
    pub async fn send(&self, batch: &[RuntimeObservation]) -> usize {
        if batch.is_empty() {
            return 0;
        }
        match self.build_request(batch).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(n = batch.len(), "reported behavioral observations");
                batch.len()
            }
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), "behavior ingest rejected batch");
                0
            }
            Err(error) => {
                tracing::warn!(%error, "behavior ingest unreachable");
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protector_behavior::{Attribution, Behavior};

    fn reporter_with(token: Option<&str>) -> Reporter {
        Reporter {
            client: reqwest::Client::new(),
            url: "http://engine.svc:9999/behavior".to_string(),
            token: token.map(str::to_string),
        }
    }

    fn sample_batch() -> Vec<RuntimeObservation> {
        vec![RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: Some("agent".into()),
            observed_at_ms: None,
            behavior: Behavior::SecretRead {
                secret: "app/session-key".into(),
            },
        }]
    }

    /// When a token is configured the POST carries `Authorization: Bearer <token>`.
    #[test]
    fn attaches_bearer_header_when_token_set() {
        let reporter = reporter_with(Some("s3cr3t"));
        let req = reporter
            .build_request(&sample_batch())
            .build()
            .expect("request builds");
        let auth = req
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .expect("Authorization header present");
        assert_eq!(auth, "Bearer s3cr3t");
    }

    /// Without a token, no Authorization header is sent (the engine warns + accepts,
    /// or rejects if it has a token — the rollout-ordering contract).
    #[test]
    fn omits_bearer_header_when_token_unset() {
        let reporter = reporter_with(None);
        let req = reporter
            .build_request(&sample_batch())
            .build()
            .expect("request builds");
        assert!(
            req.headers().get(reqwest::header::AUTHORIZATION).is_none(),
            "no Authorization header when token unset"
        );
        // The body is still the JSON batch — auth is the only thing that changed.
        assert_eq!(req.url().as_str(), "http://engine.svc:9999/behavior");
    }
}
