//! The reporter: batches observations and POSTs them to the engine's behavioral
//! ingest (`/behavior`, ADR-0014). In-cluster, mesh-protected hop; the agent never
//! sends behavioral data anywhere else (the data is a map of the cluster — it stays
//! in-cluster, per VISION's local-first conviction).

use std::time::Duration;

use protector_behavior::RuntimeObservation;

/// POSTs batches of [`RuntimeObservation`]s to `{base}/behavior`.
pub struct Reporter {
    client: reqwest::Client,
    url: String,
}

impl Reporter {
    /// `base` is the engine's runtime-ingest URL (e.g.
    /// `http://protector.protector.svc.cluster.local:9999`).
    pub fn new(base: &str) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            url: format!("{}/behavior", base.trim_end_matches('/')),
        })
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
        match self.client.post(&self.url).json(batch).send().await {
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
