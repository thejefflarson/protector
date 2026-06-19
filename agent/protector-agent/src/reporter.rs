//! The reporter: batches observations and POSTs them to the engine's behavioral
//! ingest (`/behavior`, ADR-0014). In-cluster, mesh-protected hop; the agent never
//! sends behavioral data anywhere else (the data is a map of the cluster — it stays
//! in-cluster, per VISION's local-first conviction).

use std::time::Duration;

use crate::behavior::Observation;

/// POSTs batches of [`Observation`]s to `{base}/behavior`.
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

    /// Send one batch. Best-effort: a failed POST is logged and dropped — behavioral
    /// evidence is additive, so a lost batch costs a little freshness, never
    /// correctness, and must never wedge the agent.
    pub async fn send(&self, batch: &[Observation]) {
        if batch.is_empty() {
            return;
        }
        match self.client.post(&self.url).json(batch).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(n = batch.len(), "reported behavioral observations");
            }
            Ok(resp) => tracing::warn!(status = %resp.status(), "behavior ingest rejected batch"),
            Err(error) => tracing::warn!(%error, "behavior ingest unreachable"),
        }
    }
}
