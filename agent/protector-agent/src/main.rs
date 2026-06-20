//! protector-agent — the first-party eBPF behavioral collector (ADR-0014).
//!
//! Runs as a DaemonSet on each node. It loads eBPF probes (with `--features ebpf`),
//! resolves each event's cgroup→pod, batches the normalized observations, and POSTs
//! them to the engine's behavioral ingest (`/behavior`). Passive and read-only: it
//! observes, it never blocks, kills, or rewrites — enforcement stays the engine's
//! reversible network cut.

mod behavior;
mod observer;
#[cfg(any(feature = "ebpf", test))]
mod pod;
mod reporter;

use std::time::Duration;

use tokio::sync::mpsc;

use behavior::Observation;
use reporter::Reporter;

/// Flush a batch at most this large, or every [`FLUSH_INTERVAL`], whichever first.
/// 30s (well under the engine's 300s evidence TTL): each POST wakes the engine loop,
/// so a tight interval would make it re-process every few seconds for mundane churn.
const MAX_BATCH: usize = 512;
const FLUSH_INTERVAL: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "protector_agent=info".into()),
        )
        .init();

    // The engine's runtime-evidence ingest base URL (the agent appends `/behavior`).
    let endpoint = std::env::var("PROTECTOR_AGENT_ENDPOINT")
        .unwrap_or_else(|_| "http://protector.protector.svc.cluster.local:9999".to_string());
    tracing::info!(%endpoint, "protector-agent starting");
    let reporter = Reporter::new(&endpoint)?;

    let (tx, mut rx) = mpsc::channel::<Observation>(4096);

    // Batching reporter task: flush on size or interval. Best-effort sends — a lost
    // batch costs freshness, never correctness (behavioral evidence is additive).
    let flusher = tokio::spawn(async move {
        let mut batch: Vec<Observation> = Vec::with_capacity(MAX_BATCH);
        let mut tick = tokio::time::interval(FLUSH_INTERVAL);
        loop {
            tokio::select! {
                recv = rx.recv() => match recv {
                    Some(obs) => {
                        batch.push(obs);
                        if batch.len() >= MAX_BATCH {
                            reporter.send(&batch).await;
                            batch.clear();
                        }
                    }
                    None => {
                        reporter.send(&batch).await; // drain on shutdown
                        break;
                    }
                },
                _ = tick.tick() => {
                    reporter.send(&batch).await;
                    batch.clear();
                }
            }
        }
    });

    // Collection. Default build is a no-op; `--features ebpf` loads the real probes.
    #[cfg(not(feature = "ebpf"))]
    observer::NoopObserver.run(tx).await;
    #[cfg(feature = "ebpf")]
    {
        // Events are attributed by pod UID (from the cgroup); the engine resolves UID →
        // namespace/pod via its watch, so the agent needs no cluster credentials.
        if let Err(error) = observer::EbpfObserver.run(tx).await {
            // Degrade, don't crashloop (ADR-0014): a missing hook / failed attach should
            // leave the pod up for inspection, not hammer restarts.
            tracing::error!(%error, "ebpf observer exited; idling (no collection)");
            std::future::pending::<()>().await
        }
    }

    let _ = flusher.await;
    Ok(())
}
