//! protector-agent — the first-party eBPF behavioral collector (ADR-0014).
//!
//! Runs as a DaemonSet on each node. It loads eBPF probes (with `--features ebpf`),
//! resolves each event's cgroup→pod, batches the normalized observations, and POSTs
//! them to the engine's behavioral ingest (`/behavior`). Passive and read-only: it
//! observes, it never blocks, kills, or rewrites — enforcement stays the engine's
//! reversible network cut.

mod coalesce;
mod observer;
#[cfg(any(feature = "ebpf", test))]
mod pod;
mod reporter;

use std::io::IsTerminal;
use std::time::Duration;

use protector_behavior::RuntimeObservation;
use tokio::sync::mpsc;

use coalesce::Coalescer;
use reporter::Reporter;

/// Max distinct coalesced keys the debounce buffer holds before a forced flush (JEF-296).
/// Bounds memory and keeps a flushed batch well under the engine's 1024 per-batch cap, so
/// the "behavior batch exceeds the per-batch cap" WARN stays quiet under normal load.
const MAX_BATCH: usize = 512;

/// How often the delivered/rejected heartbeat is logged (JEF-240 surfacing). Kept on its
/// own long cadence — decoupled from the (much shorter) debounce window so shrinking the
/// window doesn't spam this operator line.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Default debounce/coalesce window (JEF-296). Conservative within the ticket's 2–5s band:
/// long enough to collapse high-frequency near-duplicate churn into one compact batch, short
/// enough that a mundane signal's freshness lag stays trivial against the engine's 300s
/// evidence TTL. Tunable via `PROTECTOR_AGENT_DEBOUNCE_MS`. Alerts never wait for it.
const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(3000);

/// Parse the debounce window from `PROTECTOR_AGENT_DEBOUNCE_MS`, falling back to
/// [`DEFAULT_DEBOUNCE`] when unset, unparseable, or zero (a zero period would panic
/// `tokio::time::interval`, and "no debounce" is not a supported mode — the whole point is
/// to coalesce). Pure over its input so it's unit-testable without the environment.
fn parse_debounce_window(raw: Option<String>) -> Duration {
    match raw.as_deref().map(str::trim).map(str::parse::<u64>) {
        Some(Ok(ms)) if ms > 0 => Duration::from_millis(ms),
        _ => DEFAULT_DEBOUNCE,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "protector_agent=info".into()),
        )
        // ANSI only on a real terminal — otherwise kubectl logs are full of escape codes.
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    // The engine's runtime-evidence ingest base URL (the agent appends `/behavior`).
    let endpoint = std::env::var("PROTECTOR_AGENT_ENDPOINT")
        .unwrap_or_else(|_| "http://protector.protector.svc.cluster.local:9999".to_string());
    let debounce_window = parse_debounce_window(std::env::var("PROTECTOR_AGENT_DEBOUNCE_MS").ok());
    tracing::info!(
        %endpoint,
        debounce_ms = debounce_window.as_millis(),
        "protector-agent starting"
    );
    let mut reporter = Reporter::new(&endpoint)?;

    let (tx, mut rx) = mpsc::channel::<RuntimeObservation>(4096);

    // Debouncing reporter task (JEF-296): coalesce mundane observations over a short window
    // and flush one compact, deduped batch — collapsing the high-frequency near-duplicate
    // churn (repeated cluster egress, repeated execs) the engine would otherwise wake on and
    // dedup only after the fact. Alerts bypass the buffer and POST immediately (live
    // corroboration must stay low-latency). Best-effort sends — a lost batch costs freshness,
    // never correctness (behavioral evidence is additive). A running count is logged at info
    // once per HEARTBEAT_INTERVAL so an operator can confirm the agent is actually reporting.
    let flusher = tokio::spawn(async move {
        let mut coalescer = Coalescer::new(MAX_BATCH);
        let mut reported_since_tick: usize = 0;
        let mut window = tokio::time::interval(debounce_window);
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        // Each interval's first tick fires immediately; consume them so the first window
        // flush / heartbeat reflects a real elapsed interval, not startup.
        window.tick().await;
        heartbeat.tick().await;
        loop {
            tokio::select! {
                recv = rx.recv() => match recv {
                    Some(obs) => {
                        // `offer` returns anything to POST NOW: an alert (never debounced),
                        // or the drained buffer if this new distinct key hit the max-size cap.
                        let immediate = coalescer.offer(obs);
                        if !immediate.is_empty() {
                            reported_since_tick += reporter.send(&immediate).await;
                        }
                    }
                    None => {
                        reporter.send(&coalescer.drain()).await; // drain on shutdown
                        break;
                    }
                },
                _ = window.tick() => {
                    // Window elapsed: flush the coalesced batch. Skip the round-trip when
                    // nothing accumulated (a quiet window stays silent).
                    if !coalescer.is_empty() {
                        reported_since_tick += reporter.send(&coalescer.drain()).await;
                    }
                }
                _ = heartbeat.tick() => {
                    // JEF-240: surface cumulative delivered/rejected alongside the interval
                    // count so a wedged ingest (token skew → every batch 401'd) is visible
                    // here, not just in a per-batch WARN. A rising `rejected` against a flat
                    // `delivered` is the agent dropping 100% of signal.
                    let (delivered_total, rejected_total) = reporter.counters();
                    tracing::info!(
                        reported = reported_since_tick,
                        delivered_total,
                        rejected_total,
                        "behavioral observations reported (last {}s)",
                        HEARTBEAT_INTERVAL.as_secs(),
                    );
                    reported_since_tick = 0;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debounce_window_parses_a_valid_millis_value() {
        assert_eq!(
            parse_debounce_window(Some("2000".into())),
            Duration::from_millis(2000)
        );
        // Surrounding whitespace (a common env/file artifact) is tolerated.
        assert_eq!(
            parse_debounce_window(Some("  5000\n".into())),
            Duration::from_millis(5000)
        );
    }

    #[test]
    fn debounce_window_falls_back_to_the_default() {
        // Unset, unparseable, and zero all fall back — a zero period would panic the
        // interval, and "no debounce" is not a supported mode.
        assert_eq!(parse_debounce_window(None), DEFAULT_DEBOUNCE);
        assert_eq!(parse_debounce_window(Some("soon".into())), DEFAULT_DEBOUNCE);
        assert_eq!(parse_debounce_window(Some("0".into())), DEFAULT_DEBOUNCE);
        assert_eq!(parse_debounce_window(Some("".into())), DEFAULT_DEBOUNCE);
    }
}
