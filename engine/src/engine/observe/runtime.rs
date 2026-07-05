//! The RuntimeEvidence ingest: live behavioral signals that supply the action bar's
//! `corroborated-now` predicate. The first-party eBPF agent (and any sensor with a
//! translation adapter) POSTs normalized [`RuntimeObservation`]s to the tool-agnostic
//! behavioral port (ADR-0003), the `/behavior` route the engine exposes; [`RuntimeEvents`]
//! holds the recent ones.
//!
//! A runtime signal is a *stream*, not a Kubernetes object, so it can't be reflected like
//! the rest of the graph — hence the HTTP ingest.
//!
//! Runtime signals are deliberately **short-lived**: "something is happening now"
//! is only true for a window, so observations expire after a TTL. A stale alert
//! must not keep corroborating a chain forever — corroboration is live evidence or
//! it is nothing.
//!
//! The store is pure and unit-tested; the HTTP receiver is the cluster-facing glue.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use tokio::sync::mpsc::Sender;

use super::ingest_guard::{
    DEFAULT_BURST, DEFAULT_RATE_PER_SEC, IngestToken, RateLimit, bearer_auth, rate_limit,
};
use super::{AgentReport, RuntimeObservation};
use crate::engine::state::AgentLivenessStore;

/// A time-windowed store of recent runtime observations. Thread-safe so the HTTP
/// ingest task and the engine loop can share it.
pub struct RuntimeEvents {
    inner: Mutex<Vec<(Instant, RuntimeObservation)>>,
    ttl: Duration,
}

impl RuntimeEvents {
    /// Upper bound on retained observations, enforced on top of the TTL so an
    /// ingest flood can't grow the store without limit before entries expire.
    const MAX_EVENTS: usize = 4096;

    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
            ttl,
        }
    }

    /// Record an observation as of now, pruning anything past the TTL. Returns whether
    /// it was a **change** — see [`Self::record_at`].
    pub fn record(&self, observation: RuntimeObservation) -> bool {
        self.record_at(Instant::now(), observation)
    }

    /// The observations still within the TTL window as of now.
    pub fn current(&self) -> Vec<RuntimeObservation> {
        self.current_at(Instant::now())
    }

    /// Record an observation as of `now`, pruning expired entries. Returns whether the
    /// store actually **changed** — i.e. this was a (workload, behavior) we weren't
    /// already holding. A repeat of a signal we already have refreshes its freshness and
    /// returns `false`, so the caller can skip waking the engine for activity that
    /// wouldn't alter the graph (the same connections, again). This is what keeps the
    /// agent's high-volume churn from churning a process pass per report.
    fn record_at(&self, now: Instant, observation: RuntimeObservation) -> bool {
        let mut events = self.inner.lock().expect("runtime-events mutex poisoned");
        events.retain(|(at, _)| now.duration_since(*at) < self.ttl);
        if let Some(slot) = events
            .iter_mut()
            .find(|(_, e)| same_signal(e, &observation))
        {
            slot.0 = now; // already known — refresh its TTL, but nothing new to react to
            return false;
        }
        events.push((now, observation));
        // Hard cap independent of the TTL: an ingest flood within one TTL window
        // would otherwise grow this unbounded. Drop the oldest beyond the cap.
        if events.len() > Self::MAX_EVENTS {
            let excess = events.len() - Self::MAX_EVENTS;
            events.drain(0..excess);
        }
        true
    }

    fn current_at(&self, now: Instant) -> Vec<RuntimeObservation> {
        self.inner
            .lock()
            .expect("runtime-events mutex poisoned")
            .iter()
            .filter(|(at, _)| now.duration_since(*at) < self.ttl)
            .map(|(_, obs)| obs.clone())
            .collect()
    }
}

/// Two observations are the **same signal** when they attribute the same behavior to the
/// same workload. The sensor identity and observation time are metadata, not identity — a
/// repeat of the same behavior is not a new fact, so it shouldn't wake the engine.
fn same_signal(a: &RuntimeObservation, b: &RuntimeObservation) -> bool {
    a.behavior == b.behavior && a.attribution == b.attribution
}

/// Shared state for the ingest handlers: the event store, a wake channel, and the per-node
/// agent-liveness store (JEF-308) the `/agent-liveness` beacon feeds.
type IngestState = (Arc<RuntimeEvents>, Sender<()>, Arc<AgentLivenessStore>);

/// Receive a batch of normalized [`RuntimeObservation`]s on the tool-agnostic
/// behavioral port (ADR-0014) — the shape the first-party eBPF agent (and any sensor
/// with a translation adapter) POSTs. Each is recorded; the engine is woken once, and
/// only if the batch actually changed the store. The agent re-reports the same
/// connections continuously, so most batches are pure repeats — those refresh TTLs but
/// must not churn a process pass, which is the whole point of gating the wake here.
async fn ingest_behavior(
    State((events, notify, _liveness)): State<IngestState>,
    Json(observations): Json<Vec<RuntimeObservation>>,
) -> StatusCode {
    if record_batch(&events, observations) {
        let _ = notify.try_send(());
    }
    StatusCode::OK
}

/// Receive a batch of per-node [`AgentReport`] liveness beacons (JEF-308) and record them into the
/// liveness store. Unlike a behavior, a beacon does NOT wake the engine — liveness is read at pass
/// time; a beacon only refreshes freshness. A beacon arrives every window even when the node saw
/// nothing, which is exactly what lets a quiet node read HEALTHY-quiet instead of blind. Same body
/// cap / authn / rate limit as the sibling routes; over-cap batches are truncated defensively.
async fn ingest_agent_liveness(
    State((_events, _notify, liveness)): State<IngestState>,
    Json(reports): Json<Vec<AgentReport>>,
) -> StatusCode {
    for report in reports.into_iter().take(MAX_BATCH) {
        liveness.record(report);
    }
    StatusCode::OK
}

/// Upper bound on observations accepted per `/behavior` batch. Each `record()` is an
/// O(n) scan over up to `MAX_EVENTS` entries while the store mutex is held, so an
/// oversized batch would do O(batch x MAX_EVENTS) work under the lock — a cheap DoS
/// (Fix 7). Sized to match the audit sibling's `MAX_EVENTS_PER_BODY` (1024): under real
/// cluster load the agent legitimately posts batches of ~512 (the old 256 cap was
/// silently truncating them and dropping live runtime signals — a corroboration blind
/// spot), so 1024 gives ~2x headroom while still bounding work-under-lock for an abusive
/// batch (the 256KB body cap + per-peer rate limit are the other two bounds).
const MAX_BATCH: usize = 1024;

/// Record at most [`MAX_BATCH`] observations from one batch, returning whether the
/// store changed (so the caller wakes the engine only on a real change). Split out and
/// pure-over-the-store so the batch cap is unit-testable without an HTTP server.
fn record_batch(events: &RuntimeEvents, observations: Vec<RuntimeObservation>) -> bool {
    let total = observations.len();
    if total > MAX_BATCH {
        tracing::warn!(
            total,
            cap = MAX_BATCH,
            "behavior batch exceeds the per-batch cap; processing only the first {MAX_BATCH}"
        );
    }
    let mut changed = false;
    for obs in observations.into_iter().take(MAX_BATCH) {
        changed |= events.record(obs);
    }
    changed
}

/// Serve the runtime-evidence ingest. `/behavior` accepts a batch of normalized observations
/// on the tool-agnostic behavioral port (ADR-0003) from the first-party eBPF agent or any
/// sensor with a translation adapter; `/agent-liveness` accepts the per-node liveness beacon.
/// This is the cluster-facing glue; the store it drives is what the tests cover.
pub async fn serve_runtime(
    addr: SocketAddr,
    events: Arc<RuntimeEvents>,
    notify: Sender<()>,
    liveness: Arc<AgentLivenessStore>,
) -> anyhow::Result<()> {
    // App-layer authn (Fix A): require `Authorization: Bearer <token>` matching a
    // configured shared secret, rejected 401 BEFORE deserialization. Resolved once at
    // startup (file-before-env). If unconfigured the layer is omitted and we log a loud
    // WARNING — so the engine can be deployed ahead of the Secret/agent roll out. This
    // is authentication (who may post); the mesh's Linkerd authz (which identities may
    // connect) is layered separately in the cluster repo.
    let token = IngestToken::from_env();
    // Per-peer rate limit (Fix B): bound ingest request-rate per source even with a
    // valid token. In-process token bucket; well above legitimate agent volume.
    let limiter = RateLimit::new(DEFAULT_RATE_PER_SEC, DEFAULT_BURST);

    let mut app = Router::new()
        .route("/behavior", post(ingest_behavior))
        // The per-node agent-liveness beacon (JEF-308) — signal-flow liveness, not pod-Ready.
        .route("/agent-liveness", post(ingest_agent_liveness))
        // A real alert/batch is small; cap the body so a client can't OOM the engine
        // with a giant POST (mirrors the webhook server). The body cap, MAX_EVENTS, and
        // the per-batch MAX_BATCH all remain in force alongside authn + rate limiting.
        .layer(DefaultBodyLimit::max(256 * 1024))
        .with_state((events, notify, liveness));

    // Rate limit runs on every request, authenticated or not.
    app = app.layer(axum::middleware::from_fn_with_state(limiter, rate_limit));

    match token {
        Some(token) => {
            app = app.layer(axum::middleware::from_fn_with_state(token, bearer_auth));
            tracing::info!(%addr, "runtime-evidence ingest listening (/behavior, /agent-liveness) — bearer-authenticated");
        }
        None => {
            tracing::warn!(
                %addr,
                "runtime-evidence ingest is UNAUTHENTICATED — set PROTECTOR_INGEST_TOKEN_FILE \
                 to require a bearer token. Any caller that can reach :9999 can post forged \
                 observations."
            );
        }
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    // ConnectInfo is required by the per-peer rate limiter — serve with peer addresses.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::Attribution;
    use super::*;
    use crate::engine::graph::Behavior;
    use serde_json::json;

    fn obs(rule: &str) -> RuntimeObservation {
        RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: None,
            observed_at_ms: None,
            node: None,
            behavior: Behavior::Alert { rule: rule.into() },
        }
    }

    #[test]
    fn observations_expire_after_the_ttl() {
        let store = RuntimeEvents::new(Duration::from_secs(300));
        let t0 = Instant::now();
        store.record_at(t0, obs("Terminal shell in container"));

        // Within the window: present.
        assert_eq!(store.current_at(t0 + Duration::from_secs(60)).len(), 1);
        // Past the window: gone.
        assert!(store.current_at(t0 + Duration::from_secs(301)).is_empty());
    }

    #[test]
    fn recording_prunes_expired_entries() {
        let store = RuntimeEvents::new(Duration::from_secs(300));
        let t0 = Instant::now();
        store.record_at(t0, obs("old"));
        // A later record past the first's TTL prunes it, leaving only the new one.
        store.record_at(t0 + Duration::from_secs(400), obs("new"));
        let current = store.current_at(t0 + Duration::from_secs(400));
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].behavior, Behavior::Alert { rule: "new".into() });
    }

    #[test]
    fn repeat_signal_is_not_a_change_but_refreshes_ttl() {
        let store = RuntimeEvents::new(Duration::from_secs(300));
        let t0 = Instant::now();
        // First sighting is a change — the engine should wake.
        assert!(store.record_at(t0, obs("shell")));
        // The same (workload, behavior) again is NOT a change — no wake — but it
        // refreshes the entry's freshness.
        assert!(!store.record_at(t0 + Duration::from_secs(290), obs("shell")));
        // Past the ORIGINAL expiry (300) but within the TTL of the refresh → still held,
        // and still just one entry (the repeat updated in place, didn't duplicate).
        let current = store.current_at(t0 + Duration::from_secs(400));
        assert_eq!(current.len(), 1);
        // A different behavior on the same workload IS a change.
        assert!(store.record_at(t0 + Duration::from_secs(400), obs("c2")));
        assert_eq!(store.current_at(t0 + Duration::from_secs(400)).len(), 2);
    }

    /// Fix 7: a batch over the per-batch cap is truncated, so a single POST can't drive
    /// thousands of O(n) `record()` scans under the store mutex. Only the first
    /// `MAX_BATCH` distinct observations land.
    #[test]
    fn oversized_behavior_batch_is_truncated() {
        let store = RuntimeEvents::new(Duration::from_secs(300));
        // Each distinct rule is a distinct entry, so the count is the work done.
        let batch: Vec<RuntimeObservation> = (0..MAX_BATCH + 500)
            .map(|i| obs(&format!("rule-{i}")))
            .collect();
        let changed = record_batch(&store, batch);
        assert!(changed, "a fresh batch changes the store");
        assert_eq!(
            store.current_at(Instant::now()).len(),
            MAX_BATCH,
            "only the first MAX_BATCH observations are processed"
        );
    }

    #[test]
    fn normalized_behavior_batch_deserializes_from_the_wire_contract() {
        // The shape the first-party eBPF agent (or any sensor) POSTs to /behavior.
        let body = json!([
            {"namespace": "app", "pod": "web",
             "behavior": {"kind": "network_connection", "peer": "1.2.3.4:443", "internet": true}},
            {"namespace": "app", "pod": "web",
             "behavior": {"kind": "secret_read", "secret": "app/session-key"}},
            {"namespace": "app", "pod": "web",
             "behavior": {"kind": "library_loaded", "name": "log4j-core-2.14.jar"}}
        ]);
        let obs: Vec<RuntimeObservation> = serde_json::from_value(body).expect("deserializes");
        assert_eq!(obs.len(), 3);
        assert_eq!(
            obs[0].behavior,
            Behavior::NetworkConnection {
                peer: "1.2.3.4:443".into(),
                internet: true
            }
        );
        // A mundane behavior must NOT corroborate — only alerts do (else everything,
        // which all make connections, would fire the action bar).
        assert!(!obs[0].behavior.is_alert());
        assert!(!obs[1].behavior.is_alert());
    }

    #[test]
    fn connection_fingerprints_are_coarse_so_peer_churn_does_not_rejudge() {
        // Different peers collapse to the same coarse key, so mundane connection churn
        // doesn't bust the verdict cache and re-judge every pass on the slow model.
        let a = Behavior::NetworkConnection {
            peer: "10.0.0.1:5432".into(),
            internet: false,
        };
        let b = Behavior::NetworkConnection {
            peer: "10.0.0.2:5432".into(),
            internet: false,
        };
        assert_eq!(a.fingerprint_key(), b.fingerprint_key());
        assert_eq!(a.fingerprint_key(), "egress:cluster");
        // But a stable fact (a loaded library) keeps its identity in the fingerprint.
        let lib = Behavior::LibraryLoaded {
            name: "openssl".into(),
        };
        assert_eq!(lib.fingerprint_key(), "lib:openssl");
    }
}
