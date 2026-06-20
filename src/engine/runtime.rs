//! The RuntimeEvidence ingest: live signals from a runtime sensor (Falco via
//! falcosidekick) that supply the action bar's `corroborated-now` predicate.
//!
//! Falco is a *stream*, not a Kubernetes object, so it can't be reflected like the
//! rest of the graph. Instead falcosidekick POSTs each alert to an HTTP endpoint
//! the engine exposes; [`parse_falco_event`] normalizes it into a
//! [`RuntimeObservation`] and [`RuntimeEvents`] holds the recent ones.
//!
//! Runtime signals are deliberately **short-lived**: "something is happening now"
//! is only true for a window, so observations expire after a TTL. A stale alert
//! must not keep corroborating a chain forever — corroboration is live evidence or
//! it is nothing.
//!
//! The store and the parser are pure and unit-tested; the HTTP receiver is the
//! cluster-facing glue.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::Value;
use tokio::sync::mpsc::Sender;

use super::graph::Behavior;
use super::observe::RuntimeObservation;

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

    /// Record an observation as of now, pruning anything past the TTL.
    pub fn record(&self, observation: RuntimeObservation) {
        self.record_at(Instant::now(), observation);
    }

    /// The observations still within the TTL window as of now.
    pub fn current(&self) -> Vec<RuntimeObservation> {
        self.current_at(Instant::now())
    }

    fn record_at(&self, now: Instant, observation: RuntimeObservation) {
        let mut events = self.inner.lock().expect("runtime-events mutex poisoned");
        events.retain(|(at, _)| now.duration_since(*at) < self.ttl);
        events.push((now, observation));
        // Hard cap independent of the TTL: an ingest flood within one TTL window
        // would otherwise grow this unbounded. Drop the oldest beyond the cap.
        if events.len() > Self::MAX_EVENTS {
            let excess = events.len() - Self::MAX_EVENTS;
            events.drain(0..excess);
        }
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

/// Whether a Falco priority is **critical or higher** (Critical/Alert/Emergency).
/// protector corroborates only on these: lower priorities (Notice/Warning/…) fire
/// constantly on benign activity — a postgres health-check shell trips "Run shell
/// untrusted" at Notice — and corroboration must mean "something genuinely alarming
/// is happening now," not routine noise. Filtering here (not just at falcosidekick)
/// makes the policy protector's own, regardless of the sensor's forwarding config.
fn is_critical_or_higher(priority: &str) -> bool {
    matches!(
        priority.trim().to_ascii_lowercase().as_str(),
        "critical" | "alert" | "emergency"
    )
}

/// Normalize a Falco (falcosidekick) alert into a [`RuntimeObservation`]. Returns
/// `None` if the alert is below critical priority, or isn't attributable to a
/// specific pod (Falco's k8s metadata fields absent) — neither can corroborate a
/// chain.
pub fn parse_falco_event(event: &Value) -> Option<RuntimeObservation> {
    let priority = event.get("priority").and_then(|v| v.as_str()).unwrap_or("");
    if !is_critical_or_higher(priority) {
        return None;
    }
    let rule = event.get("rule")?.as_str()?.to_string();
    let fields = event.get("output_fields")?;
    let namespace = fields.get("k8s.ns.name")?.as_str()?.to_string();
    let pod = fields.get("k8s.pod.name")?.as_str()?.to_string();
    // Falco's rule-fired alert maps to the Alert behavior — the corroborating
    // "something alarming now" signal. It's one adapter onto the behavioral port
    // (ADR-0014); the first-party eBPF agent posts the richer behaviors directly.
    Some(RuntimeObservation {
        namespace,
        pod,
        pod_uid: None,
        behavior: Behavior::Alert { rule },
    })
}

/// Shared state for the ingest handler: the event store and a wake channel.
type IngestState = (Arc<RuntimeEvents>, Sender<()>);

/// Receive one Falco alert, record it, and wake the engine. Unparseable or
/// non-pod alerts are accepted and ignored (we still 200 so falcosidekick doesn't
/// retry-storm).
async fn ingest(
    State((events, notify)): State<IngestState>,
    Json(event): Json<Value>,
) -> StatusCode {
    if let Some(observation) = parse_falco_event(&event) {
        events.record(observation);
        // A full channel already has a pending wake — dropping this one is fine.
        let _ = notify.try_send(());
    }
    StatusCode::OK
}

/// Receive a batch of normalized [`RuntimeObservation`]s on the tool-agnostic
/// behavioral port (ADR-0014) — the shape the first-party eBPF agent (and any sensor
/// with a translation adapter) POSTs. Each is recorded and the engine is woken once.
async fn ingest_behavior(
    State((events, notify)): State<IngestState>,
    Json(observations): Json<Vec<RuntimeObservation>>,
) -> StatusCode {
    let any = !observations.is_empty();
    for obs in observations {
        events.record(obs);
    }
    if any {
        let _ = notify.try_send(());
    }
    StatusCode::OK
}

/// Serve the runtime-evidence ingest. Two routes onto the same behavioral port
/// (ADR-0014): `/` accepts a single Falco/falcosidekick alert (translated to an
/// `Alert` behavior), and `/behavior` accepts a batch of normalized observations from
/// the first-party eBPF agent or any sensor. This is the cluster-facing glue; the
/// store and parser it drives are what the tests cover.
pub async fn serve_runtime(
    addr: SocketAddr,
    events: Arc<RuntimeEvents>,
    notify: Sender<()>,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", post(ingest))
        .route("/behavior", post(ingest_behavior))
        // A real alert/batch is small; cap the body so an unauthenticated client can't
        // OOM the engine with a giant POST (mirrors the webhook server).
        .layer(DefaultBodyLimit::max(256 * 1024))
        .with_state((events, notify));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "runtime-evidence ingest listening (/, /behavior)");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obs(rule: &str) -> RuntimeObservation {
        RuntimeObservation {
            namespace: "app".into(),
            pod: "web".into(),
            pod_uid: None,
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
    fn parses_critical_falco_alert_with_pod_metadata() {
        let event = json!({
            "priority": "Critical",
            "rule": "Terminal shell in container",
            "output_fields": {
                "k8s.ns.name": "app",
                "k8s.pod.name": "web-7d8f",
                "proc.name": "bash"
            }
        });
        let parsed = parse_falco_event(&event).expect("parses");
        assert_eq!(parsed.namespace, "app");
        assert_eq!(parsed.pod, "web-7d8f");
        assert_eq!(
            parsed.behavior,
            Behavior::Alert {
                rule: "Terminal shell in container".into()
            }
        );
    }

    #[test]
    fn below_critical_alerts_are_dropped() {
        // The exact benign case from prod: postgres' health-check shell at Notice.
        let event = json!({
            "priority": "Notice",
            "rule": "Run shell untrusted",
            "output_fields": {"k8s.ns.name": "watcher", "k8s.pod.name": "watcher-db-0"}
        });
        assert!(
            parse_falco_event(&event).is_none(),
            "Notice must not corroborate"
        );
        // Warning too; only critical/alert/emergency pass.
        let warn = json!({
            "priority": "Warning", "rule": "x",
            "output_fields": {"k8s.ns.name": "a", "k8s.pod.name": "b"}
        });
        assert!(parse_falco_event(&warn).is_none());
    }

    #[test]
    fn alert_without_pod_metadata_is_dropped() {
        let event = json!({
            "priority": "Critical",
            "rule": "Some host rule",
            "output_fields": {"proc.name": "bash"}
        });
        assert!(parse_falco_event(&event).is_none());
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
