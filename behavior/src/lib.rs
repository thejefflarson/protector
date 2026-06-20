//! The behavioral-evidence wire contract (ADR-0014).
//!
//! These types are the normalized shape any sensor maps its events into and POSTs to
//! the engine's behavioral ingest: [`Behavior`] (what a workload did) and
//! [`RuntimeObservation`] (one behavior, attributed to a workload). They are shared by
//! the engine and protector's first-party eBPF agent so the two can't drift.
//!
//! Per ADR-0003 the *contract* is the JSON (`{"kind": "...", ...}`), not this Rust type
//! — a third-party sensor (Falco via its adapter) speaks the same JSON without depending
//! on this crate. The crate is a convenience for the first-party components, nothing the
//! port requires. The serde shape is pinned by the tests below.

use serde::{Deserialize, Serialize};

/// An observed runtime **behavior** — what a workload actually did, from any sensor
/// (the first-party eBPF agent, Falco, …) through the tool-agnostic behavioral port
/// (ADR-0003/0014). Typed so the engine reasons about the *signal*, not the source.
/// Serde-tagged for the normalized ingest contract (`{"kind": "...", ...}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Behavior {
    /// A sensor rule fired (e.g. a Falco alert) — "something alarming, now."
    Alert { rule: String },
    /// An outbound connection the workload made; `internet` if it left the cluster.
    NetworkConnection { peer: String, internet: bool },
    /// A read of a mounted secret's contents.
    SecretRead { secret: String },
    /// A load of a shared library / dependency artifact.
    LibraryLoaded { name: String },
}

impl Behavior {
    /// Whether this behavior **corroborates** the action bar (ADR-0009): only an
    /// alerting signal means "an attack is happening now." Mundane behaviors
    /// (connections, reads, loads) are *evidence for the model*, never blanket
    /// corroboration — otherwise every workload, which all make connections, would
    /// corroborate everything.
    pub fn is_alert(&self) -> bool {
        matches!(self, Behavior::Alert { .. })
    }

    /// A one-line, human summary for the adjudication prompt.
    pub fn summary(&self) -> String {
        match self {
            Behavior::Alert { rule } => format!("alert: {rule}"),
            Behavior::NetworkConnection { peer, internet } => format!(
                "connects to {peer}{}",
                if *internet { " (INTERNET egress)" } else { "" }
            ),
            Behavior::SecretRead { secret } => format!("reads secret {secret}"),
            Behavior::LibraryLoaded { name } => format!("loaded library {name}"),
        }
    }

    /// A COARSE, stable key for the verdict-cache fingerprint. Mundane per-peer
    /// connection churn must NOT bust the cache (that would re-judge every pass on a
    /// slow model), so connections collapse to a scope token; stable facts (alerts,
    /// libs, which secret) are kept verbatim.
    pub fn fingerprint_key(&self) -> String {
        match self {
            Behavior::Alert { rule } => format!("alert:{rule}"),
            Behavior::NetworkConnection { internet: true, .. } => "egress:internet".to_string(),
            Behavior::NetworkConnection {
                internet: false, ..
            } => "egress:cluster".to_string(),
            Behavior::SecretRead { secret } => format!("read:{secret}"),
            Behavior::LibraryLoaded { name } => format!("lib:{name}"),
        }
    }
}

/// A normalized live runtime observation about a workload — the behavioral port's input
/// shape (ADR-0014). Any sensor (the first-party eBPF agent, Falco, Tetragon, …) maps
/// its events into this; the graph sees only the normalized signal, not a vendor type.
/// `Deserialize` so a sensor can POST it directly to the normalized ingest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeObservation {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pod: String,
    /// The pod UID a sensor attributed the event to from the cgroup (the eBPF agent
    /// sets this and leaves namespace/pod empty; Falco sets namespace/pod directly).
    /// The engine resolves UID → namespace/pod via its own pod watch, so the agent
    /// needs no cluster credentials and stays node-local (ADR-0014).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_uid: Option<String>,
    /// Which sensor observed this — `"protector-agent"`, `"falco"`, … Carried into the
    /// signal's provenance so two sensors observing the same activity are corroboration,
    /// not one indistinguishable source (ADR-0003). Defaulted (older agents omit it) →
    /// the adapter falls back to its own name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// When the sensor observed it, as Unix epoch milliseconds. Freshness is a
    /// first-class correctness concern (ADR-0002), so we carry the *sensor's* observation
    /// time rather than re-stamping at adapter-run time (which can lag the real event by a
    /// batch interval + a judging pass). Defaulted → adapter uses now().
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at_ms: Option<u64>,
    /// What the workload actually did.
    pub behavior: Behavior,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behavior_serializes_to_the_kind_tagged_contract() {
        let v = serde_json::to_value(Behavior::NetworkConnection {
            peer: "1.2.3.4:443".into(),
            internet: true,
        })
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({"kind": "network_connection", "peer": "1.2.3.4:443", "internet": true})
        );
    }

    #[test]
    fn observation_roundtrips_and_omits_absent_optionals() {
        // An eBPF-agent observation: attributed by uid, ns/pod empty, source + time set.
        let obs = RuntimeObservation {
            namespace: String::new(),
            pod: String::new(),
            pod_uid: Some("uid".into()),
            source: Some("protector-agent".into()),
            observed_at_ms: Some(1_710_000_000_000),
            behavior: Behavior::SecretRead {
                secret: "app/session-key".into(),
            },
        };
        let v = serde_json::to_value(&obs).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "pod_uid": "uid",
                "source": "protector-agent",
                "observed_at_ms": 1_710_000_000_000u64,
                "behavior": {"kind": "secret_read", "secret": "app/session-key"}
            })
        );
        assert_eq!(
            serde_json::from_value::<RuntimeObservation>(v).unwrap(),
            obs
        );
    }

    #[test]
    fn falco_style_observation_deserializes_from_namespace_pod() {
        // A Falco-shaped observation: ns/pod set, no uid/source/time.
        let obs: RuntimeObservation = serde_json::from_value(serde_json::json!({
            "namespace": "app", "pod": "web",
            "behavior": {"kind": "alert", "rule": "Terminal shell in container"}
        }))
        .unwrap();
        assert_eq!(obs.namespace, "app");
        assert_eq!(obs.pod, "web");
        assert!(obs.behavior.is_alert());
    }

    #[test]
    fn only_alert_corroborates() {
        assert!(Behavior::Alert { rule: "x".into() }.is_alert());
        assert!(!Behavior::NetworkConnection {
            peer: "p".into(),
            internet: true
        }
        .is_alert());
    }
}
