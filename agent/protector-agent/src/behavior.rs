//! The behavioral-port wire contract (ADR-0014).
//!
//! These mirror the engine's `Behavior` / `RuntimeObservation` types. They are a
//! *deliberate duplicate*, not a shared crate: per ADR-0003 the contract between a
//! sensor and the engine is the **JSON**, not a Rust type — so the agent can evolve
//! and ship independently as long as the shapes agree. The serde test pins the shape.

use serde::{Deserialize, Serialize};

/// What a workload actually did. Serde-tagged exactly as the engine expects:
/// `{"kind": "network_connection", "peer": "1.2.3.4:443", "internet": true}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Behavior {
    /// A sensor rule fired — "something alarming, now." (The agent rarely emits this;
    /// it's the lane Falco's adapter uses. Kept for shape parity.)
    Alert { rule: String },
    /// An outbound connection the workload made; `internet` if it left the cluster.
    NetworkConnection { peer: String, internet: bool },
    /// A read of a mounted secret's contents.
    SecretRead { secret: String },
    /// A load of a shared library / dependency artifact.
    LibraryLoaded { name: String },
}

/// One normalized observation — the element of the batch POSTed to the engine's
/// `/behavior` ingest. The agent attributes by **pod UID** (parsed from the cgroup);
/// the engine resolves UID → namespace/pod via its pod watch, so the agent needs no
/// cluster credentials (ADR-0014). Matches the engine's `RuntimeObservation` (whose
/// namespace/pod are serde-defaulted, so omitting them here is fine).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub pod_uid: Option<String>,
    pub behavior: Behavior,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_serializes_to_the_engine_contract() {
        let obs = Observation {
            pod_uid: Some("3f5e-uid".into()),
            behavior: Behavior::NetworkConnection {
                peer: "1.2.3.4:443".into(),
                internet: true,
            },
        };
        let v: serde_json::Value = serde_json::to_value(&obs).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "pod_uid": "3f5e-uid",
                "behavior": {"kind": "network_connection", "peer": "1.2.3.4:443", "internet": true}
            })
        );
        // Round-trips back to the same value.
        let back: Observation = serde_json::from_value(v).unwrap();
        assert_eq!(back, obs);
    }
}
