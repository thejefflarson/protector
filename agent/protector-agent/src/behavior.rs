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
    /// Which sensor observed this (`"protector-agent"`). The engine carries it into the
    /// signal's provenance so sensors are distinguishable for corroboration (ADR-0003).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// When the agent observed it (Unix epoch millis) — the engine prefers this over its
    /// own ingest/adapter time, since freshness is correctness (ADR-0002/0014).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at_ms: Option<u64>,
    pub behavior: Behavior,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_serializes_to_the_engine_contract() {
        let obs = Observation {
            pod_uid: Some("3f5e-uid".into()),
            source: Some("protector-agent".into()),
            observed_at_ms: Some(1_710_000_000_000),
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
                "source": "protector-agent",
                "observed_at_ms": 1_710_000_000_000u64,
                "behavior": {"kind": "network_connection", "peer": "1.2.3.4:443", "internet": true}
            })
        );
        // Round-trips back to the same value.
        let back: Observation = serde_json::from_value(v).unwrap();
        assert_eq!(back, obs);
    }

    #[test]
    fn observation_omits_absent_optional_fields() {
        // An older/minimal sensor that sets neither source nor observed_at_ms produces a
        // wire shape the engine still accepts (both are serde-defaulted there too).
        let obs = Observation {
            pod_uid: Some("uid".into()),
            source: None,
            observed_at_ms: None,
            behavior: Behavior::SecretRead {
                secret: "app/session-key".into(),
            },
        };
        let v: serde_json::Value = serde_json::to_value(&obs).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "pod_uid": "uid",
                "behavior": {"kind": "secret_read", "secret": "app/session-key"}
            })
        );
    }
}
