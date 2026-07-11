//! The Health port (ADR-0002, Question 3): is a workload **alive**, **degraded**,
//! or **halted**?
//!
//! This is the observe-and-report half of Q3. It answers "what is production's
//! state right now," which serves two later purposes (ADR-0002): as a **guard**,
//! no automated cut may push a protected workload toward `halted`; and as the
//! basis for the **closed-loop verification** that makes a lever trustworthy
//! (predict effect → apply → measure against the prediction → auto-revert on
//! divergence). That measured loop is hard-mode — it needs actuation and live
//! probing. What this module provides is the health *signal* both depend on.
//!
//! Like the Vulnerability port, Health abstracts its source. The richest source is
//! an SLO system (Prometheus error budgets); the default adapter here derives a
//! coarse health from **pod status** — a real signal we already observe, no extra
//! dependency — and a Prometheus-backed provider can replace [`PodStatusHealth`] with
//! its own [`assess`](PodStatusHealth::assess)-shaped adapter when that source lands.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::Pod;

use super::Snapshot;
use crate::engine::graph::NodeKey;

/// A workload's serving state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Serving normally (within error budget).
    Alive,
    /// Serving but impaired — flapping, not-ready, or burning budget.
    Degraded,
    /// Not serving.
    Halted,
}

impl Health {
    pub fn label(self) -> &'static str {
        match self {
            Health::Alive => "alive",
            Health::Degraded => "degraded",
            Health::Halted => "halted",
        }
    }
}

/// Per-workload health, keyed by workload node key.
#[derive(Debug, Default, Clone)]
pub struct HealthReport {
    states: BTreeMap<NodeKey, Health>,
}

impl HealthReport {
    /// The health of `key`. A workload we have no signal for is assumed `Alive` —
    /// absence of evidence is not evidence of an outage, and over-reporting halts
    /// would be the dangerous default for a guard.
    pub fn of(&self, key: &NodeKey) -> Health {
        self.states.get(key).copied().unwrap_or(Health::Alive)
    }

    /// `(alive, degraded, halted)` counts across known workloads.
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut counts = (0, 0, 0);
        for h in self.states.values() {
            match h {
                Health::Alive => counts.0 += 1,
                Health::Degraded => counts.1 += 1,
                Health::Halted => counts.2 += 1,
            }
        }
        counts
    }

    pub fn insert(&mut self, key: NodeKey, health: Health) {
        self.states.insert(key, health);
    }

    /// The keys of currently-alive workloads — the baseline an applied action
    /// promises not to take down (the closed-loop verification's protected set).
    pub fn alive_workloads(&self) -> Vec<String> {
        self.states
            .iter()
            .filter(|(_, h)| **h == Health::Alive)
            .map(|(k, _)| k.0.clone())
            .collect()
    }
}

/// Default health source: derive each workload's health from observed pod status.
/// Coarse but real and dependency-free; an SLO/Prometheus source would replace this
/// with its own [`assess`](Self::assess)-shaped adapter (there is one source today, so
/// it is used concretely rather than behind a trait).
pub struct PodStatusHealth;

impl PodStatusHealth {
    /// Assess the health of every workload in `snapshot` from its pod status,
    /// keyed exactly like the graph's workload nodes.
    pub fn assess(&self, snapshot: &Snapshot) -> HealthReport {
        let mut report = HealthReport::default();
        for pod in &snapshot.pods {
            let Some(name) = pod.metadata.name.as_deref() else {
                continue;
            };
            let namespace = pod.metadata.namespace.as_deref().unwrap_or("default");
            report.insert(
                NodeKey::workload(namespace, "Pod", name),
                Self::pod_health(pod),
            );
        }
        report
    }

    fn pod_health(pod: &Pod) -> Health {
        let Some(status) = pod.status.as_ref() else {
            return Health::Halted; // observed but no status yet ⇒ not serving
        };
        match status.phase.as_deref() {
            Some("Failed") | Some("Pending") | Some("Unknown") | None => Health::Halted,
            // A completed Job pod terminated cleanly — not an outage.
            Some("Succeeded") => Health::Alive,
            Some("Running") => {
                let crash_looping = status
                    .container_statuses
                    .iter()
                    .flatten()
                    .filter_map(|cs| cs.state.as_ref()?.waiting.as_ref()?.reason.as_deref())
                    .any(|reason| reason == "CrashLoopBackOff");
                if crash_looping {
                    return Health::Degraded;
                }
                let ready = status
                    .conditions
                    .iter()
                    .flatten()
                    .any(|c| c.type_ == "Ready" && c.status == "True");
                if ready {
                    Health::Alive
                } else {
                    Health::Degraded
                }
            }
            Some(_) => Health::Degraded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn pod(value: Value) -> Pod {
        serde_json::from_value(value).expect("valid Pod fixture")
    }

    fn health_of(status: Value) -> Health {
        let p = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p", "namespace": "app"},
            "spec": {"containers": [{"name": "c", "image": "i:1"}]},
            "status": status
        }));
        PodStatusHealth::pod_health(&p)
    }

    #[test]
    fn running_and_ready_is_alive() {
        assert_eq!(
            health_of(
                json!({"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]})
            ),
            Health::Alive
        );
    }

    #[test]
    fn running_not_ready_is_degraded() {
        assert_eq!(
            health_of(
                json!({"phase": "Running", "conditions": [{"type": "Ready", "status": "False"}]})
            ),
            Health::Degraded
        );
    }

    #[test]
    fn crashloop_is_degraded_even_if_running() {
        assert_eq!(
            health_of(json!({
                "phase": "Running",
                "conditions": [{"type": "Ready", "status": "False"}],
                "containerStatuses": [{
                    "name": "c", "image": "i:1", "ready": false, "restartCount": 9,
                    "state": {"waiting": {"reason": "CrashLoopBackOff"}}
                }]
            })),
            Health::Degraded
        );
    }

    #[test]
    fn failed_and_pending_are_halted() {
        assert_eq!(health_of(json!({"phase": "Failed"})), Health::Halted);
        assert_eq!(health_of(json!({"phase": "Pending"})), Health::Halted);
    }

    #[test]
    fn report_keys_match_workload_nodes_and_counts() {
        let snap = Snapshot {
            pods: vec![
                pod(json!({
                    "apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": "ok", "namespace": "app"},
                    "spec": {"containers": [{"name": "c", "image": "i:1"}]},
                    "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}
                })),
                pod(json!({
                    "apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": "down", "namespace": "app"},
                    "spec": {"containers": [{"name": "c", "image": "i:1"}]},
                    "status": {"phase": "Failed"}
                })),
            ],
            ..Default::default()
        };
        let report = PodStatusHealth.assess(&snap);
        // Keyed exactly like the graph's workload nodes.
        assert_eq!(
            report.of(&NodeKey::workload("app", "Pod", "ok")),
            Health::Alive
        );
        assert_eq!(
            report.of(&NodeKey::workload("app", "Pod", "down")),
            Health::Halted
        );
        assert_eq!(report.counts(), (1, 0, 1));
    }
}
