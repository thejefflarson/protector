//! Objectives: the adversary outcomes the proof layer targets (ADR-0005).
//!
//! An objective is no longer hardcoded to "read a secret" — it is any
//! structurally-provable ATT&CK outcome, expressed as a graph node that an
//! attacker wants to reach. Each objective carries the MITRE ATT&CK
//! [`AttackRef`] it realizes, so a proven chain can say *which* technique it
//! achieves and chains can be prioritized by tactic.
//!
//! Objectives are produced by [`ObjectiveRecognizer`]s — a small registry, the
//! same pattern as the capability adapters (ADR-0003). A recognizer scans the
//! graph and marks nodes as objectives of a given technique; new objectives drop
//! in without touching the proof walk.
//!
//! Recognized objectives: Credential Access (reach a Secret), Escape to Host (reach a
//! Host), the capability-shaped outcomes (RBAC self-escalation, Deploy/Exec,
//! Persistence, Data Destruction — via the Capability node), Exfiltration (reach the
//! `internet` egress endpoint, T1041), and Data from Information Repositories (reach a
//! data-store workload, T1213).

use crate::engine::graph::attack::{
    AttackRef, CREDENTIAL_ACCESS, DATA_FROM_REPOSITORY, ESCAPE_TO_HOST, EXFILTRATION,
    capability_technique,
};
use crate::engine::graph::{Node, NodeKey, SecurityGraph};

/// A recognized objective: a graph node that is an adversary goal, with the
/// technique reaching it realizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Objective {
    pub node: NodeKey,
    pub attack: AttackRef,
}

/// Recognizes objective nodes in a graph. Each implementation marks the nodes that
/// are goals of one technique class.
pub trait ObjectiveRecognizer {
    fn recognize(&self, graph: &SecurityGraph) -> Vec<Objective>;
}

/// Every Secret is a Credential Access objective.
pub struct SecretObjective;

impl ObjectiveRecognizer for SecretObjective {
    fn recognize(&self, graph: &SecurityGraph) -> Vec<Objective> {
        graph
            .inner()
            .node_weights()
            .filter(|n| matches!(n, Node::Secret(_)))
            .map(|n| Objective {
                node: n.key(),
                attack: CREDENTIAL_ACCESS,
            })
            .collect()
    }
}

/// Every Host is an Escape-to-Host objective. Whether one is *reachable* (via an
/// `escapes-to` edge) is decided by the proof walk, not here.
pub struct HostObjective;

impl ObjectiveRecognizer for HostObjective {
    fn recognize(&self, graph: &SecurityGraph) -> Vec<Objective> {
        graph
            .inner()
            .node_weights()
            .filter(|n| matches!(n, Node::Host(_)))
            .map(|n| Objective {
                node: n.key(),
                attack: ESCAPE_TO_HOST,
            })
            .collect()
    }
}

/// Every dangerous Capability node is an objective, tagged with the technique
/// holding it realizes (Deploy Container, RBAC escalation, Data Destruction, …).
/// This is where protector targets the Impact and Persistence tactics KubeHound's
/// path-only model does not cover.
pub struct CapabilityObjective;

impl ObjectiveRecognizer for CapabilityObjective {
    fn recognize(&self, graph: &SecurityGraph) -> Vec<Objective> {
        graph
            .inner()
            .node_weights()
            .filter_map(|n| match n {
                Node::Capability(c) => {
                    capability_technique(&c.verb, &c.resource).map(|attack| Objective {
                        node: n.key(),
                        attack,
                    })
                }
                _ => None,
            })
            .collect()
    }
}

/// The `internet` egress endpoint is an Exfiltration objective (ATT&CK T1041):
/// reaching a compromised position with an internet-egress channel is where accessed
/// data leaves the cluster. The egress edges that make it reachable are minted by the
/// `EgressAdapter` (an explicit egress posture only).
pub struct ExfiltrationObjective;

impl ObjectiveRecognizer for ExfiltrationObjective {
    fn recognize(&self, graph: &SecurityGraph) -> Vec<Objective> {
        graph
            .inner()
            .node_weights()
            .filter(|n| matches!(n, Node::Endpoint(e) if e.address == "internet"))
            .map(|n| Objective {
                node: n.key(),
                attack: EXFILTRATION,
            })
            .collect()
    }
}

/// Every data-store workload (one mounting persistent storage — a database, cache, or
/// object store) is a Data-from-Information-Repositories objective (ATT&CK T1213):
/// reaching it from the internet is a data-access risk. Whether that reach is a real
/// breach or legitimate (an app reaching its OWN database) is the model's call — proof
/// only establishes that the data store is reachable.
pub struct DataStoreObjective;

impl ObjectiveRecognizer for DataStoreObjective {
    fn recognize(&self, graph: &SecurityGraph) -> Vec<Objective> {
        graph
            .inner()
            .node_weights()
            .filter(|n| matches!(n, Node::Workload(w) if w.persistent))
            .map(|n| Objective {
                node: n.key(),
                attack: DATA_FROM_REPOSITORY,
            })
            .collect()
    }
}

/// The default recognizer set for this slice.
pub fn default_recognizers() -> Vec<Box<dyn ObjectiveRecognizer>> {
    vec![
        Box::new(SecretObjective),
        Box::new(HostObjective),
        Box::new(CapabilityObjective),
        Box::new(ExfiltrationObjective),
        Box::new(DataStoreObjective),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::{Exposure, SecurityGraph, Workload};

    fn workload(name: &str, persistent: bool) -> Node {
        Node::Workload(Workload {
            namespace: "data".into(),
            name: name.into(),
            kind: "Pod".into(),
            labels: Default::default(),
            meshed: false,
            exposure: Exposure::Internal,
            runtime: vec![],
            persistent,
            misconfigs: vec![],
            rbac_findings: vec![],
        })
    }

    #[test]
    fn data_store_objective_marks_only_persistent_workloads() {
        let mut g = SecurityGraph::new();
        g.upsert_node(workload("db-0", true));
        g.upsert_node(workload("stateless-api", false));

        let objs = DataStoreObjective.recognize(&g);
        assert_eq!(
            objs.len(),
            1,
            "only the persistent workload is a data store"
        );
        assert_eq!(objs[0].node.0, "workload/data/Pod/db-0");
        assert_eq!(objs[0].attack.technique_id, "T1213");
    }
}
