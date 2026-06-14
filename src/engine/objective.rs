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
//! Scope (ADR-0005): this slice recognizes Credential Access (reach a Secret) and
//! Escape to Host (reach a Host). Capability-shaped objectives (RBAC
//! self-escalation, deploy/exec) arrive with the Capability-node work.

use super::attack::{
    AttackRef, CREDENTIAL_ACCESS, ESCAPE_TO_HOST, EXFILTRATION, capability_technique,
};
use super::graph::{Node, NodeKey, SecurityGraph};

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

/// The default recognizer set for this slice.
pub fn default_recognizers() -> Vec<Box<dyn ObjectiveRecognizer>> {
    vec![
        Box::new(SecretObjective),
        Box::new(HostObjective),
        Box::new(CapabilityObjective),
        Box::new(ExfiltrationObjective),
    ]
}
