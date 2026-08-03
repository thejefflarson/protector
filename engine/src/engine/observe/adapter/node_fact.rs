//! The node-containment rails' fleet observation (ADR-0040 §3/§6): a metadata-only
//! mapping from the watched `Node` fleet to the
//! [`node_containment::NodeFact`](crate::engine::respond::actuator::node_containment::NodeFact)
//! shape [`cordon_decision`](crate::engine::respond::actuator::node_containment::cordon_decision)/
//! [`evaluate_proposal`](crate::engine::respond::actuator::node_containment::evaluate_proposal)
//! consult.
//!
//! Mirrors [`super::placement::PlacementAdapter`] in spirit (a small, single-purpose
//! observation of one Kubernetes kind) but NOT in shape: [`observe_node_facts`] does not
//! implement the graph-contributing [`super::Adapter`] trait, because
//! [`NodeFact`](crate::engine::respond::actuator::node_containment::NodeFact) is
//! deliberately NOT the graph's [`crate::engine::graph::Node::Host`] (that module's own
//! doc) — it stays a plain, out-of-graph data type so the rail predicates remain pure and
//! testable over hand-built fixtures without a full [`crate::engine::graph::SecurityGraph`].
//! This function is [`crate::engine::Engine::process`]'s direct source for the fleet it
//! passes to the rails, built fresh each pass from [`crate::engine::observe::Snapshot::nodes`].
//!
//! **Reads exactly five fields per `Node` and nothing else** — the metadata-only
//! discipline the module doc promises: the name; the canonical
//! `node-role.kubernetes.io/control-plane` label, the legacy
//! `node-role.kubernetes.io/master` label, AND `spec.taints` (any value, including
//! absent-but-keyed, counts for the labels — kubeadm sets them to the empty string; see
//! [`is_control_plane`] for why all three are checked); `spec.unschedulable`; and whether
//! [`CORDON_OWNER_ANNOTATION`] is set to exactly [`CORDON_OWNER_VALUE`]. In particular it
//! never reads `status` (conditions, capacity, allocatable, images, kubelet version) —
//! there is no sensitive `.data` on a `Node` the way there is on a `Secret`, but the rails
//! have no use for that operational detail either, so it is left unread.

use k8s_openapi::api::core::v1::Node;

use crate::engine::respond::actuator::node_containment::{
    CORDON_OWNER_ANNOTATION, CORDON_OWNER_VALUE, NodeFact,
};

/// The label kubeadm (and every major managed-Kubernetes control plane) sets on a
/// control-plane node — the primary source of [`NodeFact::control_plane`] (VISION:
/// protector cannot touch the control plane, ADR-0040 §5). Also the taint KEY kubeadm
/// applies alongside the label (`NoSchedule`) — [`is_control_plane`] checks it as its own,
/// independent signal, since an operator can taint without labeling (or vice versa).
const CONTROL_PLANE_LABEL: &str = "node-role.kubernetes.io/control-plane";

/// The legacy pre-1.20 spelling of [`CONTROL_PLANE_LABEL`]/its taint — some distros and
/// long-lived clusters still carry `master` rather than `control-plane`. Checked as an
/// equally authoritative signal, never treated as inferior to the canonical spelling.
const LEGACY_CONTROL_PLANE_LABEL: &str = "node-role.kubernetes.io/master";

/// Whether `node` carries ANY recognized control-plane signal — the canonical label, the
/// legacy label, or a taint keyed on either (regardless of effect: a control-plane-shaped
/// taint key is itself the signal, not specifically its `NoSchedule` effect). FAIL CLOSED
/// by union, not intersection: a node matching just ONE of these is control-plane, full
/// stop — a heterogeneous or partially-migrated cluster (legacy label only, or a taint
/// applied without the modern label) must never be misread as a plain worker. A node
/// carrying NONE of these signals is treated as an ordinary, cordon-eligible worker — the
/// sound default for vanilla/kubeadm clusters, where every worker legitimately carries no
/// `node-role.kubernetes.io/*` marker at all (only control-plane nodes are labeled); the
/// deterministic rails' own worker-floor/one-node-cap remain the backstop for any
/// residual misclassification this narrower, three-signal check still misses.
fn is_control_plane(node: &Node) -> bool {
    let labelled = node.metadata.labels.as_ref().is_some_and(|labels| {
        labels.contains_key(CONTROL_PLANE_LABEL) || labels.contains_key(LEGACY_CONTROL_PLANE_LABEL)
    });
    let tainted = node
        .spec
        .as_ref()
        .and_then(|spec| spec.taints.as_ref())
        .is_some_and(|taints| {
            taints.iter().any(|taint| {
                taint.key == CONTROL_PLANE_LABEL || taint.key == LEGACY_CONTROL_PLANE_LABEL
            })
        });
    labelled || tainted
}

/// Map the observed `Node` fleet to the [`NodeFact`] shape the node-containment rails
/// consult. Pure and total: every `Node` in `nodes` yields exactly one `NodeFact`, in the
/// same order, so an empty/absent watch simply yields an empty fleet (the rails then fail
/// closed on any host they can't find, per `evaluate_proposal`'s doc — never fabricate a
/// passing rail from a missing fact).
pub fn observe_node_facts(nodes: &[Node]) -> Vec<NodeFact> {
    nodes
        .iter()
        .filter_map(|node| {
            let name = node.metadata.name.clone()?;
            let control_plane = is_control_plane(node);
            let schedulable = !node
                .spec
                .as_ref()
                .and_then(|spec| spec.unschedulable)
                .unwrap_or(false);
            let owned_by_protector = node
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(CORDON_OWNER_ANNOTATION))
                .is_some_and(|value| value == CORDON_OWNER_VALUE);
            Some(NodeFact {
                name,
                control_plane,
                schedulable,
                owned_by_protector,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(value: serde_json::Value) -> Node {
        serde_json::from_value(value).expect("valid Node fixture")
    }

    #[test]
    fn a_plain_worker_node_maps_to_a_schedulable_unowned_non_control_plane_fact() {
        let n = node(json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "node-1"},
            "spec": {}
        }));
        let facts = observe_node_facts(&[n]);
        assert_eq!(
            facts,
            vec![NodeFact {
                name: "node-1".to_string(),
                control_plane: false,
                schedulable: true,
                owned_by_protector: false,
            }]
        );
    }

    #[test]
    fn a_control_plane_labelled_node_is_marked_control_plane() {
        let n = node(json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "cp-1", "labels": {"node-role.kubernetes.io/control-plane": ""}},
            "spec": {}
        }));
        let facts = observe_node_facts(&[n]);
        assert!(
            facts[0].control_plane,
            "the control-plane label must be recognized"
        );
    }

    #[test]
    fn the_legacy_master_label_is_also_control_plane() {
        // Some distros/long-lived clusters still carry the pre-1.20 `master` spelling
        // instead of `control-plane` — it must be an equally authoritative signal, not a
        // second-class one, or a legacy-labelled control plane is misclassified as a
        // cordon-eligible worker.
        let n = node(json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "cp-1", "labels": {"node-role.kubernetes.io/master": ""}},
            "spec": {}
        }));
        let facts = observe_node_facts(&[n]);
        assert!(
            facts[0].control_plane,
            "the legacy master label must be recognized"
        );
    }

    #[test]
    fn a_control_plane_taint_with_no_label_at_all_is_still_control_plane() {
        // Fail closed: a control-plane-shaped taint is its own signal, independent of
        // whether the node also carries the label — an operator who taints without
        // labeling (or a label that was stripped) must not slip through as a worker.
        let n = node(json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "cp-1"},
            "spec": {
                "taints": [
                    {"key": "node-role.kubernetes.io/control-plane", "effect": "NoSchedule"}
                ]
            }
        }));
        let facts = observe_node_facts(&[n]);
        assert!(
            facts[0].control_plane,
            "a control-plane taint alone must mark the node control-plane"
        );
    }

    #[test]
    fn a_legacy_master_taint_is_also_recognized() {
        let n = node(json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "cp-1"},
            "spec": {
                "taints": [{"key": "node-role.kubernetes.io/master", "effect": "NoSchedule"}]
            }
        }));
        let facts = observe_node_facts(&[n]);
        assert!(facts[0].control_plane);
    }

    #[test]
    fn an_unrelated_taint_does_not_mark_a_node_control_plane() {
        // Only a control-plane-shaped taint KEY counts — an ordinary workload taint
        // (dedicated-node-pool style) must not false-positive a worker into
        // control-plane (which would make it un-cordonable but is not the fail-closed
        // direction this check protects — it is checked for completeness alongside the
        // fail-closed cases above).
        let n = node(json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "node-1"},
            "spec": {
                "taints": [{"key": "dedicated", "value": "gpu", "effect": "NoSchedule"}]
            }
        }));
        let facts = observe_node_facts(&[n]);
        assert!(!facts[0].control_plane);
    }

    #[test]
    fn a_node_with_no_role_signal_at_all_is_the_ordinary_cordon_eligible_worker_default() {
        // Vanilla/kubeadm workers carry NO node-role label or taint at all — that is the
        // expected, sound "worker" case, not a gap: only a POSITIVE control-plane signal
        // (label or taint, canonical or legacy) ever excludes a node here.
        let n = node(json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "node-1"},
            "spec": {}
        }));
        let facts = observe_node_facts(&[n]);
        assert!(!facts[0].control_plane);
    }

    #[test]
    fn spec_unschedulable_maps_to_not_schedulable() {
        let n = node(json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "node-1"},
            "spec": {"unschedulable": true}
        }));
        let facts = observe_node_facts(&[n]);
        assert!(!facts[0].schedulable);
    }

    #[test]
    fn the_cordon_ownership_annotation_maps_to_owned_by_protector() {
        let n = node(json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {
                "name": "node-1",
                "annotations": {"protector.jeffl.es/cordoned-by": "protector"}
            },
            "spec": {"unschedulable": true}
        }));
        let facts = observe_node_facts(&[n]);
        assert!(facts[0].owned_by_protector);
    }

    #[test]
    fn a_foreign_cordon_annotation_value_does_not_count_as_protector_owned() {
        // A human/autoscaler cordon carries no protector annotation at all in practice,
        // but even a look-alike key with a DIFFERENT value must not be read as ours —
        // exact-value match only (mirrors `cordon_decision`'s ownership discipline).
        let n = node(json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {
                "name": "node-1",
                "annotations": {"protector.jeffl.es/cordoned-by": "someone-else"}
            },
            "spec": {"unschedulable": true}
        }));
        let facts = observe_node_facts(&[n]);
        assert!(!facts[0].owned_by_protector);
    }

    #[test]
    fn a_node_with_no_name_is_skipped() {
        // Every real `Node` from the apiserver carries a name; this only guards the
        // theoretical malformed case rather than panicking.
        let n = node(json!({"apiVersion": "v1", "kind": "Node", "metadata": {}, "spec": {}}));
        assert!(observe_node_facts(&[n]).is_empty());
    }

    #[test]
    fn maps_the_whole_fleet_in_order() {
        let a = node(json!({
            "apiVersion": "v1", "kind": "Node", "metadata": {"name": "a"}, "spec": {}
        }));
        let b = node(json!({
            "apiVersion": "v1", "kind": "Node", "metadata": {"name": "b"}, "spec": {}
        }));
        let facts = observe_node_facts(&[a, b]);
        let names: Vec<_> = facts.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn status_fields_are_never_read_regardless_of_content() {
        // A rich `status` block (images, conditions, capacity/allocatable) must not
        // change the mapped fact at all — the metadata-only discipline this module's
        // doc promises. Compare against the same node with no status.
        let bare = node(json!({
            "apiVersion": "v1", "kind": "Node", "metadata": {"name": "node-1"}, "spec": {}
        }));
        let with_status = node(json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "node-1"},
            "spec": {},
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
                "capacity": {"cpu": "8", "memory": "32Gi"},
                "allocatable": {"cpu": "7500m", "memory": "30Gi"},
                "images": [{"names": ["example.com/some-image:1"], "sizeBytes": 12345}]
            }
        }));
        assert_eq!(
            observe_node_facts(&[bare]),
            observe_node_facts(&[with_status])
        );
    }
}
