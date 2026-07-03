//! Pure manifest rendering for the live cuts: the additive `AdminNetworkPolicy` deny
//! (ADR-0007, [`render_deny`]) and the default-deny isolation `NetworkPolicy`
//! (ADR-0010, [`render_isolation`]), plus the deterministic object naming and selector
//! helpers. Split out of the actuator module root purely to keep every file under the
//! 1,000-line cap (repo CLAUDE.md). These functions touch nothing — they only build the
//! JSON the cluster-facing actuators apply, and they are the unit-tested half.

use super::super::{Mitigation, ProposedAction};
use crate::engine::graph::NodeKey;

/// The namespace component of a `workload/<ns>/<kind>/<name>` node key — `None` for any
/// non-workload key. The key seam (kind discriminant + namespace segment) is owned by
/// [`NodeKey`]; this is the workload-only wrapper the actuator needs for ANP selectors.
pub(super) fn workload_namespace(key: &NodeKey) -> Option<&str> {
    (key.kind() == "workload").then(|| key.namespace())?
}

/// A deterministic, DNS-safe object name (`<prefix>-<hash of cut>`) so re-apply is
/// idempotent and revert can find the engine-owned object.
pub(super) fn object_name(prefix: &str, mitigation: &Mitigation) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    mitigation.cut_signature().hash(&mut hasher);
    format!("{prefix}-{:016x}", hasher.finish())
}

/// An ANP namespaced-peer selector for `namespace`, narrowed to a `podSelector`
/// when `labels` are known (pod-granularity, ADR-0007) and a namespace-only
/// selector otherwise. Used for both the `subject` and the `from` peer.
fn selector(
    namespace: &str,
    labels: &std::collections::BTreeMap<String, String>,
) -> serde_json::Value {
    let namespace_selector =
        serde_json::json!({ "matchLabels": { "kubernetes.io/metadata.name": namespace } });
    if labels.is_empty() {
        serde_json::json!({ "namespaces": namespace_selector })
    } else {
        serde_json::json!({
            "pods": {
                "namespaceSelector": namespace_selector,
                "podSelector": { "matchLabels": labels }
            }
        })
    }
}

/// Render the additive deny object for a network cut (ADR-0007): an
/// `AdminNetworkPolicy` with an `action: Deny` ingress rule selecting the target
/// and denying ingress from the source. Pod-granularity when the cut carries the
/// endpoints' labels, namespace-granularity otherwise. Returns `None` for any
/// non-network or non-workload-endpoint cut.
pub fn render_deny(mitigation: &Mitigation) -> Option<serde_json::Value> {
    if mitigation.action != ProposedAction::DenyNetworkPath {
        return None;
    }
    let source_ns = workload_namespace(&mitigation.cut.from)?;
    let target_ns = workload_namespace(&mitigation.cut.to)?;
    Some(serde_json::json!({
        "apiVersion": "policy.networking.k8s.io/v1alpha1",
        "kind": "AdminNetworkPolicy",
        "metadata": {
            "name": object_name("protector-deny", mitigation),
            "labels": { "app.kubernetes.io/managed-by": "protector" }
        },
        "spec": {
            "priority": 1000,
            "subject": selector(target_ns, &mitigation.cut.to_labels),
            "ingress": [{
                "action": "Deny",
                "from": [selector(source_ns, &mitigation.cut.from_labels)]
            }]
        }
    }))
}

/// Render the additive deny object for the **isolation** actuator (ADR-0010): a
/// default-deny `NetworkPolicy` selecting the cut's *source* workload by label, so
/// flannel/kube-router quarantines it. This serves two actions, both of which
/// isolate `cut.from`:
///
/// - [`DenyNetworkPath`](ProposedAction::DenyNetworkPath): the flannel fallback for a
///   `reaches`/`can-egress` edge-cut, quarantining the edge's source; and
/// - [`QuarantineEntry`](ProposedAction::QuarantineEntry): the *default* containment,
///   whose `cut.from` is the internet-facing breach **entry** by construction — so the
///   same `cut.from` selector isolates the entry, never a deeper/objective workload; and
/// - [`QuarantineWorkload`](ProposedAction::QuarantineWorkload): the JEF-284 quarantine of
///   a compromised pod on the chain (remotely-exploitable or actively-exploited), whose
///   `cut.from` is that qualifying pod (a self-reference carrying its labels) — so the
///   same selector isolates exactly that pod, never a merely-reached objective.
///
/// Returns `None` for any other action, a non-workload source, or a source with no
/// labels (we will not widen to a whole namespace).
pub fn render_isolation(mitigation: &Mitigation) -> Option<serde_json::Value> {
    if !matches!(
        mitigation.action,
        ProposedAction::DenyNetworkPath
            | ProposedAction::QuarantineEntry
            | ProposedAction::QuarantineWorkload
    ) {
        return None;
    }
    let source_ns = workload_namespace(&mitigation.cut.from)?;
    if mitigation.cut.from_labels.is_empty() {
        return None;
    }
    Some(serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": object_name("protector-isolate", mitigation),
            "namespace": source_ns,
            "labels": { "app.kubernetes.io/managed-by": "protector" }
        },
        // No ingress/egress rules + both policyTypes ⇒ deny all traffic to/from
        // the selected pod (quarantine).
        "spec": {
            "podSelector": { "matchLabels": mitigation.cut.from_labels },
            "policyTypes": ["Ingress", "Egress"]
        }
    }))
}
