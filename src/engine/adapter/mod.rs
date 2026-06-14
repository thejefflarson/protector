//! Capability adapters (ADR-0003): the only code that knows about specific tools
//! or object shapes. Each adapter answers one question by mapping a
//! [`Snapshot`](super::observe::Snapshot) into the graph vocabulary — and nothing
//! else. The core never names a product; it iterates [`Adapter`]s.
//!
//! Every adapter in this slice is deterministic and therefore emits
//! [`Grade::Proof`] edges:
//!
//! - [`WorkloadAdapter`] — Workload, Image, and Identity nodes, with the
//!   structural `runs-image` / `runs-as` edges.
//! - [`SecretMountAdapter`] — Secret nodes and `can-read` edges for secrets a pod
//!   mounts or references directly (readable with no API call).
//! - [`ReachabilityAdapter`] — `reaches` edges granted by NetworkPolicy ingress.
//! - [`PrivilegeAdapter`] — `can-do` edges from an Identity to the Secrets it can
//!   read via RBAC, and to Capability nodes for the dangerous verbs it holds
//!   (create pods, bind roles, delete PVCs, …) per the ATT&CK capability catalogue.
//! - [`HostEscapeAdapter`] — `escapes-to` edges from a Workload to its Host when
//!   the pod spec exposes a container-escape primitive (ATT&CK T1611).

use std::collections::{BTreeMap, HashSet};
use std::time::SystemTime;

use k8s_openapi::api::core::v1::{Pod, Service};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::rbac::v1::{PolicyRule, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

use super::attack::{self, CAPABILITY_CATALOG};
use super::graph::{
    Capability, Edge, Exposure, Grade, Host, Identity, Image, Node, NodeKey, Protocol, Provenance,
    Relation, RuntimeSignal, Scope, SecretRef, SecurityGraph, Trust, Workload, canonical_image,
};
use super::observe::Snapshot;

mod enrich;
mod escape;
mod exposure;
mod network;
mod rbac;
mod secret_mount;
mod workload;

pub use self::enrich::{RuntimeAdapter, VulnerabilityAdapter};
pub use self::escape::HostEscapeAdapter;
pub use self::exposure::ExposureAdapter;
pub use self::network::ReachabilityAdapter;
pub use self::rbac::PrivilegeAdapter;
pub use self::secret_mount::SecretMountAdapter;
pub use self::workload::WorkloadAdapter;

/// Container name a mesh proxy is injected as — used as the observed "is meshed"
/// fact, mirroring the webhook's mesh policy.
const MESH_PROXY: &str = "linkerd-proxy";

/// The annotation that declares a workload internet-exposed when the engine cannot
/// observe it (ADR-0012). Some real exposure is out-of-cluster — a Cloudflare token
/// tunnel routes the public hostname to a plain `ClusterIP` Service, with the
/// hostname→service map held in Cloudflare, not in any in-cluster object — so it
/// must be *declared*. Set `protector.jeffl.es/exposure: internet` on the fronted
/// Service (or the pod) and the engine treats it as internet-reachable.
pub const EXPOSURE_ANNOTATION: &str = "protector.jeffl.es/exposure";

/// A source of graph facts. Implementations map a [`Snapshot`] into the shared
/// graph, contributing nodes and edges. Adapters run in sequence over one graph,
/// so a later adapter can rely on the nodes an earlier one created (node upserts
/// are idempotent by key).
///
/// `Send + Sync` so the engine loop (which holds the adapter set across `await`
/// points) can run as a spawned task.
pub trait Adapter: Send + Sync {
    /// Stable identifier, recorded as edge/fact provenance.
    fn name(&self) -> &'static str;

    /// Contribute this adapter's nodes and edges to `graph` from `snapshot`.
    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph);
}

/// A deterministic, freshly-observed edge: proof-grade, stamped now, attributed to
/// `source`.
pub(super) fn observed(source: &str, relation: Relation) -> Edge {
    Edge {
        relation,
        provenance: Provenance::new(source, SystemTime::now()),
        grade: Grade::Proof,
    }
}

pub(super) fn pod_namespace(pod: &Pod) -> String {
    pod.metadata
        .namespace
        .clone()
        .unwrap_or_else(|| "default".to_string())
}

pub(super) fn pod_labels(pod: &Pod) -> BTreeMap<String, String> {
    pod.metadata.labels.clone().unwrap_or_default()
}

/// The node key of the Workload created for `pod`, without rebuilding its facts —
/// `Node::key` depends only on namespace/kind/name.
pub(super) fn workload_node(namespace: &str, name: &str) -> Node {
    Node::Workload(Workload {
        namespace: namespace.to_string(),
        name: name.to_string(),
        kind: "Pod".to_string(),
        labels: BTreeMap::new(),
        meshed: false,
        exposure: Exposure::Internal,
        runtime: vec![],
    })
}

/// True if `selector` matches `labels`. Handles `matchLabels`; an empty selector
/// matches everything. `matchExpressions` are not yet evaluated (documented
/// subset — a selector that relies on them will under-match).
pub(super) fn selector_matches(
    selector: &LabelSelector,
    labels: &BTreeMap<String, String>,
) -> bool {
    match &selector.match_labels {
        Some(want) => want.iter().all(|(k, v)| labels.get(k) == Some(v)),
        None => true,
    }
}

/// `selector_matches` only evaluates `matchLabels`; a selector carrying
/// `matchExpressions` is therefore under-matched. Reachability uses this to flag
/// the graph as incompletely modeled rather than silently dropping edges.
pub(super) fn has_match_expressions(selector: &LabelSelector) -> bool {
    selector
        .match_expressions
        .as_ref()
        .is_some_and(|e| !e.is_empty())
}

/// As [`selector_matches`], but for the optional selectors k8s-openapi models as
/// `Option<LabelSelector>`. A missing selector matches everything — the API treats
/// an empty/absent `podSelector` as "all pods in scope".
pub(super) fn selector_matches_opt(
    selector: &Option<LabelSelector>,
    labels: &BTreeMap<String, String>,
) -> bool {
    selector
        .as_ref()
        .is_none_or(|s| selector_matches(s, labels))
}

/// The default adapter set for the walking skeleton, in dependency order
/// (workloads first; later adapters reuse the workload nodes).
pub fn default_adapters() -> Vec<Box<dyn Adapter>> {
    vec![
        Box::new(WorkloadAdapter),
        Box::new(SecretMountAdapter),
        Box::new(ReachabilityAdapter),
        Box::new(PrivilegeAdapter),
        Box::new(HostEscapeAdapter),
        // Fact-enrichment adapters run last: they read-modify nodes the structural
        // adapters already created.
        Box::new(ExposureAdapter),
        Box::new(VulnerabilityAdapter),
        Box::new(RuntimeAdapter),
    ]
}

/// Build a fresh graph by running every adapter over `snapshot`.
pub fn build_graph(snapshot: &Snapshot, adapters: &[Box<dyn Adapter>]) -> SecurityGraph {
    let mut graph = SecurityGraph::new();
    for adapter in adapters {
        adapter.contribute(snapshot, &mut graph);
    }
    graph
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use serde_json::Value;

    pub fn pod(value: Value) -> Pod {
        serde_json::from_value(value).expect("valid Pod fixture")
    }
}
