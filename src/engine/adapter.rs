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
    Relation, RuntimeSignal, Scope, SecretRef, SecurityGraph, Trust, Workload,
};
use super::observe::Snapshot;

/// Container name a mesh proxy is injected as — used as the observed "is meshed"
/// fact, mirroring the webhook's mesh policy.
const MESH_PROXY: &str = "linkerd-proxy";

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
fn observed(source: &str, relation: Relation) -> Edge {
    Edge {
        relation,
        provenance: Provenance::new(source, SystemTime::now()),
        grade: Grade::Proof,
    }
}

fn pod_namespace(pod: &Pod) -> String {
    pod.metadata
        .namespace
        .clone()
        .unwrap_or_else(|| "default".to_string())
}

fn pod_labels(pod: &Pod) -> BTreeMap<String, String> {
    pod.metadata.labels.clone().unwrap_or_default()
}

/// The node key of the Workload created for `pod`, without rebuilding its facts —
/// `Node::key` depends only on namespace/kind/name.
fn workload_node(namespace: &str, name: &str) -> Node {
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
fn selector_matches(selector: &LabelSelector, labels: &BTreeMap<String, String>) -> bool {
    match &selector.match_labels {
        Some(want) => want.iter().all(|(k, v)| labels.get(k) == Some(v)),
        None => true,
    }
}

/// `selector_matches` only evaluates `matchLabels`; a selector carrying
/// `matchExpressions` is therefore under-matched. Reachability uses this to flag
/// the graph as incompletely modeled rather than silently dropping edges.
fn has_match_expressions(selector: &LabelSelector) -> bool {
    selector
        .match_expressions
        .as_ref()
        .is_some_and(|e| !e.is_empty())
}

/// As [`selector_matches`], but for the optional selectors k8s-openapi models as
/// `Option<LabelSelector>`. A missing selector matches everything — the API treats
/// an empty/absent `podSelector` as "all pods in scope".
fn selector_matches_opt(
    selector: &Option<LabelSelector>,
    labels: &BTreeMap<String, String>,
) -> bool {
    selector
        .as_ref()
        .is_none_or(|s| selector_matches(s, labels))
}

/// Workload, Image, and Identity nodes plus their structural edges.
pub struct WorkloadAdapter;

impl Adapter for WorkloadAdapter {
    fn name(&self) -> &'static str {
        "workload"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for pod in &snapshot.pods {
            let Some(name) = pod.metadata.name.clone() else {
                continue;
            };
            let namespace = pod_namespace(pod);
            let spec = pod.spec.as_ref();

            let meshed = spec.is_some_and(|s| {
                s.containers.iter().any(|c| c.name == MESH_PROXY)
                    || s.init_containers
                        .as_ref()
                        .is_some_and(|ics| ics.iter().any(|c| c.name == MESH_PROXY))
            });

            let wl = graph.upsert_node(Node::Workload(Workload {
                namespace: namespace.clone(),
                name: name.clone(),
                kind: "Pod".to_string(),
                labels: pod_labels(pod),
                meshed,
                // Exposure inference needs Services/Ingress we don't observe yet;
                // Internal is the honest default until that adapter lands.
                exposure: Exposure::Internal,
                runtime: vec![],
            }));

            let sa = spec
                .and_then(|s| s.service_account_name.clone())
                .unwrap_or_else(|| "default".to_string());
            let id = graph.upsert_node(Node::Identity(Identity {
                namespace: namespace.clone(),
                name: sa,
            }));
            graph.add_edge(wl, id, observed(self.name(), Relation::RunsAs));

            if let Some(spec) = spec {
                let images = spec
                    .containers
                    .iter()
                    .chain(spec.init_containers.iter().flatten())
                    .filter_map(|c| c.image.clone());
                for image in images {
                    // Tag-level identity for now; digest resolution arrives with
                    // the Vulnerability/Trust ports.
                    let img = graph.upsert_node(Node::Image(Image {
                        digest: image.clone(),
                        reference: Some(image),
                        trust: super::graph::Trust::Unknown,
                        vulnerabilities: vec![],
                    }));
                    graph.add_edge(wl, img, observed(self.name(), Relation::RunsImage));
                }
            }
        }
    }
}

/// Secret nodes and `can-read` edges for secrets a pod can read directly, with no
/// API call: secret volumes, `secretKeyRef` env vars, and `envFrom` secret refs.
pub struct SecretMountAdapter;

impl SecretMountAdapter {
    /// Names of secrets `pod` reads directly, in its own namespace.
    fn mounted_secrets(pod: &Pod) -> Vec<String> {
        let mut names = Vec::new();
        let Some(spec) = pod.spec.as_ref() else {
            return names;
        };
        for vol in spec.volumes.iter().flatten() {
            if let Some(secret) = &vol.secret
                && let Some(n) = &secret.secret_name
            {
                names.push(n.clone());
            }
        }
        for c in spec
            .containers
            .iter()
            .chain(spec.init_containers.iter().flatten())
        {
            for env in c.env.iter().flatten() {
                if let Some(src) = &env.value_from
                    && let Some(sel) = &src.secret_key_ref
                {
                    names.push(sel.name.clone());
                }
            }
            for from in c.env_from.iter().flatten() {
                if let Some(sel) = &from.secret_ref {
                    names.push(sel.name.clone());
                }
            }
        }
        names.sort();
        names.dedup();
        names
    }
}

impl Adapter for SecretMountAdapter {
    fn name(&self) -> &'static str {
        "secret-mount"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for pod in &snapshot.pods {
            let Some(name) = pod.metadata.name.clone() else {
                continue;
            };
            let namespace = pod_namespace(pod);
            let secrets = Self::mounted_secrets(pod);
            if secrets.is_empty() {
                continue;
            }
            let wl = graph.ensure_node(workload_node(&namespace, &name));
            for secret in secrets {
                let sec = graph.upsert_node(Node::Secret(SecretRef {
                    namespace: namespace.clone(),
                    name: secret,
                }));
                graph.add_edge(wl, sec, observed(self.name(), Relation::CanRead));
            }
        }
    }
}

/// `reaches` edges granted by NetworkPolicy **ingress** rules.
///
/// Documented subset: same-namespace `podSelector` peers only. A policy's targets
/// are the pods its `podSelector` matches; for each ingress rule, each `from` peer
/// that uses a `podSelector` (and neither `namespaceSelector` nor `ipBlock`)
/// contributes `reaches` edges from the matched source pods to the target pods.
/// `namespaceSelector`, `ipBlock`, default-allow (no policy), and `matchExpressions`
/// are not yet modeled — so this captures declared in-namespace allow-lists, not
/// the full reachability closure.
pub struct ReachabilityAdapter;

impl ReachabilityAdapter {
    fn ingress_active(policy: &NetworkPolicy) -> bool {
        let Some(spec) = &policy.spec else {
            return false;
        };
        match &spec.policy_types {
            Some(types) => types.iter().any(|t| t == "Ingress"),
            None => spec.ingress.is_some(),
        }
    }

    fn ports(
        rule_ports: Option<&Vec<k8s_openapi::api::networking::v1::NetworkPolicyPort>>,
    ) -> Vec<(Option<u16>, Protocol)> {
        let Some(ports) = rule_ports.filter(|p| !p.is_empty()) else {
            return vec![(None, Protocol::Tcp)];
        };
        ports
            .iter()
            .map(|p| {
                let protocol = match p.protocol.as_deref() {
                    Some("UDP") => Protocol::Udp,
                    _ => Protocol::Tcp,
                };
                let port = match &p.port {
                    Some(IntOrString::Int(n)) => u16::try_from(*n).ok(),
                    _ => None,
                };
                (port, protocol)
            })
            .collect()
    }
}

impl Adapter for ReachabilityAdapter {
    fn name(&self) -> &'static str {
        "networkpolicy"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        // Index pods by namespace with their labels, for selector matching.
        let pods: Vec<(String, String, BTreeMap<String, String>)> = snapshot
            .pods
            .iter()
            .filter_map(|p| {
                p.metadata
                    .name
                    .clone()
                    .map(|n| (pod_namespace(p), n, pod_labels(p)))
            })
            .collect();

        for policy in &snapshot.network_policies {
            if !Self::ingress_active(policy) {
                continue;
            }
            let Some(spec) = &policy.spec else { continue };
            // A target selector using matchExpressions is under-matched by
            // selector_matches, so the edges we derive may be incomplete.
            if spec
                .pod_selector
                .as_ref()
                .is_some_and(has_match_expressions)
            {
                graph.mark_reachability_incomplete();
            }
            let ns = policy
                .metadata
                .namespace
                .clone()
                .unwrap_or_else(|| "default".to_string());

            let targets: Vec<&(String, String, BTreeMap<String, String>)> = pods
                .iter()
                .filter(|(pns, _, labels)| {
                    *pns == ns && selector_matches_opt(&spec.pod_selector, labels)
                })
                .collect();
            if targets.is_empty() {
                continue;
            }

            for rule in spec.ingress.iter().flatten() {
                let port_specs = Self::ports(rule.ports.as_ref());
                for peer in rule.from.iter().flatten() {
                    // Documented subset: podSelector-only peers in the same namespace.
                    // A namespaceSelector/ipBlock peer is a reachability path we don't
                    // model — flag the graph incomplete so the actuation gate fails safe.
                    if peer.namespace_selector.is_some() || peer.ip_block.is_some() {
                        graph.mark_reachability_incomplete();
                        continue;
                    }
                    let Some(peer_selector) = &peer.pod_selector else {
                        continue;
                    };
                    if has_match_expressions(peer_selector) {
                        graph.mark_reachability_incomplete();
                    }
                    let sources: Vec<&(String, String, BTreeMap<String, String>)> = pods
                        .iter()
                        .filter(|(pns, _, labels)| {
                            *pns == ns && selector_matches(peer_selector, labels)
                        })
                        .collect();

                    for (sns, sname, _) in &sources {
                        for (tns, tname, _) in &targets {
                            if sns == tns && sname == tname {
                                continue; // no self-edge
                            }
                            let src = graph.ensure_node(workload_node(sns, sname));
                            let tgt = graph.ensure_node(workload_node(tns, tname));
                            for (port, protocol) in &port_specs {
                                graph.add_edge(
                                    src,
                                    tgt,
                                    observed(
                                        self.name(),
                                        Relation::Reaches {
                                            port: *port,
                                            protocol: *protocol,
                                        },
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// `can-do` edges from an Identity to a Secret it can read via RBAC.
///
/// Documented subset: ServiceAccount subjects, `Role`/`ClusterRole` refs, and the
/// read verbs (`get`/`list`/`watch`, or `*`) on `secrets` in the core group
/// (`""` or `*`). `resourceNames` restrictions are honored. A `RoleBinding`'s
/// grant is scoped to its own namespace; a `ClusterRoleBinding`'s applies in every
/// namespace. User/Group subjects, aggregation, and non-secret resources are not
/// modeled — this adapter answers exactly "which identity can read which secret",
/// which is what the proof layer needs to complete the privilege path to a secret.
pub struct PrivilegeAdapter;

impl PrivilegeAdapter {
    /// True if `rule` grants a read verb on secrets in the core API group.
    fn reads_secrets(rule: &PolicyRule) -> bool {
        let group_ok = rule
            .api_groups
            .as_ref()
            .is_some_and(|gs| gs.iter().any(|g| g.is_empty() || g == "*"));
        let resource_ok = rule
            .resources
            .as_ref()
            .is_some_and(|rs| rs.iter().any(|r| r == "secrets" || r == "*"));
        let verb_ok = rule
            .verbs
            .iter()
            .any(|v| matches!(v.as_str(), "get" | "list" | "watch" | "*"));
        group_ok && resource_ok && verb_ok
    }

    /// True if `rule` reaches the secret named `name` — either it lists no
    /// `resourceNames` (all secrets) or it names this one.
    fn names_secret(rule: &PolicyRule, name: &str) -> bool {
        match &rule.resource_names {
            Some(names) if !names.is_empty() => names.iter().any(|n| n == name),
            _ => true,
        }
    }

    /// Resolve a roleRef to the rules it carries, in `namespace` scope. A `Role`
    /// ref resolves against same-namespace Roles; a `ClusterRole` ref against
    /// ClusterRoles (whose rules then apply within `namespace`).
    fn rules_for<'a>(
        role_ref: &RoleRef,
        namespace: &str,
        snap: &'a Snapshot,
    ) -> Vec<&'a PolicyRule> {
        match role_ref.kind.as_str() {
            "Role" => snap
                .roles
                .iter()
                .find(|r| {
                    r.metadata.name.as_deref() == Some(&role_ref.name)
                        && r.metadata.namespace.as_deref() == Some(namespace)
                })
                .and_then(|r| r.rules.as_ref())
                .map(|rules| rules.iter().collect())
                .unwrap_or_default(),
            "ClusterRole" => Self::cluster_rules(&role_ref.name, snap),
            _ => Vec::new(),
        }
    }

    /// Rules of the named ClusterRole.
    fn cluster_rules<'a>(name: &str, snap: &'a Snapshot) -> Vec<&'a PolicyRule> {
        snap.cluster_roles
            .iter()
            .find(|cr| cr.metadata.name.as_deref() == Some(name))
            .and_then(|cr| cr.rules.as_ref())
            .map(|rules| rules.iter().collect())
            .unwrap_or_default()
    }

    /// The ServiceAccount identities `(namespace, name)` among `subjects`, with the
    /// binding's namespace as the default for subjects that omit one.
    fn service_accounts(
        subjects: Option<&Vec<Subject>>,
        default_ns: &str,
    ) -> Vec<(String, String)> {
        subjects
            .into_iter()
            .flatten()
            .filter(|s| s.kind == "ServiceAccount")
            .map(|s| {
                (
                    s.namespace
                        .clone()
                        .unwrap_or_else(|| default_ns.to_string()),
                    s.name.clone(),
                )
            })
            .collect()
    }
}

impl Adapter for PrivilegeAdapter {
    fn name(&self) -> &'static str {
        "rbac"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        // Both sets are deduped so a grant expressed by several rules or bindings
        // yields exactly one edge — duplicate edges would corrupt the proof
        // layer's single-edge-cut reasoning.
        //
        // Secret reads point at concrete Secret objects: (id_ns, id_name,
        // secret_ns, secret_name).
        let mut secret_grants: HashSet<(String, String, String, String)> = HashSet::new();
        // Dangerous capabilities point at Capability nodes: (id_ns, id_name, scope,
        // verb, resource).
        let mut cap_grants: HashSet<(String, String, Scope, &'static str, &'static str)> =
            HashSet::new();

        for rb in &snapshot.role_bindings {
            let ns = rb
                .metadata
                .namespace
                .clone()
                .unwrap_or_else(|| "default".to_string());
            let subjects = Self::service_accounts(rb.subjects.as_ref(), &ns);
            if subjects.is_empty() {
                continue;
            }
            for rule in Self::rules_for(&rb.role_ref, &ns, snapshot) {
                if Self::reads_secrets(rule) {
                    for secret in snapshot
                        .secrets
                        .iter()
                        .filter(|s| s.namespace == ns && Self::names_secret(rule, &s.name))
                    {
                        for (id_ns, id_name) in &subjects {
                            secret_grants.insert((
                                id_ns.clone(),
                                id_name.clone(),
                                secret.namespace.clone(),
                                secret.name.clone(),
                            ));
                        }
                    }
                }
                for cap in CAPABILITY_CATALOG.iter().filter(|c| Self::grants(rule, c)) {
                    for (id_ns, id_name) in &subjects {
                        cap_grants.insert((
                            id_ns.clone(),
                            id_name.clone(),
                            Scope::Namespace(ns.clone()),
                            cap.verb,
                            cap.resource,
                        ));
                    }
                }
            }
        }

        for crb in &snapshot.cluster_role_bindings {
            let subjects = Self::service_accounts(crb.subjects.as_ref(), "default");
            if subjects.is_empty() {
                continue;
            }
            for rule in Self::cluster_rules(&crb.role_ref.name, snapshot) {
                if Self::reads_secrets(rule) {
                    // Cluster-wide: every secret in every namespace.
                    for secret in snapshot
                        .secrets
                        .iter()
                        .filter(|s| Self::names_secret(rule, &s.name))
                    {
                        for (id_ns, id_name) in &subjects {
                            secret_grants.insert((
                                id_ns.clone(),
                                id_name.clone(),
                                secret.namespace.clone(),
                                secret.name.clone(),
                            ));
                        }
                    }
                }
                for cap in CAPABILITY_CATALOG.iter().filter(|c| Self::grants(rule, c)) {
                    for (id_ns, id_name) in &subjects {
                        cap_grants.insert((
                            id_ns.clone(),
                            id_name.clone(),
                            Scope::Cluster,
                            cap.verb,
                            cap.resource,
                        ));
                    }
                }
            }
        }

        for (id_ns, id_name, sec_ns, sec_name) in secret_grants {
            let id = graph.upsert_node(Node::Identity(Identity {
                namespace: id_ns,
                name: id_name,
            }));
            let secret = graph.upsert_node(Node::Secret(SecretRef {
                namespace: sec_ns,
                name: sec_name,
            }));
            graph.add_edge(
                id,
                secret,
                observed(
                    self.name(),
                    // Canonical read grant; get/list/watch all permit reading.
                    Relation::CanDo {
                        verb: "get".to_string(),
                        resource: "secrets".to_string(),
                    },
                ),
            );
        }

        for (id_ns, id_name, scope, verb, resource) in cap_grants {
            let id = graph.upsert_node(Node::Identity(Identity {
                namespace: id_ns,
                name: id_name,
            }));
            let capability = graph.upsert_node(Node::Capability(Capability {
                verb: verb.to_string(),
                resource: resource.to_string(),
                scope,
            }));
            graph.add_edge(
                id,
                capability,
                observed(
                    self.name(),
                    Relation::CanDo {
                        verb: verb.to_string(),
                        resource: resource.to_string(),
                    },
                ),
            );
        }
    }
}

impl PrivilegeAdapter {
    /// True if `rule` grants the dangerous capability `cap` — matching API group,
    /// resource (with `cap.resource == "*"` meaning any resource in the group),
    /// and verb, treating an RBAC `*` in the rule as matching anything.
    fn grants(rule: &PolicyRule, cap: &attack::DangerousCapability) -> bool {
        let group_ok = rule
            .api_groups
            .as_ref()
            .is_some_and(|gs| gs.iter().any(|g| g == cap.group || g == "*"));
        let resource_ok = cap.resource == "*"
            || rule
                .resources
                .as_ref()
                .is_some_and(|rs| rs.iter().any(|r| r == cap.resource || r == "*"));
        let verb_ok = rule.verbs.iter().any(|v| v == cap.verb || v == "*");
        group_ok && resource_ok && verb_ok
    }
}

/// Linux capabilities whose presence on a container is a strong container-escape
/// signal (the capability half of KubeHound's `CE_*` family).
const ESCAPE_CAPABILITIES: &[&str] = &[
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_PTRACE",
    "SYS_BOOT",
    "DAC_READ_SEARCH",
    "DAC_OVERRIDE",
    "NET_ADMIN",
];

/// `escapes-to` edges from a Workload to the Host it can break out to (ATT&CK
/// Escape to Host, T1611).
///
/// Documented subset, derived from pod spec alone: `privileged` containers,
/// `hostPID`/`hostIPC`, `hostPath` mounts (a mounted container-runtime socket is
/// flagged distinctly), and escape-enabling Linux capabilities. Each detected
/// primitive becomes one edge whose `via` names it — mirroring KubeHound's split
/// of escape into specific techniques. These prove escape *potential* (a
/// precondition), not exploitation (ADR-0001/0005); the action bar still needs
/// runtime corroboration.
pub struct HostEscapeAdapter;

impl HostEscapeAdapter {
    /// The escape primitives a pod exposes, each as a `via` label.
    fn escape_vias(pod: &Pod) -> Vec<String> {
        let mut vias = Vec::new();
        let Some(spec) = pod.spec.as_ref() else {
            return vias;
        };
        if spec.host_pid == Some(true) {
            vias.push("hostPID".to_string());
        }
        if spec.host_ipc == Some(true) {
            vias.push("hostIPC".to_string());
        }
        for c in spec
            .containers
            .iter()
            .chain(spec.init_containers.iter().flatten())
        {
            if let Some(sc) = &c.security_context {
                if sc.privileged == Some(true) {
                    vias.push("privileged".to_string());
                }
                if let Some(caps) = &sc.capabilities {
                    for cap in caps.add.iter().flatten() {
                        if ESCAPE_CAPABILITIES.contains(&cap.as_str()) {
                            vias.push(format!("cap:{cap}"));
                        }
                    }
                }
            }
        }
        for vol in spec.volumes.iter().flatten() {
            if let Some(host_path) = &vol.host_path {
                let path = host_path.path.as_str();
                if path.contains("docker.sock")
                    || path.contains("containerd.sock")
                    || path.contains("crio.sock")
                {
                    vias.push("runtime-socket".to_string());
                } else {
                    vias.push("hostPath".to_string());
                }
            }
        }
        vias.sort();
        vias.dedup();
        vias
    }
}

impl Adapter for HostEscapeAdapter {
    fn name(&self) -> &'static str {
        "host-escape"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for pod in &snapshot.pods {
            let Some(name) = pod.metadata.name.clone() else {
                continue;
            };
            let vias = Self::escape_vias(pod);
            if vias.is_empty() {
                continue;
            }
            // We can only point the escape at a concrete Host once the pod is
            // scheduled; an unscheduled pod's escape potential has no host yet.
            let Some(node_name) = pod.spec.as_ref().and_then(|s| s.node_name.clone()) else {
                continue;
            };
            let namespace = pod_namespace(pod);
            let wl = graph.ensure_node(workload_node(&namespace, &name));
            let host = graph.upsert_node(Node::Host(Host { name: node_name }));
            for via in vias {
                graph.add_edge(wl, host, observed(self.name(), Relation::EscapesTo { via }));
            }
        }
    }
}

/// Sets a Workload's `exposure` fact from the Services that select it — the entry
/// side of the action bar. A `LoadBalancer`/`NodePort` Service (or one with
/// `externalIPs`) makes its pods internet-reachable; any other selecting Service
/// makes them cluster-reachable. Reads and rewrites the Workload nodes the
/// [`WorkloadAdapter`] created, so it must run after it.
pub struct ExposureAdapter;

impl ExposureAdapter {
    fn rank(exposure: Exposure) -> u8 {
        match exposure {
            Exposure::Internal => 0,
            Exposure::ClusterExposed => 1,
            Exposure::Internet => 2,
        }
    }

    fn service_exposure(service: &Service) -> Exposure {
        let spec = service.spec.as_ref();
        let kind = spec.and_then(|s| s.type_.as_deref()).unwrap_or("ClusterIP");
        let has_external_ips = spec
            .and_then(|s| s.external_ips.as_ref())
            .is_some_and(|ips| !ips.is_empty());
        match kind {
            "LoadBalancer" | "NodePort" => Exposure::Internet,
            _ if has_external_ips => Exposure::Internet,
            _ => Exposure::ClusterExposed,
        }
    }
}

impl Adapter for ExposureAdapter {
    fn name(&self) -> &'static str {
        "exposure"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for pod in &snapshot.pods {
            let Some(name) = pod.metadata.name.clone() else {
                continue;
            };
            let namespace = pod_namespace(pod);
            let labels = pod_labels(pod);

            let mut exposure = Exposure::Internal;
            for service in &snapshot.services {
                if service.metadata.namespace.as_deref() != Some(namespace.as_str()) {
                    continue;
                }
                let Some(selector) = service.spec.as_ref().and_then(|s| s.selector.as_ref()) else {
                    continue;
                };
                if selector.is_empty() {
                    continue;
                }
                if selector.iter().all(|(k, v)| labels.get(k) == Some(v)) {
                    let e = Self::service_exposure(service);
                    if Self::rank(e) > Self::rank(exposure) {
                        exposure = e;
                    }
                }
            }
            if exposure == Exposure::Internal {
                continue;
            }

            // Layer the exposure fact onto the existing workload node, keeping its
            // identity and edges.
            let key = workload_node(&namespace, &name).key();
            graph.update_node(&key, |node| {
                if let Node::Workload(w) = node {
                    w.exposure = exposure;
                }
            });
        }
    }
}

/// Annotates Image nodes with vulnerability findings (Vulnerability port). Like
/// [`ExposureAdapter`], it enriches existing Image nodes, so it runs after the
/// structural adapters. The live scanner source is wired in the Observer; this
/// adapter just maps normalized findings onto the matching Image node.
pub struct VulnerabilityAdapter;

impl Adapter for VulnerabilityAdapter {
    fn name(&self) -> &'static str {
        "vulnerability"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for finding in &snapshot.image_vulns {
            let key = Node::Image(Image {
                digest: finding.image.clone(),
                reference: None,
                trust: Trust::Unknown,
                vulnerabilities: vec![],
            })
            .key();
            graph.update_node(&key, |node| {
                if let Node::Image(img) = node {
                    img.vulnerabilities = finding.vulnerabilities.clone();
                }
            });
        }
    }
}

/// Live runtime signals (RuntimeEvidence port): annotate a Workload with the
/// runtime events observed against it — the "is it happening now" corroboration
/// that completes the action bar. Enriches existing Workload nodes, so it runs
/// after the structural adapters.
pub struct RuntimeAdapter;

impl Adapter for RuntimeAdapter {
    fn name(&self) -> &'static str {
        "runtime"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for event in &snapshot.runtime_events {
            let key = NodeKey::workload(&event.namespace, "Pod", &event.pod);
            graph.update_node(&key, |node| {
                if let Node::Workload(w) = node {
                    w.runtime.push(RuntimeSignal {
                        rule: event.rule.clone(),
                        provenance: Provenance::new(self.name(), SystemTime::now()),
                    });
                }
            });
        }
    }
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

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::visit::EdgeRef;
    use serde_json::{Value, json};

    fn pod(value: Value) -> Pod {
        serde_json::from_value(value).expect("valid Pod fixture")
    }

    fn netpol(value: Value) -> NetworkPolicy {
        serde_json::from_value(value).expect("valid NetworkPolicy fixture")
    }

    #[test]
    fn workload_adapter_builds_nodes_and_structural_edges() {
        let snap = Snapshot {
            pods: vec![pod(json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "api", "namespace": "app", "labels": {"app": "api"}},
                "spec": {
                    "serviceAccountName": "api-sa",
                    "containers": [
                        {"name": "api", "image": "ghcr.io/x/api:1"},
                        {"name": "linkerd-proxy", "image": "linkerd/proxy:stable"}
                    ]
                }
            }))],
            network_policies: vec![],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());
        // Workload + Identity + 2 Images.
        assert_eq!(g.node_count(), 4);
        // runs-as + 2 runs-image.
        assert_eq!(g.edge_count(), 3);

        let wl_key = workload_node("app", "api").key();
        let wl = g.index_of(&wl_key).and_then(|i| g.node(i)).unwrap();
        match wl {
            Node::Workload(w) => assert!(w.meshed, "linkerd-proxy container ⇒ meshed"),
            other => panic!("expected workload, got {other:?}"),
        }
    }

    #[test]
    fn secret_mount_adapter_links_workload_to_secrets() {
        let snap = Snapshot {
            pods: vec![pod(json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "api", "namespace": "app"},
                "spec": {
                    "volumes": [{"name": "creds", "secret": {"secretName": "db-creds"}}],
                    "containers": [{
                        "name": "api",
                        "image": "ghcr.io/x/api:1",
                        "envFrom": [{"secretRef": {"name": "api-env"}}]
                    }]
                }
            }))],
            network_policies: vec![],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());
        let wl = g.index_of(&workload_node("app", "api").key()).unwrap();
        // Two can-read edges (db-creds volume, api-env envFrom).
        let can_read = g
            .inner()
            .edges(wl)
            .filter(|e| matches!(e.weight().relation, Relation::CanRead))
            .count();
        assert_eq!(can_read, 2);
    }

    #[test]
    fn reachability_adapter_emits_declared_ingress_edges() {
        let pods = vec![
            pod(json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "web", "namespace": "app", "labels": {"role": "web"}},
                "spec": {"containers": [{"name": "web", "image": "web:1"}]}
            })),
            pod(json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "db", "namespace": "app", "labels": {"role": "db"}},
                "spec": {"containers": [{"name": "db", "image": "db:1"}]}
            })),
        ];
        // Allow web → db on TCP 5432.
        let policy = netpol(json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "db-ingress", "namespace": "app"},
            "spec": {
                "podSelector": {"matchLabels": {"role": "db"}},
                "policyTypes": ["Ingress"],
                "ingress": [{
                    "from": [{"podSelector": {"matchLabels": {"role": "web"}}}],
                    "ports": [{"protocol": "TCP", "port": 5432}]
                }]
            }
        }));
        let snap = Snapshot {
            pods,
            network_policies: vec![policy],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());

        let web = g.index_of(&workload_node("app", "web").key()).unwrap();
        let reaches: Vec<_> = g
            .inner()
            .edges(web)
            .filter_map(|e| match &e.weight().relation {
                Relation::Reaches { port, protocol } => Some((*port, *protocol)),
                _ => None,
            })
            .collect();
        assert_eq!(reaches, vec![(Some(5432), Protocol::Tcp)]);

        // Regression: the ReachabilityAdapter references web/db as edge endpoints
        // via `ensure_node`, which must NOT clobber the labels the workload builder
        // set — the network actuator needs them to render a pod-scoped selector.
        let labels = match g.node(web) {
            Some(Node::Workload(w)) => w.labels.clone(),
            _ => panic!("web is a workload"),
        };
        assert_eq!(labels.get("role").map(String::as_str), Some("web"));
        let db = g.index_of(&workload_node("app", "db").key()).unwrap();
        assert!(matches!(
            g.node(db),
            Some(Node::Workload(w)) if w.labels.get("role").map(String::as_str) == Some("db")
        ));
    }

    #[test]
    fn privilege_adapter_links_identity_to_readable_secret() {
        use crate::engine::observe::SecretMeta;
        use k8s_openapi::api::rbac::v1::{Role, RoleBinding};

        let role: Role = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": "secret-reader", "namespace": "app"},
            "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}]
        }))
        .unwrap();
        let binding: RoleBinding = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": "reader-binding", "namespace": "app"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "secret-reader"},
            "subjects": [{"kind": "ServiceAccount", "name": "reader-sa", "namespace": "app"}]
        }))
        .unwrap();

        let snap = Snapshot {
            secrets: vec![
                SecretMeta {
                    namespace: "app".into(),
                    name: "db-creds".into(),
                },
                // A secret in another namespace the Role does not reach.
                SecretMeta {
                    namespace: "other".into(),
                    name: "elsewhere".into(),
                },
            ],
            roles: vec![role],
            role_bindings: vec![binding],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());

        let id = g
            .index_of(
                &Node::Identity(Identity {
                    namespace: "app".into(),
                    name: "reader-sa".into(),
                })
                .key(),
            )
            .expect("identity node");
        let targets: Vec<_> = g
            .inner()
            .edges(id)
            .filter_map(|e| match &e.weight().relation {
                Relation::CanDo { resource, .. } if resource == "secrets" => {
                    g.key_of(e.target()).map(|k| k.0)
                }
                _ => None,
            })
            .collect();
        // Exactly the in-namespace secret is reachable; the RoleBinding is
        // namespace-scoped, so `other/elsewhere` is not granted.
        assert_eq!(targets, vec!["secret/app/db-creds".to_string()]);
    }

    #[test]
    fn host_escape_adapter_detects_primitives_and_links_to_host() {
        let snap = Snapshot {
            pods: vec![pod(json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "runner", "namespace": "ci"},
                "spec": {
                    "nodeName": "node-1",
                    "hostPID": true,
                    "volumes": [{
                        "name": "sock",
                        "hostPath": {"path": "/run/containerd/containerd.sock"}
                    }],
                    "containers": [{
                        "name": "runner", "image": "runner:1",
                        "securityContext": {"capabilities": {"add": ["SYS_ADMIN", "NET_BIND_SERVICE"]}}
                    }]
                }
            }))],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());

        let wl = g.index_of(&workload_node("ci", "runner").key()).unwrap();
        let mut vias: Vec<String> = g
            .inner()
            .edges(wl)
            .filter_map(|e| match &e.weight().relation {
                Relation::EscapesTo { via } => Some(via.clone()),
                _ => None,
            })
            .collect();
        vias.sort();
        // hostPID, the runtime socket, and SYS_ADMIN are flagged; NET_BIND_SERVICE
        // is not an escape capability and is ignored.
        assert_eq!(
            vias,
            vec![
                "cap:SYS_ADMIN".to_string(),
                "hostPID".to_string(),
                "runtime-socket".to_string()
            ]
        );
    }

    #[test]
    fn privilege_adapter_mints_capability_nodes_for_cluster_admin() {
        use crate::engine::observe::SecretMeta;
        use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding};

        // A cluster-admin-style wildcard grant.
        let admin: ClusterRole = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
            "metadata": {"name": "cluster-admin"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        }))
        .unwrap();
        let binding: ClusterRoleBinding = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
            "metadata": {"name": "admin-binding"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "ops-sa", "namespace": "ops"}]
        }))
        .unwrap();

        let snap = Snapshot {
            secrets: vec![SecretMeta {
                namespace: "ops".into(),
                name: "tok".into(),
            }],
            cluster_roles: vec![admin],
            cluster_role_bindings: vec![binding],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());

        let id = g
            .index_of(
                &Node::Identity(Identity {
                    namespace: "ops".into(),
                    name: "ops-sa".into(),
                })
                .key(),
            )
            .expect("identity node");
        let mut caps: Vec<String> = g
            .inner()
            .edges(id)
            .filter_map(|e| match &e.weight().relation {
                Relation::CanDo { verb, resource } if resource != "secrets" => {
                    Some(format!("{verb}/{resource}"))
                }
                _ => None,
            })
            .collect();
        caps.sort();
        // The wildcard grant mints every catalogued capability (cluster scope),
        // and no others.
        assert_eq!(
            caps,
            vec![
                "bind/*".to_string(),
                "create/clusterrolebindings".to_string(),
                "create/cronjobs".to_string(),
                "create/pods".to_string(),
                "create/pods/attach".to_string(),
                "create/pods/exec".to_string(),
                "create/rolebindings".to_string(),
                "delete/persistentvolumeclaims".to_string(),
                "escalate/*".to_string(),
            ]
        );
    }
}
