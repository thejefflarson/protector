//! The cluster security graph vocabulary.
//!
//! This is the **stable core contract** of the engine (ADR-0003): the typed
//! nodes, edges, and facts that every capability adapter maps its tool's output
//! into, and that the proof layer walks (ADR-0004). Adapters own the mapping into
//! this vocabulary and nothing else; the vocabulary itself is deliberately small
//! and opinionated, so that adding a new *evidence source* never means adding a
//! new *rule*.
//!
//! Two cross-cutting properties are baked into the types rather than left to
//! convention:
//!
//! - **Provenance.** Every edge and every fact records which adapter asserted it
//!   ([`Provenance`]). Multiple adapters asserting the same thing is
//!   corroboration, not duplication — the generalization of ADR-0001's "trivy ∧
//!   grype agreement" to "N providers for one port agree."
//! - **Grade.** Every edge carries a [`Grade`]: `Proof` (backed by a deterministic
//!   check — eligible to move privilege) or `Hypothesis` (a heuristic or
//!   model-asserted claim — may inform a proposal, never an action). This makes
//!   "only deterministic proof moves privilege" (the VISION's rule) enforceable at
//!   the type boundary instead of by discipline.
//!
//! The graph holds **observed** state (ADR-0002): it is built from watch streams
//! and is always reconstructable from the live cluster, so it lives in memory and
//! does not persist.

use std::collections::BTreeMap;
use std::time::SystemTime;

use petgraph::stable_graph::{NodeIndex, StableGraph};

use super::attack::{self, AttackRef};

/// A node in the cluster security graph.
///
/// The six kinds are the ADR-0003 vocabulary: the things an attack chain is
/// stated in terms of. Facts that a capability port discovers (vulnerabilities,
/// trust, runtime activity) hang on the node they describe — see [`Image`] and
/// [`Workload`].
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    /// A running workload — a Pod or the controller that owns it.
    Workload(Workload),
    /// An identity a workload can act as: a ServiceAccount or other RBAC subject.
    Identity(Identity),
    /// A sensitive object worth reaching — a Secret (or comparable).
    Secret(SecretRef),
    /// A network endpoint: a Service/port, or an external (e.g. internet) exposure.
    Endpoint(Endpoint),
    /// A container image, keyed by digest — where vulnerability and trust facts live.
    Image(Image),
    /// A cluster node / host.
    Host(Host),
    /// A dangerous RBAC capability (a verb on a resource type, at some scope) that
    /// is itself an attacker goal — e.g. create pods, bind roles, delete PVCs.
    /// Unlike a Secret, it is a *power* an identity holds, not a concrete object.
    Capability(Capability),
}

impl Node {
    /// Stable identity used to deduplicate nodes when folding watch events into
    /// the graph. Two observations with the same key are the same node.
    pub fn key(&self) -> NodeKey {
        let raw = match self {
            Node::Workload(w) => NodeKey::workload(&w.namespace, &w.kind, &w.name).0,
            Node::Identity(i) => format!("identity/{}/{}", i.namespace, i.name),
            Node::Secret(s) => format!("secret/{}/{}", s.namespace, s.name),
            Node::Endpoint(e) => format!("endpoint/{}", e.address),
            Node::Image(im) => format!("image/{}", im.digest),
            Node::Host(h) => format!("host/{}", h.name),
            Node::Capability(c) => {
                format!("capability/{}/{}/{}", c.scope.label(), c.verb, c.resource)
            }
        };
        NodeKey(raw)
    }
}

/// Canonicalize an image reference so the Vulnerability port's findings land on the
/// same Image node as the workload that runs the image. A pod's `nginx:alpine` and
/// trivy's reconstructed `index.docker.io/library/nginx:alpine` must resolve to one
/// key — otherwise a CVE silently fails to attach and a vulnerable image looks clean
/// (the foothold, and log4j promotion, never fire). Prefers a digest when present;
/// falls back to the raw string if the reference doesn't parse.
pub fn canonical_image(reference: &str) -> String {
    use sigstore::registry::OciReference;
    match reference.parse::<OciReference>() {
        Ok(r) => {
            let base = format!("{}/{}", r.registry(), r.repository());
            match (r.digest(), r.tag()) {
                (Some(digest), _) => format!("{base}@{digest}"),
                (None, Some(tag)) => format!("{base}:{tag}"),
                (None, None) => format!("{base}:latest"),
            }
        }
        Err(_) => reference.to_string(),
    }
}

/// A stable, comparable handle for a [`Node`], derived from its identity (not its
/// facts) so a node keeps the same key as its facts change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeKey(pub String);

impl NodeKey {
    /// The key for a Workload node, without building the full struct — so a
    /// fact-only consumer (e.g. the Health port) can address a workload it didn't
    /// construct. Must match [`Node::key`]'s `Workload` arm.
    pub fn workload(namespace: &str, kind: &str, name: &str) -> NodeKey {
        NodeKey(format!("workload/{namespace}/{kind}/{name}"))
    }
}

/// A running workload. Carries the runtime/exposure facts a workload-scoped port
/// (RuntimeEvidence, and exposure inference) discovers.
#[derive(Debug, Clone, PartialEq)]
pub struct Workload {
    pub namespace: String,
    pub name: String,
    /// The owning kind as observed — `"Pod"`, `"Deployment"`, `"DaemonSet"`, …
    pub kind: String,
    /// The pod's labels — used by the actuator to render a precise pod-level
    /// selector when severing an edge (ADR-0007), not just a namespace one.
    pub labels: BTreeMap<String, String>,
    /// Whether a mesh proxy is injected (the webhook's mesh policy, as a fact).
    pub meshed: bool,
    /// How reachable this workload is from outside its own namespace.
    pub exposure: Exposure,
    /// Live corroboration that something is happening *now* (RuntimeEvidence port).
    pub runtime: Vec<RuntimeSignal>,
    /// Whether the workload mounts persistent storage (a PersistentVolumeClaim) — the
    /// signal that it is a **data store** (database, cache, object store), i.e. an
    /// information repository an attacker reaching it could mine (ATT&CK T1213).
    pub persistent: bool,
}

/// An identity (ServiceAccount / RBAC subject) a workload acts as.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub namespace: String,
    pub name: String,
}

/// A sensitive object worth reaching.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretRef {
    pub namespace: String,
    pub name: String,
}

/// A network endpoint — a Service/port or an external address.
#[derive(Debug, Clone, PartialEq)]
pub struct Endpoint {
    /// A stable address string: `svc/ns/name:port`, a CIDR, or `internet`.
    pub address: String,
}

/// A container image, keyed by digest. Vulnerability and trust facts live here so
/// they are shared by every workload running the same digest.
#[derive(Debug, Clone, PartialEq)]
pub struct Image {
    /// The content digest (`sha256:…`) — the stable identity of the image.
    pub digest: String,
    /// The reference as deployed (tag/repo), if known — for human narration only.
    pub reference: Option<String>,
    /// Signature/trust status (Trust port).
    pub trust: Trust,
    /// Vulnerabilities present in this image (Vulnerability ∧ ExploitIntel ports).
    pub vulnerabilities: Vec<Vulnerability>,
}

/// A cluster node / host.
#[derive(Debug, Clone, PartialEq)]
pub struct Host {
    pub name: String,
}

/// A dangerous RBAC capability: a `verb` on a `resource` type, at some [`Scope`].
/// The Privilege port mints these only for security-relevant verb/resource pairs
/// (the capability catalogue), never the full cartesian product.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Capability {
    pub verb: String,
    pub resource: String,
    pub scope: Scope,
}

/// Where a capability applies: cluster-wide (a ClusterRoleBinding) or within one
/// namespace (a RoleBinding).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scope {
    Cluster,
    Namespace(String),
}

impl Scope {
    /// Compact label used in the capability node key.
    pub fn label(&self) -> String {
        match self {
            Scope::Cluster => "cluster".to_string(),
            Scope::Namespace(ns) => format!("ns:{ns}"),
        }
    }
}

/// How reachable a workload is. Coarse on purpose — the precise reachability lives
/// on [`Relation::Reaches`] edges; this is the entry-point hint a chain starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    /// Reachable only within its own namespace.
    Internal,
    /// Reachable from elsewhere in the cluster.
    ClusterExposed,
    /// Reachable from outside the cluster.
    Internet,
}

/// Image signature/trust status (Trust port).
#[derive(Debug, Clone, PartialEq)]
pub enum Trust {
    /// Not yet evaluated.
    Unknown,
    /// Evaluated and not trusted (unsigned, or signed by an untrusted identity).
    Untrusted,
    /// Verified trusted by the named source.
    Signed(Provenance),
}

/// A vulnerability fact on an [`Image`]. The fields are exactly the predicates the
/// proof bar tests: presence (with corroborating `sources`), severity, and
/// active exploitation in the wild.
#[derive(Debug, Clone, PartialEq)]
pub struct Vulnerability {
    /// CVE (or other advisory) identifier.
    pub id: String,
    pub severity: Severity,
    /// Listed in a known-exploited catalogue (e.g. CISA KEV) — ExploitIntel port.
    pub exploited_in_wild: bool,
    /// Exploit-prediction score in `[0, 1]`, if available — ExploitIntel port.
    pub epss: Option<f32>,
    /// Which Vulnerability adapters reported this; >1 distinct source is
    /// cross-scanner corroboration.
    pub sources: Vec<Provenance>,
}

/// Severity band of a vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// An observed runtime **behavior** — what a workload actually did, from any sensor
/// (the first-party eBPF agent, Falco, …) through the tool-agnostic behavioral port
/// (ADR-0003/0014). Typed so the engine reasons about the *signal*, not the source.
/// Serde-tagged for the normalized ingest contract (`{"kind": "...", ...}`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
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

/// A live runtime signal corroborating that activity is happening now
/// (RuntimeEvidence port) — the difference between "theoretically vulnerable" and
/// "something is happening."
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeSignal {
    /// The observed behavior, from any sensor via the behavioral port (ADR-0014).
    pub behavior: Behavior,
    pub provenance: Provenance,
}

/// A directed edge: a relation one node bears to another, with the evidence that
/// asserts it.
#[derive(Debug, Clone, PartialEq)]
pub struct Edge {
    pub relation: Relation,
    pub provenance: Provenance,
    pub grade: Grade,
}

impl Edge {
    /// Whether this edge is backed by a deterministic check and therefore eligible
    /// to justify a privileged action. Hypothesis-grade edges may inform a
    /// proposal but must never move privilege (the VISION's rule).
    pub fn is_proof_grade(&self) -> bool {
        matches!(self.grade, Grade::Proof)
    }
}

/// The relation an [`Edge`] expresses. The first three are the proof-bar edges
/// (reachability, privilege, data access); the rest are structural edges that
/// connect a workload to the image it runs, the identity it acts as, and the host
/// it lands on, so chains can be walked end to end.
#[derive(Debug, Clone, PartialEq)]
pub enum Relation {
    /// Network reachability (Reachability port): source can open a connection to
    /// the target, optionally on a specific port.
    Reaches {
        port: Option<u16>,
        protocol: Protocol,
    },
    /// Privilege (Privilege port): the source identity can perform `verb` on the
    /// target resource.
    CanDo { verb: String, resource: String },
    /// Data access: the source can read the target Secret directly (mounted as a
    /// volume or env), without an API call.
    CanRead,
    /// Container escape: the source workload can break out to the target Host via
    /// `via` (e.g. `privileged`, `hostPID`, `hostPath`, `runtime-socket`,
    /// `cap:SYS_ADMIN`). The ATT&CK Escape-to-Host (T1611) movement edge.
    EscapesTo { via: String },
    /// Exfiltration channel: the source workload can egress to the internet (an
    /// `internet` Endpoint), so a compromise there can ship accessed data out. `via`
    /// names the signal (`annotation`, `egress-0.0.0.0/0`). ATT&CK T1041.
    CanEgress { via: String },
    /// Structural: the workload runs as the target identity.
    RunsAs,
    /// Structural: the workload runs the target image.
    RunsImage,
    /// Structural: the workload is scheduled on the target host.
    ScheduledOn,
}

impl Relation {
    /// Structural substrate — a workload to its image, its identity, or its host.
    /// These connect a chain end to end but are never sensible *cut* candidates: you
    /// don't sever a pod from its ServiceAccount to mitigate an RBAC path (the
    /// meaningful cut is the privilege/movement edge). The minimal-cut search skips
    /// these so a chain isn't reported as cuttable on a `runs-as` edge.
    pub fn is_structural(&self) -> bool {
        matches!(
            self,
            Relation::RunsAs | Relation::RunsImage | Relation::ScheduledOn
        )
    }

    /// A compact, stable label for the relation — used in diff signatures and in
    /// the threat-delta log lines. Two edges with the same endpoints and label are
    /// the same edge for diffing.
    pub fn label(&self) -> String {
        match self {
            Relation::Reaches { port, protocol } => match port {
                Some(p) => format!("reaches/{protocol:?}/{p}"),
                None => format!("reaches/{protocol:?}"),
            },
            Relation::CanDo { verb, resource } => format!("can-do/{verb}/{resource}"),
            Relation::CanRead => "can-read".to_string(),
            Relation::EscapesTo { via } => format!("escapes-to/{via}"),
            Relation::CanEgress { via } => format!("can-egress/{via}"),
            Relation::RunsAs => "runs-as".to_string(),
            Relation::RunsImage => "runs-image".to_string(),
            Relation::ScheduledOn => "scheduled-on".to_string(),
        }
    }

    /// The MITRE ATT&CK technique this relation realizes, if it is an attack step.
    /// Structural edges (`reaches`, `runs-as`, `runs-image`, `scheduled-on`) are
    /// the substrate a chain is walked over, not techniques themselves, so they
    /// return `None`. This is how the model speaks ATT&CK rather than any tool's
    /// edge nomenclature.
    pub fn technique(&self) -> Option<AttackRef> {
        match self {
            Relation::CanRead => Some(attack::CREDENTIAL_ACCESS),
            Relation::CanDo { verb, resource } => match (verb.as_str(), resource.as_str()) {
                ("get" | "list" | "watch", "secrets") => Some(attack::CREDENTIAL_ACCESS),
                (v, r) => attack::capability_technique(v, r),
            },
            Relation::EscapesTo { .. } => Some(attack::ESCAPE_TO_HOST),
            Relation::CanEgress { .. } => Some(attack::EXFILTRATION),
            _ => None,
        }
    }
}

/// Transport protocol for a [`Relation::Reaches`] edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Whether a piece of evidence is deterministic proof or a heuristic hypothesis.
///
/// This is the type-level enforcement of the platform's central rule: only
/// `Proof`-grade evidence may justify a privileged response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grade {
    /// Backed by a deterministic check (a real graph/RBAC query, a KEV lookup,
    /// cross-scanner agreement). Eligible to move privilege.
    Proof,
    /// A heuristic or model-asserted claim. May inform a proposal; never an action.
    Hypothesis,
}

/// Who asserted a fact or edge, and when — for corroboration and freshness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Adapter identifier, e.g. `"rbac"`, `"networkpolicy"`, `"trivy"`, `"kev"`.
    pub source: String,
    /// When the adapter observed it. Freshness is a first-class correctness
    /// concern (ADR-0002): a stale edge can produce a wrong cut.
    pub observed_at: SystemTime,
}

impl Provenance {
    pub fn new(source: impl Into<String>, observed_at: SystemTime) -> Self {
        Self {
            source: source.into(),
            observed_at,
        }
    }
}

/// The cluster security graph: an in-memory, directed, observed-state graph
/// (ADR-0004).
///
/// Backed by a [`StableGraph`] so node/edge indices survive the incremental
/// add/remove churn that deltas produce. Nodes are deduplicated by [`Node::key`]
/// via the `index` map, so folding a repeated observation upserts rather than
/// duplicates.
#[derive(Debug, Default)]
pub struct SecurityGraph {
    graph: StableGraph<Node, Edge>,
    index: BTreeMap<NodeKey, NodeIndex>,
    /// Set when an adapter could not fully model reachability (e.g. a NetworkPolicy
    /// used a peer/selector construct the Reachability adapter doesn't evaluate). The
    /// actuation gate treats this as "blast radius may be under-counted" and refuses
    /// to auto-apply a network cut — defaults false (complete) for a fresh graph.
    reachability_incomplete: bool,
}

impl SecurityGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark the graph's reachability as not fully modeled (see the field).
    pub fn mark_reachability_incomplete(&mut self) {
        self.reachability_incomplete = true;
    }

    /// Whether reachability could be under-modeled — the actuation gate fails safe
    /// (proposes instead of auto-applying network cuts) when this is true.
    pub fn reachability_incomplete(&self) -> bool {
        self.reachability_incomplete
    }

    /// Insert `node` if its key is new, or replace the stored node (keeping its
    /// index and edges) if the key already exists. Returns the node's index.
    ///
    /// Replacement is how a fact update lands: the same workload observed again
    /// with a fresh vulnerability list keeps its identity and its edges.
    pub fn upsert_node(&mut self, node: Node) -> NodeIndex {
        let key = node.key();
        if let Some(&idx) = self.index.get(&key) {
            self.graph[idx] = node;
            idx
        } else {
            let idx = self.graph.add_node(node);
            self.index.insert(key, idx);
            idx
        }
    }

    /// Return the index of the node with this key, inserting `node` only if it is
    /// absent. Unlike [`upsert_node`], an existing node is left **untouched** — for
    /// callers that only need an endpoint's index to attach an edge and must not
    /// clobber the facts a richer adapter (e.g. the workload builder, which sets
    /// labels/mesh/exposure) already wrote. Order-independent by construction.
    pub fn ensure_node(&mut self, node: Node) -> NodeIndex {
        let key = node.key();
        if let Some(&idx) = self.index.get(&key) {
            idx
        } else {
            let idx = self.graph.add_node(node);
            self.index.insert(key, idx);
            idx
        }
    }

    /// Mutate an existing node in place if present; a no-op if the key is unknown.
    /// The enrichment adapters (exposure, vulnerability, runtime) use this to layer
    /// a fact onto a node the structural adapters already built, without the
    /// read-clone-upsert dance.
    pub fn update_node(&mut self, key: &NodeKey, update: impl FnOnce(&mut Node)) {
        if let Some(&idx) = self.index.get(key) {
            update(&mut self.graph[idx]);
        }
    }

    /// Look up a node's index by key, if present.
    pub fn index_of(&self, key: &NodeKey) -> Option<NodeIndex> {
        self.index.get(key).copied()
    }

    /// Add a directed `edge` from `source` to `target`.
    pub fn add_edge(&mut self, source: NodeIndex, target: NodeIndex, edge: Edge) {
        self.graph.add_edge(source, target, edge);
    }

    /// Borrow the node at `idx`, if it exists.
    pub fn node(&self, idx: NodeIndex) -> Option<&Node> {
        self.graph.node_weight(idx)
    }

    /// The key of the node at `idx`, if it exists — for resolving an edge's
    /// endpoints back to stable identities when diffing or logging.
    pub fn key_of(&self, idx: NodeIndex) -> Option<NodeKey> {
        self.graph.node_weight(idx).map(Node::key)
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// The underlying graph, for the proof layer's walks.
    pub fn inner(&self) -> &StableGraph<Node, Edge> {
        &self.graph
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_image_converges_pod_and_scanner_forms() {
        // A pod's short ref and a scanner's fully-qualified ref for the SAME image
        // must canonicalize identically, or CVEs never attach (security fix [15]).
        let pod = canonical_image("nginx:alpine");
        eprintln!("canonical(nginx:alpine) = {pod}");
        assert_eq!(pod, canonical_image("docker.io/library/nginx:alpine"));
        assert_eq!(pod, canonical_image("index.docker.io/library/nginx:alpine"));
        // A digest pins identity regardless of how it's written.
        let d = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            canonical_image(&format!("nginx@{d}")),
            canonical_image(&format!("docker.io/library/nginx@{d}"))
        );
        // A private-registry ref round-trips and stays distinct from docker.io.
        assert_eq!(
            canonical_image("ghcr.io/thejefflarson/api:1.2.3"),
            "ghcr.io/thejefflarson/api:1.2.3"
        );
        assert_ne!(
            canonical_image("nginx:alpine"),
            canonical_image("nginx:1.27")
        );
    }

    fn prov(source: &str) -> Provenance {
        Provenance::new(source, SystemTime::UNIX_EPOCH)
    }

    fn proof_edge(relation: Relation, source: &str) -> Edge {
        Edge {
            relation,
            provenance: prov(source),
            grade: Grade::Proof,
        }
    }

    #[test]
    fn node_key_is_stable_across_fact_changes() {
        let clean = Node::Image(Image {
            digest: "sha256:abc".into(),
            reference: Some("ghcr.io/x:1".into()),
            trust: Trust::Unknown,
            vulnerabilities: vec![],
        });
        let scanned = Node::Image(Image {
            digest: "sha256:abc".into(),
            reference: Some("ghcr.io/x:1".into()),
            trust: Trust::Untrusted,
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2026-0001".into(),
                severity: Severity::Critical,
                exploited_in_wild: true,
                epss: Some(0.9),
                sources: vec![prov("trivy"), prov("grype")],
            }],
        });
        // Identity (digest) drives the key; facts (trust, vulns) do not.
        assert_eq!(clean.key(), scanned.key());
    }

    #[test]
    fn upsert_replaces_in_place_and_keeps_edges() {
        let mut g = SecurityGraph::new();
        let img = g.upsert_node(Node::Image(Image {
            digest: "sha256:abc".into(),
            reference: None,
            trust: Trust::Unknown,
            vulnerabilities: vec![],
        }));
        let wl = g.upsert_node(Node::Workload(Workload {
            namespace: "app".into(),
            name: "api".into(),
            kind: "Pod".into(),
            labels: BTreeMap::new(),
            meshed: true,
            exposure: Exposure::Internet,
            runtime: vec![],
            persistent: false,
        }));
        g.add_edge(wl, img, proof_edge(Relation::RunsImage, "kube"));
        assert_eq!(g.node_count(), 2);
        assert_eq!(g.edge_count(), 1);

        // Re-observe the image with a fresh vuln list: same node, edge intact.
        let img2 = g.upsert_node(Node::Image(Image {
            digest: "sha256:abc".into(),
            reference: None,
            trust: Trust::Untrusted,
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2026-0001".into(),
                severity: Severity::High,
                exploited_in_wild: false,
                epss: None,
                sources: vec![prov("trivy")],
            }],
        }));
        assert_eq!(img2, img, "upsert keeps the same index");
        assert_eq!(g.node_count(), 2, "no duplicate node");
        assert_eq!(g.edge_count(), 1, "edge survives the fact update");
        match g.node(img) {
            Some(Node::Image(i)) => assert_eq!(i.vulnerabilities.len(), 1),
            other => panic!("expected image node, got {other:?}"),
        }
    }

    #[test]
    fn relations_map_to_attack_techniques() {
        // Attack-step edges carry their ATT&CK technique...
        assert_eq!(
            Relation::EscapesTo {
                via: "privileged".into()
            }
            .technique(),
            Some(super::super::attack::ESCAPE_TO_HOST)
        );
        assert_eq!(
            Relation::CanRead.technique(),
            Some(super::super::attack::CREDENTIAL_ACCESS)
        );
        assert_eq!(
            Relation::CanDo {
                verb: "get".into(),
                resource: "secrets".into()
            }
            .technique(),
            Some(super::super::attack::CREDENTIAL_ACCESS)
        );
        // ...structural substrate edges do not.
        assert_eq!(Relation::RunsAs.technique(), None);
        assert_eq!(
            Relation::Reaches {
                port: None,
                protocol: Protocol::Tcp
            }
            .technique(),
            None
        );
    }

    #[test]
    fn grade_gates_what_may_move_privilege() {
        let proof = proof_edge(Relation::CanRead, "rbac");
        let hypo = Edge {
            relation: Relation::CanRead,
            provenance: prov("model"),
            grade: Grade::Hypothesis,
        };
        assert!(proof.is_proof_grade());
        assert!(!hypo.is_proof_grade());
    }
}
