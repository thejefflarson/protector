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

pub mod attack;
pub mod delta;

use std::collections::BTreeMap;
use std::time::SystemTime;

use petgraph::stable_graph::{NodeIndex, StableGraph};
use petgraph::visit::EdgeRef;

use self::attack::AttackRef;

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
            Node::Image(im) => NodeKey::image(&im.digest).0,
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

    /// The key for an Image node, by its content `digest`, without building the full
    /// struct — so the vulnerability/exposed-secret enrichment adapters can address
    /// the Image node they want to annotate (after [`canonical_image`]-ing a finding's
    /// reference) instead of constructing a throwaway [`Node::Image`] just for its key.
    /// Must match [`Node::key`]'s `Image` arm.
    pub fn image(digest: &str) -> NodeKey {
        NodeKey(format!("image/{digest}"))
    }

    /// The leading path segment that names the node's kind — the discriminant every
    /// key shape carries first: `workload`, `identity`, `secret`, `endpoint`, `image`,
    /// `host`, `capability` (see [`Node::key`] for the constructors). Always present:
    /// keys are never empty, so this is the substring up to the first `/` (or the whole
    /// key when there is no `/`). The single source of truth for the kind seam that
    /// consumers used to re-derive by hand-splitting.
    pub fn kind(&self) -> &str {
        Self::kind_of(&self.0)
    }

    /// [`NodeKey::kind`] over a borrowed key string — the same parsing without owning a
    /// `NodeKey`, so string-typed consumers (the dashboard) share this one parser.
    pub fn kind_of(key: &str) -> &str {
        key.split('/').next().unwrap_or(key)
    }

    /// The namespace segment, for the namespace-scoped key shapes only. Workload
    /// (`workload/<ns>/<kind>/<name>`), secret (`secret/<ns>/<name>`), and identity
    /// (`identity/<ns>/<name>`) carry their namespace as the second segment. A
    /// `capability` key's second segment is its [`Scope::label`] (`cluster` or
    /// `ns:<ns>`), not a bare namespace — it is included here to preserve the historical
    /// behavior of the adjudicator's `namespace_of`, which treated that label as the
    /// namespace. Cluster-scoped shapes (`host/<name>`, `endpoint/<addr>`,
    /// `image/<digest>`) have no namespace and return `None`.
    pub fn namespace(&self) -> Option<&str> {
        let mut parts = self.0.split('/');
        match parts.next()? {
            "workload" | "secret" | "identity" | "capability" => parts.next(),
            _ => None,
        }
    }

    /// The object name — the final segment of a namespace-scoped key: the workload /
    /// secret / identity name. `None` for kinds whose tail is not a single bare name
    /// (`host`, `endpoint`, `image`, `capability`) or when the expected segment count is
    /// not met. Workload is `workload/<ns>/<kind>/<name>` (4 segments); secret and
    /// identity are `<kind>/<ns>/<name>` (3 segments).
    pub fn name(&self) -> Option<&str> {
        let count = self.0.split('/').count();
        match self.0.split('/').next()? {
            "workload" if count == 4 => self.0.split('/').nth(3),
            "secret" | "identity" if count == 3 => self.0.split('/').nth(2),
            _ => None,
        }
    }

    /// Everything after the kind prefix — the human-facing remainder of the key with the
    /// leading `<kind>/` stripped (e.g. `app/Pod/web` for `workload/app/Pod/web`). Falls
    /// back to the whole key when there is no `/`. Used for compact labels (the dashboard)
    /// where the kind is conveyed by node shape rather than by text.
    pub fn short(&self) -> &str {
        Self::short_of(&self.0)
    }

    /// [`NodeKey::short`] over a borrowed key string — the same parsing without owning a
    /// `NodeKey`, so string-typed consumers (the dashboard) share this one parser.
    pub fn short_of(key: &str) -> &str {
        key.split_once('/').map_or(key, |(_, rest)| rest)
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
    /// FAILED configuration-audit checks from trivy-operator's `ConfigAuditReport`
    /// (JEF-244) — misconfiguration evidence (a hostPath mount, a missing securityContext,
    /// …) for this workload. STRUCTURAL severity/context for the model, NOT exploitation
    /// evidence; surfaced as static-posture findings the same way CVE severity is. Each
    /// finding's free-text is UNTRUSTED third-party scanner output, fenced/capped before it
    /// reaches the prompt or escaped before the dashboard. Empty when trivy-operator's
    /// config-audit reports are absent.
    pub misconfigs: Vec<ScanFinding>,
    /// FAILED role / cluster-role checks from trivy-operator's `RbacAssessmentReport`
    /// (JEF-244) — structural RBAC-exposure evidence (a role granting `*` verbs, secret
    /// access, …) attached to the workloads in the report's namespace. INFORMS the model's
    /// authorization reasoning (JEF-79 already reasons about RBAC-authorized breadth); it
    /// does not re-implement or double-count that logic. Untrusted scanner free-text, fenced
    /// like the others. Empty when the reports are absent.
    pub rbac_findings: Vec<ScanFinding>,
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
    /// Exposed secrets baked into this image, from trivy-operator's `ExposedSecretReport`
    /// (JEF-244) — a credential committed into the image layers (an AWS key, a private key,
    /// a token). EXPLOITATION-grade exposure: a usable secret sitting in the image is a real
    /// breach primitive, not mere posture. The finding carries only the rule id, category,
    /// severity, target path, and trivy's **redacted** match — the raw secret value is NEVER
    /// parsed, stored, or rendered (the redaction guarantee, enforced in the adapter + tests).
    /// Lives on the Image (not the Workload) so it is shared by every workload running the
    /// same digest, exactly like [`Vulnerability`]. Empty when the reports are absent.
    pub exposed_secrets: Vec<ScanFinding>,
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
/// active exploitation in the wild — plus the package coordinates and a
/// [`Reachability`] annotation (JEF-51) used as model evidence.
#[derive(Debug, Clone, PartialEq, Default)]
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
    /// Whether the vulnerable code is reachable at runtime (JEF-51) — evidence for
    /// the model, never a gate in v1.
    pub reachability: Reachability,
    /// The vulnerable package's name (e.g. `log4j-core`, `openssl`), if the scanner
    /// reported it. Drives the runtime library-load correlation (JEF-51).
    pub pkg_name: Option<String>,
    /// The installed (vulnerable) package version, if reported.
    pub installed_version: Option<String>,
    /// The version that fixes the vulnerability, if a fix is available.
    pub fixed_version: Option<String>,
    /// A short human title for the advisory (trivy's `title`), if reported. UNTRUSTED
    /// free-text from a third-party feed — must be fenced/sanitized before it reaches
    /// the model prompt (JEF-66).
    pub title: Option<String>,
    /// The advisory's primary reference URL (trivy's `primaryLink`), if reported. Also
    /// untrusted third-party text — fenced before it reaches the prompt (JEF-66).
    pub primary_link: Option<String>,
    /// The CVSS base score (`0.0`–`10.0`) trivy-operator emits per vulnerability, if
    /// reported (JEF-242). A STRUCTURED, low-cardinality severity signal — a numeric
    /// field, never untrusted free-text — surfaced to the model as static-severity
    /// evidence alongside the categorical `severity`. `None` when the scanner omits it.
    pub score: Option<f64>,
}

/// Whether a vulnerability's code is reachable (JEF-51). v1 populates only the
/// *dynamic* variants by correlating CVEs against the agent's runtime
/// [`Behavior::LibraryLoaded`] signal; `Unknown` is the default (no signal yet).
///
/// v3 will add `StaticReachable`/`StaticUnreachable` from a scanner's static
/// call-graph reachability analysis — orthogonal to the runtime signal here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Reachability {
    /// Not yet evaluated — no correlation pass has run, or no runtime evidence exists.
    #[default]
    Unknown,
    /// The vulnerable package was observed loaded at runtime (a `LibraryLoaded`
    /// signal matched its package name) — the strongest dynamic-reachability signal.
    LoadedAtRuntime,
    /// The correlation pass ran but no matching runtime load was observed.
    NotObserved,
}

impl Reachability {
    /// A stable, low-cardinality label for the prompt, fingerprint, and metrics.
    pub fn label(&self) -> &'static str {
        match self {
            Reachability::Unknown => "unknown",
            Reachability::LoadedAtRuntime => "loaded-at-runtime",
            Reachability::NotObserved => "not-observed",
        }
    }
}

/// A non-CVE scanner finding from one of trivy-operator's other report kinds (JEF-244):
/// an exposed secret ([`Image::exposed_secrets`]), a failed config-audit check
/// ([`Workload::misconfigs`]), or a failed RBAC-assessment check
/// ([`Workload::rbac_findings`]). One small shared shape rather than three parallel
/// structs — the fields are the same STRUCTURED, low-cardinality coordinates trivy emits
/// for each: a stable rule/check id, a severity band, a category, and a short title.
///
/// `title` (and any path baked into it) is UNTRUSTED third-party scanner text — it is
/// fenced/capped before the prompt and HTML-escaped before the dashboard, exactly as the
/// CVE `title` is. For an exposed secret the title carries trivy's already-**redacted**
/// match only; the raw secret value never enters this type (the redaction guarantee).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanFinding {
    /// The scanner's stable identifier for the rule/check — trivy's `ruleID` (exposed
    /// secret) or `checkID` (config-audit / RBAC), e.g. `aws-access-key-id`, `KSV017`. A
    /// low-cardinality token, surfaced verbatim like a CVE id.
    pub id: String,
    pub severity: Severity,
    /// The scanner's category for the finding (`AWS`, `Kubernetes Security Check`, …) —
    /// short, low-cardinality classification; absent ⇒ `None`.
    pub category: Option<String>,
    /// A short human title/description trivy reports for the finding. UNTRUSTED free-text:
    /// fenced+capped before the model prompt, HTML-escaped before the dashboard.
    pub title: Option<String>,
    /// What the finding is about: the file path (exposed secret), or the audited
    /// resource/object. Untrusted — sanitized alongside `title`. Absent ⇒ `None`.
    pub target: Option<String>,
    /// Which adapter asserted this finding (e.g. `trivy-exposed-secret`,
    /// `trivy-config-audit`, `trivy-rbac`), for provenance/corroboration.
    pub sources: Vec<Provenance>,
}

/// Severity band of a vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Severity {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// A stable, low-cardinality label for the prompt and metrics.
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// The behavioral-port wire type, defined in the shared [`protector_behavior`] crate so
/// the engine and the first-party agent can't drift (ADR-0003/0014). Re-exported here
/// because the graph reasons in terms of `Behavior` and the rest of the engine refers to
/// it as `graph::Behavior`.
pub use protector_behavior::Behavior;

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

    /// The evidence (ADR-0016 enrichment) attached to an `entry` node: the CVEs its
    /// image carries and the runtime [`Behavior`]s observed on it. This is the SINGLE
    /// source of truth for "what is the evidence on this entry" — the adjudicator's
    /// prompt assembly and the dashboard's per-finding evidence blocks (JEF-133) both
    /// read it, so the model and the operator see the same facts and can't drift.
    ///
    /// CVE selection mirrors the deterministic foothold's compromise bar:
    /// exploited-in-wild (KEV) OR critical severity. Lower-severity CVEs are real but
    /// don't clear the foothold bar, so they aren't surfaced as entry evidence (showing
    /// them would tell the model/operator "this is the foothold-relevant set" when it
    /// isn't). Behaviors are returned verbatim; the entry's runtime signals are already
    /// attributed by pod UID at ingest, so this is low-cardinality.
    ///
    /// Returns empty vecs for an unknown key or a non-workload node.
    pub fn entry_evidence(&self, entry_key: &NodeKey) -> (Vec<Vulnerability>, Vec<Behavior>) {
        let Some(entry) = self.index_of(entry_key) else {
            return (Vec::new(), Vec::new());
        };
        let behaviors: Vec<Behavior> = match self.graph.node_weight(entry) {
            Some(Node::Workload(w)) => w.runtime.iter().map(|s| s.behavior.clone()).collect(),
            _ => Vec::new(),
        };
        let mut cves = Vec::new();
        for edge in self.graph.edges(entry) {
            if matches!(edge.weight().relation, Relation::RunsImage)
                && let Some(Node::Image(image)) = self.graph.node_weight(edge.target())
            {
                cves.extend(
                    image
                        .vulnerabilities
                        .iter()
                        // Same bar as the deterministic foothold (compromisable): KEV or
                        // critical. Keeps the model's "no CVE" and the operator's CVE block
                        // honest about the foothold-relevant set.
                        .filter(|v| v.exploited_in_wild || v.severity == Severity::Critical)
                        .cloned(),
                );
            }
        }
        (cves, behaviors)
    }

    /// The non-CVE scanner findings behind an `entry` node (JEF-244): the exposed secrets
    /// baked into its image(s), and the failed config-audit / RBAC-assessment checks on the
    /// workload itself. Companion to [`entry_evidence`](Self::entry_evidence) — kept separate
    /// so the established CVE/runtime evidence tuple (and its many callers) is untouched while
    /// the new trivy report kinds get one shared SOURCE OF TRUTH for the prompt and the
    /// dashboard, so the model and the operator can never see a different set.
    ///
    /// Returns `(exposed_secrets, misconfigs, rbac_findings)`; all empty for an unknown key
    /// or a non-workload node. Exposed secrets are followed across the entry's `RunsImage`
    /// edges (they live on the Image, shared by every workload on that digest); the two
    /// config findings live directly on the Workload.
    pub fn entry_findings(
        &self,
        entry_key: &NodeKey,
    ) -> (Vec<ScanFinding>, Vec<ScanFinding>, Vec<ScanFinding>) {
        let empty = (Vec::new(), Vec::new(), Vec::new());
        let Some(entry) = self.index_of(entry_key) else {
            return empty;
        };
        let (misconfigs, rbac_findings) = match self.graph.node_weight(entry) {
            Some(Node::Workload(w)) => (w.misconfigs.clone(), w.rbac_findings.clone()),
            _ => return empty,
        };
        let mut exposed_secrets = Vec::new();
        for edge in self.graph.edges(entry) {
            if matches!(edge.weight().relation, Relation::RunsImage)
                && let Some(Node::Image(image)) = self.graph.node_weight(edge.target())
            {
                exposed_secrets.extend(image.exposed_secrets.iter().cloned());
            }
        }
        (exposed_secrets, misconfigs, rbac_findings)
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

    #[test]
    fn fingerprint_key_collapses_connection_churn() {
        // The verdict cache is keyed on fingerprint_key; a high-cardinality behavior arm
        // would bust it every pass and starve the slow CPU model (ADR-0013). Connections
        // are the churny case — many distinct peers must collapse to a bounded set of
        // scope tokens, NOT one key per peer. This guards future arms from regressing it.
        use std::collections::HashSet;
        let keys: HashSet<String> = (0..1000)
            .flat_map(|i| {
                [
                    Behavior::NetworkConnection {
                        peer: format!("10.0.0.{i}"),
                        internet: false,
                    },
                    Behavior::NetworkConnection {
                        peer: format!("93.184.{}.{}", i / 256, i % 256),
                        internet: true,
                    },
                ]
            })
            .map(|b| b.fingerprint_key())
            .collect();
        // 2000 distinct peers → exactly two scope tokens.
        assert_eq!(
            keys,
            HashSet::from(["egress:cluster".into(), "egress:internet".into()])
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
            exposed_secrets: vec![],
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
                ..Default::default()
            }],
            exposed_secrets: vec![],
        });
        // Identity (digest) drives the key; facts (trust, vulns) do not.
        assert_eq!(clean.key(), scanned.key());
    }

    #[test]
    fn node_key_constructors_match_node_key() {
        // The struct-free constructors the enrichment adapters use must produce exactly the
        // key `Node::key` derives from a full node — otherwise a finding silently fails to
        // attach (the security-fix [15] / JEF-244 attach bugs). Guards both arms that route
        // through a constructor.
        let image = Node::Image(Image {
            digest: "sha256:abc".into(),
            reference: Some("ghcr.io/x:1".into()),
            trust: Trust::Untrusted,
            vulnerabilities: vec![],
            exposed_secrets: vec![],
        });
        assert_eq!(NodeKey::image("sha256:abc"), image.key());

        let workload = Node::Workload(Workload {
            namespace: "app".into(),
            name: "web".into(),
            kind: "Pod".into(),
            labels: BTreeMap::new(),
            meshed: false,
            exposure: Exposure::Internal,
            runtime: vec![],
            persistent: false,
            misconfigs: vec![],
            rbac_findings: vec![],
        });
        assert_eq!(NodeKey::workload("app", "Pod", "web"), workload.key());
    }

    #[test]
    fn upsert_replaces_in_place_and_keeps_edges() {
        let mut g = SecurityGraph::new();
        let img = g.upsert_node(Node::Image(Image {
            digest: "sha256:abc".into(),
            reference: None,
            trust: Trust::Unknown,
            vulnerabilities: vec![],
            exposed_secrets: vec![],
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
            misconfigs: vec![],
            rbac_findings: vec![],
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
                ..Default::default()
            }],
            exposed_secrets: vec![],
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
            Some(super::attack::ESCAPE_TO_HOST)
        );
        assert_eq!(
            Relation::CanRead.technique(),
            Some(super::attack::CREDENTIAL_ACCESS)
        );
        assert_eq!(
            Relation::CanDo {
                verb: "get".into(),
                resource: "secrets".into()
            }
            .technique(),
            Some(super::attack::CREDENTIAL_ACCESS)
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
