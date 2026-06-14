//! The proof layer (ADR-0002, Question 2): find **provable** attack chains in the
//! graph and the single edge that breaks each one.
//!
//! This is the deterministic half of "a model may propose; only deterministic
//! proof may move privilege." It walks the graph directly — no model — and it
//! traverses **only proof-grade edges** ([`Edge::is_proof_grade`]), so a chain it
//! reports is grounded entirely in deterministic facts. A hypothesis-grade edge
//! (a future model's guess) is invisible here and can never appear in a proven
//! chain.
//!
//! ## What "proven" means in this slice
//!
//! A chain is a proof-grade path from an **entry** (a workload an attacker is
//! assumed to control) to an **objective** (a Secret — the thing worth reaching).
//! Traversal follows attacker *movement* edges: `reaches` (lateral movement),
//! `runs-as` (assume the workload's identity), `can-read` and `can-do` (use that
//! position to reach data). `runs-image` is deliberately excluded — it is how a
//! workload becomes *compromisable* (an entry-enabler), not how an attacker moves
//! toward an objective; it re-enters the bar when the Vulnerability/exposure ports
//! land.
//!
//! The exposure and vulnerability ports now provide the entry side of the bar: a
//! chain whose entry is internet-exposed **and** runs an exploited-in-wild image
//! carries a proven foothold (T1190). Per ADR-0009 the action bar is *asymmetric*:
//! a live-corroborated chain is auto-actionable on its own
//! ([`ProvenChain::meets_action_bar`]), while a foothold without live activity is
//! the weaker, propose-only [`ProvenChain::is_latent_foothold`] case.
//!
//! ## Entries
//!
//! Every workload is still a candidate *starting point* (assume-breach), so we
//! surface structural chains even without vuln data — but each chain is now
//! classified by whether its entry is a *proven foothold* (see [`entry_foothold`]).
//! A chain with no foothold is "if this workload were compromised…"; a chain with
//! one is "this workload is a real, exploitable front door."

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use petgraph::stable_graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;

use super::attack::{AttackRef, EXPLOIT_PUBLIC_FACING};
use super::graph::{Exposure, Node, NodeKey, Relation, SecurityGraph, Severity};
use super::objective::{ObjectiveRecognizer, default_recognizers};

/// One proven edge on a chain: a proof-grade relation from one node to the next,
/// with the ATT&CK technique it realizes (if it is an attack step rather than
/// structural substrate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub from: NodeKey,
    pub to: NodeKey,
    pub relation: String,
    pub technique: Option<AttackRef>,
    /// Labels of the `from`/`to` workloads (empty for non-workload endpoints), so a
    /// cut on this edge can be rendered as a precise pod selector (ADR-0007).
    pub from_labels: BTreeMap<String, String>,
    pub to_labels: BTreeMap<String, String>,
}

/// A proven attack chain: a proof-grade path from `entry` to `objective`, plus the
/// edges that individually sever it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenChain {
    pub entry: NodeKey,
    pub objective: NodeKey,
    /// The ATT&CK technique this chain achieves by reaching `objective`.
    pub attack: AttackRef,
    /// The Initial Access technique that proves the *entry* is a real foothold —
    /// `Some(EXPLOIT_PUBLIC_FACING)` when the entry workload is internet-exposed
    /// **and** runs an image with an exploited-in-wild vulnerability. `None` means
    /// the entry is an assume-breach starting point, not a proven foothold. This is
    /// the entry side of the action bar: a chain with both a foothold and a
    /// privileged objective has reachable ∧ exploited ∧ privileged proven; only
    /// runtime corroboration (the RuntimeEvidence port) is then still missing.
    pub foothold: Option<AttackRef>,
    /// Whether the entry workload has a live runtime signal (RuntimeEvidence port)
    /// — the `corroborated-now` predicate. With a foothold, this completes the full
    /// action bar: the front door is exploitable *and* something is happening on it
    /// right now.
    pub corroborated: bool,
    /// Whether the model adjudicator confirmed this is a real, contextually-
    /// exploitable attack (ADR-0013). Defaults `true`; the adjudicator can only set
    /// it `false` — a one-way veto demoting an eligible auto-action to a human
    /// proposal. Absent a model it stays `true` and the deterministic bar governs.
    pub adjudicated: bool,
    /// Whether the model *promoted* this proven-but-uncorroborated chain to
    /// auto-eligible (ADR-0011) — its positive "game-over" judgement on an
    /// internet-exposed entry. Defaults `false`; only an affirmative model verdict
    /// (never `NullAdjudicator`) sets it, and only behind the `judgement` opt-in.
    pub promoted: bool,
    /// Whether the **entry** workload is internet-facing (`Exposure::Internet`) — a
    /// front door an external attacker can actually start from. This is the
    /// discriminator between a *breach path* (internet → entry → objective) and the
    /// assume-breach blast-radius map ("if this internal workload were compromised,
    /// what could it reach"). An internal-only entry reaching a secret is normal
    /// Kubernetes topology, not a breach. See [`ProvenChain::is_breach_relevant`].
    pub exposed_entry: bool,
    /// The model's adjudication summary for this chain, when it was judged (ADR-0013)
    /// — both positive ("exploitable — …") and negative ("not exploitable — …")
    /// calls, kept so the dashboard can show *why* the model did or didn't act. `None`
    /// when no model was consulted (no evidence to weigh, or no model configured).
    pub verdict: Option<String>,
    /// The path, entry → objective, in order.
    pub links: Vec<Link>,
    /// Edges on the path whose removal alone disconnects `entry` from `objective`
    /// — the minimal-cut candidates (ADR-0002). Empty means no single edge
    /// suffices: redundant paths exist, and breaking the chain needs more than one
    /// cut. That emptiness is itself a finding, not a failure.
    pub single_edge_cuts: Vec<Link>,
}

impl ProvenChain {
    /// Chain strength is the number of proven links — the ADR-0001 measure.
    pub fn strength(&self) -> usize {
        self.links.len()
    }

    /// The *latent-exposure* signal (ADR-0009): a proven foothold at the entry
    /// (internet-exposed ∧ exploited-in-wild) on a privileged path, but **no** live
    /// activity. This is the weaker, propose-only case — a real exploitable front
    /// door that isn't being exploited yet.
    pub fn is_latent_foothold(&self) -> bool {
        self.foothold.is_some() && !self.corroborated
    }

    /// Whether this chain is a real **breach path** worth flagging, versus
    /// assume-breach context. True only when the entry is internet-facing — an
    /// origin an external attacker can actually reach. A purely-internal access path
    /// (a control-plane workload that can read a secret, a backend that can reach the
    /// database) is the *normal* shape of a cluster, not a breach; it belongs in the
    /// blast-radius map you consult after a compromise, not on a to-do list. The
    /// engine still proves and surfaces those chains — just as context, not findings.
    pub fn is_breach_relevant(&self) -> bool {
        self.exposed_entry
    }

    /// Whether the chain is **live-actionable**: a breach-relevant (internet-facing
    /// entry) chain that is either live-corroborated (ADR-0009) or model-promoted
    /// (ADR-0011). Both are filtered by the adjudicator's veto and bounded by the
    /// reversible, self-reverting action. Auto-action is reserved for *remote*
    /// exploitation paths, so an internal-only corroborated chain — normal cluster
    /// activity, not a breach — never clears the bar. This gates auto-action.
    pub fn meets_action_bar(&self) -> bool {
        self.is_breach_relevant() && (self.corroborated || self.promoted)
    }

    /// Log the chain as a structured line, including the ATT&CK technique it
    /// achieves, whether the entry is a proven foothold, and whether a single-edge
    /// cut exists (the surgical action a response layer would later take).
    pub fn emit(&self) {
        tracing::info!(
            entry = %self.entry.0,
            objective = %self.objective.0,
            tactic = self.attack.tactic.id(),
            technique = self.attack.technique_id,
            technique_name = self.attack.technique,
            foothold = self.foothold.map(|f| f.technique_id).unwrap_or("none"),
            corroborated = self.corroborated,
            exposed_entry = self.exposed_entry,
            breach_relevant = self.is_breach_relevant(),
            action_bar = self.meets_action_bar(),
            strength = self.strength(),
            single_edge_cuts = self.single_edge_cuts.len(),
            "proven chain"
        );
    }
}

/// Whether an edge is a valid attacker-movement edge for chain traversal.
fn is_movement(relation: &Relation) -> bool {
    !matches!(relation, Relation::RunsImage)
}

/// Whether `entry` is a proven foothold: an internet-exposed workload running an
/// image with a vulnerability serious enough to treat as an exploitable front door
/// (ATT&CK T1190). "Serious enough" is **exploited-in-wild (KEV) OR critical
/// severity** — a critical, reachable CVE is a foothold on its own, even if it
/// isn't on the KEV catalogue yet. (This drives the propose-only latent case;
/// auto-action still requires live corroboration, ADR-0009.)
fn entry_foothold(graph: &SecurityGraph, entry: NodeIndex) -> Option<AttackRef> {
    let g = graph.inner();
    let exposed = matches!(
        g.node_weight(entry),
        Some(Node::Workload(w)) if w.exposure == Exposure::Internet
    );
    if !exposed {
        return None;
    }
    let exploitable = g.edges(entry).any(|e| {
        matches!(e.weight().relation, Relation::RunsImage)
            && matches!(
                g.node_weight(e.target()),
                Some(Node::Image(im)) if im.vulnerabilities.iter()
                    .any(|v| v.exploited_in_wild || v.severity == Severity::Critical)
            )
    });
    exploitable.then_some(EXPLOIT_PUBLIC_FACING)
}

/// Whether `entry` is internet-facing — a front door an external attacker can start
/// from. Drives [`ProvenChain::is_breach_relevant`].
fn entry_exposed(graph: &SecurityGraph, entry: NodeIndex) -> bool {
    matches!(
        graph.inner().node_weight(entry),
        Some(Node::Workload(w)) if w.exposure == Exposure::Internet
    )
}

/// Whether `entry` has a live runtime signal — the `corroborated-now` predicate
/// (RuntimeEvidence port). True when the entry workload carries any runtime signal.
fn entry_corroborated(graph: &SecurityGraph, entry: NodeIndex) -> bool {
    matches!(
        graph.inner().node_weight(entry),
        Some(Node::Workload(w)) if !w.runtime.is_empty()
    )
}

/// BFS over proof-grade movement edges from `start`. Returns, for every reachable
/// node, the (predecessor, edge) it was first reached by — a shortest-path tree.
/// If `excluded` is set, that one edge is skipped (used to test cuts).
fn movement_tree(
    graph: &SecurityGraph,
    start: NodeIndex,
    excluded: Option<EdgeIndex>,
) -> HashMap<NodeIndex, (NodeIndex, EdgeIndex)> {
    let g = graph.inner();
    let mut came: HashMap<NodeIndex, (NodeIndex, EdgeIndex)> = HashMap::new();
    let mut seen: HashSet<NodeIndex> = HashSet::from([start]);
    let mut queue = VecDeque::from([start]);

    while let Some(u) = queue.pop_front() {
        for edge in g.edges(u) {
            if Some(edge.id()) == excluded {
                continue;
            }
            if !edge.weight().is_proof_grade() || !is_movement(&edge.weight().relation) {
                continue;
            }
            let v = edge.target();
            if seen.insert(v) {
                came.insert(v, (u, edge.id()));
                queue.push_back(v);
            }
        }
    }
    came
}

/// True if `target` is reachable from `start` over proof-grade movement edges with
/// `excluded` removed.
/// Whether the edge `e` is a sensible *cut* candidate — a privilege/movement edge,
/// not structural substrate (`runs-as`/`runs-image`/`scheduled-on`). Severing a
/// workload from its ServiceAccount isn't a mitigation; the meaningful cut is the
/// RBAC/network/data edge.
fn is_cuttable_edge(graph: &SecurityGraph, e: EdgeIndex) -> bool {
    graph
        .inner()
        .edge_weight(e)
        .is_some_and(|edge| !edge.relation.is_structural())
}

fn reachable_without(
    graph: &SecurityGraph,
    start: NodeIndex,
    target: NodeIndex,
    excluded: EdgeIndex,
) -> bool {
    movement_tree(graph, start, Some(excluded)).contains_key(&target)
}

/// Reconstruct the path entry → target from a shortest-path tree, as a list of
/// `(from, to, edge)` steps in order.
fn path_steps(
    came: &HashMap<NodeIndex, (NodeIndex, EdgeIndex)>,
    entry: NodeIndex,
    target: NodeIndex,
) -> Vec<(NodeIndex, NodeIndex, EdgeIndex)> {
    let mut steps = Vec::new();
    let mut cur = target;
    while cur != entry {
        let (prev, edge) = came[&cur];
        steps.push((prev, cur, edge));
        cur = prev;
    }
    steps.reverse();
    steps
}

/// The labels of the workload at `idx`, or empty for any non-workload node.
fn workload_labels(graph: &SecurityGraph, idx: NodeIndex) -> BTreeMap<String, String> {
    match graph.inner().node_weight(idx) {
        Some(Node::Workload(w)) => w.labels.clone(),
        _ => BTreeMap::new(),
    }
}

/// Build a [`Link`] for the edge `edge` running `from`→`to`.
fn link_of(graph: &SecurityGraph, from: NodeIndex, to: NodeIndex, edge: EdgeIndex) -> Link {
    let relation = &graph
        .inner()
        .edge_weight(edge)
        .expect("edge exists")
        .relation;
    Link {
        from: graph.key_of(from).expect("edge source exists"),
        to: graph.key_of(to).expect("edge target exists"),
        relation: relation.label(),
        technique: relation.technique(),
        from_labels: workload_labels(graph, from),
        to_labels: workload_labels(graph, to),
    }
}

/// Confirm a *proposed* chain against the graph — the deterministic gate a
/// hypothesis (e.g. a model's guess) must pass before it counts (ADR-0001: "a
/// model may propose; only deterministic proof may move privilege").
///
/// `steps` is the proposed path as `(from, to)` node-key pairs. The chain is
/// confirmed only if every step is backed by a real **proof-grade movement edge**
/// in the graph, the steps form a connected path from `entry`, and the final node
/// is a recognized objective. A step with no such edge — a hallucinated
/// relationship, or one backed only by a hypothesis-grade edge — drops the whole
/// chain (returns `None`). A confirmed chain is identical to one [`prove`] would
/// find, cuts and foothold included.
pub fn confirm(
    graph: &SecurityGraph,
    entry: &NodeKey,
    steps: &[(NodeKey, NodeKey)],
) -> Option<ProvenChain> {
    if steps.is_empty() {
        return None;
    }
    let g = graph.inner();
    let entry_idx = graph.index_of(entry)?;

    // Validate connectivity and that each step is a real proof-grade movement edge.
    let mut prev = entry.clone();
    let mut edges: Vec<(NodeIndex, NodeIndex, EdgeIndex)> = Vec::new();
    for (from, to) in steps {
        if *from != prev {
            return None; // steps don't form a path from the entry
        }
        let from_idx = graph.index_of(from)?;
        let to_idx = graph.index_of(to)?;
        let edge = g.edges(from_idx).find(|e| {
            e.target() == to_idx && e.weight().is_proof_grade() && is_movement(&e.weight().relation)
        })?;
        edges.push((from_idx, to_idx, edge.id()));
        prev = to.clone();
    }

    // The path's end must be a recognized objective; its technique tags the chain.
    let objective = prev;
    let attack = default_recognizers()
        .iter()
        .flat_map(|r| r.recognize(graph))
        .find(|o| o.node == objective)
        .map(|o| o.attack)?;
    let objective_idx = graph.index_of(&objective)?;

    let links = edges
        .iter()
        .map(|&(u, v, e)| link_of(graph, u, v, e))
        .collect();
    let single_edge_cuts = edges
        .iter()
        .filter(|&&(_, _, e)| {
            is_cuttable_edge(graph, e) && !reachable_without(graph, entry_idx, objective_idx, e)
        })
        .map(|&(u, v, e)| link_of(graph, u, v, e))
        .collect();
    Some(ProvenChain {
        entry: entry.clone(),
        objective,
        attack,
        foothold: entry_foothold(graph, entry_idx),
        corroborated: entry_corroborated(graph, entry_idx),
        adjudicated: true,
        promoted: false,
        exposed_entry: entry_exposed(graph, entry_idx),
        verdict: None,
        links,
        single_edge_cuts,
    })
}

/// Find every proven chain in `graph` using the default objective recognizers
/// (ADR-0005).
pub fn prove(graph: &SecurityGraph) -> Vec<ProvenChain> {
    prove_with(graph, &default_recognizers())
}

/// As [`prove`], but with an explicit recognizer set. For each workload entry,
/// each recognized objective node it can reach over proof-grade movement edges
/// yields one chain — tagged with the objective's ATT&CK technique — plus its
/// minimal-cut candidates.
pub fn prove_with(
    graph: &SecurityGraph,
    recognizers: &[Box<dyn ObjectiveRecognizer>],
) -> Vec<ProvenChain> {
    let g = graph.inner();
    let entries: Vec<NodeIndex> = g
        .node_indices()
        .filter(|&i| matches!(g.node_weight(i), Some(Node::Workload(_))))
        .collect();
    // Recognized objective nodes, resolved to indices and paired with their
    // ATT&CK technique.
    let objectives: Vec<(NodeIndex, AttackRef)> = recognizers
        .iter()
        .flat_map(|r| r.recognize(graph))
        .filter_map(|o| graph.index_of(&o.node).map(|i| (i, o.attack)))
        .collect();

    let mut chains = Vec::new();
    for &entry in &entries {
        let tree = movement_tree(graph, entry, None);
        let foothold = entry_foothold(graph, entry);
        let corroborated = entry_corroborated(graph, entry);
        let exposed_entry = entry_exposed(graph, entry);
        for &(objective, attack) in &objectives {
            if objective == entry || !tree.contains_key(&objective) {
                continue;
            }
            let steps = path_steps(&tree, entry, objective);
            let links = steps
                .iter()
                .map(|&(u, v, e)| link_of(graph, u, v, e))
                .collect();
            let single_edge_cuts = steps
                .iter()
                .filter(|&&(_, _, e)| {
                    is_cuttable_edge(graph, e) && !reachable_without(graph, entry, objective, e)
                })
                .map(|&(u, v, e)| link_of(graph, u, v, e))
                .collect();
            chains.push(ProvenChain {
                entry: graph.key_of(entry).expect("entry exists"),
                objective: graph.key_of(objective).expect("objective exists"),
                attack,
                foothold,
                corroborated,
                adjudicated: true,
                promoted: false,
                exposed_entry,
                verdict: None,
                links,
                single_edge_cuts,
            });
        }
    }
    chains
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::adapter::{build_graph, default_adapters};
    use crate::engine::observe::Snapshot;
    use serde_json::{Value, json};

    fn pod(value: Value) -> k8s_openapi::api::core::v1::Pod {
        serde_json::from_value(value).expect("valid Pod fixture")
    }

    fn netpol(value: Value) -> k8s_openapi::api::networking::v1::NetworkPolicy {
        serde_json::from_value(value).expect("valid NetworkPolicy fixture")
    }

    fn web(name: &str, role: &str) -> Value {
        json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": "app", "labels": {"role": role}},
            "spec": {"containers": [{"name": "c", "image": "img:1"}]}
        })
    }

    /// db mounts the secret; an ingress policy allows web → db. The proven chain
    /// from web is web →(reaches) db →(can-read) secret, and — being a single
    /// linear path — either edge alone cuts it.
    #[test]
    fn proves_lateral_chain_and_finds_single_edge_cuts() {
        let db = json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "db", "namespace": "app", "labels": {"role": "db"}},
            "spec": {
                "containers": [{
                    "name": "db", "image": "db:1",
                    "envFrom": [{"secretRef": {"name": "db-creds"}}]
                }]
            }
        });
        let policy = netpol(json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "db-ingress", "namespace": "app"},
            "spec": {
                "podSelector": {"matchLabels": {"role": "db"}},
                "policyTypes": ["Ingress"],
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": "web"}}}]}]
            }
        }));
        let snap = Snapshot {
            pods: vec![pod(web("web", "web")), pod(db)],
            network_policies: vec![policy],
            ..Default::default()
        };
        let chains = prove(&build_graph(&snap, &default_adapters()));

        let lateral = chains
            .iter()
            .find(|c| c.entry.0.contains("/web") && c.links.len() == 2)
            .expect("web → db → secret chain");
        assert_eq!(lateral.strength(), 2);
        // Linear path ⇒ both edges are individually sufficient cuts.
        assert_eq!(lateral.single_edge_cuts.len(), 2);

        // db itself is an entry with a 1-link direct-read chain.
        assert!(
            chains
                .iter()
                .any(|c| c.entry.0.contains("/db") && c.links.len() == 1)
        );
    }

    /// web can reach the secret via two distinct workloads (db and cache), both of
    /// which mount it. No single edge on the shortest path breaks reachability, so
    /// `single_edge_cuts` is empty — the honest "needs more than one cut" finding.
    #[test]
    fn redundant_paths_have_no_single_edge_cut() {
        let mount = |name: &str, role: &str| {
            json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": name, "namespace": "app", "labels": {"role": role}},
                "spec": {
                    "containers": [{
                        "name": "c", "image": "x:1",
                        "envFrom": [{"secretRef": {"name": "shared"}}]
                    }]
                }
            })
        };
        // One policy selecting both backends, allowing web in.
        let policy = netpol(json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "backends", "namespace": "app"},
            "spec": {
                "podSelector": {"matchLabels": {"tier": "backend"}},
                "policyTypes": ["Ingress"],
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": "web"}}}]}]
            }
        }));
        let mut db = mount("db", "db");
        db["metadata"]["labels"]["tier"] = json!("backend");
        let mut cache = mount("cache", "cache");
        cache["metadata"]["labels"]["tier"] = json!("backend");

        let snap = Snapshot {
            pods: vec![pod(web("web", "web")), pod(db), pod(cache)],
            network_policies: vec![policy],
            ..Default::default()
        };
        let chains = prove(&build_graph(&snap, &default_adapters()));

        let from_web = chains
            .iter()
            .find(|c| c.entry.0.contains("/web"))
            .expect("a chain from web to the shared secret");
        assert!(
            from_web.single_edge_cuts.is_empty(),
            "redundant paths ⇒ no single edge severs the chain"
        );
    }

    /// The RBAC path class: a workload assumes its ServiceAccount identity, which
    /// can read a secret via RBAC. The proven chain is
    /// workload →(runs-as) identity →(can-do) secret — strength 2, no network hop.
    #[test]
    fn proves_rbac_privilege_chain() {
        use crate::engine::observe::SecretMeta;
        use k8s_openapi::api::rbac::v1::{Role, RoleBinding};

        let app = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "app", "namespace": "app"},
            "spec": {
                "serviceAccountName": "app-sa",
                "containers": [{"name": "app", "image": "app:1"}]
            }
        }));
        let role: Role = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": "reader", "namespace": "app"},
            "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
        }))
        .unwrap();
        let binding: RoleBinding = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": "reader-binding", "namespace": "app"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reader"},
            "subjects": [{"kind": "ServiceAccount", "name": "app-sa", "namespace": "app"}]
        }))
        .unwrap();

        let snap = Snapshot {
            pods: vec![app],
            secrets: vec![SecretMeta {
                namespace: "app".into(),
                name: "api-key".into(),
            }],
            roles: vec![role],
            role_bindings: vec![binding],
            ..Default::default()
        };
        let chains = prove(&build_graph(&snap, &default_adapters()));

        let chain = chains
            .iter()
            .find(|c| c.entry.0.contains("/app") && c.objective.0 == "secret/app/api-key")
            .expect("app → identity → secret chain");
        assert_eq!(chain.strength(), 2);
        let relations: Vec<&str> = chain.links.iter().map(|l| l.relation.as_str()).collect();
        assert_eq!(relations, vec!["runs-as", "can-do/get/secrets"]);
        // Both edges sever the path, but the structural `runs-as` is not a cut
        // candidate (you don't sever a pod from its SA) — the only cut is the RBAC
        // grant, the meaningful, durable fix.
        assert_eq!(chain.single_edge_cuts.len(), 1);
        assert_eq!(chain.single_edge_cuts[0].relation, "can-do/get/secrets");
    }

    /// A privileged pod scheduled on a node yields a one-link Escape-to-Host chain
    /// (T1611), tagged with the Privilege Escalation tactic.
    #[test]
    fn proves_escape_to_host_chain_tagged_with_attack() {
        use crate::engine::attack::{ESCAPE_TO_HOST, Tactic};

        let privileged = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "runner", "namespace": "ci"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{
                    "name": "runner", "image": "runner:1",
                    "securityContext": {"privileged": true}
                }]
            }
        }));
        let snap = Snapshot {
            pods: vec![privileged],
            ..Default::default()
        };
        let chains = prove(&build_graph(&snap, &default_adapters()));

        let escape = chains
            .iter()
            .find(|c| c.objective.0 == "host/node-1")
            .expect("escape-to-host chain");
        assert_eq!(escape.entry.0, "workload/ci/Pod/runner");
        assert_eq!(escape.attack, ESCAPE_TO_HOST);
        assert_eq!(escape.attack.tactic, Tactic::PrivilegeEscalation);
        assert_eq!(escape.strength(), 1);
        assert_eq!(escape.links[0].relation, "escapes-to/privileged");
        // The single escape edge is the cut.
        assert_eq!(escape.single_edge_cuts.len(), 1);
    }

    /// A workload whose ServiceAccount can create pods yields an Execution / Deploy
    /// Container (T1610) chain to a Capability objective — the path class KubeHound
    /// models as `POD_CREATE`, here tagged in MITRE terms.
    #[test]
    fn proves_capability_chain_to_deploy_container() {
        use crate::engine::attack::{DEPLOY_CONTAINER, Tactic};
        use k8s_openapi::api::rbac::v1::{Role, RoleBinding};

        let deployer = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "deployer", "namespace": "ci"},
            "spec": {
                "serviceAccountName": "deployer-sa",
                "containers": [{"name": "c", "image": "c:1"}]
            }
        }));
        let role: Role = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": "pod-creator", "namespace": "ci"},
            "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]
        }))
        .unwrap();
        let binding: RoleBinding = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": "deployer-binding", "namespace": "ci"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "pod-creator"},
            "subjects": [{"kind": "ServiceAccount", "name": "deployer-sa", "namespace": "ci"}]
        }))
        .unwrap();

        let snap = Snapshot {
            pods: vec![deployer],
            roles: vec![role],
            role_bindings: vec![binding],
            ..Default::default()
        };
        let chains = prove(&build_graph(&snap, &default_adapters()));

        let chain = chains
            .iter()
            .find(|c| c.objective.0 == "capability/ns:ci/create/pods")
            .expect("deploy-container chain");
        assert_eq!(chain.entry.0, "workload/ci/Pod/deployer");
        assert_eq!(chain.attack, DEPLOY_CONTAINER);
        assert_eq!(chain.attack.tactic, Tactic::Execution);
        let relations: Vec<&str> = chain.links.iter().map(|l| l.relation.as_str()).collect();
        assert_eq!(relations, vec!["runs-as", "can-do/create/pods"]);
    }

    /// The entry side of the action bar: an internet-exposed (LoadBalancer) pod
    /// running an image with an exploited-in-wild CVE, reaching a secret. The chain
    /// is tagged with a proven foothold (T1190) and meets the structural action bar.
    #[test]
    fn proves_foothold_when_exposed_and_exploitable() {
        use crate::engine::attack::EXPLOIT_PUBLIC_FACING;
        use crate::engine::graph::{Provenance, Severity, Vulnerability};
        use crate::engine::observe::{ImageVulnerabilities, SecretMeta};
        use std::time::SystemTime;

        let web = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
            "spec": {
                "containers": [{
                    "name": "web", "image": "web:1",
                    "envFrom": [{"secretRef": {"name": "session-key"}}]
                }]
            }
        }));
        let lb: k8s_openapi::api::core::v1::Service = serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "web-lb", "namespace": "app"},
            "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
        }))
        .unwrap();
        let vuln = Vulnerability {
            id: "CVE-2026-9999".into(),
            severity: Severity::Critical,
            exploited_in_wild: true,
            epss: Some(0.97),
            sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
        };

        let snap = Snapshot {
            pods: vec![web],
            services: vec![lb],
            secrets: vec![SecretMeta {
                namespace: "app".into(),
                name: "session-key".into(),
            }],
            image_vulns: vec![ImageVulnerabilities {
                image: "web:1".into(),
                vulnerabilities: vec![vuln],
            }],
            ..Default::default()
        };
        let chains = prove(&build_graph(&snap, &default_adapters()));

        let chain = chains
            .iter()
            .find(|c| {
                c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/session-key"
            })
            .expect("web → secret chain");
        assert_eq!(chain.foothold, Some(EXPLOIT_PUBLIC_FACING));
        // Exposed + exploitable but no live activity ⇒ latent foothold (propose-only),
        // not live-actionable.
        assert!(chain.is_latent_foothold());
        assert!(!chain.corroborated);
        assert!(!chain.meets_action_bar());
    }

    /// A reachable *critical* CVE is a foothold on its own, even without KEV.
    #[test]
    fn critical_cve_alone_is_a_foothold() {
        use crate::engine::graph::{Provenance, Severity, Vulnerability};
        use crate::engine::observe::{ImageVulnerabilities, SecretMeta};
        use std::time::SystemTime;

        let web = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
            "spec": {"containers": [{
                "name": "web", "image": "web:1",
                "envFrom": [{"secretRef": {"name": "session-key"}}]
            }]}
        }));
        let lb: k8s_openapi::api::core::v1::Service = serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "web-lb", "namespace": "app"},
            "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
        }))
        .unwrap();
        let snap = Snapshot {
            pods: vec![web],
            services: vec![lb],
            secrets: vec![SecretMeta {
                namespace: "app".into(),
                name: "session-key".into(),
            }],
            image_vulns: vec![ImageVulnerabilities {
                image: "web:1".into(),
                vulnerabilities: vec![Vulnerability {
                    id: "CVE-2026-0042".into(),
                    severity: Severity::Critical,
                    // Critical, but NOT on the KEV catalogue.
                    exploited_in_wild: false,
                    epss: None,
                    sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                }],
            }],
            ..Default::default()
        };
        let chains = prove(&build_graph(&snap, &default_adapters()));
        let chain = chains
            .iter()
            .find(|c| {
                c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/session-key"
            })
            .expect("web → secret chain");
        assert_eq!(chain.foothold, Some(EXPLOIT_PUBLIC_FACING));
    }

    /// Adding a live runtime signal on the foothold workload supplies the final
    /// predicate — the full action bar is then met.
    #[test]
    fn runtime_signal_completes_the_action_bar() {
        use crate::engine::graph::{Provenance, Severity, Vulnerability};
        use crate::engine::observe::{ImageVulnerabilities, RuntimeObservation, SecretMeta};
        use std::time::SystemTime;

        let web = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
            "spec": {"containers": [{
                "name": "web", "image": "web:1",
                "envFrom": [{"secretRef": {"name": "session-key"}}]
            }]}
        }));
        let lb: k8s_openapi::api::core::v1::Service = serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "web-lb", "namespace": "app"},
            "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
        }))
        .unwrap();
        let snap = Snapshot {
            pods: vec![web],
            services: vec![lb],
            secrets: vec![SecretMeta {
                namespace: "app".into(),
                name: "session-key".into(),
            }],
            image_vulns: vec![ImageVulnerabilities {
                image: "web:1".into(),
                vulnerabilities: vec![Vulnerability {
                    id: "CVE-2026-9999".into(),
                    severity: Severity::Critical,
                    exploited_in_wild: true,
                    epss: None,
                    sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                }],
            }],
            runtime_events: vec![RuntimeObservation {
                namespace: "app".into(),
                pod: "web".into(),
                rule: "Outbound connection to C2".into(),
            }],
            ..Default::default()
        };
        let chains = prove(&build_graph(&snap, &default_adapters()));
        let chain = chains
            .iter()
            .find(|c| {
                c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/session-key"
            })
            .expect("web → secret chain");
        assert!(
            chain.corroborated,
            "runtime signal on the entry corroborates"
        );
        assert!(
            chain.meets_action_bar(),
            "foothold + corroboration = full bar"
        );
    }
}
