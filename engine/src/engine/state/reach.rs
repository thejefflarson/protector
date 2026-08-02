//! The adversary-reach annotation (ADR-0040 §"Adversary-reach annotation: presentation-only,
//! never judge context"): a value-free "if compromised, this workload grants the attacker …"
//! line, composed from a closed-vocabulary secret-*purpose* inference and this entry's
//! already-proven assume-breach reach (reachable data stores, RBAC capabilities, an internet
//! egress path).
//!
//! **PRESENTATION-ONLY.** This is *context-not-evidence*
//! (ADR-0029/ADR-0034 — the model's `contain` is pinned to the exact evidence-bearing set,
//! leaving no legitimate discretion for reach-context to inform); the guarantee is enforced by
//! ABSENCE from the judge prompt, never by a runtime filter — see
//! `reason::adjudicate::tests::reach_absence` for the regression that asserts no judge-prompt
//! build path ever renders a reach line. Nothing in `reason::adjudicate::prompt` imports this
//! module; keep it that way.
//!
//! **Never reads a secret's `.data`.** The purpose inference is a closed-vocabulary GUESS from
//! the secret's bare NAME only — the same privacy door the graph already keeps shut (a
//! [`crate::engine::graph::SecretRef`] never carries a value either). Reading a k8s Secret's
//! `type` field would be a legitimate additional signal (ADR-0040 names it explicitly) but
//! would require abandoning the metadata-only `PartialObjectMeta<Secret>` watch
//! (`engine::run_loop`) for a full-object one; that infra change is deliberately out of scope
//! here — name-only heuristics are a strict subset of the ADR's allowed signals, never a
//! stronger read than today's.
//!
//! The closed vocabulary is fixed by ADR-0040's "Build-settled decisions": extending it needs a
//! new ADR, never an open-ended free-text path.

use petgraph::visit::EdgeRef;

use crate::engine::graph::{Node, NodeKey, Relation, SecurityGraph};
use crate::engine::reason::proof::ProvenChain;

/// A mounted secret's inferred PURPOSE — never its name or value. Closed vocabulary
/// (ADR-0040): extending this set needs a new ADR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretPurpose {
    ServiceAccountToken,
    TlsPrivateKey,
    RegistryPull,
    CloudProviderCredential,
    DatabaseCredential,
    /// The honest fallback when no heuristic matches — still discloses that SOME secret is
    /// mounted (its purpose can't be inferred without reading its `.data`, which stays closed).
    GenericOpaque,
}

impl SecretPurpose {
    /// The stable, human-facing category word.
    pub fn label(self) -> &'static str {
        match self {
            SecretPurpose::ServiceAccountToken => "service-account-token",
            SecretPurpose::TlsPrivateKey => "tls-private-key",
            SecretPurpose::RegistryPull => "registry-pull",
            SecretPurpose::CloudProviderCredential => "cloud-provider-credential",
            SecretPurpose::DatabaseCredential => "database-credential",
            SecretPurpose::GenericOpaque => "generic-opaque",
        }
    }

    /// Infer a category from the secret's bare NAME alone (never `.data`) — a best-effort
    /// substring match against common Kubernetes/cloud naming conventions. An unmatched name
    /// is the honest [`SecretPurpose::GenericOpaque`] default, never a guess dressed up as a
    /// stronger category.
    fn infer(name: &str) -> Self {
        let n = name.to_ascii_lowercase();
        let has_any = |words: &[&str]| words.iter().any(|w| n.contains(w));
        if has_any(&["token"]) {
            SecretPurpose::ServiceAccountToken
        } else if has_any(&["tls", "cert"]) {
            SecretPurpose::TlsPrivateKey
        } else if has_any(&["registry", "regcred", "docker", "pull-secret"]) {
            SecretPurpose::RegistryPull
        } else if has_any(&["aws", "gcp", "azure", "cloud"]) {
            SecretPurpose::CloudProviderCredential
        } else if has_any(&[
            "db", "database", "postgres", "mysql", "mongo", "redis", "sql",
        ]) {
            SecretPurpose::DatabaseCredential
        } else {
            SecretPurpose::GenericOpaque
        }
    }
}

/// The value-free "if compromised, this workload grants the attacker …" annotation
/// (ADR-0040). Composed from the entry's DIRECTLY-mounted secrets' inferred purposes (never a
/// name) and counts drawn from this pass's already-proven [`ProvenChain`]s rooted at the entry
/// — never re-walked, never re-derived from anything the judge prompt doesn't also see as
/// reachability.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReachAnnotation {
    /// Sorted, deduped purpose categories of the entry's directly-mounted secrets.
    pub secret_purposes: Vec<SecretPurpose>,
    /// Count of distinct persistent-storage (data-store) objectives this entry can reach.
    pub data_stores: usize,
    /// Count of distinct dangerous-RBAC-capability objectives this entry can reach.
    pub capabilities: usize,
    /// Whether this entry can reach an internet egress channel.
    pub egress: bool,
}

impl ReachAnnotation {
    /// Compute the annotation for `entry`. Secret purposes come from the graph's already-
    /// observed `can-read` edges (the secret-mount adapter's output — never `.data`); the
    /// reach counts come from `chains`, this pass's already-proven chains — filtered to the
    /// ones rooted at `entry`, never re-walked. `None` when `entry` isn't a known workload
    /// node (nothing to annotate).
    pub fn for_entry(
        graph: &SecurityGraph,
        entry: &NodeKey,
        chains: &[ProvenChain],
    ) -> Option<Self> {
        let idx = graph.index_of(entry)?;
        if !matches!(graph.node(idx), Some(Node::Workload(_))) {
            return None;
        }

        let mut secret_purposes: Vec<SecretPurpose> = graph
            .inner()
            .edges(idx)
            .filter(|e| matches!(e.weight().relation, Relation::CanRead))
            .filter_map(|e| match graph.node(e.target()) {
                Some(Node::Secret(s)) => Some(SecretPurpose::infer(&s.name)),
                _ => None,
            })
            .collect();
        secret_purposes.sort();
        secret_purposes.dedup();

        let mut data_stores = 0usize;
        let mut capabilities = 0usize;
        let mut egress = false;
        for c in chains.iter().filter(|c| &c.entry == entry) {
            let Some(obj_idx) = graph.index_of(&c.objective) else {
                continue;
            };
            match graph.node(obj_idx) {
                Some(Node::Workload(w)) if w.persistent => data_stores += 1,
                Some(Node::Capability(_)) => capabilities += 1,
                Some(Node::Endpoint(e)) if e.address == "internet" => egress = true,
                _ => {}
            }
        }

        Some(Self {
            secret_purposes,
            data_stores,
            capabilities,
            egress,
        })
    }

    /// Render the value-free line: closed-vocabulary categories and COUNTS only — never a
    /// secret or workload NAME. Safe at every MCP tier and in the default redacted notifier
    /// payload, the same "a count, never the target" precedent the notifier's
    /// `objectives_reached` field already sets (ADR-0018).
    pub fn line(&self) -> String {
        let mut clauses: Vec<String> = Vec::new();
        if !self.secret_purposes.is_empty() {
            let items: Vec<String> = self
                .secret_purposes
                .iter()
                .map(|p| format!("a {} secret", p.label()))
                .collect();
            clauses.push(join_and(&items));
        }
        let mut reach: Vec<String> = Vec::new();
        if self.data_stores > 0 {
            reach.push(format!(
                "{} reachable {}",
                self.data_stores,
                pluralize(self.data_stores, "data store", "data stores")
            ));
        }
        if self.capabilities > 0 {
            reach.push(format!(
                "{} reachable {}",
                self.capabilities,
                pluralize(self.capabilities, "RBAC capability", "RBAC capabilities")
            ));
        }
        if self.egress {
            reach.push("an internet egress path".to_string());
        }
        if !reach.is_empty() {
            clauses.push(join_and(&reach));
        }
        if clauses.is_empty() {
            return "if compromised, this workload grants the attacker no additional reach beyond itself".to_string();
        }
        format!(
            "if compromised, this workload grants the attacker: {}",
            clauses.join("; ")
        )
    }
}

/// `singular` for a count of 1, `plural` otherwise — shared by [`ReachAnnotation::line`]'s two
/// irregular-plural count words (`data store`/`data stores`, `RBAC capability`/`RBAC
/// capabilities`).
fn pluralize(count: usize, singular: &'static str, plural: &'static str) -> &'static str {
    if count == 1 { singular } else { plural }
}

/// A small "a, b, and c" join, used by [`ReachAnnotation::line`]'s two clauses.
fn join_and(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [only] => only.clone(),
        [a, b] => format!("{a} and {b}"),
        _ => {
            let (last, rest) = items.split_last().expect("non-empty checked above");
            format!("{}, and {}", rest.join(", "), last)
        }
    }
}

#[cfg(test)]
mod tests;
