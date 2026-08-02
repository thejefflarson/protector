//! `boundary_break(X)` (ADR-0040 §3): typed evidence that the adversary broke the
//! **pod** boundary on workload `X` — a process now acting in the host namespace,
//! rather than merely reached over the pod-scoped movement edges the proof layer
//! walks. Node containment ([`docs/adr/0040-node-scoped-containment-mechanism-
//! escalation.md`]) resolves a model-named workload `X` to the node-scoped cut
//! iff this predicate holds; otherwise `X` keeps its existing pod-scoped cut. That
//! resolver is a follow-up build — this module is the pure predicate alone (no
//! proposal surface, no actuation, no model-prompt change).
//!
//! Typed evidence only (ADR-0029 anti-fabrication): every trigger grounds on a typed
//! [`Behavior`] variant or a typed graph edge, never on untrusted scanner/CVE title
//! text. Any ONE of the four triggers is a break:
//!
//! - (a) [`host_path_secret_read`] — a host-path `SecretRead` on `X`;
//! - (b) [`root_escalation_with_escape`] — a `PrivilegeChange` to uid 0 on `X` AND an
//!   outgoing [`Relation::EscapesTo`] edge; either fact alone is not a break;
//! - (c) [`kernel_tamper`] — a `PtraceAttach` or `ModuleLoad` on `X`;
//! - (d) [`co_resident_dual_compromise`] — `X` and at least one OTHER workload
//!   co-resident on its `Host` (the [`Relation::ScheduledOn`] placement edge,
//!   ADR-0040) are BOTH a decisive model `attack` AND actively exploited
//!   ([`super::chain::actively_exploited`]) — determinism composing two model
//!   decisions, not replacing one. The stricter reading the ADR left open
//!   (build-settled 2026-08-02): both pods must clear the bar, not one confirmed
//!   plus one merely live.

use std::collections::BTreeSet;

use petgraph::stable_graph::NodeIndex;
use petgraph::visit::EdgeRef;

use super::chain::actively_exploited;
use super::corroborate::entry_runtime;
use crate::engine::graph::{Behavior, NodeKey, Relation, SecretReadSource, SecurityGraph};

/// Whether workload `x` has broken the pod boundary (ADR-0040 §3): any one of the
/// four typed triggers documented on the module. `model_attack` is the set of
/// workloads the model has decisively named `assessment=attack` (ADR-0034's
/// `IncidentDecision`/`contain` output) — supplied by the caller rather than
/// re-derived here, so this predicate stays a pure function of its inputs and
/// composes with whichever judged decision the caller already holds.
pub fn boundary_break(
    graph: &SecurityGraph,
    x: NodeIndex,
    model_attack: &BTreeSet<NodeKey>,
) -> bool {
    host_path_secret_read(graph, x)
        || root_escalation_with_escape(graph, x)
        || kernel_tamper(graph, x)
        || co_resident_dual_compromise(graph, x, model_attack)
}

/// Trigger (a): a host-path `SecretRead` on `x` — the host-credential class
/// (`engine::observe::host_credential_class`), a well-known ON-HOST credential path
/// read outside any k8s Secret mount. Distinct from an ordinary `Mounted`/`Api`
/// secret read, which stays inside the pod boundary.
fn host_path_secret_read(graph: &SecurityGraph, x: NodeIndex) -> bool {
    entry_runtime(graph, x).iter().any(|s| {
        matches!(
            &s.behavior,
            Behavior::SecretRead { source, .. } if *source == SecretReadSource::HostPath
        )
    })
}

/// Trigger (b): a `PrivilegeChange` to uid 0 on `x` **and** `x` carries an outgoing
/// `EscapesTo` edge. Either fact alone is not a break (ADR-0040 §3(b)): a routine
/// entrypoint escalating to root on an ordinary pod is common, and escape
/// *potential* without a live root escalation is only a precondition
/// (ADR-0001/0005) — the typed conjunction is what proves the boundary actually
/// broke.
fn root_escalation_with_escape(graph: &SecurityGraph, x: NodeIndex) -> bool {
    let escalated_to_root = entry_runtime(graph, x).iter().any(|s| {
        matches!(
            &s.behavior,
            Behavior::PrivilegeChange { from_uid, to_uid } if *from_uid != 0 && *to_uid == 0
        )
    });
    escalated_to_root && has_outgoing_escape(graph, x)
}

/// Whether `x` carries at least one outgoing `EscapesTo` edge (any `via`).
fn has_outgoing_escape(graph: &SecurityGraph, x: NodeIndex) -> bool {
    graph
        .inner()
        .edges(x)
        .any(|e| matches!(e.weight().relation, Relation::EscapesTo { .. }))
}

/// Trigger (c): a `PtraceAttach` or `ModuleLoad` on `x` (Retire-Falco G2 parity) —
/// process-injection / kernel-tamper primitives that mean host-kernel-level
/// compromise regardless of any other evidence.
fn kernel_tamper(graph: &SecurityGraph, x: NodeIndex) -> bool {
    entry_runtime(graph, x)
        .iter()
        .any(|s| matches!(s.behavior, Behavior::PtraceAttach | Behavior::ModuleLoad))
}

/// Trigger (d): `x` and at least one OTHER workload co-resident on `x`'s `Host`
/// (via the [`Relation::ScheduledOn`] placement edge, ADR-0040) are BOTH a
/// decisive model `attack` AND actively exploited. `x` itself must clear the bar —
/// this is the escalation for the workload the model already named, corroborated
/// by proof that the compromise has spread to a second pod on the same node, not a
/// blanket "any two compromised pods anywhere" rule.
fn co_resident_dual_compromise(
    graph: &SecurityGraph,
    x: NodeIndex,
    model_attack: &BTreeSet<NodeKey>,
) -> bool {
    if !is_decisive_attack_and_exploited(graph, x, model_attack) {
        return false;
    }
    let Some(host) = scheduled_host(graph, x) else {
        return false;
    };
    // Every OTHER workload with an outgoing `ScheduledOn` edge into `host` — the rest
    // of the co-resident set.
    graph
        .inner()
        .edges_directed(host, petgraph::Direction::Incoming)
        .filter(|e| matches!(e.weight().relation, Relation::ScheduledOn))
        .map(|e| e.source())
        .filter(|&n| n != x)
        .any(|n| is_decisive_attack_and_exploited(graph, n, model_attack))
}

/// Whether `n` is BOTH named in `model_attack` (a decisive model `assessment=attack`)
/// AND actively exploited (live runtime evidence, [`actively_exploited`]) — the
/// per-pod bar trigger (d) applies to every co-resident workload it considers.
fn is_decisive_attack_and_exploited(
    graph: &SecurityGraph,
    n: NodeIndex,
    model_attack: &BTreeSet<NodeKey>,
) -> bool {
    actively_exploited(graph, n) && graph.key_of(n).is_some_and(|k| model_attack.contains(&k))
}

/// The `Host` `x` is scheduled on, via its outgoing `ScheduledOn` placement edge —
/// `None` for an unscheduled (or non-workload) node, which has no host to be
/// co-resident on.
fn scheduled_host(graph: &SecurityGraph, x: NodeIndex) -> Option<NodeIndex> {
    graph
        .inner()
        .edges(x)
        .find(|e| matches!(e.weight().relation, Relation::ScheduledOn))
        .map(|e| e.target())
}
