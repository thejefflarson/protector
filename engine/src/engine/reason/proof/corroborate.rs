//! Corroboration (ADR-0014): whether a live runtime signal evidences a proven chain.
//! Split out of the proof module root purely to keep every file under the 1,000-line
//! cap (repo CLAUDE.md). These predicates are shadow-gated — they only set
//! `corroborated`; they never actuate. `corroborates` is the per-objective seam the ADR
//! is stated in terms of; `corroborated_for` resolves it for an entry's signals.

use petgraph::stable_graph::NodeIndex;

use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{Behavior, Node, SecurityGraph};

/// Whether a runtime `behavior` corroborates a chain whose objective has technique
/// `attack` — the `corroborates(behavior, objective)` relation (ADR-0014). This is the
/// per-objective seam the ADR's non-shadow design is stated in terms of.
///
/// An *alerting* signal corroborates **any** objective: an alert means "an attack is
/// happening now" regardless of which chain. An alert arrives via the tool-agnostic
/// behavioral port (ADR-0003), so any sensor can raise one. An interactive-shell or
/// package-manager exec (JEF-55) corroborates the same broad way (JEF-117): a
/// hands-on-keyboard / tamper-now signal that, like the alert, evidences active intrusion
/// irrespective of which chain it lands on. An *alarming* file write (JEF-309) — a write to
/// a sensitive path (drop-and-execute / config tamper) — is the third such blanket source
/// (`observe::alarm_class::alarming_write`). The agent's own mundane behaviors
/// (connection / secret-read / library-load) corroborate per objective — each only for
/// the objective class whose ATT&CK *tactic* it evidences (JEF-49), so they are never the
/// "everything corroborates everything" blanket the alert gate intentionally is.
///
/// Matching on `attack.tactic` (not the precise technique) is the stable key: the
/// recognizers tag a Secret-read chain CREDENTIAL_ACCESS (T1552), an internet-egress
/// chain EXFILTRATION (T1041), and a proven foothold INITIAL_ACCESS / EXPLOIT_PUBLIC_FACING
/// (T1190). A connection to a **high-signal foothold peer** — a cloud-metadata/IMDS
/// endpoint or the Kubernetes API server — also corroborates INITIAL_ACCESS (JEF-307), the
/// engine-side classification of a cloud-metadata / API-server contact.
///
/// **Shadow-gated (ADR-0014):** these arms only set `corroborated=true`; they are inert
/// for *actuation*, which stays gated behind `engine.enable` (empty = shadow). They
/// remain observe-only until the shadow bake clears and an operator sets `enable` — this
/// change does NOT touch any default/enable config.
pub(super) fn corroborates(behavior: &Behavior, attack: &AttackRef) -> bool {
    use crate::engine::graph::attack::Tactic;
    match behavior {
        // Unchanged: an alerting signal corroborates any objective.
        Behavior::Alert { .. } => true,
        // Actual internet egress corroborates an EXFILTRATION objective (T1041): a
        // compromised workload shipping data out of the cluster. An in-cluster
        // connection (`internet: false`) to an ordinary peer is normal traffic and
        // corroborates nothing.
        //
        // JEF-307: a connection to a **high-signal foothold peer** — a cloud-metadata /
        // IMDS credential endpoint or the Kubernetes API server — corroborates a FOOTHOLD
        // (Initial Access, T1190) instead. Classified ENGINE-SIDE: the node-local agent has
        // no cluster creds to know what a peer is, so the engine classifies it from the
        // JEF-131-resolved peer (`observe::peer_class`, zero-egress, no wire change).
        // Conservative on purpose (ADR-0011): only these specific peers promote — ordinary
        // in-cluster and ordinary internet egress do NOT.
        Behavior::NetworkConnection { internet, .. } => {
            (*internet && attack.tactic == Tactic::Exfiltration)
                || (attack.tactic == Tactic::InitialAccess
                    && crate::engine::observe::peer_class::foothold_peer(behavior).is_some())
        }
        // A read of a mounted secret corroborates a CREDENTIAL_ACCESS objective (T1552):
        // the workload is actually touching the credential the chain reaches.
        Behavior::SecretRead { .. } => attack.tactic == Tactic::CredentialAccess,
        // A library load corroborates a FOOTHOLD (Initial Access / Exploit Public-Facing,
        // T1190): after JEF-75 a LibraryLoaded surviving on a workload is already pruned
        // to a *vulnerable* library, so its presence is the runtime foothold signal.
        // (JEF-51 v2: this is also where dynamic CVE reachability promotes a foothold.)
        Behavior::LibraryLoaded { .. } => attack.tactic == Tactic::InitialAccess,
        // FileRead never reaches here — the RuntimeAdapter refines it to SecretRead or
        // drops it before it becomes graph state.
        Behavior::FileRead { .. } => false,
        // A *notable* exec — an interactive shell or package manager in the container
        // (JEF-55) — corroborates ANY objective like an Alert does (JEF-117): a tamper-now
        // signal that evidences active intrusion regardless of chain. Conservative on
        // purpose: a *bare* ProcessExec
        // (anything else) stays NON-corroborating — legit entrypoints exec constantly
        // (the ADR-0011 on-call-engineer false positive), so it remains model evidence
        // only. `notable_exec` is `Some` exactly for shell/pkg-mgr execs (JEF-113: the
        // classifier is engine policy in `observe::exec_class`, not on the wire type).
        Behavior::ProcessExec { .. } => {
            crate::engine::observe::exec_class::notable_exec(behavior).is_some()
        }
        // PrivilegeChange is NON-corroborating here: model evidence, not a per-objective
        // "now" signal (legit entrypoints escalate too — the same ADR-0011 false positive).
        // Wiring it into a specific attack chain would be a JEF-49-style follow-up.
        Behavior::PrivilegeChange { .. } => false,
        // An *alarming* FileWrite — a sensitive-path / drop-and-execute / config-tamper drift
        // write (JEF-309) — corroborates ANY objective like an Alert / notable exec does: a
        // tamper-now signal that evidences active intrusion regardless of chain. Conservative
        // on purpose (ADR-0011): a *benign* write (an app
        // writing its own `/data`/`/tmp`/logs — the common case) stays NON-corroborating and
        // remains model evidence only. `alarming_write` is `Some` exactly for the sensitive
        // subset (JEF-113: the path judgement is engine policy in `observe::alarm_class`, not on
        // the wire type — a policy change rebuilds only the engine).
        Behavior::FileWrite { .. } => {
            crate::engine::observe::alarm_class::alarming_write(behavior).is_some()
        }
    }
}

/// Whether any live signal on `entry` corroborates a chain whose objective has technique
/// `attack` and whose entry is the proven foothold `foothold` — the `corroborated-now`
/// predicate (ADR-0009). See [`corroborates`] for the underlying per-behavior relation.
///
/// A behavior corroborates if it evidences **either** the objective's tactic **or** the
/// foothold's tactic (JEF-77). The objective side is the per-objective seam (a SecretRead
/// corroborates the CredentialAccess objective, an internet egress the Exfiltration one);
/// the foothold side closes the gap that left the `LibraryLoaded → InitialAccess` arm
/// dormant — a vuln-matched library load (already pruned by JEF-75) on an internet-facing
/// entry evidences the *entry* foothold (T1190), never an objective's `attack`. With no
/// foothold (`None`) only the objective side applies, so an assume-breach chain is
/// unaffected.
pub(super) fn corroborated_for(
    runtime: &[crate::engine::graph::RuntimeSignal],
    attack: &AttackRef,
    foothold: Option<&AttackRef>,
) -> bool {
    runtime.iter().any(|s| {
        corroborates(&s.behavior, attack) || foothold.is_some_and(|f| corroborates(&s.behavior, f))
    })
}

/// The entry workload's runtime signals (empty for a non-workload node), resolved once
/// per entry so [`corroborated_for`] doesn't re-look-up the constant entry node on every
/// objective in the per-objective loop.
pub(super) fn entry_runtime(
    graph: &SecurityGraph,
    entry: NodeIndex,
) -> &[crate::engine::graph::RuntimeSignal] {
    match graph.inner().node_weight(entry) {
        Some(Node::Workload(w)) => &w.runtime,
        _ => &[],
    }
}
