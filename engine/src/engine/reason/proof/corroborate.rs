//! Corroboration (ADR-0014): whether a live runtime signal evidences a proven chain.
//! Split out of the proof module root purely to keep every file under the 1,000-line
//! cap (repo CLAUDE.md). These predicates are shadow-gated — they only set
//! `corroborated`; they never actuate. `corroborates` is the per-objective seam the ADR
//! is stated in terms of; `corroborated_for` resolves it for an entry's signals.

use std::time::Duration;

use petgraph::stable_graph::NodeIndex;

use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{Behavior, Node, RuntimeSignal, SecretReadSource, SecurityGraph};

/// The context the entry workload provides to the corroboration predicate (JEF-319, JEF-314).
/// The flat per-behavior [`corroborates`] relation is context-free on purpose
/// (regression-safe); the entry-scoped shapes below (cross-tenant lateral, privilege
/// escalation) need MORE than `behavior + attack`, so they read the entry's own namespace
/// and foothold status from here.
///
/// Both shapes are scoped to a real internet-facing entry so an ordinary cross-namespace
/// service call — or an ordinary setuid — from a non-entry pod never corroborates
/// (ADR-0011 / ADR-0014 conservatism). `source_ns` is the entry workload's namespace;
/// `is_foothold` is true only when the entry is a proven internet-facing foothold (a
/// critical/KEV front door).
#[derive(Clone, Copy)]
pub(super) struct EntryContext<'a> {
    /// The entry workload's own namespace — the SOURCE side of the cross-tenant comparison.
    pub source_ns: &'a str,
    /// Whether the entry is a proven internet-facing foothold (ADR-0009): the gate that
    /// scopes every entry-scoped shape to a real front door, not any workload.
    pub is_foothold: bool,
}

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
/// a sensitive path (drop-and-execute / config tamper) — is a further such blanket source
/// (`observe::alarm_class::alarming_write`). The agent's own mundane behaviors
/// (connection / secret-read / library-load) corroborate per objective — each only for
/// the objective class whose ATT&CK *tactic* it evidences (JEF-49), so they are never the
/// "everything corroborates everything" blanket the alert gate intentionally is.
///
/// **JEF-317 (anon-inode exec) is deliberately NOT one of these blanket sources.** An
/// earlier version routed a "fileless exec" classification (matched on exec *path shape*)
/// into this same blanket gate — withdrawn by security review: the kernel synthesizes the
/// identical path shape for a benign `fexecve()` of an on-disk file, and runc copies
/// itself into a memfd and re-execs via that shape on ~every container start, so it forged
/// corroboration on routine behavior at a high base rate. The real (inode-based) signal —
/// `Behavior::ProcessExec::exe_anon_inode` — is scoped MUCH more narrowly, at the
/// entry-scoped seam: see [`anon_inode_exec_on_foothold`].
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
        // A read of a k8s-mounted or API-fetched secret corroborates a CREDENTIAL_ACCESS
        // objective (T1552) context-free: the workload is actually touching a credential
        // the chain reaches, unambiguous regardless of foothold status.
        //
        // `SecretReadSource::HostPath` (JEF-320) is DELIBERATELY EXCLUDED here (security
        // rework): an on-host credential path can be read by an ordinary, legitimate
        // in-container process unrelated to the chain (a bastion pod's own `sshd` reading
        // its own `/etc/shadow` for PAM), so it needs the proven-foothold gate the flat,
        // context-free relation can't apply — that shape lives at the entry-scoped seam
        // ([`host_credential_read_on_foothold`]), mirroring how `PrivilegeChange` defers to
        // [`privilege_escalation_on_foothold`].
        Behavior::SecretRead { source, .. } => {
            attack.tactic == Tactic::CredentialAccess && *source != SecretReadSource::HostPath
        }
        // A library load corroborates a FOOTHOLD (Initial Access / Exploit Public-Facing,
        // T1190): after JEF-75 a LibraryLoaded surviving on a workload is already pruned
        // to a *vulnerable* library, so its presence is the runtime foothold signal.
        // (JEF-51 v2: this is also where dynamic CVE reachability promotes a foothold.)
        Behavior::LibraryLoaded { .. } => attack.tactic == Tactic::InitialAccess,
        // FileRead never reaches here — the RuntimeAdapter refines it to SecretRead or
        // drops it before it becomes graph state.
        Behavior::FileRead { .. } => false,
        // A *notable* exec — an interactive shell or a package manager run in the container
        // (JEF-55) — corroborates ANY objective like an Alert does (JEF-117): a tamper-now
        // signal that evidences active intrusion regardless of chain. Conservative on
        // purpose: a *bare* ProcessExec (anything else, including one with
        // `exe_anon_inode: true` — see [`anon_inode_exec_on_foothold`] for that shape's
        // own, much narrower gate) stays NON-corroborating here — legit entrypoints exec
        // constantly (the ADR-0011 on-call-engineer false positive), so it remains model
        // evidence only. `notable_exec` is `Some` exactly for shell/pkg-mgr execs (JEF-113:
        // the classifier is engine policy in `observe::exec_class`, not on the wire type).
        Behavior::ProcessExec { .. } => {
            crate::engine::observe::exec_class::notable_exec(behavior).is_some()
        }
        // PrivilegeChange is NON-corroborating here: model evidence, not a per-objective
        // "now" signal (legit entrypoints escalate too — the same ADR-0011 false positive).
        // Context-free root escalation stays this way for ANY pod on purpose: a root
        // escalation on the proven internet-facing foothold DOES corroborate a
        // PrivilegeEscalation objective, but that needs the entry's foothold status, which
        // this flat relation doesn't have — so that shape lives at the entry-scoped seam
        // ([`privilege_escalation_on_foothold`]), not here (JEF-314).
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
        // ImageLinkage is a structural per-image fact (JEF-407), NOT a runtime "now" signal —
        // it never corroborates any objective. It is also diverted by the RuntimeAdapter into
        // `Image::static_binary` before it becomes workload runtime state, so in practice it
        // never reaches here; this arm keeps the match exhaustive and the invariant explicit
        // (only `LoadedAtRuntime` is CVE evidence — a static-linkage fact must never read as
        // exploitation or reassurance).
        Behavior::ImageLinkage { .. } => false,
    }
}

/// Whether any live signal on the entry corroborates a chain whose objective has technique
/// `attack`, whose entry is the proven foothold `foothold`, and whose entry has
/// [`EntryContext`] `entry` — the `corroborated-now` predicate (ADR-0009). See
/// [`corroborates`] for the underlying per-behavior relation.
///
/// A behavior corroborates via the flat relation if it evidences **either** the objective's
/// tactic **or** the foothold's tactic (JEF-77). The objective side is the per-objective seam
/// (a SecretRead corroborates the CredentialAccess objective, an internet egress the
/// Exfiltration one); the foothold side closes the gap that left the `LibraryLoaded →
/// InitialAccess` arm dormant — a vuln-matched library load (already pruned by JEF-75) on an
/// internet-facing entry evidences the *entry* foothold (T1190), never an objective's
/// `attack`. With no foothold (`None`) only the objective side applies, so an assume-breach
/// chain is unaffected.
///
/// A chain is corroborated if EITHER the context-free per-behavior relation holds for any
/// signal (the objective's tactic OR the foothold's tactic, JEF-77) OR one of the
/// entry-scoped shapes fires: **cross-tenant lateral** (JEF-319) — a connection from the
/// entry to a peer in a DIFFERENT namespace ([`cross_tenant_lateral`]) — **privilege
/// escalation on the foothold** (JEF-314) — a root escalation on the entry itself
/// ([`privilege_escalation_on_foothold`]) — **drop-then-execute** (JEF-321) — a
/// `ProcessExec` of a path a RECENT `FileWrite` dropped ([`drop_then_execute`]) — **an
/// on-host credential read on the foothold** (JEF-320 security rework) — a `SecretRead` with
/// [`SecretReadSource::HostPath`] on the entry itself
/// ([`host_credential_read_on_foothold`]) — or **anon-inode exec on the foothold** (JEF-317,
/// Route A) — an Execution-tactic objective with an `exe_anon_inode` exec on the entry
/// ([`anon_inode_exec_on_foothold`]). All five are scoped to a proven foothold entry.
///
/// None of these shapes widens the flat predicates it sits beside: ordinary internet egress,
/// ordinary in-cluster traffic, an ordinary setuid, an ordinary write-then-run of a benign
/// path, and an ordinary in-container process reading a host credential path off a
/// non-foothold pod all still corroborate nothing (ADR-0011). Like every arm here this only
/// sets `corroborated`; it never actuates
/// (shadow-gated, ADR-0014).
pub(super) fn corroborated_for(
    runtime: &[RuntimeSignal],
    attack: &AttackRef,
    foothold: Option<&AttackRef>,
    entry: EntryContext<'_>,
) -> bool {
    runtime.iter().any(|s| {
        corroborates(&s.behavior, attack) || foothold.is_some_and(|f| corroborates(&s.behavior, f))
    }) || cross_tenant_lateral(runtime, entry)
        || privilege_escalation_on_foothold(runtime, attack, entry)
        || drop_then_execute(runtime, entry)
        || host_credential_read_on_foothold(runtime, attack, entry)
        || anon_inode_exec_on_foothold(runtime, attack, entry)
}

/// The cross-tenant lateral-movement shape (JEF-319): a `NetworkConnection` from the entry to
/// a service/pod in a DIFFERENT namespace corroborates lateral movement — the classic move an
/// attacker makes after owning the front door.
///
/// Conservative scoping (ADR-0011 / ADR-0014): corroborates ONLY when the entry is a proven
/// internet-facing foothold (`entry.is_foothold`) AND the peer resolved (JEF-131) to a real
/// `namespace/name` label in a namespace other than the entry's. A same-namespace call, an
/// unresolved/internet peer, or ANY call from a non-foothold entry returns `false`, so a legit
/// cross-namespace service call from an ordinary pod never corroborates.
pub(super) fn cross_tenant_lateral(runtime: &[RuntimeSignal], entry: EntryContext<'_>) -> bool {
    if !entry.is_foothold {
        return false;
    }
    runtime.iter().any(|s| match &s.behavior {
        Behavior::NetworkConnection { peer, .. } => {
            crate::engine::observe::peer_class::is_cross_tenant(entry.source_ns, peer)
        }
        _ => false,
    })
}

/// The narrowest gap a `FileWrite` and the `ProcessExec` of the SAME path can sit apart and
/// still read as one drop-then-execute act rather than coincidental path reuse (JEF-321): a
/// script dropped and immediately run is seconds to low minutes apart; the same path written
/// and re-run much later (a build cache, a rotated log re-opened for append) is unrelated.
pub(super) const DROP_EXEC_WINDOW: Duration = Duration::from_secs(300);

/// The drop-then-execute shape (JEF-321): a `ProcessExec` of a path RECENTLY `FileWrite`n by
/// the SAME workload — the classic "drop a payload under a benign-looking path (e.g. `/tmp`),
/// then run it" pattern. Neither behavior alone is `corroborates`-blanket here: an ordinary
/// `ProcessExec` is not a [`notable_exec`](crate::engine::observe::exec_class::notable_exec) and
/// an ordinary `/tmp` `FileWrite` is not an
/// [`alarming_write`](crate::engine::observe::alarm_class::alarming_write) — apps legitimately
/// write and run their own scripts. It's the CORRELATION of the two on the same path that is
/// the tell — and that needs cross-signal state the flat per-behavior [`corroborates`] relation
/// can't carry (it only ever sees one behavior at a time).
///
/// **Where the cross-signal state lives:** the entry's own `runtime` slice — already a bounded,
/// time-windowed per-workload record of recent signals ([`RuntimeEvents`](crate::engine::observe::runtime::RuntimeEvents),
/// TTL'd + capped at `MAX_EVENTS`, resolved once per entry by [`entry_runtime`]) — IS the
/// "recent writes to match the exec against" this needs. No new store is introduced; this
/// function only correlates two entries already in that slice. [`DROP_EXEC_WINDOW`] narrows
/// "recent" further than the general runtime TTL (default 30 minutes) to the few minutes that
/// actually reads as one drop-and-run act, and requires the write to have happened AT OR BEFORE
/// the exec (an exec that merely precedes an unrelated later write of the same path is not
/// drop-then-execute).
///
/// Conservative scoping (ADR-0011 / ADR-0014), mirroring [`cross_tenant_lateral`]: corroborates
/// ONLY when the entry is a proven internet-facing foothold. Apps legitimately write-then-run
/// scripts under `/tmp` constantly — scoping to the proven entry/foothold is what keeps that the
/// ADR-0011 on-call-engineer false positive, rather than turning every ordinary pod into a
/// corroboration source.
pub(super) fn drop_then_execute(runtime: &[RuntimeSignal], entry: EntryContext<'_>) -> bool {
    if !entry.is_foothold {
        return false;
    }
    runtime.iter().any(|exec| {
        let Behavior::ProcessExec {
            path: exec_path, ..
        } = &exec.behavior
        else {
            return false;
        };
        runtime.iter().any(|write| {
            let Behavior::FileWrite { path: write_path } = &write.behavior else {
                return false;
            };
            write_path == exec_path
                && exec
                    .provenance
                    .observed_at
                    .duration_since(write.provenance.observed_at)
                    .is_ok_and(|elapsed| elapsed <= DROP_EXEC_WINDOW)
        })
    })
}

/// The privilege-escalation-on-foothold shape (JEF-314): a `PrivilegeChange` non-root→root
/// on the entry itself corroborates a PrivilegeEscalation-tactic objective (T1611 Escape to
/// Host / T1098.006 RBAC self-escalation, and any future T1548-tactic technique) — the setuid
/// Falco fires critical on, here scoped to close the parity gap without the false positive
/// Falco doesn't guard against.
///
/// Conservative scoping (ADR-0011 / ADR-0014), mirroring [`cross_tenant_lateral`]:
/// corroborates ONLY when the entry is a proven internet-facing foothold (`entry.is_foothold`)
/// AND `attack.tactic` is `PrivilegeEscalation`. The flat [`corroborates`] relation
/// deliberately leaves `PrivilegeChange` non-corroborating everywhere (legit entrypoints and
/// init processes escalate to root on ordinary pods constantly — the ADR-0011 false
/// positive); gating on the proven foothold is what makes a root escalation there mean
/// something a routine setuid on an unrelated pod does not: the attacker who owns the
/// internet-facing front door escalating on that SAME workload.
pub(super) fn privilege_escalation_on_foothold(
    runtime: &[RuntimeSignal],
    attack: &AttackRef,
    entry: EntryContext<'_>,
) -> bool {
    use crate::engine::graph::attack::Tactic;
    if !entry.is_foothold || attack.tactic != Tactic::PrivilegeEscalation {
        return false;
    }
    runtime.iter().any(|s| match &s.behavior {
        Behavior::PrivilegeChange { from_uid, to_uid } => *from_uid != 0 && *to_uid == 0,
        _ => false,
    })
}

/// The on-host-credential-path-read-on-foothold shape (JEF-320 security rework, HIGH/MEDIUM
/// findings from a HELD security review): a `SecretRead` with [`SecretReadSource::HostPath`]
/// — a read of a well-known on-host credential path
/// (`crate::engine::observe::host_credential_class`) OUTSIDE any k8s Secret mount — on the
/// entry itself corroborates a CredentialAccess-tactic objective.
///
/// Conservative scoping (ADR-0011 / ADR-0014), mirroring [`cross_tenant_lateral`] /
/// [`privilege_escalation_on_foothold`] / [`drop_then_execute`]: corroborates ONLY when the
/// entry is a proven internet-facing foothold (`entry.is_foothold`) AND `attack.tactic` is
/// `CredentialAccess`. This is deliberately NOT in the flat, context-free [`corroborates`]
/// relation the way a `Mounted`/`Api` `SecretRead` is: reading the pod's OWN declared k8s
/// Secret is unambiguous credential access, but an on-host credential path can be read by an
/// ordinary, legitimate in-container process that has nothing to do with any chain (a
/// bastion pod's own `sshd` reading its own `/etc/shadow` for PAM, an init process reading
/// `/etc/sudoers`) — gating on the proven foothold is what keeps that the same ADR-0011
/// on-call-engineer false positive the sibling shapes guard against, rather than turning
/// every ordinary pod's mundane host-file access into a standing corroboration source.
pub(super) fn host_credential_read_on_foothold(
    runtime: &[RuntimeSignal],
    attack: &AttackRef,
    entry: EntryContext<'_>,
) -> bool {
    use crate::engine::graph::attack::Tactic;
    if !entry.is_foothold || attack.tactic != Tactic::CredentialAccess {
        return false;
    }
    runtime.iter().any(|s| {
        matches!(
            &s.behavior,
            Behavior::SecretRead { source, .. } if *source == SecretReadSource::HostPath
        )
    })
}

/// The anon-inode-exec-on-foothold shape (JEF-317, Route A): a `ProcessExec` with
/// `exe_anon_inode: true` on the entry corroborates an Execution-tactic objective (T1610
/// Deploy Container, T1609 Container Administration Command, and any future T1059-family
/// technique) — the memfd_create/anonymous-fd `execve` Falco fires critical on, here
/// scoped to close the parity gap without forging corroboration on routine behavior.
///
/// **Why this is conservative in TWO ways, mirroring [`privilege_escalation_on_foothold`]:**
/// scoped to a proven internet-facing foothold entry (`entry.is_foothold`) AND to an
/// Execution-tactic objective — a bare `exe_anon_inode` exec is NEVER routed into the flat
/// [`corroborates`] blanket gate (unlike a shell/package-manager exec), so it can only ever
/// corroborate this one specific tactic on this one specific entry, never "any objective"
/// the way an Alert does.
///
/// This predicate runs unconditionally once the foothold/tactic gate above is met — it is
/// NOT behind any operator-facing flag; like every arm in this module it is shadow-gated
/// (ADR-0014): it only ever sets `corroborated`, never actuates.
///
/// **CAVEAT this scoping does NOT fully close (flagged, not silently assumed away):** the
/// real inode signal is genuinely more specific than the withdrawn path-shape one, but it
/// is not proven false-positive-free. runc copies itself into a memfd and re-execs via that
/// memfd on ~every container start (the CVE-2019-5736 mitigation) — whether that re-exec
/// attributes to the WORKLOAD's cgroup (this entry) or to the host container runtime
/// depends on `setns` timing relative to `security_bprm_check` firing, which is UNKNOWN
/// until measured on a live node. If it attributes to the workload, this shape will need an
/// additional discriminator (e.g. pairing with another signal) before it can be trusted at
/// face value — do not widen this scoping further without that on-node measurement.
///
/// **Gated OFF by default pending that on-node measurement (security review follow-up,
/// JEF-317):** until runc-attribution is measured on a live node, shipping this LIVE would
/// make it a standing false corroboration on every foothold pod (re)start if the runc
/// memfd re-exec attributes to the workload cgroup. `PROTECTOR_ANON_EXEC_CORROBORATION`
/// (unset/false by default) is the deliberate gate — mirrors the Rekor lane's opt-in-off
/// posture (`PROTECTOR_REKOR_ENABLE`, [`crate::policies::signature::rekor`]): an operator
/// sets it during the measurement window to turn this shape on; until then it never
/// corroborates. Do NOT flip the default without the on-node measurement landing.
pub(super) fn anon_inode_exec_on_foothold(
    runtime: &[RuntimeSignal],
    attack: &AttackRef,
    entry: EntryContext<'_>,
) -> bool {
    use crate::engine::graph::attack::Tactic;
    if !anon_exec_corroboration_enabled()
        || !entry.is_foothold
        || attack.tactic != Tactic::Execution
    {
        return false;
    }
    runtime.iter().any(|s| match &s.behavior {
        Behavior::ProcessExec { exe_anon_inode, .. } => *exe_anon_inode,
        _ => false,
    })
}

/// Whether the operator has deliberately turned on [`anon_inode_exec_on_foothold`]
/// (`PROTECTOR_ANON_EXEC_CORROBORATION`; unset/anything else is OFF) — see that function's
/// doc-comment for why it defaults off. Read once per predicate call, ahead of the
/// per-signal `runtime.iter()` loop — never re-parsed per `RuntimeSignal` — mirroring
/// `RegistryAuth::from_env`'s uncached-but-called-once-per-resolution env reads
/// (`policies::signature::auth`) rather than a process-lifetime cache: this crate's test
/// suite already hit process-global env-var caching races once (JEF-412), so config reads
/// stay uncached and are exercised under the same `EnvGuard`-style serialization used there.
fn anon_exec_corroboration_enabled() -> bool {
    std::env::var("PROTECTOR_ANON_EXEC_CORROBORATION")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// The entry workload's runtime signals (empty for a non-workload node), resolved once
/// per entry so [`corroborated_for`] doesn't re-look-up the constant entry node on every
/// objective in the per-objective loop.
pub(super) fn entry_runtime(graph: &SecurityGraph, entry: NodeIndex) -> &[RuntimeSignal] {
    match graph.inner().node_weight(entry) {
        Some(Node::Workload(w)) => &w.runtime,
        _ => &[],
    }
}

/// The entry workload's own namespace (`""` for a non-workload node) — the SOURCE side of the
/// cross-tenant comparison (JEF-319). Resolved once per entry alongside [`entry_runtime`] so
/// the per-objective loop reads it without re-looking-up the constant entry node.
pub(super) fn entry_namespace(graph: &SecurityGraph, entry: NodeIndex) -> &str {
    match graph.inner().node_weight(entry) {
        Some(Node::Workload(w)) => &w.namespace,
        _ => "",
    }
}
