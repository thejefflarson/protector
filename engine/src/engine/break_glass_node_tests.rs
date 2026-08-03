//! Engine-level acceptance tests for ADR-0040 §5's `ContainNode` revert wiring AND its
//! propose-only invariant: break-glass (ADR-0036) and the standard ledger self-revert
//! lifecycle (ADR-0017) must uncordon a standing node-containment cut within one pass —
//! never leave it silently in place through the wrong-shaped generic network `actuator` —
//! while `ContainNode` itself must NEVER be reachable through any apply call, at any
//! arming/scope/rails state (there is no such call site to reach: `ContainNode` is
//! propose-first by construction, ADR-0040 §5). Split out of `break_glass_tests.rs` purely
//! to keep every file under the 1,000-line cap (repo CLAUDE.md); `use super::*` resolves to
//! the engine module, matching every sibling `*_tests.rs` file.
//!
//! Deliberately does NOT depend on the `node` arming rung
//! (`respond::actuator::arming_ladder::ArmingRung::Node`) or a live fleet watch:
//! `EnabledActions::enable(ProposedAction::ContainNode)` arms the class directly, bypassing
//! `EnabledActions::from_names` (which has no `node` name), and each test seeds its own
//! `NodeFact`/actuator double via `Engine::with_node_fact`/`Engine::with_node_containment_actuator`.
//! The PROPOSAL half is real production machinery — the model naming a boundary-broken
//! workload, the menu escalating it to `ContainNode`
//! (`reason::proof::boundary_break`, `reason::adjudicate::incident::menu`), the ledger
//! tracking it, and (for the revert tests below) `Engine::process`'s own proposal-side gate
//! (`respond::actuator::node_containment::evaluate_proposal`) all run for real. Only the
//! "this was already applied" step in the REVERT tests is synthesized directly into the
//! action log — standing in for a HYPOTHETICAL future human-approval-to-apply flow
//! (out of scope of every ticket to date); there is no code path that does this for real.

use super::*;
use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{NodeKey, SecurityGraph};
use crate::engine::observe::Snapshot;
use crate::engine::reason::adjudicate::incident::{Assessment, IncidentDecision, Menu};
use crate::engine::respond::actuator::{Actuation, Actuator, node_containment};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// A unique temp flag path for a test, without a temp-file crate — mirrors
/// `break_glass_tests::temp_flag_path`.
fn temp_flag_path(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::AtomicU64;
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let n = NONCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "protector-engine-break-glass-node-{tag}-{}-{n}",
        std::process::id()
    ))
}

/// A breach-relevant chain on `web` — the exact `tests::exposed_snapshot(true)` fixture
/// (internet-exposed via `web-lb`, reads `session-key`, runs a critical CVE loaded at
/// runtime) — with `web` additionally scheduled on `node-1` (the `ScheduledOn` placement
/// edge, ADR-0040 §3) alongside a labelled `neighbor` pod, so the co-resident default-deny
/// sweep has a real target.
///
/// When `tampered`, `web` also carries a live kernel-tamper signal (`Behavior::PtraceAttach`)
/// — `boundary_break` trigger (c), ADR-0040 §3 — so `menu::build_menu` escalates the entry's
/// own line to `ProposedAction::ContainNode` instead of its ordinary pod-scoped quarantine.
/// `tampered = false` is the "healed" snapshot: the CVE/exposure still breach-relevant, but
/// boundary_break no longer holds, so the entry line resolves back to its pod-scoped
/// mechanism — the fixture the self-revert test needs to prove no chain still carries `web`
/// as a boundary-broken target.
fn boundary_broken_snapshot(tampered: bool) -> Snapshot {
    use crate::engine::graph::Behavior;
    use crate::engine::observe::{Attribution, RuntimeObservation};

    let mut snap = super::tests::exposed_snapshot(true);
    snap.pods[0]
        .spec
        .as_mut()
        .expect("exposed_snapshot's web pod always carries a spec")
        .node_name = Some("node-1".to_string());
    snap.pods.push(
        serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "neighbor", "namespace": "app", "labels": {"app": "neighbor"}},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "neighbor", "image": "neighbor:1"}]
            }
        }))
        .unwrap(),
    );
    if tampered {
        snap.runtime_events.push(RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: None,
            observed_at_ms: None,
            node: None,
            behavior: Behavior::PtraceAttach,
        });
    }
    snap
}

/// A model that always decisively attacks the entry, naming exactly whatever
/// [`Menu::resolve`] resolves for it — for `boundary_broken_snapshot(true)`'s `web` entry
/// that resolution is `ProposedAction::ContainNode` on its host (`menu::escalate`,
/// ADR-0040 §1); for the healed variant it falls back to `web`'s ordinary pod-scoped
/// mechanism. Mirrors `break_glass_tests::AlwaysAttacksTheEntry`, duplicated here (that
/// struct is private to its own file) so this file stays self-contained.
struct NamesWhateverTheMenuResolves;

#[async_trait::async_trait]
impl reason::adjudicate::Adjudicator for NamesWhateverTheMenuResolves {
    async fn judge(
        &self,
        entry: &NodeKey,
        _objectives: &[(NodeKey, AttackRef)],
        _graph: &SecurityGraph,
        _prompt: &str,
        _downstream: &[NodeKey],
        menu: &Menu,
    ) -> IncidentDecision {
        let cut = menu
            .resolve(entry)
            .expect("the entry is selectable on its own menu");
        IncidentDecision {
            assessment: Assessment::Attack,
            reason: "names whatever the deterministic menu resolved for the entry".to_string(),
            cuts: vec![cut],
        }
    }
}

/// A test double for [`node_containment::NodeContainmentRevert`] that mirrors
/// [`node_containment::NodeContainmentActuator::revert`]'s own logic — self-gated on
/// [`node_containment::revert_decision`] — but records counts instead of touching a
/// cluster, so a test can assert the ENGINE actually reached this seam with the right
/// mitigation/target/co-resident set, and that the ownership rail (not a fabricated
/// cluster success) is what decided whether the uncordon happened.
struct RecordingNodeContainmentActuator {
    reverted: Arc<AtomicUsize>,
    co_resident_lifted: Arc<AtomicUsize>,
    refused: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl node_containment::NodeContainmentRevert for RecordingNodeContainmentActuator {
    async fn revert(
        &self,
        _mitigation: &Mitigation,
        target: &node_containment::NodeFact,
        co_resident: &[Mitigation],
    ) -> Actuation {
        if node_containment::revert_decision(target).is_err() {
            self.refused.fetch_add(1, Ordering::SeqCst);
            return Actuation::DryRun;
        }
        self.reverted.fetch_add(1, Ordering::SeqCst);
        self.co_resident_lifted
            .fetch_add(co_resident.len(), Ordering::SeqCst);
        Actuation::Reverted
    }
}

/// Build a `ContainNode`-armed engine (enabled DIRECTLY via `EnabledActions::enable` — no
/// `node` rung needed) wired to [`NamesWhateverTheMenuResolves`] and a fresh
/// [`RecordingNodeContainmentActuator`], with one seeded [`node_containment::NodeFact`] for
/// `node-1`. Returns the engine plus the double's shared counters.
fn node_containment_engine(
    break_glass: break_glass::BreakGlass,
    owned_by_protector: bool,
) -> (Engine, Arc<AtomicUsize>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let reverted = Arc::new(AtomicUsize::new(0));
    let co_resident_lifted = Arc::new(AtomicUsize::new(0));
    let refused = Arc::new(AtomicUsize::new(0));
    let actuator = RecordingNodeContainmentActuator {
        reverted: reverted.clone(),
        co_resident_lifted: co_resident_lifted.clone(),
        refused: refused.clone(),
    };
    let engine = Engine::new(
        EnabledActions::from_names(["judgement"]).enable(ProposedAction::ContainNode),
        ActuationScope::unscoped(),
        Box::new(respond::actuator::DryRunActuator),
        Box::new(NamesWhateverTheMenuResolves),
    )
    .with_break_glass(break_glass)
    .with_node_containment_actuator(Box::new(actuator))
    .with_node_fact(node_containment::NodeFact {
        name: "node-1".to_string(),
        control_plane: false,
        schedulable: false,
        owned_by_protector,
    });
    (engine, reverted, co_resident_lifted, refused)
}

/// Run one pass over `snap` and pull out the resulting `ContainNode` mitigation the ledger
/// proposed for `web`'s entry — real production proof + menu resolution, not hand-built.
/// Panics if the fixture didn't produce one (a fixture regression, not an assertion about
/// the code under test).
async fn contain_node_mitigation(engine: &mut Engine, snap: &Snapshot) -> Mitigation {
    engine.process(snap).await;
    engine
        .ledger
        .active()
        .find(|m| m.action == ProposedAction::ContainNode)
        .cloned()
        .expect("the boundary-broken entry proposes a ContainNode mitigation")
}

/// (a) Engaging break-glass with a standing `ContainNode` cut uncordons the node AND drops
/// the co-resident deny set within the SAME pass — the core ADR-0040 §5 safety property this
/// ticket verifies.
#[tokio::test]
async fn engaging_break_glass_uncordons_the_node_and_lifts_co_resident_denies_within_one_pass() {
    let path = temp_flag_path("reverts");
    let (mut engine, reverted, co_resident_lifted, _refused) =
        node_containment_engine(break_glass::BreakGlass::at(&path), true);
    let snap = boundary_broken_snapshot(true);

    // The real proof + menu resolution produce the ContainNode mitigation; synthesize it as
    // already-applied — standing in for the sibling ticket's future apply-side rail wiring
    // (ADR-0040 §6), which this ticket deliberately does not depend on.
    let mitigation = contain_node_mitigation(&mut engine, &snap).await;
    engine.actions.record(mitigation, Vec::new());
    assert_eq!(
        engine.actions.active_count(),
        1,
        "the synthesized cut is standing"
    );

    // Pass 1 (break-glass clear, identical facts): still armed and still justified — must
    // NOT be touched, so the next pass's revert is attributable to break-glass alone.
    engine.process(&snap).await;
    assert_eq!(reverted.load(Ordering::SeqCst), 0, "not yet engaged");
    assert_eq!(engine.actions.active_count(), 1);

    // Engage break-glass — presence only, no chart change, no restart.
    std::fs::write(&path, "").expect("write the flag file");

    // Pass 2 (identical facts, break-glass now engaged): uncordon + co-resident lift within
    // this ONE pass.
    engine.process(&snap).await;
    assert_eq!(
        reverted.load(Ordering::SeqCst),
        1,
        "break-glass uncordons the standing ContainNode cut within one pass"
    );
    assert_eq!(
        co_resident_lifted.load(Ordering::SeqCst),
        2,
        "both labelled pods scheduled on node-1 (web itself and neighbor) have their \
         default-deny lifted in the SAME call — the cordon alone doesn't touch an already-\
         running pod's traffic"
    );
    assert_eq!(
        engine.actions.active_count(),
        0,
        "the applied-action log agrees nothing is standing"
    );

    let reversions = engine.reversions().snapshot();
    let reasons: Vec<&str> = reversions.iter().map(|r| r.reason.as_str()).collect();
    assert!(
        reasons.iter().any(|r| r.contains("armed")),
        "the reversion log names the disarm, not just \"unjustified\": got {reasons:?}"
    );

    std::fs::remove_file(&path).ok();
}

/// (b) The ledger self-reverts the cordon on the standard lifecycle (ADR-0017) once no
/// chain still carries `web` as a boundary-broken target — no break-glass involved.
#[tokio::test]
async fn self_reverts_when_no_chain_still_carries_the_boundary_broken_target() {
    let (mut engine, reverted, _co_resident_lifted, _refused) =
        node_containment_engine(break_glass::BreakGlass::disabled(), true);
    let broken = boundary_broken_snapshot(true);

    let mitigation = contain_node_mitigation(&mut engine, &broken).await;
    assert_eq!(mitigation.action, ProposedAction::ContainNode);
    engine.actions.record(mitigation, Vec::new());
    assert_eq!(engine.actions.active_count(), 1);

    // Still boundary-broken: the cut stays standing (still armed, still justified).
    engine.process(&broken).await;
    assert_eq!(reverted.load(Ordering::SeqCst), 0);
    assert_eq!(engine.actions.active_count(), 1);

    // The kernel-tamper signal clears — boundary_break(web) no longer holds, so the menu
    // resolves web's line back to its ordinary pod-scoped mechanism. No chain still carries
    // `web` as a boundary-broken target, so the ContainNode cut's justification is gone.
    let healed = boundary_broken_snapshot(false);
    engine.process(&healed).await;
    assert_eq!(
        reverted.load(Ordering::SeqCst),
        1,
        "the ledger self-revert lifts the cordon once boundary_break no longer holds"
    );
    assert_eq!(engine.actions.active_count(), 0);

    let reversions = engine.reversions().snapshot();
    let reasons: Vec<&str> = reversions.iter().map(|r| r.reason.as_str()).collect();
    assert!(
        reasons.iter().any(|r| r.contains("no proven chain")),
        "reverted via the ordinary chain-justification path, not break-glass: got {reasons:?}"
    );
}

/// (c) Revert uncordons ONLY nodes carrying protector's own ownership annotation — a
/// human/autoscaler-cordoned node (no annotation) is left untouched. Falls out of
/// `NodeContainmentActuator::revert`'s own self-gate (`revert_decision`), asserted here
/// end-to-end through the engine's break-glass path.
#[tokio::test]
async fn revert_skips_a_node_lacking_the_ownership_annotation() {
    let path = temp_flag_path("not-owned");
    let (mut engine, reverted, co_resident_lifted, refused) =
        node_containment_engine(break_glass::BreakGlass::at(&path), false); // NOT protector-owned
    let snap = boundary_broken_snapshot(true);

    let mitigation = contain_node_mitigation(&mut engine, &snap).await;
    engine.actions.record(mitigation, Vec::new());

    std::fs::write(&path, "").expect("write the flag file");
    engine.process(&snap).await;

    assert_eq!(
        reverted.load(Ordering::SeqCst),
        0,
        "a node protector never cordoned (no ownership annotation) is never uncordoned"
    );
    assert_eq!(
        co_resident_lifted.load(Ordering::SeqCst),
        0,
        "no co-resident deny is lifted either — nothing about this node is touched"
    );
    assert_eq!(
        refused.load(Ordering::SeqCst),
        1,
        "the ownership rail explicitly refused, rather than silently doing nothing"
    );

    std::fs::remove_file(&path).ok();
}

/// A `ContainNode` revert with no observed [`node_containment::NodeFact`] for the host is
/// SKIPPED, not fabricated as "no data ⇒ pass" — the same discipline
/// `respond::actuator::node_containment`'s own doc already applies to the cordon rails.
#[tokio::test]
async fn revert_skips_when_no_nodefact_is_observed_for_the_host() {
    let path = temp_flag_path("no-fact");
    let reverted = Arc::new(AtomicUsize::new(0));
    let co_resident_lifted = Arc::new(AtomicUsize::new(0));
    let refused = Arc::new(AtomicUsize::new(0));
    let actuator = RecordingNodeContainmentActuator {
        reverted: reverted.clone(),
        co_resident_lifted: co_resident_lifted.clone(),
        refused: refused.clone(),
    };
    let mut engine = Engine::new(
        EnabledActions::from_names(["judgement"]).enable(ProposedAction::ContainNode),
        ActuationScope::unscoped(),
        Box::new(respond::actuator::DryRunActuator),
        Box::new(NamesWhateverTheMenuResolves),
    )
    .with_break_glass(break_glass::BreakGlass::at(&path))
    .with_node_containment_actuator(Box::new(actuator));
    // Deliberately no `.with_node_fact(...)` — no observed fleet for this host at all.

    let snap = boundary_broken_snapshot(true);
    let mitigation = contain_node_mitigation(&mut engine, &snap).await;
    engine.actions.record(mitigation, Vec::new());

    std::fs::write(&path, "").expect("write the flag file");
    engine.process(&snap).await;

    assert_eq!(
        reverted.load(Ordering::SeqCst) + refused.load(Ordering::SeqCst),
        0,
        "with no observed NodeFact for this host the actuator is never even called — \
         ownership can't be verified, so the revert is skipped rather than fabricated"
    );
    assert_eq!(
        engine.actions.active_count(),
        0,
        "the applied-action log still drops the entry — the SAME bookkeeping asymmetry the \
         network-cut path already has (a failed/skipped cluster call doesn't re-queue)"
    );

    std::fs::remove_file(&path).ok();
}

/// (d) Clearing break-glass restores the node class's posture byte-identically. Unlike the
/// network-cut mirror (`clearing_break_glass_restores_the_configured_posture_byte_identical`,
/// where the standing cut auto-applies again once cleared), `ContainNode` never auto-applies
/// at all (ADR-0040 §5: propose-first by construction) — so the honest analogue is that the
/// ledger's model-chosen `ContainNode` proposal is EXACTLY the cut+mechanism whether
/// break-glass ever engaged or not: disarm narrows ACTUATION only (ADR-0036), so it has
/// nothing to disarm on the propose-only side.
#[tokio::test]
async fn clearing_break_glass_leaves_the_node_classs_posture_byte_identical() {
    let snap = boundary_broken_snapshot(true);

    let (mut never_engaged, ..) =
        node_containment_engine(break_glass::BreakGlass::disabled(), true);
    let baseline = contain_node_mitigation(&mut never_engaged, &snap).await;
    assert_eq!(baseline.action, ProposedAction::ContainNode);

    let path = temp_flag_path("posture");
    std::fs::write(&path, "").expect("write the flag file"); // engaged from boot
    let (mut engaged_then_cleared, ..) =
        node_containment_engine(break_glass::BreakGlass::at(&path), true);
    let while_engaged = contain_node_mitigation(&mut engaged_then_cleared, &snap).await;
    assert_eq!(
        while_engaged.cut, baseline.cut,
        "same cut while disarmed from boot"
    );
    assert_eq!(
        while_engaged.action, baseline.action,
        "break-glass narrows ACTUATION only (ADR-0036) — it must not perturb the mechanism \
         the ledger itself resolved"
    );
    assert_eq!(
        engaged_then_cleared.actions.active_count(),
        0,
        "ContainNode never auto-applies regardless of break-glass — propose-first by \
         construction (ADR-0040 §5)"
    );

    std::fs::remove_file(&path).expect("clear the flag file");
    let after_clear = contain_node_mitigation(&mut engaged_then_cleared, &snap).await;
    assert_eq!(
        after_clear.cut, baseline.cut,
        "clearing break-glass restores exactly the same node-class posture — byte-identical \
         to never having engaged it at all"
    );
    assert_eq!(after_clear.action, baseline.action);
    assert_eq!(engaged_then_cleared.actions.active_count(), 0);
}

/// A spy [`Actuator`] that records every `apply()` call it receives, by action, via a
/// shared handle — the acceptance-level proof that `ContainNode` has NO reachable apply
/// call through the GENERIC actuator, at any arming/scope/rails state. Mirrors
/// [`RecordingNodeContainmentActuator`]'s pattern of sharing state through a clone rather
/// than downcasting the `Box<dyn Actuator>` `Engine` owns.
struct SpyActuator {
    applied: Arc<Mutex<Vec<ProposedAction>>>,
}

#[async_trait::async_trait]
impl Actuator for SpyActuator {
    async fn apply(&self, mitigation: &Mitigation) -> Actuation {
        self.applied.lock().unwrap().push(mitigation.action);
        Actuation::DryRun
    }
    async fn revert(&self, _mitigation: &Mitigation) -> Actuation {
        Actuation::DryRun
    }
}

/// ADR-0040 §5 acceptance proof: `ContainNode` never reaches ANY apply call — not the
/// generic network [`Actuator::apply`] (already structurally forbidden by `decide()`'s
/// `is_additive_live()` check, `respond::actuator::tests::decide_forbids_contain_node_even_when_the_class_would_be_enabled`),
/// and there is no SEPARATE node-apply seam in `Engine` to call instead (only
/// [`Engine::with_node_containment_actuator`] for REVERT exists — there is no
/// `with_node_containment_actuator`-for-apply counterpart). Armed, unscoped (so
/// `enforceScope` can't be the reason nothing applies), and every deterministic rail
/// passing (three plain workers, no control-plane, no one-node-cap conflict) — the
/// maximally-eligible case for the proposal gate to say "yes" — still applies nothing.
#[tokio::test]
async fn contain_node_never_reaches_an_apply_call_even_fully_eligible() {
    let applied = Arc::new(Mutex::new(Vec::new()));
    let actuator = SpyActuator {
        applied: applied.clone(),
    };
    let mut engine = Engine::new(
        EnabledActions::from_names(["judgement"]).enable(ProposedAction::ContainNode),
        ActuationScope::unscoped(),
        Box::new(actuator),
        Box::new(NamesWhateverTheMenuResolves),
    )
    .with_node_fact(node_containment::NodeFact {
        name: "node-1".to_string(),
        control_plane: false,
        schedulable: true,
        owned_by_protector: false,
    })
    .with_node_fact(node_containment::NodeFact {
        name: "node-2".to_string(),
        control_plane: false,
        schedulable: true,
        owned_by_protector: false,
    })
    .with_node_fact(node_containment::NodeFact {
        name: "node-3".to_string(),
        control_plane: false,
        schedulable: true,
        owned_by_protector: false,
    });
    let snap = boundary_broken_snapshot(true);

    // Proves eligibility was genuinely reached (not vacuously "nothing to apply because
    // nothing was even proposed"): the real proof + menu resolution produced a
    // `ContainNode` mitigation over a healthy 3-node fleet with no control-plane/
    // one-node-cap conflict — exactly the fleet shape `evaluate_proposal`'s own unit
    // tests confirm resolves to `ProposalOutcome::Proposed`.
    let mitigation = contain_node_mitigation(&mut engine, &snap).await;
    assert_eq!(mitigation.action, ProposedAction::ContainNode);

    assert!(
        applied.lock().unwrap().is_empty(),
        "no apply call of any kind must ever be made for a ContainNode-eligible pass"
    );
    assert_eq!(
        engine.actions.active_count(),
        0,
        "ContainNode must never be recorded as an applied/standing action"
    );
}
