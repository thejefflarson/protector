//! Engine-level acceptance test for the pre-arm scope-simulation preview (ADR-0021,
//! ADR-0016): computing/reading the preview must never apply, arm, or mutate anything.
//! Proven here by processing a REAL standing, justified cut through a spy actuator, then
//! calling the pure [`preview_scope`] repeatedly against a candidate scope that WOULD
//! cover it, and asserting the actuator is never invoked and the applied-action log stays
//! empty throughout — even though the preview itself correctly reports the cut as
//! "would fire". Split out of `tests.rs`/`break_glass_tests.rs` purely to keep every file
//! under the 1,000-line cap (repo CLAUDE.md); the adjudicator/actuator test doubles mirror
//! the pattern already established there.

use super::*;
use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{NodeKey, SecurityGraph};
use crate::engine::reason::adjudicate::incident::{Assessment, IncidentDecision, Menu};
use crate::engine::respond::actuator::scope_preview::preview_scope;
use crate::engine::respond::actuator::{Actuation, ActuationScope};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::tests::exposed_snapshot;

/// A model that always decisively attacks the entry, naming it as its own cut — the same
/// shape `break_glass_tests::AlwaysAttacksTheEntry` uses, reused here (own copy: privacy
/// keeps sibling `*_tests` modules from sharing each other's doubles) so the cut this file
/// previews against is exactly the kind `enforce` would actually apply.
struct AlwaysAttacksTheEntry;

#[async_trait::async_trait]
impl reason::adjudicate::Adjudicator for AlwaysAttacksTheEntry {
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
            reason: "RCE reaches the secret".to_string(),
            cuts: vec![cut],
        }
    }
}

/// A test-double actuator that records every apply/revert call — used here to prove the
/// scope-preview path NEVER reaches it.
struct RecordingActuator {
    applied: Arc<AtomicUsize>,
    reverted: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl respond::actuator::Actuator for RecordingActuator {
    async fn apply(&self, _mitigation: &respond::Mitigation) -> Actuation {
        self.applied.fetch_add(1, Ordering::SeqCst);
        Actuation::Applied
    }

    async fn revert(&self, _mitigation: &respond::Mitigation) -> Actuation {
        self.reverted.fetch_add(1, Ordering::SeqCst);
        Actuation::Reverted
    }
}

/// Computing the pre-arm scope-simulation preview NEVER applies, arms, or mutates
/// anything (ADR-0016). Built with `judgement` promotion armed but the `network` action
/// class NOT armed — a real, justified, would-otherwise-eligible cut stands (-style
/// model promotion), but the REAL engine never actually applies it (the ordinary
/// `enforceScope`/arming-ladder gate this test does not touch). The preview is asked,
/// against a candidate scope that WOULD cover the cut, over and over — the spy actuator +
/// applied-action log must stay untouched throughout, proving the preview is a pure read
/// even when it correctly classifies the cut as "would fire".
#[tokio::test]
async fn computing_the_preview_never_applies_or_arms_the_cut_it_previews() {
    let applied = Arc::new(AtomicUsize::new(0));
    let reverted = Arc::new(AtomicUsize::new(0));
    let actuator = RecordingActuator {
        applied: applied.clone(),
        reverted: reverted.clone(),
    };
    // `judgement` alone (no `network`): the chain is promoted (auto-actionable in
    // principle) but no action class is armed, so the REAL engine only ever proposes.
    let mut engine = Engine::new(
        EnabledActions::from_names(["judgement"]),
        ActuationScope::unscoped(),
        Box::new(actuator),
        Box::new(AlwaysAttacksTheEntry),
    );

    engine.process(&exposed_snapshot(true)).await;
    assert_eq!(
        applied.load(Ordering::SeqCst),
        0,
        "no action class armed ⇒ the real engine proposes, never applies"
    );
    assert_eq!(engine.actions.active_count(), 0);

    let standing = engine.scope_preview().snapshot();
    assert!(
        !standing.is_empty(),
        "the promoted, justified cut is standing this pass"
    );

    // A candidate scope that WOULD cover the cut (the entry's namespace is `app`) — the
    // preview must report it as would-fire, proving the classification is real, not
    // vacuously empty.
    let candidate = ActuationScope::enforce_namespaces(["app".to_string()]);
    for _ in 0..5 {
        let preview = preview_scope(&standing, &candidate);
        assert!(
            !preview.would_fire.is_empty(),
            "the preview must classify the standing cut as would-fire for this candidate \
             scope — otherwise this test would vacuously pass"
        );
    }

    // The whole point: none of the above touched the actuator or the applied-action log.
    assert_eq!(
        applied.load(Ordering::SeqCst),
        0,
        "computing the scope preview must never apply a cut"
    );
    assert_eq!(reverted.load(Ordering::SeqCst), 0);
    assert_eq!(
        engine.actions.active_count(),
        0,
        "the applied-action log must stay empty — the preview is a pure read"
    );

    // Reading the store repeatedly leaves it unchanged.
    assert_eq!(standing.len(), engine.scope_preview().snapshot().len());
}
