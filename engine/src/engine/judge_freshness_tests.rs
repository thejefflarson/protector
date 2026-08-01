//! Tests for the actuation JUDGE FRESHNESS gate (`Engine::gate_on_judge_freshness`): a NEW cut
//! only auto-applies behind a breaker-closed, recently-decisive verdict, while a REVERT is
//! wholly unaffected — the fail-safe asymmetry (always safe to lift a cut, never safe to trust
//! a judge that isn't demonstrably running to arm a new one). Split out of `tests.rs` purely to
//! keep every file under the 1,000-line cap (repo CLAUDE.md). `use super::*` resolves to the
//! engine module; the shared fixtures come from `super::tests`, matching the sibling
//! `*_tests.rs` pattern (`journal_tests.rs`).

use super::*;
use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{NodeKey, SecurityGraph};
use crate::engine::reason::adjudicate::incident::{Assessment, IncidentDecision, Menu};
use crate::engine::reason::proof::Link;
use crate::engine::respond::actuator::DryRunActuator;
use crate::engine::respond::{Justification, ProposedAction};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::tests::exposed_snapshot;

/// A minimal armed engine (no journal / no findings-log wiring needed for these tests), so
/// `self.verdicts` can be driven directly.
fn armed_engine(adjudicator: Box<dyn reason::adjudicate::Adjudicator>) -> Engine {
    Engine::new(
        EnabledActions::from_names(["network"]),
        ActuationScope::unscoped(),
        Box::new(DryRunActuator),
        adjudicator,
    )
}

/// A reversible, additive network mitigation whose one justification is corroborated,
/// adjudicated, and breach-relevant — i.e. it clears `is_live_corroborated` on its
/// own, so `decide()` would return `AutoApply` before the freshness gate is even considered.
fn live_corroborated_mitigation(entry: &str) -> Mitigation {
    Mitigation {
        cut: Link {
            from: NodeKey("workload/app/Pod/web".to_string()),
            to: NodeKey("workload/ext/Pod/attacker".to_string()),
            relation: "reaches/Tcp/443".to_string(),
            technique: None,
            from_labels: Default::default(),
            to_labels: Default::default(),
        },
        action: ProposedAction::DenyNetworkPath,
        justifications: vec![Justification {
            entry: entry.to_string(),
            objective: "workload/ext/Pod/attacker".to_string(),
            attack: crate::engine::graph::attack::CREDENTIAL_ACCESS,
            foothold: false,
            corroborated: true,
            adjudicated: true,
            promoted: false,
            breach_relevant: true,
        }],
    }
}

// ---------------------------------------------------------------------------------------------
// Unit tests: `Engine::gate_on_judge_freshness` in isolation (no full `process()` pass).
// ---------------------------------------------------------------------------------------------

/// `Propose`/`Forbidden` pass through byte-identical — the gate only ever touches `AutoApply`.
#[test]
fn gate_passes_through_non_auto_apply_decisions_unchanged() {
    let engine = armed_engine(Box::new(super::tests::CountingAdjudicator(Arc::new(
        std::sync::atomic::AtomicUsize::new(0),
    ))));
    let now = Instant::now();
    let m = live_corroborated_mitigation("workload/app/Pod/web");

    assert!(matches!(
        engine.gate_on_judge_freshness(&m, Decision::Propose("needs approval".into()), now),
        Decision::Propose(reason) if reason == "needs approval"
    ));
    assert!(matches!(
        engine.gate_on_judge_freshness(&m, Decision::Forbidden("never".into()), now),
        Decision::Forbidden(reason) if reason == "never"
    ));
}

/// Cold start: the entry has never been decisively judged this run (no `record_decisive` call
/// at all) — `AutoApply` is held as a degraded-judge `Propose`, never trusted by default.
#[test]
fn gate_holds_auto_apply_when_the_entry_has_never_been_decisively_judged() {
    let engine = armed_engine(Box::new(super::tests::CountingAdjudicator(Arc::new(
        std::sync::atomic::AtomicUsize::new(0),
    ))));
    let m = live_corroborated_mitigation("workload/app/Pod/web");

    assert!(matches!(
        engine.gate_on_judge_freshness(&m, Decision::AutoApply, Instant::now()),
        Decision::Propose(_)
    ));
}

/// A fresh decisive verdict for the JUSTIFYING entry, breaker closed ⇒ `AutoApply` passes
/// through unchanged.
#[test]
fn gate_lets_auto_apply_through_on_a_fresh_decisive_verdict() {
    let engine = armed_engine(Box::new(super::tests::CountingAdjudicator(Arc::new(
        std::sync::atomic::AtomicUsize::new(0),
    ))));
    let now = Instant::now();
    let m = live_corroborated_mitigation("workload/app/Pod/web");
    engine.verdicts.record_decisive("workload/app/Pod/web", now);

    assert_eq!(
        engine.gate_on_judge_freshness(&m, Decision::AutoApply, now),
        Decision::AutoApply
    );
}

/// A decisive verdict older than `JUDGE_FRESHNESS_BOUND` no longer trusts a NEW `AutoApply`,
/// even with the breaker closed — the "verdict age under a bound" half of the gate.
#[test]
fn gate_holds_auto_apply_once_the_decisive_verdict_ages_out() {
    let engine = armed_engine(Box::new(super::tests::CountingAdjudicator(Arc::new(
        std::sync::atomic::AtomicUsize::new(0),
    ))));
    let now = Instant::now();
    let m = live_corroborated_mitigation("workload/app/Pod/web");
    engine.verdicts.record_decisive("workload/app/Pod/web", now);

    let still_fresh = now + JUDGE_FRESHNESS_BOUND;
    assert_eq!(
        engine.gate_on_judge_freshness(&m, Decision::AutoApply, still_fresh),
        Decision::AutoApply,
        "still inside the bound"
    );

    let stale = now + JUDGE_FRESHNESS_BOUND + Duration::from_secs(1);
    assert!(
        matches!(
            engine.gate_on_judge_freshness(&m, Decision::AutoApply, stale),
            Decision::Propose(_)
        ),
        "past the bound, the verdict is too old to trust for a NEW cut"
    );
}

/// A fresh decisive verdict for THIS entry does not help once the GLOBAL breaker is open — the
/// "breaker closed" half of the gate is fleet-wide, mirroring 's own pass-wide skip:
/// this is exactly the gap `decide()`'s own `is_live_corroborated` check can't see, because a
/// cache hit subtractive hold resolves BEFORE the breaker check.
#[test]
fn gate_holds_auto_apply_when_the_global_breaker_is_open_even_with_a_fresh_local_verdict() {
    let engine = armed_engine(Box::new(super::tests::CountingAdjudicator(Arc::new(
        std::sync::atomic::AtomicUsize::new(0),
    ))));
    let now = Instant::now();
    let m = live_corroborated_mitigation("workload/app/Pod/web");
    engine.verdicts.record_decisive("workload/app/Pod/web", now);

    for i in 0..crate::engine::reason::backoff::BREAKER_TRIP {
        engine
            .verdicts
            .record_inconclusive(&format!("other-entry-{i}"), now);
    }
    assert!(
        engine.verdicts.breaker_open(now),
        "test setup: breaker open"
    );

    assert!(matches!(
        engine.gate_on_judge_freshness(&m, Decision::AutoApply, now),
        Decision::Propose(_)
    ));
}

// ---------------------------------------------------------------------------------------------
// Full-pass integration: a real `Engine::process()` exercising the gate end to end.
// ---------------------------------------------------------------------------------------------

/// A model that starts decisive (naming the entry's own menu cut) and can be flipped, mid-test,
/// to a permanent inconclusive outage — the shape of a judge that goes dark after having
/// worked.
struct SwitchableAdjudicator(Arc<AtomicBool>);

#[async_trait::async_trait]
impl reason::adjudicate::Adjudicator for SwitchableAdjudicator {
    async fn judge(
        &self,
        entry: &NodeKey,
        _objectives: &[(NodeKey, AttackRef)],
        _graph: &SecurityGraph,
        _prompt: &str,
        _downstream: &[NodeKey],
        menu: &Menu,
    ) -> IncidentDecision {
        if self.0.load(Ordering::SeqCst) {
            return IncidentDecision::uncertain("model unavailable (simulated outage)");
        }
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

/// Acceptance: breaker open / no fresh verdict ⇒ no NEW cut auto-applies — it stays a
/// proposal. `network` + `judgement` are armed throughout (so an operator flipping enforcement
/// on is not itself what's under test), but the model has NEVER once answered decisively — the
/// exact cold-start "don't arm blind" scenario.
#[tokio::test]
async fn a_cold_never_decisive_judge_never_auto_applies_a_new_cut() {
    let degraded = Arc::new(AtomicBool::new(true));
    let mut engine = Engine::new(
        EnabledActions::from_names(["network", "judgement"]),
        ActuationScope::unscoped(),
        Box::new(DryRunActuator),
        Box::new(SwitchableAdjudicator(degraded)),
    );

    engine.process(&exposed_snapshot(true)).await;

    assert_eq!(
        engine.actions.active_count(),
        0,
        "a judge that has never answered decisively must never auto-apply a brand-new cut"
    );
    // The proposal itself is still on the table (shadow's honest default) — only the LIVE
    // apply is held.
    assert!(
        !engine.ledger.active().collect::<Vec<_>>().is_empty(),
        "the mitigation is still PROPOSED, only the actuation is held"
    );
}

/// Acceptance: the fail-safe asymmetry. A cut auto-applied while the judge was healthy still
/// self-reverts once its justifying chain clears — even though the judge has since gone
/// degraded and can no longer vouch for anything. Reverts run on the wholly separate
/// `ActionLog::reconcile` path, never through `gate_on_judge_freshness`/`decide()`.
#[tokio::test]
async fn a_standing_cut_still_reverts_while_the_judge_is_degraded() {
    let degraded = Arc::new(AtomicBool::new(false));
    let mut engine = Engine::new(
        EnabledActions::from_names(["network", "judgement"]),
        ActuationScope::unscoped(),
        Box::new(DryRunActuator),
        Box::new(SwitchableAdjudicator(degraded.clone())),
    );

    // Phase 1: the judge is healthy and decisive ⇒ the model-chosen cut auto-applies.
    engine.process(&exposed_snapshot(true)).await;
    assert!(
        engine.actions.active_count() > 0,
        "setup: the cut must be live before we can prove it reverts"
    );

    // Phase 2: the judge goes dark (every call now Uncertain) AND the exposure clears (no more
    // secret access, no CVE) — the chain that justified the cut no longer exists this pass. The
    // ledger retires it regardless of the model's (currently unavailable) opinion, and the
    // self-revert loop lifts the now-unjustified cut.
    degraded.store(true, Ordering::SeqCst);
    engine.process(&observe::Snapshot::default()).await;

    assert_eq!(
        engine.actions.active_count(),
        0,
        "a cleared chain still self-reverts its cut while the judge is degraded — reverts are \
         never gated on judge freshness, only NEW auto-applies are"
    );
}
