//! Engine-level acceptance tests for the disarm kill switch: `enforce`→`audit` (simulated
//! here via engaging break-glass, the only in-process lever that narrows a running engine's
//! posture without a restart — flipping `PROTECTOR_MODE` itself always restarts the pod, since
//! it's read once at boot) must revert every standing engine-applied cut within one pass, and
//! the break-glass file itself must behave as documented: fast, narrow-only, and a no-op when
//! clear. Split out of `tests.rs` purely to keep every file under the 1,000-line cap (repo
//! CLAUDE.md). `use super::*` resolves to the engine module, matching the sibling `*_tests.rs`
//! files; the adjudicator/actuator test doubles mirror the ADR-0034 pattern already established
//! in `tests.rs` (`a_model_chosen_cut_auto_applies_in_enforce_mode`).

use super::*;
use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{NodeKey, SecurityGraph};
use crate::engine::reason::adjudicate::incident::{Assessment, IncidentDecision, Menu};
use crate::engine::respond::actuator::Actuation;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::tests::exposed_snapshot;

/// A unique temp flag path for a test, without a temp-file crate (mirrors
/// `journal_tests::temp_journal_path`).
fn temp_flag_path(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::AtomicU64;
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let n = NONCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "protector-engine-break-glass-{tag}-{}-{n}",
        std::process::id()
    ))
}

/// A model that always decisively attacks the entry, naming it as its own cut — the same
/// shape `tests::a_model_chosen_cut_auto_applies_in_enforce_mode` uses to exercise a real
/// AutoApply through the live ledger, reused here so the cut this file reverts is exactly the
/// kind `enforce` actually applies.
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

/// A test-double [`Actuator`](respond::actuator::Actuator) that records apply/revert calls via
/// shared counters, so a test can inspect them after moving the actuator into the `Engine`'s
/// `Box<dyn Actuator>`. Unlike [`respond::actuator::DryRunActuator`] (which only logs), this
/// lets a test assert the SPECIFIC apply-then-revert sequence break-glass must drive.
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

/// Build an `enforce`-posture engine (`network` + `judgement` armed) wired to a fresh
/// [`RecordingActuator`] and [`AlwaysAttacksTheEntry`] watching `break_glass` — the common
/// fixture every test below but the byte-identical-default one shares. Returns the engine plus
/// its actuator's shared apply/revert counters.
fn enforce_engine(
    break_glass: break_glass::BreakGlass,
) -> (Engine, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let applied = Arc::new(AtomicUsize::new(0));
    let reverted = Arc::new(AtomicUsize::new(0));
    let actuator = RecordingActuator {
        applied: applied.clone(),
        reverted: reverted.clone(),
    };
    let engine = Engine::new(
        EnabledActions::from_names(["network", "judgement"]),
        ActuationScope::unscoped(),
        Box::new(actuator),
        Box::new(AlwaysAttacksTheEntry),
    )
    .with_break_glass(break_glass);
    (engine, applied, reverted)
}

/// The core acceptance test: a cut applied under `enforce` must be gone — actuator `revert`
/// called, and the reversion log reflects it — within the SAME pass break-glass engages, with
/// no restart and no chain/health change (the only thing that changed is the flag file).
#[tokio::test]
async fn engaging_break_glass_reverts_a_standing_enforce_mode_cut_within_one_pass() {
    let path = temp_flag_path("reverts");
    let (mut engine, applied, reverted) = enforce_engine(break_glass::BreakGlass::at(&path));

    // Pass 1 (break-glass clear): the model-chosen cut auto-applies for real.
    engine.process(&exposed_snapshot(true)).await;
    assert_eq!(
        applied.load(Ordering::SeqCst),
        1,
        "enforce mode applies the model-chosen cut"
    );
    assert_eq!(reverted.load(Ordering::SeqCst), 0);

    // Engage break-glass — presence only, no chart change, no restart.
    std::fs::write(&path, "").expect("write the flag file");

    // Pass 2 (identical facts, break-glass now engaged): the standing cut must revert THIS
    // pass — it is still perfectly justified by the same proven, decisive chain, so the ONLY
    // thing that changed is the disarm.
    engine.process(&exposed_snapshot(true)).await;
    assert_eq!(
        reverted.load(Ordering::SeqCst),
        1,
        "break-glass reverts the standing cut within one pass, with no restart"
    );
    assert_eq!(
        applied.load(Ordering::SeqCst),
        1,
        "no re-apply while disarmed"
    );
    assert_eq!(
        engine.actions.active_count(),
        0,
        "the applied-action log agrees nothing is standing"
    );

    // The reversion log — the operator-visible record — reflects it, distinctly from an
    // ordinary chain-retirement revert.
    let reversions = engine.reversions().snapshot();
    let reasons: Vec<&str> = reversions.iter().map(|r| r.reason.as_str()).collect();
    assert!(
        reasons.iter().any(|r| r.contains("armed")),
        "the reversion log names the disarm, not just \"unjustified\": got {reasons:?}"
    );

    std::fs::remove_file(&path).ok();
}

/// Clearing break-glass restores exactly the arming the process booted with — byte-identical
/// to running without this module at all. A FRESH chain proven while break-glass is engaged
/// only proposes (never applies); once cleared, the SAME still-standing chain auto-applies on
/// the very next pass with no special re-arm step.
#[tokio::test]
async fn clearing_break_glass_restores_the_configured_posture_byte_identical() {
    let path = temp_flag_path("clears");
    // Engaged from the very first pass this time — enforce is configured, but disarmed.
    std::fs::write(&path, "").expect("write the flag file");
    let (mut engine, applied, reverted) = enforce_engine(break_glass::BreakGlass::at(&path));

    engine.process(&exposed_snapshot(true)).await;
    assert_eq!(
        applied.load(Ordering::SeqCst),
        0,
        "break-glass engaged from boot ⇒ the model-chosen cut only proposes, never applies"
    );
    assert!(
        !engine
            .ledger
            .active()
            .cloned()
            .collect::<Vec<_>>()
            .is_empty(),
        "the cut is still PROPOSED (ledger-active) — break-glass narrows actuation, not proof"
    );

    // Clear it — the flag file is simply removed, no chart/env change.
    std::fs::remove_file(&path).expect("clear the flag file");

    // The same still-standing, still-justified chain now applies — exactly the enforce
    // behavior configured at boot, with no restart needed to "reactivate" it.
    engine.process(&exposed_snapshot(true)).await;
    assert_eq!(
        applied.load(Ordering::SeqCst),
        1,
        "clearing break-glass restores the configured enforce posture on the very next pass"
    );
    assert_eq!(
        reverted.load(Ordering::SeqCst),
        0,
        "nothing was ever standing to revert"
    );
}

/// A break-glass watcher that is never engaged (the default — every engine built without
/// `with_break_glass`) changes nothing: the SAME enforce scenario auto-applies exactly as it
/// does with this module absent entirely. Deliberately does NOT use `enforce_engine` (which
/// always calls `.with_break_glass`) — the point here is specifically that skipping the builder
/// call altogether is safe, so the engine is built by hand.
#[tokio::test]
async fn disabled_break_glass_is_byte_identical_to_before_this_module_existed() {
    let applied = Arc::new(AtomicUsize::new(0));
    let reverted = Arc::new(AtomicUsize::new(0));
    let actuator = RecordingActuator {
        applied: applied.clone(),
        reverted: reverted.clone(),
    };

    // No `.with_break_glass(...)` call at all — `Engine::new`'s default
    // (`BreakGlass::disabled()`).
    let mut engine = Engine::new(
        EnabledActions::from_names(["network", "judgement"]),
        ActuationScope::unscoped(),
        Box::new(actuator),
        Box::new(AlwaysAttacksTheEntry),
    );

    engine.process(&exposed_snapshot(true)).await;
    assert_eq!(
        applied.load(Ordering::SeqCst),
        1,
        "with no break-glass attached, enforce applies exactly as before this module existed"
    );

    engine.process(&exposed_snapshot(true)).await;
    assert_eq!(
        reverted.load(Ordering::SeqCst),
        0,
        "a never-engaged break-glass never reverts a still-justified, still-armed cut"
    );
}
