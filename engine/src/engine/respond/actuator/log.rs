//! The applied-action ledger and the self-revert lifecycle (ADR-0002): tracks active
//! mitigations and decides each cycle which to revert — a control that took down a
//! workload it promised to protect, one no longer justified by a proven chain, or one
//! whose action class is no longer armed (ADR-0021's enforcement gate narrowing —
//! `enforce`→`audit`, or the break-glass kill switch engaging). Split out of the
//! actuator module root purely to keep every file under the 1,000-line cap (repo
//! CLAUDE.md). The revert decision ([`super::verify`]) is pure and tested.

use std::collections::HashSet;

use super::super::Mitigation;
use super::{EnabledActions, Verdict, verify};
use crate::engine::observe::health::HealthReport;

/// One applied (or dry-run-applied) mitigation the engine is tracking so it can
/// revert it.
#[derive(Debug, Clone)]
struct ActiveAction {
    mitigation: Mitigation,
    /// Workloads that were alive at apply time and the action promised not to take
    /// down — the protected set the closed loop verifies against.
    baseline_alive: Vec<String>,
}

/// A reversion the lifecycle decided on, with why.
#[derive(Debug, Clone)]
pub struct Reversion {
    pub mitigation: Mitigation,
    pub reason: String,
}

/// Tracks active mitigations and decides when to revert them — the self-reverting
/// half of the closed loop (ADR-0002). Each cycle, an action is reverted if a
/// workload it promised to keep alive went down (the lever did something we didn't
/// intend), if no proven chain still justifies it (posture improved), or if the
/// posture that armed it has narrowed (`enforce`→`audit`, or break-glass engaged) —
/// see [`Self::reconcile`]. All three keep the active set honest: a control exists
/// only while it is *armed*, *needed*, and *not hurting*.
#[derive(Debug, Default)]
pub struct ActionLog {
    active: Vec<ActiveAction>,
}

impl ActionLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an applied mitigation so it can later be verified and reverted.
    pub fn record(&mut self, mitigation: Mitigation, baseline_alive: Vec<String>) {
        // Replace any existing record for the same cut so re-applies don't stack.
        let sig = mitigation.cut_signature();
        self.active.retain(|a| a.mitigation.cut_signature() != sig);
        self.active.push(ActiveAction {
            mitigation,
            baseline_alive,
        });
    }

    /// True if a mitigation for this cut is already tracked (so the caller doesn't
    /// re-apply it every cycle).
    pub fn is_active(&self, mitigation: &Mitigation) -> bool {
        let sig = mitigation.cut_signature();
        self.active
            .iter()
            .any(|a| a.mitigation.cut_signature() == sig)
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Reconcile tracked actions against current health, the set of cut signatures
    /// still justified by a proven chain, and `active` — THIS PASS'S effective armed
    /// classes (the caller narrows it to [`EnabledActions::none`] while break-glass is
    /// engaged, ADR-0021's fast disarm path). The order mirrors [`super::decide`]'s
    /// safety ordering: an action reverts on health divergence first (the lever did
    /// something unintended), then when its own class is no longer armed (the posture
    /// that justified applying it has narrowed — an enforce→audit flip or break-glass
    /// engaging must revert every standing cut, not just gate NEW ones), then when no
    /// proven chain justifies it (posture improved). Returns the reversions to carry
    /// out and drops them from the active set.
    pub fn reconcile(
        &mut self,
        health: &HealthReport,
        justified_cuts: &HashSet<String>,
        active: &EnabledActions,
    ) -> Vec<Reversion> {
        let mut reversions = Vec::new();
        let mut keep = Vec::new();
        for action in std::mem::take(&mut self.active) {
            if let Verdict::Revert(reason) = verify(&action.baseline_alive, health) {
                reversions.push(Reversion {
                    mitigation: action.mitigation,
                    reason,
                });
            } else if !active.is_enabled(action.mitigation.action) {
                reversions.push(Reversion {
                    mitigation: action.mitigation,
                    reason: "action class no longer armed (mode/enforceScope narrowed, \
                             or break-glass engaged)"
                        .to_string(),
                });
            } else if !justified_cuts.contains(&action.mitigation.cut_signature()) {
                reversions.push(Reversion {
                    mitigation: action.mitigation,
                    reason: "no proven chain still justifies this control".to_string(),
                });
            } else {
                keep.push(action);
            }
        }
        self.active = keep;
        reversions
    }
}
