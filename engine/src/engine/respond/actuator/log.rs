//! The applied-action ledger and the self-revert lifecycle (ADR-0002): tracks active
//! mitigations and decides each cycle which to revert — a control that took down a
//! workload it promised to protect, or one no longer justified by a proven chain.
//! Split out of the actuator module root purely to keep every file under the 1,000-line
//! cap (repo CLAUDE.md). The revert decision ([`super::verify`]) is pure and tested.

use std::collections::HashSet;

use super::super::Mitigation;
use super::{Verdict, verify};
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
/// intend) or if no proven chain still justifies it (posture improved). Both keep
/// the active set honest: a control exists only while it is both *needed* and *not
/// hurting*.
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

    /// Reconcile tracked actions against current health and the set of cut
    /// signatures still justified by a proven chain. Returns the reversions to
    /// carry out and drops them from the active set.
    pub fn reconcile(
        &mut self,
        health: &HealthReport,
        justified_cuts: &HashSet<String>,
    ) -> Vec<Reversion> {
        let mut reversions = Vec::new();
        let mut keep = Vec::new();
        for action in std::mem::take(&mut self.active) {
            if let Verdict::Revert(reason) = verify(&action.baseline_alive, health) {
                reversions.push(Reversion {
                    mitigation: action.mitigation,
                    reason,
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
