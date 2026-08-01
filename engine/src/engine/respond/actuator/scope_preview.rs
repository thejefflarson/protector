//! The pre-arm scope-simulation preview (ADR-0021, ADR-0016): given a CANDIDATE
//! `enforceScope`, answer "what would fire, and what live traffic would it sever, if I
//! armed `mode: enforce` on this scope right now" — before the operator ever flips the
//! switch that arms the live cut across the whole scope at once.
//!
//! ## Why this is a pure projection, not a second decision path
//!
//! [`predict_blast_radius`](super::predict_blast_radius) was ALREADY a pure, side-effect-
//! free function of `(&Mitigation, &SecurityGraph, &HealthReport)` — no extraction was
//! needed to reach the live blast gate's own collateral computation read-only. What this
//! module adds is a way to ask that SAME question against a *candidate* scope instead of
//! the engine's actually-configured one, and to do so from outside the one pass where the
//! live `SecurityGraph`/`HealthReport` borrow exists: [`super::super::super::state::ScopePreviewStore`]
//! (the engine's output-state layer) captures the exact `(Mitigation, BlastRadius)` pairs
//! this pass already computed at the point the live actuator loop computes them — so the
//! preview reuses the SAME collateral numbers the gate acted on this pass, never a second,
//! independently derived copy that could drift from it. [`preview_scope`] below then does
//! nothing but read that snapshot and classify it against a candidate [`ActuationScope`] —
//! it applies, arms, or mutates nothing.
//!
//! ## Scope, and only scope
//!
//! The preview isolates exactly the `enforceScope` axis. It intentionally does NOT gate on
//! which action classes are currently armed (the ordered arming ladder, ADR-0035) — that is
//! a separate, already-visible knob, and folding it in would make the preview answer a
//! moving-target question ("what fires under scope X *and* today's rung") instead of the
//! one ADR-0021 poses: a single `enforceScope` arms every in-scope entry across all three
//! surfaces at once, and this preview shows exactly that surface.

use super::{ActuationScope, BlastRadius};
use crate::engine::respond::{Mitigation, ProposedAction};

/// One currently-standing cut that WOULD fire under the candidate scope: its predicted live
/// collateral, read verbatim from the SAME [`BlastRadius`] the live blast gate computed this
/// pass (never recomputed here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiringCut {
    pub cut: String,
    pub action: ProposedAction,
    /// Currently-alive peer workloads this cut would sever, other than its own endpoints
    /// (the intended severance) — empty means "none known". See `collateral_unknown` for
    /// the "can't tell" case, which is NEVER collapsed into this empty reading.
    pub alive_collateral: Vec<String>,
    /// Reachability wasn't fully modeled for this cut this pass (an adapter flagged the
    /// graph, e.g. an unmodeled `NetworkPolicy` peer/selector) — `alive_collateral` may be
    /// under-counted. Surfaced explicitly so an unknown blast radius is never presented as
    /// an empty, implied-safe one — the same "collateral unknown, never implied safe" rule
    /// the live gate itself applies (it refuses to auto-apply on this flag too).
    pub collateral_unknown: bool,
}

/// One currently-standing, otherwise-actionable cut the candidate scope does NOT cover — the
/// gate would HOLD it as a proposal (needs a human, exactly like today) rather than arm it,
/// because at least one of its endpoints falls outside the candidate scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldCut {
    pub cut: String,
    pub action: ProposedAction,
}

/// The read-only scope-simulation result: every currently-standing, otherwise-actionable cut,
/// partitioned by whether the CANDIDATE `enforceScope` would cover it. An empty candidate
/// scope naturally classifies every eligible cut as [`held_out_of_scope`](Self::held_out_of_scope)
/// — an honest zero in [`would_fire`](Self::would_fire), never confused with `collateral_unknown`
/// (a distinct, per-cut flag: "zero fires" and "we can't tell" are never the same reading).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopePreview {
    pub would_fire: Vec<FiringCut>,
    pub held_out_of_scope: Vec<HeldCut>,
}

/// Whether a standing mitigation is even mechanically eligible to ever arm, independent of
/// scope: reversible, additive-live (the only kind the engine can apply at all — a subtractive
/// or irreversible cut is durable-fix/human territory regardless of scope), and justified by a
/// live-corroborated-or-promoted, adjudicated, breach-relevant chain. These mirror the first and
/// third gates [`super::decide`] checks before it ever looks at scope; a cut that fails this bar
/// stays a proposal no matter what `enforceScope` says, so the preview leaves it out entirely
/// rather than mislabeling it "held (out of scope)" for the wrong reason.
fn would_ever_act(mitigation: &Mitigation) -> bool {
    mitigation.action.is_reversible()
        && mitigation.action.is_additive_live()
        && mitigation.is_live_corroborated()
}

/// Classify this pass's standing cuts (each mitigation paired with the blast radius already
/// computed for it) against a CANDIDATE `enforceScope`. Pure: reads only its arguments, mutates
/// nothing, applies/arms nothing (ADR-0016 — presentation is a view, never a decision gate).
pub fn preview_scope(
    standing: &[(Mitigation, BlastRadius)],
    candidate: &ActuationScope,
) -> ScopePreview {
    let mut would_fire = Vec::new();
    let mut held_out_of_scope = Vec::new();
    for (mitigation, blast) in standing {
        if !would_ever_act(mitigation) {
            continue;
        }
        if candidate.endpoints_within(mitigation) {
            would_fire.push(FiringCut {
                cut: mitigation.cut_signature(),
                action: mitigation.action,
                alive_collateral: blast.alive_collateral.clone(),
                collateral_unknown: blast.reachability_incomplete,
            });
        } else {
            held_out_of_scope.push(HeldCut {
                cut: mitigation.cut_signature(),
                action: mitigation.action,
            });
        }
    }
    would_fire.sort_by(|a, b| a.cut.cmp(&b.cut));
    held_out_of_scope.sort_by(|a, b| a.cut.cmp(&b.cut));
    ScopePreview {
        would_fire,
        held_out_of_scope,
    }
}

#[cfg(test)]
mod tests;
