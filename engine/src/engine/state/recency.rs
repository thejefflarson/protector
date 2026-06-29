//! Per-finding recency / Δ data (JEF-201): the small, pure types the verdict store tracks
//! per entry to answer "what changed since the last pass?" — the [`StoredPosture`] the
//! engine diffs pass-to-pass, the resulting [`Delta`] verdict, and the [`RecencyInfo`] the
//! findings snapshot carries per row.
//!
//! These are DATA-layer types: they carry no markup. The recency they encode is derived from
//! the store's first-seen / previous-posture history, NOT from any render time, so it is stable
//! across repeated reads (a re-read with no new pass keeps the stored [`Delta`]) and a
//! journal-restore on boot (a restored entry reads [`Delta::Restored`], never [`Delta::New`]).
//! Pure presentation metadata: it gates nothing, feeds no model, and the engine stays SHADOW
//! (ADR-0016: recency is a view).

use serde::Serialize;

use crate::engine::reason::adjudicate::Verdict;

/// The model's POSTURE for an entry as the recency tracker stores it (JEF-201). Kept here so the
/// engine can diff this pass's posture against the previous one without pulling in any
/// presentation. Derived from the TYPED [`Verdict`] by [`StoredPosture::of_verdict`] (JEF-255) —
/// the single source of truth, so the recency diff and any rendered posture can never disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredPosture {
    /// The model affirmed a real breach (a `Confirmed` / `Exploitable` verdict).
    Breach,
    /// The model judged this NOT a breach (a `Refuted` / `Uncertain` call).
    Safe,
    /// No verdict has been displayed for this entry yet (the model hasn't reached it).
    Awaiting,
}

impl StoredPosture {
    /// The posture a TYPED verdict carries (JEF-255) — `Confirmed`/`Exploitable`
    /// ([`Verdict::is_confirmed`]) is a BREACH, any decisive negative (`Refuted`/`Uncertain`)
    /// is `Safe`, and `None` (no verdict yet) is `Awaiting`. This is the one place posture is
    /// derived from a verdict, so the recency diff and any downstream posture can never drift.
    /// (v1 string-matched the "exploitable" prefix here, and missed `Confirmed`; JEF-255 fixes
    /// that.)
    pub fn of_verdict(verdict: Option<&Verdict>) -> Self {
        match verdict {
            None => StoredPosture::Awaiting,
            Some(v) if v.is_confirmed() => StoredPosture::Breach,
            Some(_) => StoredPosture::Safe,
        }
    }

    /// Rank for the escalation diff (lower = calmer): Awaiting < Safe < Breach. A rise in
    /// rank is an escalation (`↑`), a fall a de-escalation (`↓`). Awaiting ranks lowest so a
    /// NEW entry's first real verdict reads via [`Delta::New`], not a spurious arrow.
    pub fn rank(self) -> u8 {
        match self {
            StoredPosture::Awaiting => 0,
            StoredPosture::Safe => 1,
            StoredPosture::Breach => 2,
        }
    }

    /// The Δ for moving FROM a previous posture TO this one — the pure diff the store applies
    /// each pass. Equal postures are [`Delta::Unchanged`]; a higher rank is an escalation, a
    /// lower one a de-escalation. (`New` / `Restored` are decided by first-seen state, not by
    /// this diff — they have no "previous" posture.)
    pub fn delta_from(prev: StoredPosture, now: StoredPosture) -> Delta {
        match now.rank().cmp(&prev.rank()) {
            std::cmp::Ordering::Greater => Delta::Escalated,
            std::cmp::Ordering::Less => Delta::DeEscalated,
            std::cmp::Ordering::Equal => Delta::Unchanged,
        }
    }
}

/// The per-entry recency verdict for the Δ a finding carries (JEF-201) — "what changed since the
/// last pass". Computed by the store from the diff of this pass's [`StoredPosture`] against the
/// previous one (NOT from render time), so it is stable across repeated reads and a
/// journal-restore. Pure presentation metadata (ADR-0016: recency is a view).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Delta {
    /// First seen THIS run, this pass — there was no previous posture for the key.
    New,
    /// Posture worsened since the previous pass (e.g. Safe → Breach, awaiting → flagged).
    Escalated,
    /// Posture de-escalated since the previous pass (e.g. Breach → Safe, a cut lifted).
    DeEscalated,
    /// Posture unchanged since the previous pass — steady state.
    Unchanged,
    /// Restored from the durable journal on boot (JEF-141) — present before this run began,
    /// so it must NOT be mislabeled `New`. Carries the quiet "seen before" reading.
    Restored,
}

impl Delta {
    /// Whether this Δ counts toward the "N new this pass" tally (JEF-201).
    #[allow(dead_code)]
    pub fn is_new(self) -> bool {
        matches!(self, Delta::New)
    }

    /// Whether this Δ counts toward the "N newly flagged since last pass" tally — a fresh
    /// escalation into (or onto) a breach. Escalations are the "newly flagged" signal.
    #[allow(dead_code)]
    pub fn is_escalation(self) -> bool {
        matches!(self, Delta::Escalated)
    }
}

/// The resolved recency facts for one entry (JEF-201), the data a finding carries in its Δ
/// glyph + age cell. Pulled from the verdict store at `Findings::snapshot` time, like the
/// verdict itself, so the Δ tracks the stored first-seen / posture history rather than the
/// render clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RecencyInfo {
    /// The Δ verdict for this entry's latest pass.
    pub delta: Delta,
    /// How long ago the entry was first seen this run, in whole seconds — the quiet "age"
    /// the steady-state Δ cell shows instead of a glyph. `None` for a journal-restored entry
    /// whose first_seen is synthetic (its age is not meaningful) or before the first pass.
    pub age_secs: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_of_verdict_keys_on_is_confirmed() {
        assert_eq!(StoredPosture::of_verdict(None), StoredPosture::Awaiting);
        assert_eq!(
            StoredPosture::of_verdict(Some(&Verdict::Exploitable("CVE-2021-44228".into()))),
            StoredPosture::Breach
        );
        // A `Confirmed` verdict is ALSO a breach — v1's string-match missed it (JEF-255).
        assert_eq!(
            StoredPosture::of_verdict(Some(&Verdict::Confirmed)),
            StoredPosture::Breach
        );
        assert_eq!(
            StoredPosture::of_verdict(Some(&Verdict::Refuted("internal only".into()))),
            StoredPosture::Safe
        );
        assert_eq!(
            StoredPosture::of_verdict(Some(&Verdict::Uncertain("model timed out".into()))),
            StoredPosture::Safe
        );
    }

    #[test]
    fn delta_from_diffs_by_rank() {
        use StoredPosture::*;
        assert_eq!(StoredPosture::delta_from(Safe, Breach), Delta::Escalated);
        assert_eq!(
            StoredPosture::delta_from(Awaiting, Breach),
            Delta::Escalated
        );
        assert_eq!(StoredPosture::delta_from(Breach, Safe), Delta::DeEscalated);
        assert_eq!(StoredPosture::delta_from(Breach, Breach), Delta::Unchanged);
        assert_eq!(StoredPosture::delta_from(Safe, Safe), Delta::Unchanged);
    }

    #[test]
    fn delta_tally_predicates() {
        assert!(Delta::New.is_new());
        assert!(Delta::Escalated.is_escalation());
        assert!(!Delta::Unchanged.is_new());
        assert!(!Delta::Unchanged.is_escalation());
    }
}
