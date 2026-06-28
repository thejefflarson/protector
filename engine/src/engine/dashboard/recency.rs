//! Per-finding recency / Δ data (JEF-201): the small, pure types the verdict store tracks
//! per entry to answer "what changed since I last looked?" — the [`StoredPosture`] the
//! engine diffs pass-to-pass, the resulting [`Delta`] glyph verdict, and the [`RecencyInfo`]
//! the view maps into the dense table's Δ column.
//!
//! These are DATA-layer types (they live beside [`super::model`] and carry no markup). The
//! recency they encode is derived from the store's first-seen / previous-posture history,
//! NOT from render time, so it survives the `/fragment` 30s poll (a re-render with no new
//! pass keeps the stored [`Delta`]) and a journal-restore on boot (a restored entry reads
//! [`Delta::Restored`], never [`Delta::New`]). Pure presentation metadata: it gates nothing,
//! feeds no model, and the engine stays SHADOW (ADR-0016: recency is a view).

use serde::Serialize;

/// The model's POSTURE for an entry as the recency tracker stores it (JEF-201) — the
/// data-layer twin of the view's `Posture`, kept here so the engine can diff this pass's
/// posture against the previous one WITHOUT pulling the presentation layer into the engine
/// (the view's `Posture` lives in `view_model::findings`, which the components own). Derived
/// from a display verdict summary by [`StoredPosture::of_summary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredPosture {
    /// The model affirmed a real breach (its summary begins with "exploitable").
    Breach,
    /// The model judged this NOT a breach (a "not exploitable — …" call).
    Safe,
    /// No verdict has been displayed for this entry yet (the model hasn't reached it).
    Awaiting,
}

impl StoredPosture {
    /// The posture a display-verdict summary string carries — the same "exploitable …" test
    /// the view's `Posture::of` uses, applied to the engine's display summary so the recency
    /// diff and the rendered posture chip can never disagree. `None` ⇒ `Awaiting`.
    pub fn of_summary(summary: Option<&str>) -> Self {
        match summary {
            None => StoredPosture::Awaiting,
            Some(s)
                if s.trim_start()
                    .to_ascii_lowercase()
                    .starts_with("exploitable") =>
            {
                StoredPosture::Breach
            }
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

/// The per-entry recency verdict the dashboard's Δ column renders (JEF-201) — "what changed
/// since the last pass". Computed by the store from the diff of this pass's [`StoredPosture`]
/// against the previous one (NOT from render time), so it survives the `/fragment` poll and a
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
    /// The terse glyph the Δ cell shows. Meaning is ALSO carried in text via the cell's
    /// `aria-label` ([`Delta::aria_label`]) — never the glyph/arrow alone (JEF-201 AC #4).
    /// `Unchanged` renders no glyph (the cell shows the quiet age instead).
    pub fn glyph(self) -> &'static str {
        match self {
            Delta::New => "NEW",
            Delta::Escalated => "↑",
            Delta::DeEscalated => "↓",
            Delta::Restored => "·",
            Delta::Unchanged => "·",
        }
    }

    /// The screen-reader label for the Δ cell (JEF-201 AC #4): the meaning IN WORDS, so the
    /// glyph never carries meaning by color/arrow alone. `age` (when present) personalizes
    /// the unchanged/restored reading with a human age.
    pub fn aria_label(self, age: Option<&str>) -> String {
        match self {
            Delta::New => "new this pass".to_string(),
            Delta::Escalated => "escalated since last pass".to_string(),
            Delta::DeEscalated => "de-escalated since last pass".to_string(),
            Delta::Restored => "restored from history".to_string(),
            Delta::Unchanged => match age {
                Some(a) => format!("unchanged, first seen {a} ago"),
                None => "unchanged".to_string(),
            },
        }
    }

    /// Whether this Δ counts toward the findings-region "N new" tally (JEF-201).
    pub fn is_new(self) -> bool {
        matches!(self, Delta::New)
    }

    /// Whether this Δ counts toward the "N newly flagged since last pass" tally — a fresh
    /// escalation into (or onto) a breach. Escalations are the "newly flagged" signal.
    pub fn is_escalation(self) -> bool {
        matches!(self, Delta::Escalated)
    }
}

/// The resolved recency facts for one entry (JEF-201), the data the view maps into the Δ
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
    fn posture_of_summary_matches_exploitable_prefix() {
        assert_eq!(StoredPosture::of_summary(None), StoredPosture::Awaiting);
        assert_eq!(
            StoredPosture::of_summary(Some("exploitable — CVE-2021-44228")),
            StoredPosture::Breach
        );
        assert_eq!(
            StoredPosture::of_summary(Some("  Exploitable now")),
            StoredPosture::Breach
        );
        assert_eq!(
            StoredPosture::of_summary(Some("not exploitable — internal only")),
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
    fn glyphs_and_aria_carry_meaning_in_words() {
        assert_eq!(Delta::New.glyph(), "NEW");
        assert_eq!(Delta::New.aria_label(None), "new this pass");
        assert_eq!(
            Delta::Escalated.aria_label(None),
            "escalated since last pass"
        );
        assert_eq!(
            Delta::DeEscalated.aria_label(None),
            "de-escalated since last pass"
        );
        assert_eq!(
            Delta::Unchanged.aria_label(Some("2m")),
            "unchanged, first seen 2m ago"
        );
        assert!(Delta::New.is_new());
        assert!(Delta::Escalated.is_escalation());
        assert!(!Delta::Unchanged.is_new());
    }
}
