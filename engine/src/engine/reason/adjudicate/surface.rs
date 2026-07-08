//! The delta-aware adjudication surface (ADR-0023, JEF-391): "the state is the context, the
//! delta is the question." A [`JudgedSurface`] is the projection of an entry's judged evidence
//! into sorted key-sets — reachable objectives (with their reach tags), running CVEs, exposed
//! secrets, static posture, and observed runtime behavior. It is derived from the SAME rendered
//! evidence lines that go into the full-state prompt (no second source of truth, per the ADR),
//! so a change the model would see in the prompt is exactly a change the surface records.
//!
//! On a DECISIVE verdict the surface is snapshotted as the entry's BASELINE (stored on
//! `VerdictEntry`). The re-judge gate then compares the CURRENT surface against that baseline:
//!
//! - an ADDITIVE delta (any category gained an element) ⇒ re-judge, and the added elements are
//!   surfaced to the model as the "Changes since the last decisive verdict" section so the call
//!   is a focused delta-judgment rather than a from-scratch re-derivation of the world;
//! - a PURELY SUBTRACTIVE delta (elements only removed — a pod vanished, a peer aged out) ⇒ NO
//!   fresh model call: the prior decisive verdict holds, its supporting surface only shrank, and
//!   removal is de-escalated by the existing recency/reversion path (ADR-0009/JEF-141), never a
//!   re-judge. This stops the ephemeral-churn ping-pong at its root.
//!
//! CORRECTNESS (non-negotiable, security-relevant): the full current state ALWAYS stays in the
//! prompt — the delta only DIRECTS attention, it never REPLACES the state. And the gate fails
//! toward re-judging: the diff is a set-difference over the rendered lines, so a modified element
//! (a CVE whose CVSS escalated, an objective whose reach tag changed) reads as a removed-old +
//! added-new pair and the added-new counts as an addition ⇒ re-judge. Only a provably pure
//! removal is ever skipped.

use std::collections::BTreeSet;

/// One entry's judged surface: the sorted key-sets the re-judge gate diffs across passes. Each
/// set holds the EXACT rendered evidence lines the prompt carries for that category, so the
/// baseline↔current diff is over the same text the model reasons about (ADR-0023's "same proven
/// graph" requirement). Bounded by the entry's proven surface — the same bound the prompt (and
/// the JEF-390 LRU that already stores whole prompts) is under; one snapshot per entry, replaced
/// on each decisive verdict, so it never grows across passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JudgedSurface {
    objectives: BTreeSet<String>,
    cves: BTreeSet<String>,
    secrets: BTreeSet<String>,
    posture: BTreeSet<String>,
    behaviors: BTreeSet<String>,
}

impl JudgedSurface {
    /// Project the surface from the already-rendered prompt evidence lines (the SAME vectors
    /// the full-state prompt interpolates), so a change visible to the model is a change the
    /// surface records. Deterministic: the inputs are already sorted+deduped, and a `BTreeSet`
    /// re-sorts regardless.
    pub(super) fn from_lines(
        objectives: &[String],
        cves: &[String],
        secrets: &[String],
        posture: &[String],
        behaviors: &[String],
    ) -> Self {
        let set = |v: &[String]| v.iter().cloned().collect::<BTreeSet<String>>();
        Self {
            objectives: set(objectives),
            cves: set(cves),
            secrets: set(secrets),
            posture: set(posture),
            behaviors: set(behaviors),
        }
    }

    /// The ADDITIVE delta — elements present in `self` (current) but absent from `baseline` (the
    /// surface at this entry's last decisive verdict). With NO baseline (first judgment) there is
    /// nothing to diff against, so this is empty: the full state is itself the baseline, and the
    /// re-judge is driven by "no decisive baseline exists yet" in the gate, not by this delta.
    ///
    /// Fail-safe by construction: a set-DIFFERENCE, so any element newly present — including a
    /// mutated element, which appears as a NEW line the baseline lacks — is an addition. Purely
    /// removed elements never appear here, so only a provable pure removal yields an empty delta.
    pub(super) fn additions_since(&self, baseline: Option<&JudgedSurface>) -> ChangesSince {
        let Some(base) = baseline else {
            return ChangesSince::default();
        };
        let diff = |cur: &BTreeSet<String>, old: &BTreeSet<String>| {
            cur.difference(old).cloned().collect::<Vec<String>>()
        };
        ChangesSince {
            objectives: diff(&self.objectives, &base.objectives),
            cves: diff(&self.cves, &base.cves),
            secrets: diff(&self.secrets, &base.secrets),
            posture: diff(&self.posture, &base.posture),
            behaviors: diff(&self.behaviors, &base.behaviors),
        }
    }
}

/// The additions since a baseline (ADR-0023) — what became NEWLY present on the entry's surface,
/// grouped by category so the "Changes since the last decisive verdict" prompt section can name
/// each. Empty ⇒ nothing was added (purely subtractive or unchanged), which the gate reads as
/// "the prior decisive verdict still holds."
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangesSince {
    objectives: Vec<String>,
    cves: Vec<String>,
    secrets: Vec<String>,
    posture: Vec<String>,
    behaviors: Vec<String>,
}

impl ChangesSince {
    /// Whether nothing was added since the baseline — the gate's "purely subtractive / unchanged"
    /// signal. When true (and a decisive baseline exists) the prior verdict holds with no fresh
    /// model call.
    pub(super) fn is_empty(&self) -> bool {
        self.objectives.is_empty()
            && self.cves.is_empty()
            && self.secrets.is_empty()
            && self.posture.is_empty()
            && self.behaviors.is_empty()
    }

    /// The additions as labeled prompt lines, in a fixed category order (each category's lines
    /// are already sorted — they come from a `BTreeSet` difference). The caller fences the result
    /// like all other untrusted evidence; an empty result fences to `(none)`.
    pub(super) fn rendered_lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut push = |label: &str, lines: &[String]| {
            for line in lines {
                // Objective lines carry a leading "  - " list marker; drop it so the addition
                // reads as one flat, labeled item. Other categories have no such prefix.
                out.push(format!("{label}: {}", line.trim_start_matches([' ', '-'])));
            }
        };
        push("newly-reachable objective", &self.objectives);
        push("newly-running CVE", &self.cves);
        push("newly-exposed secret", &self.secrets);
        push("new static-posture finding", &self.posture);
        push("newly-observed runtime behavior", &self.behaviors);
        out
    }
}
