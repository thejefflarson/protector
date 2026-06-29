//! Map the engine's would-have-acted [`Report`] + audit handles into the [`ActionViewProps`] the
//! Action view renders (brief §4/§6) — the merged Trust + Activity story in LIFECYCLE order:
//!
//! 1. **Proposed cuts** — the would-act proposals ([`WouldActEntry`], sustained-first;
//!    `short_lived` = likely FP; `coverage_gap` = affirmed with no CVE backing → scrutinise first;
//!    `open` = still standing) PLUS the cuts that were applied then self-reverted
//!    ([`ReversionRecord`] — the reverted tail of the lifecycle, with reason + age).
//! 2. **Left alone (cleared)** — proven paths the model cleared ([`LeftAloneEntry`], the trust half).
//! 3. **Judgement audit** — the verbatim prompt/reply ring ([`Judgement`], for debugging the model).
//!
//! Honest empties are preserved: `journal_empty` (no journal history) is distinct from "none in this
//! window"; an empty reversion/judgement set is left empty so the component renders its own explicit
//! "none yet" line. Data layer: touches `state::`; the components never do.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::engine::state::{Judgement, LeftAloneEntry, Report, ReversionRecord, WouldActEntry};

use super::posture::human_age;
use super::props::{
    ActionViewProps, JudgementEntryProps, LeftAloneProps, ReversionProps, StatusStripProps,
    WouldActProps,
};

/// Project one would-act entry into its props (a still-standing proposed cut).
fn would_act_props(w: &WouldActEntry) -> WouldActProps {
    WouldActProps {
        entry: w.entry.clone(),
        episodes: w.episodes,
        would_act_decisions: w.would_act_decisions,
        max_lifetime: human_age(w.max_lifetime_secs),
        open: w.open,
        short_lived: w.short_lived,
        coverage_gap: w.coverage_gap,
        last_verdict: w.last_verdict.clone(),
    }
}

/// Project one left-alone entry into its props (the trust half).
fn left_alone_props(l: &LeftAloneEntry) -> LeftAloneProps {
    LeftAloneProps {
        entry: l.entry.clone(),
        verdict: l.verdict.clone(),
    }
}

/// Human "NNs ago" age for a reversion timestamp (Unix epoch ms), clamped at 0 so a clock skew
/// never renders a negative age. `now_ms` is injected for testability.
fn age_since(at_ms: u64, now_ms: u64) -> String {
    let secs = now_ms.saturating_sub(at_ms) / 1000;
    human_age(secs)
}

/// Project one reversion record into its props (the reverted tail of the proposed-cut lifecycle),
/// formatting its age relative to `now_ms`.
fn reversion_props(r: &ReversionRecord, now_ms: u64) -> ReversionProps {
    ReversionProps {
        cut: r.cut.clone(),
        reason: r.reason.clone(),
        age: age_since(r.at_ms, now_ms),
    }
}

/// Project one judgement into its props (the verbatim prompt/reply behind a model call).
fn judgement_props(j: &Judgement) -> JudgementEntryProps {
    JudgementEntryProps {
        entry: j.entry.clone(),
        objectives: j.objectives,
        verdict: Some(j.verdict.clone()),
        prompt: j.prompt.clone(),
        reply: j.reply.clone(),
    }
}

/// Build the whole Action view's props from the would-have-acted report, the self-reverted-cuts
/// snapshot, and the judgement ring (both newest-first), plus the persistent strip the caller
/// supplies. `now_ms` is the wall clock the reversion ages are measured against (injected for
/// testability). The report's headline counts/ordering are preserved (the aggregation already sorts
/// would-acts most-sustained-first and left-alone by entry). Pure given its inputs.
pub(super) fn build_at(
    strip: StatusStripProps,
    report: &Report,
    reversions: &[ReversionRecord],
    judgements: &[Judgement],
    now_ms: u64,
) -> ActionViewProps {
    ActionViewProps {
        strip,
        window_human: human_age(report.window_secs),
        journal_empty: report.journal_empty,
        decisions_in_window: report.decisions_in_window,
        would_act: report.would_act.iter().map(would_act_props).collect(),
        reversions: reversions
            .iter()
            .map(|r| reversion_props(r, now_ms))
            .collect(),
        left_alone: report.left_alone.iter().map(left_alone_props).collect(),
        judgements: judgements.iter().map(judgement_props).collect(),
        would_act_count: report.would_act_count(),
        short_lived_count: report.short_lived_count(),
        coverage_gap_count: report.coverage_gap_count(),
        left_alone_count: report.left_alone_count(),
        reverted_count: reversions.len(),
    }
}

/// Build the Action view's props against the current wall clock.
pub(super) fn build(
    strip: StatusStripProps,
    report: &Report,
    reversions: &[ReversionRecord],
    judgements: &[Judgement],
) -> ActionViewProps {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    build_at(strip, report, reversions, judgements, now_ms)
}

#[cfg(test)]
mod tests;
