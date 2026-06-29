//! Map the engine's would-have-acted [`Report`] into the [`TrustViewProps`] the Trust view
//! renders (brief §6): the arm/don't-arm evidence — *would have cut* (sustained-first;
//! `short_lived` = likely FP; `coverage_gap` = affirmed with no CVE backing → scrutinise first;
//! `open` = still standing) vs *left alone* (proven paths the model cleared — the trust half).
//! Honest empty: `journal_empty` (no journal history) is distinct from "none in this window".
//! Data layer: touches `state::`; the components never do.

use crate::engine::state::{LeftAloneEntry, Report, WouldActEntry};

use super::posture::human_age;
use super::props::{LeftAloneProps, StatusStripProps, TrustViewProps, WouldActProps};

/// Project one would-act entry into its props (the scrutinize side of the diff).
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

/// Build the whole Trust view's props from the would-have-acted report + the persistent strip the
/// caller supplies. The report's headline counts and ordering are preserved (the aggregation
/// already sorts would-acts most-sustained-first and left-alone by entry). Pure given its inputs.
pub(super) fn build(strip: StatusStripProps, report: &Report) -> TrustViewProps {
    TrustViewProps {
        strip,
        window_human: human_age(report.window_secs),
        journal_empty: report.journal_empty,
        decisions_in_window: report.decisions_in_window,
        would_act: report.would_act.iter().map(would_act_props).collect(),
        left_alone: report.left_alone.iter().map(left_alone_props).collect(),
        would_act_count: report.would_act_count(),
        short_lived_count: report.short_lived_count(),
        coverage_gap_count: report.coverage_gap_count(),
        left_alone_count: report.left_alone_count(),
    }
}

#[cfg(test)]
mod tests;
