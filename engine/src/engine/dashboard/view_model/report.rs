//! The `/report` view-model (ADR-0019, the DATA layer): pure functions that shape the
//! aggregated would-have-acted [`Report`] (JEF-143) into the plain `Props` the
//! `components::report` renderer consumes. No maud, no markup — only the mapping from the
//! engine's report aggregation into presentation-shaped data (the human window span, the
//! headline counts, and the per-entry rows with their lifetime/coverage classification
//! already resolved to plain strings).
//!
//! The aggregation itself ([`aggregate_report`](crate::engine::dashboard::legacy::aggregate_report))
//! and the JSON contract ([`Report`]) stay in `legacy` — this layer only reshapes that data
//! for the view, never recomputes it.

use crate::engine::dashboard::legacy::{Report, human_span, short};

/// The body state of `/report`: the honest empty/quiet states, or the populated diff. The
/// component renders exactly one of these — the view-model decides which from the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportBody {
    /// No breach decision in the durable journal at all — the honest "no decisions yet"
    /// state. Carries the human window span for the explanatory sentence.
    Empty { window: String },
    /// The journal has history, but nothing fell in this window — suggest widening it.
    OutOfWindow { window: String },
    /// The populated would-have-acted diff: the headline counts + both tables' rows.
    Diff(ReportDiff),
}

/// The populated would-have-acted diff (JEF-143): the headline counts and the two tables'
/// rows, all pre-shaped to plain presentation data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportDiff {
    /// The human window span ("7d") the headline frames the diff over.
    pub window: String,
    /// Distinct workloads protector would have isolated.
    pub would_act_count: usize,
    /// Distinct proven-but-cleared paths left alone.
    pub left_alone_count: usize,
    /// Would-acts flagged short-lived (likely FP).
    pub short_lived_count: usize,
    /// Would-acts that fired during an enrichment-coverage gap (scrutinize first).
    pub coverage_gap_count: usize,
    /// The would-act table rows, most-sustained first.
    pub would_act: Vec<WouldActRow>,
    /// The left-alone (trust-evidence) table rows.
    pub left_alone: Vec<LeftAloneRow>,
}

/// How a would-act episode's projected cut lifetime reads — the FP tell made into a CSS
/// tone the component renders. `Open`/`Sustained` are not an FP; `ShortLived` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    /// Still standing (the breach condition is the entry's latest verdict).
    Open,
    /// Lifted within the short-lived threshold — likely false positive.
    ShortLived,
    /// A sustained would-be cut (the real signal).
    Sustained,
}

/// One would-act table row, pre-shaped: the short workload label, the would-cut decision
/// count, the lifetime span + its classification, the coverage-gap flag, and the latest
/// verdict (the model's own words). All text fields render through auto-escaping braces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WouldActRow {
    /// The short workload label (kind prefix dropped) — escaped at render.
    pub entry: String,
    /// How many would-cut decisions fired for this entry in the window.
    pub would_act_decisions: usize,
    /// The human lifetime span ("2h", "60s") for the most-sustained episode.
    pub lifetime: String,
    /// How that lifetime reads (open / short-lived / sustained) — the tone class.
    pub lifetime_kind: Lifetime,
    /// Whether this would-act fired during an enrichment-coverage gap (scrutinize first).
    pub coverage_gap: bool,
    /// The model's latest verdict (its own words) — escaped at render.
    pub last_verdict: String,
}

/// One left-alone table row: a proven path the model cleared. The trust evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftAloneRow {
    /// The short workload label — escaped at render.
    pub entry: String,
    /// The model's clearing verdict (its own words) — escaped at render.
    pub verdict: String,
}

/// The plain-data props for the `/report` page (ADR-0019 view-model). The component turns
/// this into the would-have-acted diff HTML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportProps {
    /// The body state to render (empty / out-of-window / the populated diff).
    pub body: ReportBody,
}

/// Build the `/report` props from the aggregated [`Report`] — the pure mapping from the
/// engine's would-have-acted aggregation to the data the report component renders. Mirrors
/// the old `report_panel` branching exactly so the rendered HTML is byte-stable.
pub fn report_props(report: &Report) -> ReportProps {
    let window = human_span(report.window_secs);
    if report.journal_empty {
        return ReportProps {
            body: ReportBody::Empty { window },
        };
    }
    if report.would_act.is_empty() && report.left_alone.is_empty() {
        return ReportProps {
            body: ReportBody::OutOfWindow { window },
        };
    }
    let would_act = report
        .would_act
        .iter()
        .map(|w| {
            let lifetime_kind = if w.open {
                Lifetime::Open
            } else if w.short_lived {
                Lifetime::ShortLived
            } else {
                Lifetime::Sustained
            };
            WouldActRow {
                entry: short(&w.entry),
                would_act_decisions: w.would_act_decisions,
                lifetime: human_span(w.max_lifetime_secs),
                lifetime_kind,
                coverage_gap: w.coverage_gap,
                last_verdict: w.last_verdict.clone(),
            }
        })
        .collect();
    let left_alone = report
        .left_alone
        .iter()
        .map(|l| LeftAloneRow {
            entry: short(&l.entry),
            verdict: l.verdict.clone(),
        })
        .collect();
    ReportProps {
        body: ReportBody::Diff(ReportDiff {
            window,
            would_act_count: report.would_act_count(),
            left_alone_count: report.left_alone_count(),
            short_lived_count: report.short_lived_count(),
            coverage_gap_count: report.coverage_gap_count(),
            would_act,
            left_alone,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::legacy::{LeftAloneEntry, Report, WouldActEntry};

    fn would(open: bool, short_lived: bool) -> WouldActEntry {
        WouldActEntry {
            entry: "workload/app/Pod/web".into(),
            episodes: 1,
            would_act_decisions: 2,
            max_lifetime_secs: 7200,
            open,
            short_lived,
            coverage_gap: false,
            last_verdict: "exploitable — RCE".into(),
        }
    }

    fn report_with(would_act: Vec<WouldActEntry>, left_alone: Vec<LeftAloneEntry>) -> Report {
        Report {
            window_secs: 7 * 24 * 3600,
            short_lived_secs: 300,
            decisions_in_window: 1,
            journal_empty: false,
            would_act,
            left_alone,
        }
    }

    #[test]
    fn empty_journal_maps_to_the_empty_body() {
        let r = report_with(vec![], vec![]);
        let empty = Report {
            journal_empty: true,
            ..r
        };
        assert_eq!(
            report_props(&empty).body,
            ReportBody::Empty {
                window: "7d".into()
            }
        );
    }

    #[test]
    fn history_but_no_window_decisions_maps_to_out_of_window() {
        let r = report_with(vec![], vec![]);
        assert_eq!(
            report_props(&r).body,
            ReportBody::OutOfWindow {
                window: "7d".into()
            }
        );
    }

    #[test]
    fn would_act_lifetime_kind_follows_open_then_short_lived_then_sustained() {
        let open = report_props(&report_with(vec![would(true, false)], vec![]));
        let short = report_props(&report_with(vec![would(false, true)], vec![]));
        let sustained = report_props(&report_with(vec![would(false, false)], vec![]));
        for (props, want) in [
            (open, Lifetime::Open),
            (short, Lifetime::ShortLived),
            (sustained, Lifetime::Sustained),
        ] {
            let ReportBody::Diff(diff) = props.body else {
                panic!("expected a diff body");
            };
            assert_eq!(diff.would_act[0].lifetime_kind, want);
        }
    }

    #[test]
    fn entry_keys_are_shortened_for_display() {
        let r = report_with(
            vec![would(true, false)],
            vec![LeftAloneEntry {
                entry: "workload/app/Pod/safe".into(),
                verdict: "not exploitable".into(),
            }],
        );
        let ReportBody::Diff(diff) = report_props(&r).body else {
            panic!("expected a diff body");
        };
        assert_eq!(diff.would_act[0].entry, "app/Pod/web");
        assert_eq!(diff.left_alone[0].entry, "app/Pod/safe");
    }
}
