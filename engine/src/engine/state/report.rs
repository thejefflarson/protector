//! The would-have-acted report aggregation (JEF-143): the [`Report`] shape and its
//! [`WouldActEntry`] / [`LeftAloneEntry`] rows, the [`aggregate_report`] fold over the journal's
//! breach decisions, and [`default_window_report`] — the default-window aggregation the engine's
//! per-pass OTLP mirror reads.
//!
//! This is data, not markup — it holds no rendering. The aggregation exists SOLELY to back the
//! engine's per-pass OTLP would-have-acted mirror over the default window.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::engine::journal::{Decision, DecisionJournal, EnrichmentCoverage, JournalEntry};

/// Default rolling window for the OTLP would-have-acted mirror, in hours (7 days). The
/// journal's own rotation bounds how far back history actually reaches.
pub(crate) const DEFAULT_WINDOW_HOURS: u64 = 24 * 7;

/// A would-be cut lifted within this long is **short-lived** — the likely-false-positive
/// signature (a transient breach condition that cleared in minutes). A sustained would-act (at
/// or above this) is the one worth a real cut. Five minutes is the conservative default.
pub(crate) const DEFAULT_SHORT_LIVED_SECS: u64 = 5 * 60;

/// One workload the engine WOULD have isolated in the window: the entry, how often
/// the breach condition held, the projected would-be cut lifetime, and the FP-vs-real
/// classification. JSON-serializable so the aggregation is self-contained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WouldActEntry {
    /// The internet-facing workload key that reached the exploitable verdict.
    pub entry: String,
    /// How many would-act episodes occurred in the window (consecutive runs of
    /// exploitable verdicts) — the frequency of the breach condition recurring.
    pub episodes: usize,
    /// How many breach decisions in the window affirmed exploitability for this entry
    /// (the raw "would-cut" frequency, ≥ `episodes`).
    pub would_act_decisions: usize,
    /// The longest projected would-be cut lifetime across this entry's episodes, in
    /// seconds — how long the cut would have stood at its most sustained.
    pub max_lifetime_secs: u64,
    /// Whether the longest episode is still OPEN (the breach condition is the entry's
    /// latest verdict in the window — the cut would still be standing now).
    pub open: bool,
    /// Short-lived (lifted within the threshold) ⇒ likely false positive. `false`
    /// when sustained. An open episode is never short-lived (it's still standing).
    pub short_lived: bool,
    /// At least one would-act episode fired during an enrichment-coverage gap — the
    /// model affirmed exploitability WITHOUT a CVE backing it. These are the would-acts
    /// to scrutinize first.
    pub coverage_gap: bool,
    /// The model's verdict for the most recent would-act episode (its own words) — the
    /// human-readable "why it would have cut".
    pub last_verdict: String,
}

/// One proven path the model deliberately CLEARED in the window — the entry's latest
/// breach decision affirmed it is NOT exploitable. The trust half of the diff: a
/// reachable path protector proved out and left alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeftAloneEntry {
    /// The internet-facing workload key whose latest verdict cleared it.
    pub entry: String,
    /// The model's clearing verdict (its own words — "not exploitable — …").
    pub verdict: String,
}

/// The aggregated shadow report (JEF-143): the would-have-acted diff over a rolling
/// window. JSON-serializable; the engine mirrors its headline counts to OTLP per pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The window length aggregated over, in seconds.
    pub window_secs: u64,
    /// The short-lived threshold applied, in seconds.
    pub short_lived_secs: u64,
    /// How many breach decisions fell within the window (the raw material).
    pub decisions_in_window: usize,
    /// Whether the journal had NO breach decisions at all (durable history is empty) —
    /// drives the honest "no decisions yet" state, distinct from "decisions, but none
    /// in this window".
    pub journal_empty: bool,
    /// Workloads the engine would have isolated, most-sustained first.
    pub would_act: Vec<WouldActEntry>,
    /// Proven paths the model cleared and left alone, the trust evidence.
    pub left_alone: Vec<LeftAloneEntry>,
}

impl Report {
    /// The headline would-act count: distinct workloads that would have been cut.
    pub fn would_act_count(&self) -> usize {
        self.would_act.len()
    }

    /// The headline left-alone count: distinct proven-but-cleared paths.
    pub fn left_alone_count(&self) -> usize {
        self.left_alone.len()
    }

    /// Would-acts flagged short-lived (the likely-FP subset).
    pub fn short_lived_count(&self) -> usize {
        self.would_act.iter().filter(|w| w.short_lived).count()
    }

    /// Would-acts that fired during an enrichment-coverage gap (scrutinize first).
    pub fn coverage_gap_count(&self) -> usize {
        self.would_act.iter().filter(|w| w.coverage_gap).count()
    }
}

/// A model verdict AFFIRMS exploitability when its own words begin with "exploitable"
/// (or "confirmed" — an already-corroborated live attack that should stand). A "not
/// exploitable — …" / "refuted" / "uncertain" verdict does not. This mirrors the
/// posture convention so the aggregation and the findings snapshot agree on what counts
/// as a would-act.
pub(crate) fn verdict_would_act(verdict: &str) -> bool {
    let v = verdict.trim_start().to_ascii_lowercase();
    v.starts_with("exploitable") || v.starts_with("confirmed")
}

/// A would-act decision fired during an enrichment-coverage gap when the model had NO
/// real enrichment to weigh: no CVE evidence AND no behavioral signal (JEF-145). The
/// classification reads the breach line's STRUCTURED [`EnrichmentCoverage`] — the same
/// evidence the model was given at decision time — never the verdict prose. A prose
/// mention of a CVE no longer reads as covered, and a well-enriched verdict that happens
/// not to print a CVE id no longer reads as a gap.
///
/// Back-compat (AC #3): a pre-JEF-145 line has no structured coverage (`None`). That is
/// "unknown", deliberately NOT a gap — an old record never inflates the scrutinize-first
/// count with a false positive.
pub(crate) fn is_coverage_gap(coverage: Option<&EnrichmentCoverage>) -> bool {
    match coverage {
        Some(c) => !c.is_backed(),
        None => false,
    }
}

/// Aggregate the journal's breach decisions into the would-have-acted diff (JEF-143).
/// Pure and total: takes the replayed entries (any order — they are sorted here by
/// time) and the wall-clock `now` (injected for testability), and folds each entry's
/// breach decisions into would-act episodes vs. left-alone clears. Read-only.
pub(crate) fn aggregate_report(
    entries: &[JournalEntry],
    now: SystemTime,
    window: Duration,
    short_lived: Duration,
) -> Report {
    let window_start = now.checked_sub(window).unwrap_or(SystemTime::UNIX_EPOCH);
    let window_start_ms = window_start
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let now_ms = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Did the journal hold ANY breach decision at all? (Distinguishes a truly empty
    // journal from one with history but nothing in this particular window.)
    let mut any_breach = false;

    // Collect breach decisions per entry, in time order, restricted to the window.
    // BTreeMap keeps the output stable (entry-keyed) before the final sustained-first sort.
    // Each breach carries its structured enrichment-coverage (JEF-145) so the gap is
    // classified from the model's actual evidence, not the verdict prose.
    type Breach<'a> = (u64, &'a str, Option<&'a EnrichmentCoverage>); // (at_ms, verdict, coverage)
    let mut by_entry: BTreeMap<&str, Vec<Breach>> = BTreeMap::new();
    let mut sorted: Vec<&JournalEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| e.at_ms);
    let mut decisions_in_window = 0usize;
    for e in sorted {
        if let Decision::Breach {
            entry,
            verdict,
            coverage,
            ..
        } = &e.decision
        {
            any_breach = true;
            if e.at_ms >= window_start_ms {
                by_entry.entry(entry.as_str()).or_default().push((
                    e.at_ms,
                    verdict,
                    coverage.as_ref(),
                ));
                decisions_in_window += 1;
            }
        }
    }

    let mut would_act: Vec<WouldActEntry> = Vec::new();
    let mut left_alone: Vec<LeftAloneEntry> = Vec::new();

    for (entry, decisions) in by_entry {
        // Walk the entry's window decisions, folding consecutive exploitable verdicts
        // into episodes. An episode's lifetime runs from its first exploitable verdict
        // to the first NON-exploitable verdict that follows (the clear) — or to `now`
        // if it never cleared (still open). The closing decision's timestamp is the
        // best evidence of when the breach condition lifted in the journal.
        let mut episodes = 0usize;
        let mut would_act_decisions = 0usize;
        let mut max_lifetime_ms = 0u64;
        let mut max_open = false;
        let mut coverage_gap = false;
        let mut last_would_act_verdict: Option<&str> = None;

        let mut i = 0usize;
        while i < decisions.len() {
            let (start_ms, verdict, _) = decisions[i];
            if !verdict_would_act(verdict) {
                i += 1;
                continue;
            }
            // Start of an episode: consume the run of consecutive exploitable verdicts.
            episodes += 1;
            let mut j = i;
            let mut episode_gap = false;
            while j < decisions.len() && verdict_would_act(decisions[j].1) {
                would_act_decisions += 1;
                if is_coverage_gap(decisions[j].2) {
                    episode_gap = true;
                }
                last_would_act_verdict = Some(decisions[j].1);
                j += 1;
            }
            // The episode closes at the next (non-exploitable) decision if there is one,
            // else it's still open and projected to `now`.
            let (end_ms, open) = if j < decisions.len() {
                (decisions[j].0, false)
            } else {
                (now_ms, true)
            };
            let lifetime_ms = end_ms.saturating_sub(start_ms);
            if open {
                // An open episode is the most-sustained by definition (still standing);
                // prefer it, and never mark it short-lived.
                if !max_open || lifetime_ms > max_lifetime_ms {
                    max_lifetime_ms = lifetime_ms;
                }
                max_open = true;
            } else if !max_open && lifetime_ms > max_lifetime_ms {
                max_lifetime_ms = lifetime_ms;
            }
            coverage_gap |= episode_gap;
            i = j;
        }

        if episodes > 0 {
            let short = !max_open && max_lifetime_ms < short_lived.as_millis() as u64;
            would_act.push(WouldActEntry {
                entry: entry.to_string(),
                episodes,
                would_act_decisions,
                max_lifetime_secs: max_lifetime_ms / 1000,
                open: max_open,
                short_lived: short,
                coverage_gap,
                last_verdict: last_would_act_verdict.unwrap_or_default().to_string(),
            });
        } else {
            // No would-act episode in the window: the entry's paths were all proven and
            // CLEARED. The trust half — surface the latest (clearing) verdict.
            if let Some((_, verdict, _)) = decisions.last() {
                left_alone.push(LeftAloneEntry {
                    entry: entry.to_string(),
                    verdict: verdict.to_string(),
                });
            }
        }
    }

    // Most-sustained first: open episodes, then by lifetime descending, then by entry
    // for a stable order.
    would_act.sort_by(|a, b| {
        b.open
            .cmp(&a.open)
            .then(b.max_lifetime_secs.cmp(&a.max_lifetime_secs))
            .then(a.entry.cmp(&b.entry))
    });
    left_alone.sort_by(|a, b| a.entry.cmp(&b.entry));

    Report {
        window_secs: window.as_secs(),
        short_lived_secs: short_lived.as_secs(),
        decisions_in_window,
        journal_empty: !any_breach,
        would_act,
        left_alone,
    }
}

/// Aggregate the would-have-acted report over the DEFAULT window from a journal handle
/// (JEF-143), for the engine to mirror its headline counts to OTLP per pass — the in-process
/// metrics mirror like the bake counts. A disabled journal replays nothing, so this is an empty
/// report (all-zero headline). This aggregation exists solely to feed the OTLP mirror in
/// `engine::mod`.
pub fn default_window_report(journal: &DecisionJournal) -> Report {
    aggregate_report(
        &journal.replay(),
        SystemTime::now(),
        Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
        Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breach(at_ms: u64, entry: &str, verdict: &str) -> JournalEntry {
        JournalEntry {
            at_ms,
            decision: Decision::Breach {
                entry: entry.to_string(),
                objectives: 1,
                verdict: verdict.to_string(),
                coverage: None,
                fingerprint: None,
                verdict_typed: None,
            },
        }
    }

    #[test]
    fn verdict_would_act_keys_on_affirmative_prefix() {
        assert!(verdict_would_act("exploitable — CVE reachable"));
        assert!(verdict_would_act("confirmed live attack"));
        assert!(verdict_would_act("  Exploitable"));
        assert!(!verdict_would_act("not exploitable — internal only"));
        assert!(!verdict_would_act("refuted"));
        assert!(!verdict_would_act("uncertain — model timed out"));
    }

    #[test]
    fn aggregate_folds_an_open_would_act_episode() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let now_ms = 10_000_000;
        let entries = vec![
            breach(now_ms - 600_000, "web", "exploitable — RCE"),
            breach(now_ms - 300_000, "web", "exploitable — RCE"),
        ];
        let report = aggregate_report(
            &entries,
            now,
            Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
            Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
        );
        assert_eq!(report.would_act_count(), 1);
        assert_eq!(report.left_alone_count(), 0);
        let w = &report.would_act[0];
        assert_eq!(w.entry, "web");
        assert!(w.open, "still the latest verdict → open episode");
        assert!(!w.short_lived, "an open episode is never short-lived");
        assert_eq!(w.episodes, 1);
        assert_eq!(w.would_act_decisions, 2);
    }

    #[test]
    fn aggregate_classifies_a_cleared_path_as_left_alone() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let now_ms = 10_000_000;
        let entries = vec![breach(
            now_ms - 60_000,
            "api",
            "not exploitable — internal only",
        )];
        let report = aggregate_report(
            &entries,
            now,
            Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
            Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
        );
        assert_eq!(report.would_act_count(), 0);
        assert_eq!(report.left_alone_count(), 1);
        assert_eq!(report.left_alone[0].entry, "api");
    }

    #[test]
    fn aggregate_marks_a_short_lived_episode() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let now_ms = 10_000_000;
        // An episode that opened then cleared within a minute (< the 5-minute threshold).
        let entries = vec![
            breach(now_ms - 120_000, "web", "exploitable — RCE"),
            breach(now_ms - 90_000, "web", "not exploitable — patched"),
        ];
        let report = aggregate_report(
            &entries,
            now,
            Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
            Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
        );
        assert_eq!(report.would_act_count(), 1);
        assert!(report.would_act[0].short_lived);
        assert_eq!(report.short_lived_count(), 1);
    }

    #[test]
    fn empty_journal_reports_journal_empty() {
        let report = aggregate_report(
            &[],
            SystemTime::UNIX_EPOCH + Duration::from_secs(10_000),
            Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
            Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
        );
        assert!(report.journal_empty);
        assert_eq!(report.decisions_in_window, 0);
    }
}
