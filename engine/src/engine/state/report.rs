//! The would-have-acted report aggregation (JEF-143): the [`Report`] shape and its
//! [`WouldActEntry`] / [`LeftAloneEntry`] / [`AttackNoCutEntry`] rows, the [`aggregate_report`]
//! fold over the journal's decisions, and [`default_window_report`] — the default-window
//! aggregation the engine's per-pass OTLP mirror reads.
//!
//! **JEF-674 (realigned to the ADR-0034 contract):** classification is keyed on the TYPED
//! cut-choice decision (`Decision::Incident`'s `assessment` + `cuts`), never on the legacy
//! `Decision::Breach` line's verdict PROSE. The Breach timeline is still the cadence backbone
//! (it alone carries the structured [`crate::engine::journal::EnrichmentCoverage`] the
//! coverage-gap classification needs), but at every point on it the would-act question is
//! answered by looking up the typed decision IN EFFECT at that moment
//! ([`incident_state_as_of`]) — `assessment == Attack && !cuts.is_empty()`. A journal that
//! predates ADR-0034 (Breach lines only, no `Incident` lines ever recorded) therefore resolves
//! "no typed state known" everywhere and contributes NOTHING to `would_act`: it replays
//! display-only (via the engine's separate verdict-restore path), never inflating this
//! aggregation's counts.
//!
//! This is data, not markup — it holds no rendering. The aggregation exists SOLELY to back the
//! engine's per-pass OTLP would-have-acted mirror over the default window.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::engine::journal::{
    Decision, DecisionJournal, EnrichmentCoverage, JournalEntry, JournaledCut,
};
use crate::engine::reason::adjudicate::incident::Assessment;

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
    /// How many would-act episodes occurred in the window (consecutive runs of a decisive
    /// `Attack` assessment naming at least one node) — the frequency of the breach condition
    /// recurring.
    pub episodes: usize,
    /// How many breach decisions in the window fell inside a would-act episode for this entry
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
    /// The model's own one-sentence reason for the most recent would-act episode (JEF-674: the
    /// typed [`Decision::Incident`]'s `reason`, never re-derived from the legacy Breach verdict
    /// prose this field used to carry).
    pub last_verdict: String,
    /// The distinct node keys the model chose to contain across this entry's would-act
    /// episodes in the window (JEF-674), sorted + deduped. Would-act classification requires a
    /// non-empty cut set for every episode folded in here, so this is never empty.
    pub contained_nodes: Vec<String>,
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

/// One proven path where the model called a REAL attack (`Assessment::Attack`) but named
/// NOTHING to contain (ADR-0034 D1 — "attack, but no cut warranted" is a VALID decision, not a
/// parse failure or a downgrade). A distinct, honest class: it is neither a would-act (nothing
/// stands ready to isolate) nor a left-alone clear (the model did not clear the path) — JEF-674
/// gives it its own bucket rather than folding it into either and misreporting the shadow diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttackNoCutEntry {
    /// The internet-facing workload key the model called an attack with no cut warranted.
    pub entry: String,
    /// The model's own one-sentence reason.
    pub reason: String,
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
    /// Proven paths the model called a real attack with no cut warranted (JEF-674) — the third
    /// honest class, distinct from both `would_act` and `left_alone`.
    pub attack_no_cut: Vec<AttackNoCutEntry>,
}

impl Report {
    /// The headline would-act count: DISTINCT contained nodes across every standing proposal in
    /// the window (JEF-674) — not distinct entries. One entry's decision can name several nodes
    /// (its own front door plus a downstream workload, ADR-0034 D4), so the true "workloads
    /// that would have been isolated" figure is the union of those node keys, not the row
    /// count.
    pub fn would_act_count(&self) -> usize {
        self.would_act
            .iter()
            .flat_map(|w| w.contained_nodes.iter())
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// The headline left-alone count: distinct proven-but-cleared paths.
    pub fn left_alone_count(&self) -> usize {
        self.left_alone.len()
    }

    /// The headline attack-no-cut count: distinct paths the model called a real attack with no
    /// cut warranted (JEF-674) — the third honest class.
    pub fn attack_no_cut_count(&self) -> usize {
        self.attack_no_cut.len()
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

/// One [`Decision::Incident`] line reduced to what the would-act classification needs: WHEN it
/// was recorded, the 3-value call, the nodes it named, and the model's one-sentence reason.
type IncidentPoint<'a> = (u64, &'a Assessment, &'a [JournaledCut], &'a str);

/// The typed cut-choice decision in effect for an entry at `at_ms` — the LATEST
/// [`Decision::Incident`] line recorded at or before that time. `None` when no `Incident` line
/// has EVER been recorded for this entry by `at_ms`: a pre-ADR-0034 journal, or an entry only
/// the legacy path ever judged — so the caller can tell "no typed state" apart from every one
/// of the three real assessments (JEF-674: never invent a positive from missing data).
fn incident_state_as_of<'a>(
    timeline: &[IncidentPoint<'a>],
    at_ms: u64,
) -> Option<(&'a Assessment, &'a [JournaledCut], &'a str)> {
    timeline
        .iter()
        .filter(|(t, ..)| *t <= at_ms)
        .max_by_key(|(t, ..)| *t)
        .map(|&(_, assessment, cuts, reason)| (assessment, cuts, reason))
}

/// Aggregate the journal's decisions into the would-have-acted diff (JEF-143, realigned to the
/// typed contract by JEF-674). Pure and total: takes the replayed entries (any order — they are
/// sorted here by time) and the wall-clock `now` (injected for testability), and folds each
/// entry's breach decisions into would-act / attack-no-cut / left-alone, classified by the typed
/// [`Decision::Incident`] in effect at each point — never by verdict prose. Read-only.
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

    // Collect breach decisions per entry, in time order, restricted to the window — the cadence
    // backbone this aggregation still walks (it alone carries the structured
    // enrichment-coverage the coverage-gap classification needs). BTreeMap keeps the output
    // stable (entry-keyed) before the final sustained-first sort.
    type Breach<'a> = (u64, &'a str, Option<&'a EnrichmentCoverage>); // (at_ms, verdict, coverage)
    let mut by_entry: BTreeMap<&str, Vec<Breach>> = BTreeMap::new();
    let mut sorted: Vec<&JournalEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| e.at_ms);
    let mut decisions_in_window = 0usize;
    for e in &sorted {
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
                    verdict.as_str(),
                    coverage.as_ref(),
                ));
                decisions_in_window += 1;
            }
        }
    }

    // The typed cut-choice timeline (ADR-0034 D8), per entry, deliberately UNWINDOWED: a Breach
    // decision at the window's leading edge still needs to resolve "what was the model's typed
    // call at this point", which may have been recorded before the window opened.
    let mut incidents_by_entry: BTreeMap<&str, Vec<IncidentPoint>> = BTreeMap::new();
    for e in &sorted {
        if let Decision::Incident {
            entry,
            assessment,
            cuts,
            reason,
            ..
        } = &e.decision
        {
            incidents_by_entry.entry(entry.as_str()).or_default().push((
                e.at_ms,
                assessment,
                cuts.as_slice(),
                reason.as_str(),
            ));
        }
    }
    let empty_timeline: Vec<IncidentPoint> = Vec::new();

    let mut would_act: Vec<WouldActEntry> = Vec::new();
    let mut left_alone: Vec<LeftAloneEntry> = Vec::new();
    let mut attack_no_cut: Vec<AttackNoCutEntry> = Vec::new();

    for (entry, decisions) in by_entry {
        let timeline = incidents_by_entry.get(entry).unwrap_or(&empty_timeline);

        // Walk the entry's window decisions, folding consecutive would-act moments into
        // episodes. A moment is would-act when the typed decision IN EFFECT at that Breach
        // line's timestamp is a decisive `Attack` naming at least one node (JEF-674) — never
        // the Breach line's own verdict prose. An episode's lifetime runs from its first
        // would-act moment to the first non-would-act one that follows (the clear) — or to
        // `now` if it never cleared (still open).
        let mut episodes = 0usize;
        let mut would_act_decisions = 0usize;
        let mut max_lifetime_ms = 0u64;
        let mut max_open = false;
        let mut coverage_gap = false;
        let mut last_reason: Option<&str> = None;
        let mut contained_nodes: BTreeSet<String> = BTreeSet::new();

        let mut i = 0usize;
        while i < decisions.len() {
            let start_ms = decisions[i].0;
            // Consume the run of consecutive would-act decisions starting at `i`. The loop's own
            // FIRST iteration (`j == i`) is what decides whether an episode begins at all — no
            // separate pre-check duplicating this same lookup at `start_ms`.
            let mut j = i;
            let mut episode_gap = false;
            while j < decisions.len() {
                let at = decisions[j].0;
                let Some((Assessment::Attack, cuts, reason)) = incident_state_as_of(timeline, at)
                else {
                    break;
                };
                if cuts.is_empty() {
                    break;
                }
                would_act_decisions += 1;
                if is_coverage_gap(decisions[j].2) {
                    episode_gap = true;
                }
                last_reason = Some(reason);
                contained_nodes.extend(cuts.iter().map(|c| c.node.clone()));
                j += 1;
            }
            if j == i {
                // No would-act moment at `start_ms` — not the start of an episode.
                i += 1;
                continue;
            }
            episodes += 1;
            // The episode closes at the next (non-would-act) decision if there is one,
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
                last_verdict: last_reason.unwrap_or_default().to_string(),
                contained_nodes: contained_nodes.into_iter().collect(),
            });
        } else if let Some(&(last_at, last_verdict, _)) = decisions.last() {
            // No would-act episode in the window. Resolve the entry's LATEST typed state
            // (JEF-674): a decisive attack with no cut warranted is its own honest class,
            // never folded into the calm "cleared" tail; everything else — a real clear, an
            // uncertain call, or no typed state at all (a pre-ADR-0034 line, display-only) —
            // reads as left-alone using the Breach line's own verdict text, exactly as before.
            match incident_state_as_of(timeline, last_at) {
                Some((Assessment::Attack, [], reason)) => {
                    attack_no_cut.push(AttackNoCutEntry {
                        entry: entry.to_string(),
                        reason: reason.to_string(),
                    });
                }
                _ => {
                    left_alone.push(LeftAloneEntry {
                        entry: entry.to_string(),
                        verdict: last_verdict.to_string(),
                    });
                }
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
    attack_no_cut.sort_by(|a, b| a.entry.cmp(&b.entry));

    Report {
        window_secs: window.as_secs(),
        short_lived_secs: short_lived.as_secs(),
        decisions_in_window,
        journal_empty: !any_breach,
        would_act,
        left_alone,
        attack_no_cut,
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
#[path = "report_tests.rs"]
mod tests;
