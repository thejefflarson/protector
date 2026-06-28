//! The report DATA layer (ADR-0019): the would-have-acted [`Report`] aggregation and its
//! shapes ([`WouldActEntry`] / [`LeftAloneEntry`]), the [`ReportQuery`] window parsing, and
//! the [`aggregate_report`] fold over the journal's breach decisions.
//!
//! This is data, not markup — it holds NO rendering. `/report.json` serializes [`Report`]
//! directly, and `view_model::report` shapes the same aggregation into the `Props` the
//! `components::report` renderer consumes.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::engine::journal::{Decision, EnrichmentCoverage, JournalEntry};

/// Default rolling window for `/report`, in hours (7 days). The journal's own
/// rotation bounds how far back history actually reaches; this is the default the
/// view aggregates over when `?hours=`/`?days=` isn't supplied. Configurable per
/// request, never narrower than the journal — a window wider than the on-disk
/// history simply yields everything that survived rotation.
pub(crate) const DEFAULT_WINDOW_HOURS: u64 = 24 * 7;

/// A would-be cut lifted within this long is **short-lived** — the likely-false-
/// positive signature (a transient breach condition that cleared in minutes, e.g. a
/// scanner blip or a pod that restarted clean). A sustained would-act (at or above
/// this) is the one worth a real cut. The ticket frames "lifted within minutes" as
/// the FP tell; five minutes is the conservative default, configurable via
/// `?short_lived_secs=`.
pub(crate) const DEFAULT_SHORT_LIVED_SECS: u64 = 5 * 60;

/// Query parameters for `/report` (and `/report.json`): the rolling window and the
/// short-lived threshold, all optional with sane defaults. `days` is sugar for
/// `hours`; if both are given, `hours` wins (the finer unit).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReportQuery {
    /// Window length in hours. Defaults to [`DEFAULT_WINDOW_HOURS`].
    pub hours: Option<u64>,
    /// Window length in days (sugar for `hours`). Ignored when `hours` is set.
    pub days: Option<u64>,
    /// Short-lived threshold in seconds. Defaults to [`DEFAULT_SHORT_LIVED_SECS`].
    pub short_lived_secs: Option<u64>,
}

impl ReportQuery {
    /// The resolved window length, falling back through `hours` → `days` → default.
    pub(crate) fn window(&self) -> Duration {
        let hours = self
            .hours
            .or(self.days.map(|d| d.saturating_mul(24)))
            .unwrap_or(DEFAULT_WINDOW_HOURS);
        Duration::from_secs(hours.saturating_mul(3600))
    }

    /// The resolved short-lived threshold.
    pub(crate) fn short_lived(&self) -> Duration {
        Duration::from_secs(self.short_lived_secs.unwrap_or(DEFAULT_SHORT_LIVED_SECS))
    }
}

/// One workload the engine WOULD have isolated in the window: the entry, how often
/// the breach condition held, the projected would-be cut lifetime, and the FP-vs-real
/// classification. JSON-serializable so `/report.json` is self-contained.
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
/// window. JSON-serializable for `/report.json`; the HTML view renders the same data.
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
/// dashboard's [`flagged`] convention so the report and the findings table agree on
/// what counts as a would-act.
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

/// Render a `Duration`-in-seconds as a compact human span ("4m", "2h", "3d") for the
/// would-be cut lifetime column. Sub-minute spans read as seconds (the short-lived
/// tell).
pub(crate) fn human_span(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

// The `/report` and `/judgements` HTML renders moved to the maud `components::report` /
// `components::judgements` layer, fed by the `view_model::report` / `view_model::judgements`
// data layer (JEF-207). The aggregation ([`aggregate_report`], [`Report`], [`human_span`])
// and the [`Judgement`] / [`Posture`] shapes stay here — the data layer the JSON contracts
// and the view-model both read.

// ===========================================================================
// The readiness / coverage panel (JEF-160)
// ===========================================================================
//
// When the model, KEV file, Falco feed, eBPF agent, or journal volume is
// unconfigured or down, protector degrades SILENTLY — a cluster with no model renders the
// same "quiet" empty page as a genuinely clean one (ADR-0016: enrichment coverage is
// load-bearing). This panel lists each enrichment/decision input and its LIVE state, so
// the operator can tell "all clear" from "blind", and a new operator gets a guided start.
// Read-only, zero-egress: presence/health only — no secret names, no graph data, no values.
