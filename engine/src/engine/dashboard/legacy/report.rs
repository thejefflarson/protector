//! Transitional legacy module (pre-ADR-0019 string-concat rendering).
//!
//! Migrated piecemeal in tickets 3–6; extracted here only so each file
//! stays under the 1,000-line cap (repo CLAUDE.md). New work goes in the
//! `components`/`view_model` maud layers, not here.
#![allow(dead_code)]

use super::*;

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
    /// model affirmed exploitability WITHOUT a CVE backing it (no advisory enrichment
    /// matched). These are the would-acts to scrutinize first.
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

/// The `/report` HTML body: the would-have-acted diff (JEF-143). Empty journal ⇒ an
/// honest "no decisions yet" state. Otherwise the headline diff sentence, the would-act
/// table (short-lived visually distinct, coverage-gap flagged), and the left-alone
/// trust evidence.
pub(crate) fn report_panel(report: &Report) -> String {
    let window = human_span(report.window_secs);
    if report.journal_empty {
        return format!(
            "<p class=\"muted\">no decisions yet — the decision journal is empty (no pass has \
             recorded a breach decision, or no durable journal volume is configured). Once the \
             engine judges an internet-facing workload, this report fills in over the last \
             {window}.</p>"
        );
    }
    if report.would_act.is_empty() && report.left_alone.is_empty() {
        return format!(
            "<p class=\"muted\">no breach decisions in the last {window} (the journal has older \
             history — widen the window with <code>?days=N</code>).</p>"
        );
    }

    // The diff headline: would-isolate N, left M proven-but-cleared paths alone.
    let head = format!(
        "<div class=\"sum\">over the last <b>{window}</b> protector would have isolated \
         <b>{act}</b> workload{act_s} and deliberately left <b>{left}</b> proven-but-cleared \
         path{left_s} alone. {short} short-lived (likely FP) · {gap} with thin evidence \
         coverage (scrutinize first).</div>",
        act = report.would_act_count(),
        act_s = if report.would_act_count() == 1 {
            ""
        } else {
            "s"
        },
        left = report.left_alone_count(),
        left_s = if report.left_alone_count() == 1 {
            ""
        } else {
            "s"
        },
        short = report.short_lived_count(),
        gap = report.coverage_gap_count(),
    );

    let would_rows: String = if report.would_act.is_empty() {
        "<tr><td class=\"muted\" colspan=\"5\">none — every proven path was cleared</td></tr>"
            .to_string()
    } else {
        report
            .would_act
            .iter()
            .map(|w| {
                // Lifetime: sustained vs short-lived is the FP tell, made visually distinct.
                let life = if w.open {
                    format!(
                        "<span class=\"sustained\">{} (open)</span>",
                        human_span(w.max_lifetime_secs)
                    )
                } else if w.short_lived {
                    format!(
                        "<span class=\"shortlived\">{} (short-lived)</span>",
                        human_span(w.max_lifetime_secs)
                    )
                } else {
                    format!(
                        "<span class=\"sustained\">{}</span>",
                        human_span(w.max_lifetime_secs)
                    )
                };
                let gap = if w.coverage_gap {
                    "<span class=\"flagged\">coverage gap</span>".to_string()
                } else {
                    "<span class=\"muted\">—</span>".to_string()
                };
                format!(
                    "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td>\
                     <td class=\"verdict-cell\">{}</td></tr>",
                    escape(&short(&w.entry)),
                    w.would_act_decisions,
                    life,
                    gap,
                    escape(&w.last_verdict),
                )
            })
            .collect()
    };

    let left_rows: String = if report.left_alone.is_empty() {
        "<tr><td class=\"muted\" colspan=\"2\">none</td></tr>".to_string()
    } else {
        report
            .left_alone
            .iter()
            .map(|l| {
                format!(
                    "<tr><td><code>{}</code></td><td class=\"verdict-cell\">{}</td></tr>",
                    escape(&short(&l.entry)),
                    escape(&l.verdict),
                )
            })
            .collect()
    };

    format!(
        "{head}\
         <h3>Would have isolated <span class=\"muted\">({act})</span></h3>\
         <table class=\"vectors\"><thead><tr><th>Workload</th><th>Would-cut decisions</th>\
         <th>Projected cut lifetime</th><th>Evidence coverage</th><th>Latest verdict</th></tr></thead>\
         <tbody>{would_rows}</tbody></table>\
         <h3>Left alone <span class=\"muted\">({left}) — proven, then cleared</span></h3>\
         <table class=\"vectors\"><thead><tr><th>Workload</th><th>Clearing verdict</th></tr></thead>\
         <tbody>{left_rows}</tbody></table>",
        act = report.would_act_count(),
        left = report.left_alone_count(),
    )
}

/// The full `/report` HTML page (JEF-143): a self-contained page wrapping
/// [`report_panel`], styled in the dashboard's idiom. No graph renderer needed (no
/// Mermaid), so the page is plain HTML — the would-have-acted diff that gates exiting
/// shadow (JEF-50).
pub(crate) fn render_report_html(report: &Report) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>protector — would-have-acted report</title>\
         <link rel=\"stylesheet\" href=\"/assets/dashboard.css\">\
         </head><body>\
         <h1>protector — would-have-acted report</h1>\
         <p class=\"sum\">The shadow diff that gates exiting shadow: over a rolling \
         window, the workloads protector <b>would</b> have isolated, how often the breach \
         condition held, the projected cut lifetime (short-lived = likely false positive), and \
         the proven paths the model deliberately <b>left alone</b> — the trust evidence. \
         Read-only; no action. Tune the window with <code>?days=N</code> or <code>?hours=N</code> \
         and the short-lived threshold with <code>?short_lived_secs=N</code>. \
         &nbsp;|&nbsp; <a href=\"/\">dashboard</a> &nbsp;|&nbsp; <a href=\"/report.json\">json</a></p>\
         <h2>Shadow would-have-acted diff</h2>\
         {body}\
         </body></html>",
        body = report_panel(report),
    )
}

// ===========================================================================
// The human "why" view for /judgements (JEF-161)
// ===========================================================================
//
// `/judgements` was JSON-only — an operator hitting it got a wall of escaped prompt
// text. This adds a human HTML view (mirroring how `/report` is wired) that leads with
// the posture chip + the model's prose, surfaces the three honest meta-states, and tucks
// the raw prompt+reply behind a `<details>` expander. The prompt is the injection surface
// (JEF-106); operators read the verdict, not the prompt. The JSON moves to
// `/judgements.json` (the route is documented in [`serve_dashboard`]).

/// One `/judgements` card (JEF-161): the posture chip + the model's prose, then the
/// three meta-states surfaced honestly, with the raw prompt+reply behind an expander.
pub(crate) fn judgement_card(j: &Judgement) -> String {
    // The posture from the final verdict (Debug form, e.g. `Exploitable("…")`). `flagged`
    // lowercases, so the capitalized Debug variant still maps correctly.
    let posture = Posture::of(Some(&j.verdict));
    let chip = format!(
        "<span class=\"chip {}\">{}</span>",
        posture.tone(),
        posture.label()
    );

    // The three honest meta-states (JEF-161 AC #3):
    //   prompt: None  → the deterministic pre-filter decided without the model (JEF-112).
    //   reply:  None  → the model timed out; the engine fell back to a safe verdict.
    //   normal        → the model answered; show its prose verdict.
    let lead = if j.prompt.is_none() {
        "<span class=\"meta\">decided without the model (pre-filter)</span>".to_string()
    } else if j.reply.is_none() {
        "<span class=\"meta\">model timed out — safe fallback</span>".to_string()
    } else {
        format!("<span class=\"vwords\">{}</span>", escape(&j.verdict))
    };

    // The raw prompt+reply behind a power-user expander — the injection surface stays a
    // diagnostic, not something operators are asked to grade (JEF-106).
    let raw = format!(
        "<details class=\"raw\"><summary>show full prompt</summary>\
         <div class=\"raw-cap\">prompt sent to the model</div><pre>{}</pre>\
         <div class=\"raw-cap\">raw model reply</div><pre>{}</pre></details>",
        escape(j.prompt.as_deref().unwrap_or("(none — pre-filter decided)")),
        escape(j.reply.as_deref().unwrap_or("(none — model timed out)")),
    );

    format!(
        "<div class=\"card\"><div class=\"vline\">{chip} {lead}</div>\
         <div class=\"kc2\"><code>{}</code> <span class=\"muted\">· {} target{} it can reach weighed</span></div>\
         {raw}</div>",
        escape(&short(&j.entry)),
        j.objectives,
        if j.objectives == 1 { "" } else { "s" },
    )
}

/// The full `/judgements` HTML page (JEF-161): the human "why" view — one card per recent
/// judgement, led by the posture chip + the model's prose, the three meta-states surfaced,
/// the raw prompt behind an expander. Self-contained, styled in the dashboard's idiom. The
/// machine-readable form stays at `/judgements.json`.
pub(crate) fn render_judgements_html(judgements: &[Judgement]) -> String {
    let body = if judgements.is_empty() {
        "<p class=\"muted\">no model judgements yet (the model hasn't reached an \
         internet-facing service — a slow CPU model takes a few passes after a restart)</p>"
            .to_string()
    } else {
        judgements.iter().map(judgement_card).collect()
    };
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>protector — judgements</title>\
         <link rel=\"stylesheet\" href=\"/assets/dashboard.css\">\
         </head><body>\
         <h1>protector — judgements</h1>\
         <p class=\"sum\">Why the model called each internet-facing service the way it did — \
         the posture and the model's own words first. The raw prompt+reply is behind \
         <i>show full prompt</i> (a power-user diagnostic; the prompt is the part an attacker \
         could try to poison). &nbsp;|&nbsp; <a href=\"/\">dashboard</a> &nbsp;|&nbsp; \
         <a href=\"/judgements.json\">json</a></p>\
         <h2>Recent judgements <span class=\"muted\">({n})</span></h2>\
         {body}\
         </body></html>",
        n = judgements.len(),
    )
}

// ===========================================================================
// The readiness / coverage panel (JEF-160)
// ===========================================================================
//
// When the model, KEV/advisory file, Falco feed, eBPF agent, or journal volume is
// unconfigured or down, protector degrades SILENTLY — a cluster with no model renders the
// same "quiet" empty page as a genuinely clean one (ADR-0016: enrichment coverage is
// load-bearing). This panel lists each enrichment/decision input and its LIVE state, so
// the operator can tell "all clear" from "blind", and a new operator gets a guided start.
// Read-only, zero-egress: presence/health only — no secret names, no graph data, no values.
