//! Transitional legacy module (pre-ADR-0019 string-concat rendering).
//!
//! Migrated piecemeal in tickets 3–6; extracted here only so each file
//! stays under the 1,000-line cap (repo CLAUDE.md). New work goes in the
//! `components`/`view_model` maud layers, not here.
#![allow(dead_code)]

use super::*;

/// The expandable card BODY for one endpoint (JEF-202) — TODAY's full finding card,
/// UNCHANGED (the verbatim verdict prose, the certainty rail, both ADR-0016 evidence
/// blocks, the Mermaid graph, the disposition "what to do", and the fan-out expanders). It
/// is the EXPAND TARGET of the dense findings table's row; the at-a-glance cells live in the
/// summary row ([`endpoint_row`]). The graph stays collapsed-by-default even for a flagged
/// entry (open on demand) — the whole body is already one click behind the row.
pub(crate) fn endpoint_card_body(entry: &str, fs: &[&Finding]) -> (String, RowMeta) {
    let mut m = Mermaid::default();
    m.add_internet(entry);
    let mut seen_intermediate: BTreeSet<String> = BTreeSet::new();
    // Terminal fan-out grouped by (from-node, relation, objective-kind) → the
    // objective keys in that group. One group → one node (or aggregate).
    let mut groups: BTreeMap<(String, String, String), Vec<String>> = BTreeMap::new();
    let mut objectives = 0usize;

    for f in fs {
        for step in &f.path {
            if step.to == f.objective {
                objectives += 1;
                let kind = kind(&step.to).to_string();
                groups
                    .entry((step.from.clone(), step.relation.clone(), kind))
                    .or_default()
                    .push(step.to.clone());
            } else if seen_intermediate
                .insert(format!("{}|{}|{}", step.from, step.to, step.relation))
            {
                m.edge(
                    &step.from,
                    &step.to,
                    &humanize_relation(&step.relation),
                    false,
                );
            }
        }
    }

    for ((from, relation, kind), objs) in &groups {
        let label = humanize_relation(relation);
        if objs.len() == 1 {
            m.edge(from, &objs[0], &label, false);
        } else {
            // Collapse the fan-out into one aggregate node.
            let agg_key = format!("{kind}/__agg/{from}/{relation}");
            let agg_label = format!("{} {}", objs.len(), plural(kind, objs.len()));
            m.edge_to_labeled(from, &agg_key, &agg_label, &label);
        }
    }

    // The number of edges actually drawn in the collapsed graph (deduped intermediate hops
    // + one edge per terminal group) — the "N hops" the watch-tier collapse summary names,
    // so the operator knows how deep the hidden path is before opening it.
    let hops = seen_intermediate.len() + groups.len();

    // ONE model judgement for the whole endpoint — the model judges per internet-facing
    // entry, over everything it reaches, in a single call (ADR-0013); it is NOT a
    // per-edge or per-objective verdict. So show the entry's one verdict (the model's
    // own words), not a count that would imply many judgements. `None` = the model
    // hasn't reached this entry yet (slow CPU model); the paths still render.
    //
    // JEF-161 verdict-first card: the posture chip + the model's words VERBATIM are
    // foregrounded ABOVE everything, then the "what's proven" certainty rail draws the
    // proof-vs-judgement line, then the graph, then a disposition-derived "what to do".
    let verdict = fs.iter().find_map(|f| f.verdict.as_deref());
    let posture = Posture::of(verdict);
    let verdict_line = verdict_line(verdict);

    // The per-path evidence (JEF-133): the entry's CVEs + runtime alerts, the two ADR-0016
    // blocks. The model judges per ENTRY over everything it reaches, so the whole card
    // shares ONE entry's evidence — take it from the first finding (all `fs` are this
    // entry's paths). Behaviors are attributed by pod UID, so this is the entry's own
    // low-cardinality signal set, no per-objective sprawl. The certainty rail reads this
    // SAME evidence for its CVE fact, so the rail and the block below it never disagree.
    let entry_evidence = fs.first().map(|f| &f.evidence);

    // The certainty rail — deterministic facts, captioned so the model's call (above) is
    // clearly the judgement and these are the proof (ADR-0016 proof-vs-judgement line). The
    // CVE fact is derived from `entry_evidence`, not the prose verdict. With no findings at
    // all (no entry to read evidence from) the rail falls back to the honest-empty state.
    let empty_evidence = EntryEvidence::default();
    let facts: String = proven_facts(entry, fs, entry_evidence.unwrap_or(&empty_evidence))
        .iter()
        .map(|b| format!("<li>{b}</li>"))
        .collect();
    let rail = format!(
        "<div class=\"rail\"><div class=\"rail-cap\">proven facts</div>\
         <ul>{facts}</ul></div>"
    );

    let evidence = entry_evidence.map(evidence_blocks).unwrap_or_default();

    // Wide reach ≠ break-in (ADR-0016, the argocd case): a broadly-privileged entry fans
    // out to a huge graph that LOOKS alarming, but breadth is the intended picture, not a
    // break-in. The verbose reassurance prose is GONE (JEF-200) — the "working as intended"
    // next-lever tag and the calm row styling carry it now. A Safe + broad entry is the calm
    // case; an Awaiting + broad entry keeps a one-line honest note that the model hasn't
    // finished (and is NOT calm-green, since it isn't cleared).
    let broad = is_broad(objectives);
    let (broad_lead, calm_card) = if broad && posture == Posture::Safe {
        (String::new(), true)
    } else if broad && posture == Posture::Awaiting {
        (
            "<p class=\"broad-lead\">Broad reach — the model hasn't finished judging this \
             one. Wide access isn't itself a break-in.</p>"
                .to_string(),
            false,
        )
    } else {
        (String::new(), false)
    };

    // What to do — derived from the disposition class plus the finding's own proven path
    // (no model call). The endpoint card groups many findings; they share the entry's
    // posture, so take the first as the representative next step for this entry's paths —
    // its concrete object/edge names the operator's fix (JEF-179).
    let todo = fs
        .first()
        .map(|f| what_to_do(f))
        .unwrap_or_else(|| "manual — no automatic cut classified for this path".to_string());
    let todo_line = format!("<div class=\"todo\"><b>what to do:</b> {todo}</div>");

    let aria = escape(&path_aria_label(entry, fs));

    // Expand the coalesced fan-out: a collapsed aggregate node ("47 secrets") hides
    // the names, so list each aggregated group's members under a native <details>
    // the operator can open. Singletons are already named in the graph, so skip them.
    let expand: String = groups
        .iter()
        .filter(|(_, objs)| objs.len() > 1)
        .map(|((_, relation, kind), objs)| {
            let mut names: Vec<String> = objs.iter().map(|o| short(o)).collect();
            names.sort();
            let items: String = names
                .iter()
                .map(|n| format!("<li>{}</li>", escape(n)))
                .collect();
            format!(
                "<details><summary>{} {} <span class=\"muted\">via {}</span></summary><ul>{}</ul></details>",
                objs.len(),
                plural(kind, objs.len()),
                escape(relation),
                items
            )
        })
        .collect();

    // The caption + the Mermaid source. The graph is the most intimidating element on the
    // card, and the whole card is already one expand behind its table row, so it stays
    // collapsed-by-default for EVERY tier (open on demand, JEF-202). A collapsed graph sits
    // inside a native <details>, so its <summary> control is keyboard-reachable for free and
    // the Mermaid hydration re-renders it on first open (a graph laid out while display:none
    // gets zero dimensions), see the page <script>. The summary names the reach when broad
    // ("show what it can reach (N targets)") and the depth otherwise ("show attack path (N
    // hops)").
    let caption = format!(
        "<div class=\"kc2\">the picture of those facts — \
         <span class=\"muted\">{} ({} target{} reachable)</span></div>",
        escape(&short(entry)),
        objectives,
        if objectives == 1 { "" } else { "s" },
    );
    let pre = format!(
        "<pre class=\"mermaid\" data-aria=\"{aria}\">{}</pre>",
        m.finish()
    );
    let graph_summary = if broad {
        format!(
            "show what it can reach ({objectives} target{})",
            if objectives == 1 { "" } else { "s" },
        )
    } else {
        format!(
            "show attack path ({hops} hop{})",
            if hops == 1 { "" } else { "s" },
        )
    };
    let graph_block = format!(
        "{caption}<details class=\"graphwrap\"><summary>{graph_summary}</summary>{pre}</details>"
    );

    // The card body — the full finding card, verdict-first (the verbatim model prose leads),
    // then the broad-reach lead (NON-muted, ADR-0016), the proof rail, both evidence blocks,
    // the collapsed graph, the disposition "what to do", and the fan-out expanders.
    let body = format!(
        "{verdict_line}{broad_lead}{rail}{evidence}{graph_block}{todo_line}{}",
        if expand.is_empty() {
            String::new()
        } else {
            format!("<div class=\"expand\">{expand}</div>")
        },
    );

    (
        body,
        RowMeta {
            posture,
            objectives,
            calm: calm_card,
        },
    )
}

/// One endpoint as a pair of dense-table rows (JEF-202): a SUMMARY `<tr>` of decisive cells
/// (`tier · entry → reaches · verdict(tag+clause) · evidence · next lever · age`) whose tier
/// cell is the row-expand control, and a hidden DETAIL `<tr><td colspan>` carrying TODAY's
/// full card body ([`endpoint_card_body`]). The expand control is a real
/// `<button aria-expanded aria-controls>` (a bare `<details>` wrapping a `<tr>` is invalid
/// table markup), toggling the detail row; its open-state AND the lazy graph survive the
/// `/fragment` swap via a STABLE [`row_id`] and the page's persistence machinery. `cols` is
/// the table's column count, for the detail row's `colspan`.
pub(crate) fn endpoint_row(
    entry: &str,
    fs: &[&Finding],
    tier: Tier,
    last_pass: Option<SystemTime>,
    cols: usize,
) -> String {
    let (body, meta) = endpoint_card_body(entry, fs);
    let id = row_id(entry);
    let detail_id = format!("{id}-detail");

    // tier cell — the existing chip idiom, doubling as the expand control's label.
    let tier_chip = format!(
        "<span class=\"chip {}\">{}</span>",
        tier.chip_class(),
        tier.label()
    );

    // entry → reaches: the short entry name + the dominant terminal reach ("N secrets"),
    // the aggregate form the card body also computes.
    let reaches = terminal_reach_clause(fs).unwrap_or_else(|| {
        format!(
            "{} target{}",
            meta.objectives,
            if meta.objectives == 1 { "" } else { "s" }
        )
    });
    let entry_cell = format!(
        "<code>{}</code> <span class=\"r-arrow\">→</span> <span class=\"muted\">{}</span>",
        escape(&short(entry)),
        escape(&reaches),
    );

    // verdict: the TAG + ONE decisive clause (JEF-199) — never the paragraph (that is in the
    // expanded body, verbatim).
    let verdict = fs.iter().find_map(|f| f.verdict.as_deref());
    let (tag, clause) = verdict_gist(
        verdict,
        fs.first().map_or(&EMPTY_EVIDENCE, |f| &f.evidence),
        fs,
    );
    let tag_class = meta.posture.tone();
    let clause_html = if clause.is_empty() {
        String::new()
    } else {
        format!(" <span class=\"v-clause\">{}</span>", escape(&clause))
    };
    let verdict_cell = format!("<span class=\"chip {tag_class}\">{tag}</span>{clause_html}");

    // evidence glyphs — compact CVE/KEV/crit/live badges, or — / unjudged.
    let awaiting = meta.posture == Posture::Awaiting;
    let corroborated = fs.iter().any(|f| f.corroborated);
    let evidence_cell = evidence_glyphs(
        fs.first().map_or(&EMPTY_EVIDENCE, |f| &f.evidence),
        corroborated,
        awaiting,
    );

    // next lever — the terse disposition tag; the calm "working as intended" case wins for a
    // broadly-privileged, model-cleared entry (ADR-0016).
    let lever = if meta.calm {
        "working as intended"
    } else {
        fs.first().map_or("manual", |f| next_lever_tag(f))
    };
    let lever_cell = format!("<span class=\"lever\">{lever}</span>");

    // age — the pass-age ("as of Nm ago"); the richer per-finding Δ column is JEF-201.
    let age_cell = format!("as of {}", escape(&relative_time(last_pass)));

    let row_class = if meta.calm { "f-row f-calm" } else { "f-row" };
    format!(
        "<tr class=\"{row_class}\">\
         <td class=\"c-tier\"><button class=\"row-toggle\" aria-expanded=\"false\" \
         aria-controls=\"{detail_id}\">{tier_chip}</button></td>\
         <td class=\"c-entry\">{entry_cell}</td>\
         <td class=\"c-verdict\">{verdict_cell}</td>\
         <td class=\"c-ev\">{evidence_cell}</td>\
         <td class=\"c-lever\">{lever_cell}</td>\
         <td class=\"c-age\">{age_cell}</td>\
         </tr>\
         <tr id=\"{detail_id}\" class=\"f-detail\" hidden><td colspan=\"{cols}\">{body}</td></tr>"
    )
}

/// A shared empty evidence set for entries with no findings to read evidence from (keeps
/// the row builders allocation-free in that degenerate case).
static EMPTY_EVIDENCE: EntryEvidence = EntryEvidence {
    cves: Vec::new(),
    runtime: Vec::new(),
};

/// A model verdict counts as a flag only when the model affirmed exploitability —
/// its own words begin with "exploitable" (a "not exploitable — …" verdict does not).
pub(crate) fn flagged(verdict: Option<&str>) -> bool {
    verdict.is_some_and(|v| {
        v.trim_start()
            .to_ascii_lowercase()
            .starts_with("exploitable")
    })
}

/// The operator-attention TIER a finding falls in (JEF-163) — the **view** label that
/// says *why a card is where it is*, NOT a decision (ADR-0016: ordering is a view, never
/// a gate). It does not feed the model, gate any action, or touch a verdict/disposition;
/// it is computed read-only from existing [`Finding`] fields at render time and only
/// reorders + labels the already-decided cards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// The model judged this a real breach (its verdict affirms `exploitable`). Always
    /// at the top — a flagged endpoint sorts above a larger-but-unflagged one (AC #2).
    Flagged,
    /// Warrants a look but the model hasn't flagged a breach: either a coverage-gap /
    /// latent foothold carrying a cited CVE, or a runtime-corroborated chain.
    Watch,
    /// Everything else — proven-reachable but neither flagged, CVE-bearing-latent, nor
    /// runtime-corroborated. De-emphasized / collapsible in the view.
    Context,
}

impl Tier {
    /// The short label shown on the card so the operator sees its tier at a glance.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Tier::Flagged => "flagged",
            Tier::Watch => "watch",
            Tier::Context => "context",
        }
    }

    /// The chip tone class (reusing the existing card chip idiom): red for flagged,
    /// amber for watch, grey for the de-emphasized context tier.
    pub(crate) fn chip_class(self) -> &'static str {
        match self {
            Tier::Flagged => "tier-flagged",
            Tier::Watch => "tier-watch",
            Tier::Context => "tier-context",
        }
    }
}

/// The OPERATOR-PRIORITY rank of a single finding (JEF-163) — a TESTED PURE FUNCTION over
/// existing [`Finding`] fields (AC #4). Lower number = more attention. This is the
/// presentation-only "look at this first" key (ADR-0016: severity is a view, breach is the
/// model's; a sort key never gates, decides, or feeds the model). The four levels, in the
/// ticket's order:
///
///   1. model-flagged exploitable — the model judged a real breach ([`flagged`]).
///   2. coverage-gap / latent foothold WITH a CVE present — `disposition` is the latent
///      case AND the verdict cites a `CVE-…` ([`cve_id`], the only per-finding CVE signal
///      that exists today; see the note below).
///   3. runtime-corroborated — a live signal completed the chain (`corroborated`).
///   4. everything else.
///
/// NOTE on "KEV / critical CVE": `Finding` has no per-finding KEV flag or CVE severity
/// field — the sole CVE signal present is the id the model cited in its verdict text
/// (`cve_id`). We therefore treat *any* cited CVE on a latent foothold as level 2 rather
/// than fabricating a severity/KEV field. This is the conservative reading: it cannot
/// over-promote (a cited CVE is, at worst, slightly broader than "KEV/critical only"), and
/// it invents nothing. If a KEV/severity field is later added to `Finding`, tighten this.
pub(crate) fn attention_priority(f: &Finding) -> u8 {
    if flagged(f.verdict.as_deref()) {
        0
    } else if f.disposition.contains("latent foothold")
        && f.verdict.as_deref().and_then(cve_id).is_some()
    {
        1
    } else if f.corroborated {
        2
    } else {
        3
    }
}

/// The [`Tier`] a priority level maps to for display (AC #3): level 1 is `Flagged`,
/// levels 2–3 are `Watch`, level 4 is the de-emphasized `Context` tier.
pub(crate) fn tier_of_priority(priority: u8) -> Tier {
    match priority {
        0 => Tier::Flagged,
        1 | 2 => Tier::Watch,
        _ => Tier::Context,
    }
}

/// The attention rank of one finding: its priority level and the display tier. The pure,
/// unit-testable key for the per-card sort (AC #4) — view-only, no mutation, no model input.
pub(crate) fn attention_rank(f: &Finding) -> (u8, Tier) {
    let priority = attention_priority(f);
    (priority, tier_of_priority(priority))
}

/// The attention rank of an ENDPOINT card — a card coalesces every finding from one
/// internet-facing entry, so the card takes its group's WORST-CASE (lowest-number)
/// priority: a single flagged path makes the whole card flagged. Returns the card's
/// priority level and its display tier. Pure over the group; the BLAST RADIUS (group
/// size) is NOT folded in here — it is applied only as the final tiebreak at the sort
/// site, so it can never lift a card above a higher tier (AC #1, AC #2).
pub(crate) fn endpoint_attention_rank(fs: &[&Finding]) -> (u8, Tier) {
    // The card's priority is the most-attention-worthy of its findings (lowest number),
    // via the per-finding `attention_rank` so card and finding rankings can never drift.
    let priority = fs.iter().map(|f| attention_rank(f).0).min().unwrap_or(3);
    (priority, tier_of_priority(priority))
}
