//! Transitional legacy module (pre-ADR-0019 string-concat rendering).
//!
//! Migrated piecemeal in tickets 3–6; extracted here only so each file
//! stays under the 1,000-line cap (repo CLAUDE.md). New work goes in the
//! `components`/`view_model` maud layers, not here.
#![allow(dead_code)]

use super::*;

/// The attack-vector summary: the ATT&CK outcomes an external attacker can actually
/// reach, aggregated across the breach-relevant findings. Each row is one
/// tactic→technique pair with how many distinct objectives are reachable and how many
/// the model has affirmed exploitable. This is the "what can hit us, by ATT&CK
/// technique" overview that sits above the per-endpoint graphs — proof winnows the
/// reachable set, the model decides which are genuinely exploitable (ADR-0013).
pub(crate) fn attack_vectors(findings: &[Finding]) -> String {
    // (tactic, technique_id, technique_name) → (objectives reachable, objectives the
    // model flagged exploitable). Distinct objectives, since several chains may reach
    // the same one. BTreeMap keeps the table stable, ordered by tactic then technique.
    type VectorKey = (String, String, String);
    type VectorCounts = (BTreeSet<String>, BTreeSet<String>);
    let mut rows: BTreeMap<VectorKey, VectorCounts> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.breach_relevant) {
        let entry = rows
            .entry((
                f.tactic_name.clone(),
                f.technique.clone(),
                f.technique_name.clone(),
            ))
            .or_default();
        entry.0.insert(f.objective.clone());
        if flagged(f.verdict.as_deref()) {
            entry.1.insert(f.objective.clone());
        }
    }

    if rows.is_empty() {
        return "<p class=\"muted\">no internet-facing service can reach a target</p>".to_string();
    }

    let body: String = rows
        .iter()
        .map(|((tactic, tid, tname), (reachable, flagged))| {
            let flag = if flagged.is_empty() {
                "<span class=\"muted\">—</span>".to_string()
            } else {
                format!("<span class=\"flagged\">{}</span>", flagged.len())
            };
            format!(
                "<tr><td>{}</td><td><abbr title=\"{} {}\">{}</abbr></td><td>{}</td><td>{}</td></tr>",
                escape(tactic),
                escape(tid),
                escape(tname),
                escape(tname),
                reachable.len(),
                flag,
            )
        })
        .collect();

    format!(
        "<table class=\"vectors\"><thead><tr><th>Tactic</th><th>Technique</th>\
         <th>Reachable</th><th>Model-flagged</th></tr></thead><tbody>{body}</tbody></table>"
    )
}

/// The behavioral-bake panel (JEF-48): the at-a-glance view of what the behavioral
/// port saw in the most recent pass — signal volume by variant, attribution
/// resolved/unresolved, the live runtime-store size, and corroborations fired. This is
/// the dashboard mirror of the OTLP bake counters (JEF-100), so the bake's exit criteria
/// ("signal volume sane", "attribution resolves", "corroboration would fire") are
/// readable on the dashboard itself, not only through a collector. Read-only, shadow-safe.
pub(crate) fn bake_panel(bake: &BakeStats) -> String {
    let total = bake.total_signals();
    if total == 0 && bake.runtime_store == 0 {
        return "<p class=\"muted\">no behavioral signals observed yet \
                (no sensor reporting, or a quiet cluster)</p>"
            .to_string();
    }

    // Per-variant volume rows, ordered by the BTreeMap (stable, variant-name keyed).
    let variant_rows: String = bake
        .signals_by_variant
        .iter()
        .map(|(variant, n)| {
            format!(
                "<tr><td><code>{}</code></td><td>{}</td></tr>",
                escape(variant),
                n
            )
        })
        .collect();

    // The attribution line: resolved vs unresolved with the unresolved share, the
    // JEF-48 attribution exit-criterion. A nonzero unresolved share is highlighted.
    let pct = bake.unresolved_fraction() * 100.0;
    let attribution = if bake.unresolved == 0 {
        format!(
            "<b>{}</b> resolved · <span class=\"muted\">0 unresolved</span>",
            bake.resolved
        )
    } else {
        format!(
            "<b>{}</b> resolved · <span class=\"flagged\">{} unresolved ({:.1}%)</span>",
            bake.resolved, bake.unresolved, pct
        )
    };

    format!(
        "<div class=\"sum\">last pass: <b>{total}</b> signal{} · {attribution} · \
         live store <b>{store}</b> · corroborations <b>{corr}</b></div>\
         <table class=\"vectors\"><thead><tr><th>Signal variant</th><th>Count (last pass)</th>\
         </tr></thead><tbody>{rows}</tbody></table>",
        if total == 1 { "" } else { "s" },
        store = bake.runtime_store,
        corr = bake.corroborations,
        rows = if variant_rows.is_empty() {
            "<tr><td class=\"muted\" colspan=\"2\">no signals this pass</td></tr>".to_string()
        } else {
            variant_rows
        },
    )
}

/// The recent-reversions panel (JEF-141): lifted cuts and why — the visible record of
/// the self-revert (ADR-0016). Quiet when nothing has been lifted (a healthy default,
/// not an error). Newest first.
pub(crate) fn reversions_panel(reversions: &[ReversionRecord]) -> String {
    if reversions.is_empty() {
        return "<p class=\"muted\">no cuts have been lifted yet</p>".to_string();
    }
    let rows: String = reversions
        .iter()
        .map(|r| {
            let when = relative_time(Some(
                SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(r.at_ms),
            ));
            format!(
                "<tr><td><code>{}</code></td><td>{}</td><td class=\"muted\">{}</td></tr>",
                escape(&r.cut),
                escape(&r.reason),
                escape(&when),
            )
        })
        .collect();
    format!(
        "<table class=\"vectors\"><thead><tr><th>Lifted cut</th><th>Reason</th>\
         <th>When</th></tr></thead><tbody>{rows}</tbody></table>"
    )
}

// ===========================================================================
// The shadow "would-have-acted" report (JEF-143)
// ===========================================================================
//
// Nothing else answers the question that gates exiting shadow (JEF-50): "over the
// last N days, how many cuts WOULD protector have made, on what, and were any
// wrong?" `/report` aggregates the durable decision journal (JEF-141) into that
// diff — read-side only, no new signals, no action.
//
// The journal records one [`Decision::Breach`] per pass per internet-facing entry,
// carrying the model's verdict in its own words ("exploitable — …" / "not
// exploitable — …"). In shadow the engine never cuts, but a breach decision whose
// verdict AFFIRMS exploitability is exactly the workload it WOULD have isolated. So
// the report walks each entry's breach decisions chronologically and folds them into
// **would-act episodes**: a run of consecutive exploitable verdicts. The projected
// would-be cut lifetime is from the episode's first exploitable verdict to when it
// cleared (the next non-exploitable verdict for that entry) — or to now, if it never
// cleared (still open). An entry whose latest verdict in the window is NOT
// exploitable is a **proven-but-cleared** path the model deliberately left alone:
// the trust half of the diff.
