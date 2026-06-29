//! The ENDPOINT-row view-model (JEF-255): one exposed entry → its dense-table row props and
//! its expanded detail props. The row is the answer's unit; the detail is the "why".
//!
//! Posture is derived ONCE from the entry's TYPED verdict (the SSOT, `posture::Posture`); the
//! row's decisive clause is the model's own prose (the verdict summary), shown verbatim — the
//! view never re-derives the call from the prose. The detail composes the verbatim verdict +
//! raw-prompt expander, the proof/certainty rail, the evidence blocks, the text hop-list, and
//! the posture-gated what-to-do. Pure data; the renderer takes only these props (ADR-0019).

use crate::engine::dashboard::model::{Finding, relative_time};
use crate::engine::dashboard::recency::RecencyInfo;
use crate::engine::dashboard::view_model::evidence::{
    EvidenceBlocks, GlyphStrip, evidence_blocks, glyph_strip,
};
use crate::engine::dashboard::view_model::hops::{HopList, hop_list};
use crate::engine::dashboard::view_model::posture::Posture;
use crate::engine::graph::NodeKey;
use std::time::SystemTime;

/// The dense-table row for one exposed entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowProps {
    /// The stable detail id (`detail-<entry-slug>`) the row-toggle controls.
    pub detail_id: String,
    /// The entry's model posture (BREACH / SAFE / awaiting) — from the typed verdict SSOT.
    pub posture: Posture,
    /// The short entry label (the front door).
    pub entry: String,
    /// What it reaches, summarized: "→ N targets" or the single objective's short label.
    pub reaches: String,
    /// The decisive verdict clause — the model's own prose, trimmed to one line. Empty when
    /// the model hasn't judged this entry (awaiting).
    pub clause: String,
    /// The evidence glyph strip.
    pub glyphs: GlyphStrip,
    /// The Δ glyph + screen-reader label (recency), if any.
    pub delta: Option<DeltaCell>,
    /// The age since first seen ("2m"), if known.
    pub age: Option<String>,
}

/// The Δ cell: the terse glyph plus its meaning-in-words (never glyph alone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaCell {
    pub glyph: String,
    pub aria: String,
}

/// The full expanded detail for one entry — the "why" surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailProps {
    pub detail_id: String,
    pub posture: Posture,
    /// The model's VERBATIM verdict summary ("exploitable — …" / "not exploitable — …"), or
    /// the honest "not yet judged" line when awaiting.
    pub verdict: String,
    /// The raw prompt the model saw for this entry (from the judgement log), behind an
    /// expander. `None` when no prompt was captured (the deterministic pre-filter, or no model).
    pub raw_prompt: Option<String>,
    /// The proof/certainty rail facts.
    pub rail: Rail,
    /// The labeled evidence blocks (CVEs / runtime / scanner findings).
    pub evidence: EvidenceBlocks,
    /// The attack path as a text hop-list (entry → … → objective, cut point marked).
    pub hops: HopList,
    /// The posture-gated "what to do" — present ONLY for a breach.
    pub what_to_do: Option<String>,
}

/// The proof / certainty rail (JEF-255): the deterministic facts that bound certainty —
/// proven-reachable (always, the chain is proven), live-corroborated (a runtime alert), and
/// how many objectives the entry reaches (the breadth the model weighed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rail {
    /// Always true here — the path is deterministically proven (the chain exists).
    pub proven: bool,
    /// A live runtime signal corroborated it (ADR-0009).
    pub corroborated: bool,
    /// The entry is an internet-facing front door.
    pub internet_facing: bool,
    /// How many distinct objectives this entry reaches (the blast radius).
    pub objectives: usize,
}

/// Build the dense-table row props for an entry from its findings group (all chains rooted at
/// the same entry). The recency Δ/age are resolved at snapshot time on the finding, so this is
/// pure over the group.
pub fn row_props(entry: &str, fs: &[&Finding]) -> RowProps {
    let lead = lead_finding(fs);
    let posture = entry_posture(fs);
    let recency = endpoint_recency(fs);
    RowProps {
        detail_id: detail_id(entry),
        posture,
        entry: NodeKey::short_of(entry).to_string(),
        reaches: reaches_summary(fs),
        clause: clause_of(lead),
        glyphs: glyph_strip(&lead.evidence, fs.iter().any(|f| f.corroborated)),
        delta: recency.map(delta_cell),
        age: recency.and_then(|r| r.age_secs).map(humanize_age),
    }
}

/// Build the expanded detail props for an entry. `raw_prompt` is looked up from the judgement
/// log by the caller (the page) and threaded in, since the findings rows don't carry it.
pub fn detail_props(entry: &str, fs: &[&Finding], raw_prompt: Option<String>) -> DetailProps {
    let lead = lead_finding(fs);
    let posture = entry_posture(fs);
    DetailProps {
        detail_id: detail_id(entry),
        posture,
        verdict: verbatim_verdict(lead, posture),
        raw_prompt,
        rail: Rail {
            proven: true,
            corroborated: fs.iter().any(|f| f.corroborated),
            internet_facing: fs.iter().any(|f| f.foothold),
            objectives: distinct_objectives(fs),
        },
        evidence: evidence_blocks(&lead.evidence),
        hops: hop_list(lead),
        what_to_do: what_to_do(lead, posture),
    }
}

/// The entry's overall posture: the LOUDEST across its chains (a single breach chain makes the
/// entry a breach), derived from each chain's typed verdict (the SSOT).
pub fn entry_posture(fs: &[&Finding]) -> Posture {
    fs.iter()
        .map(|f| Posture::of_verdict(f.verdict.as_ref()))
        .fold(Posture::Awaiting, max_posture)
}

/// The "lead" finding for the row/detail: the one whose posture is loudest (breach first), so
/// the decisive clause and hop-list show the most-relevant chain.
fn lead_finding<'a>(fs: &'a [&'a Finding]) -> &'a Finding {
    fs.iter()
        .copied()
        .max_by_key(|f| posture_rank(Posture::of_verdict(f.verdict.as_ref())))
        .expect("endpoint group is never empty")
}

/// The model's verdict prose for the row clause, trimmed to a single line.
fn clause_of(f: &Finding) -> String {
    match f.verdict.as_ref() {
        Some(v) => first_line(&v.summary()),
        None => String::new(),
    }
}

/// The verbatim verdict for the detail — the model's own words, or the honest awaiting line.
fn verbatim_verdict(f: &Finding, posture: Posture) -> String {
    match f.verdict.as_ref() {
        Some(v) => v.summary(),
        None => {
            let _ = posture;
            "not yet judged — the model has not reached this entry this run".to_string()
        }
    }
}

/// The posture-gated remediation guidance — only for a BREACH (ADR-0016: SAFE/awaiting get no
/// "do this", that would be noise). Names the cut lever honestly by disposition.
fn what_to_do(f: &Finding, posture: Posture) -> Option<String> {
    if !posture.is_breach() {
        return None;
    }
    let action = match f.disposition.as_str() {
        d if d.contains("durable-fix") => {
            "open a PR to remove the grant/mount — this path needs a durable fix"
        }
        d if d.contains("forbidden") => {
            "needs a human — the only cut is an irreversible escape-primitive removal"
        }
        d if d.contains("no-cut") => "no single-edge cut severs this — review the path",
        _ => "arm the network class to apply the reversible isolation automatically",
    };
    Some(action.to_string())
}

/// A short "what it reaches" summary for the row: the single objective's short label, or
/// "N targets" when the entry reaches several.
fn reaches_summary(fs: &[&Finding]) -> String {
    let n = distinct_objectives(fs);
    if n == 1 {
        NodeKey::short_of(&fs[0].objective).to_string()
    } else {
        format!("{n} targets")
    }
}

fn distinct_objectives(fs: &[&Finding]) -> usize {
    fs.iter()
        .map(|f| f.objective.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

/// The recency for an endpoint group: the loudest Δ across its chains (an escalation on any
/// chain is the endpoint's Δ), or the first available.
fn endpoint_recency(fs: &[&Finding]) -> Option<RecencyInfo> {
    fs.iter().filter_map(|f| f.recency).next()
}

fn delta_cell(r: RecencyInfo) -> DeltaCell {
    let age = r.age_secs.map(humanize_age);
    DeltaCell {
        glyph: r.delta.glyph().to_string(),
        aria: r.delta.aria_label(age.as_deref()),
    }
}

/// A stable detail id derived from the entry key (so the row-toggle + JS persistence map the
/// same endpoint to the same id pass-to-pass). Non-alnum chars collapse to `-`.
pub fn detail_id(entry: &str) -> String {
    let slug: String = entry
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("detail-{slug}")
}

/// Humanize an age in whole seconds to a terse "12s" / "3m" / "2h" / "1d".
pub fn humanize_age(secs: u64) -> String {
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

/// The freshness line for the page footer ("pass 12s ago").
pub fn freshness(last_pass: Option<SystemTime>) -> String {
    relative_time(last_pass)
}

fn posture_rank(p: Posture) -> u8 {
    match p {
        Posture::Awaiting => 0,
        Posture::Safe => 1,
        Posture::Breach => 2,
    }
}

fn max_posture(a: Posture, b: Posture) -> Posture {
    if posture_rank(b) > posture_rank(a) {
        b
    } else {
        a
    }
}

/// The first line of a possibly multi-line string, trimmed.
fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::model::{EntryEvidence, PathStep};
    use crate::engine::reason::adjudicate::Verdict;

    fn f(entry: &str, objective: &str, verdict: Option<Verdict>) -> Finding {
        Finding {
            entry: entry.into(),
            objective: objective.into(),
            foothold: true,
            corroborated: false,
            disposition: "auto-eligible".into(),
            cut: Some(format!("{entry} -[reaches/Tcp]-> {objective}")),
            breach_relevant: true,
            verdict,
            path: vec![PathStep {
                from: entry.into(),
                relation: "reaches/Tcp".into(),
                to: objective.into(),
            }],
            evidence: EntryEvidence::default(),
            recency: None,
        }
    }

    #[test]
    fn entry_posture_is_the_loudest_chain() {
        let a = f("web", "secret/a", Some(Verdict::Refuted("no".into())));
        let b = f("web", "secret/b", Some(Verdict::Exploitable("yes".into())));
        assert_eq!(entry_posture(&[&a, &b]), Posture::Breach);
    }

    #[test]
    fn row_clause_is_the_model_prose_verbatim() {
        let b = f(
            "web",
            "secret/b",
            Some(Verdict::Exploitable("RCE via CVE-x".into())),
        );
        let row = row_props("workload/app/Pod/web", &[&b]);
        assert_eq!(row.posture, Posture::Breach);
        assert_eq!(row.entry, "app/Pod/web");
        assert_eq!(row.clause, "exploitable — RCE via CVE-x");
        assert_eq!(row.reaches, "b");
    }

    #[test]
    fn awaiting_row_has_no_clause() {
        let b = f("web", "secret/b", None);
        let row = row_props("web", &[&b]);
        assert_eq!(row.posture, Posture::Awaiting);
        assert_eq!(row.clause, "");
    }

    #[test]
    fn what_to_do_only_for_breach() {
        let breach = f("web", "s", Some(Verdict::Exploitable("y".into())));
        let safe = f("web", "s", Some(Verdict::Refuted("n".into())));
        assert!(detail_props("web", &[&breach], None).what_to_do.is_some());
        assert!(detail_props("web", &[&safe], None).what_to_do.is_none());
    }

    #[test]
    fn detail_carries_verbatim_verdict_rail_and_hops() {
        let breach = f("web", "secret/b", Some(Verdict::Exploitable("RCE".into())));
        let d = detail_props("workload/app/Pod/web", &[&breach], Some("PROMPT".into()));
        assert_eq!(d.verdict, "exploitable — RCE");
        assert_eq!(d.raw_prompt.as_deref(), Some("PROMPT"));
        assert!(d.rail.proven);
        assert!(d.rail.internet_facing);
        assert_eq!(d.rail.objectives, 1);
        // The hop-list entry is the FINDING's entry key (here the bare "web" the fixture used),
        // shortened — not the group key passed to `detail_props`.
        assert_eq!(d.hops.entry, "web");
        assert!(d.hops.hops[0].is_cut);
    }

    #[test]
    fn awaiting_detail_says_not_yet_judged() {
        let a = f("web", "s", None);
        let d = detail_props("web", &[&a], None);
        assert!(d.verdict.contains("not yet judged"));
    }

    #[test]
    fn detail_id_is_stable_and_slugged() {
        assert_eq!(
            detail_id("workload/app/Pod/web"),
            "detail-workload-app-Pod-web"
        );
    }
}
