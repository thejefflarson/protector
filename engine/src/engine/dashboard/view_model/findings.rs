//! Map the engine's [`Finding`] rows (with their evidence, path, and typed verdict) into the
//! presentation [`FindingProps`] the components render, and apply the URGENCY sort (ADR-0016 /
//! brief §5) — corroborated-live → model-promoted → escalations → awaiting → cleared. This is
//! the data layer: it touches `state::`/`graph::` domain types; the components never do.

use crate::engine::graph::{Behavior, NodeKey};
use crate::engine::state::{
    CveEvidence, EntryEvidence, Finding, FindingEvidence, Judgement, PathStep,
};

use super::posture::{delta_of, live_tag_of, posture_of};
use super::props::{
    BehaviorProps, CveProps, EvidenceProps, EvidenceSummary, FindingProps, HopProps,
    JudgementProps, LiveTag, Posture, ScanProps,
};

/// A reasonable threshold past which an entry's reachable-objective set reads as a fan-out
/// (argocd → ~120 secrets), collapsed to `→ ×N` rather than listed as alarms (brief §5/§10).
const FANOUT_THRESHOLD: usize = 8;

/// Map a finding's entry node key to a kind glyph. An internet foothold is the globe; the
/// other kinds get a compact glyph so the entry column reads structurally.
fn entry_glyph(key: &str, foothold: bool) -> String {
    if foothold {
        return "\u{1F310}".to_string(); // 🌐
    }
    match NodeKey::kind_of(key) {
        "workload" => "\u{25A2}",   // ▢
        "secret" => "\u{1F511}",    // 🔑
        "identity" => "\u{1F464}",  // 👤
        "endpoint" => "\u{2192}",   // →
        "image" => "\u{25A3}",      // ▣
        "host" => "\u{1F5A5}",      // 🖥
        "capability" => "\u{26A1}", // ⚡
        _ => "\u{2022}",            // •
    }
    .to_string()
}

/// Project a CVE evidence record into its props (the subordinate severity channel).
fn cve_props(c: &CveEvidence) -> CveProps {
    CveProps {
        id: c.id.clone(),
        severity: c.severity.clone(),
        score: c.score.clone(),
        kev: c.kev,
        epss: c.epss.clone(),
        reachability: c.reachability.clone(),
        fix: c.fix.clone(),
        title: c.title.clone(),
    }
}

/// Project a scanner finding (exposed secret / misconfig / RBAC) into its props.
fn scan_props(f: &FindingEvidence) -> ScanProps {
    ScanProps {
        id: f.id.clone(),
        severity: f.severity.clone(),
        category: f.category.clone(),
        title: f.title.clone(),
    }
}

/// Project a runtime behavior into its props, marking whether it corroborates the chain.
fn behavior_props(b: &Behavior) -> BehaviorProps {
    BehaviorProps {
        variant: b.variant_label().to_string(),
        summary: b.summary(),
        corroborating: b.is_alert(),
    }
}

/// Build the full evidence panel props from an entry's evidence, splitting runtime behaviors
/// into corroborating (alerts) vs context.
fn evidence_props(ev: &EntryEvidence) -> EvidenceProps {
    EvidenceProps {
        cves: ev.cves.iter().map(cve_props).collect(),
        corroborating: ev
            .runtime
            .iter()
            .filter(|b| b.is_alert())
            .map(behavior_props)
            .collect(),
        context: ev
            .runtime
            .iter()
            .filter(|b| !b.is_alert())
            .map(behavior_props)
            .collect(),
        exposed_secrets: ev.exposed_secrets.iter().map(scan_props).collect(),
        misconfigs: ev.misconfigs.iter().map(scan_props).collect(),
        rbac_findings: ev.rbac_findings.iter().map(scan_props).collect(),
    }
}

/// The compact evidence-cluster summary for the row.
fn evidence_summary(ev: &EntryEvidence) -> EvidenceSummary {
    EvidenceSummary {
        cve_count: ev.cves.len(),
        kev: ev.cves.iter().any(|c| c.kev),
        runtime_alerts: ev.runtime.iter().filter(|b| b.is_alert()).count(),
        exposed_secrets: ev.exposed_secrets.len(),
    }
}

/// Map the proven path's hops, marking structural (substrate) hops muted and the cut point.
/// `cut` is the cut signature (`from -[relation]-> to`); a hop matching it is marked.
fn path_props(path: &[PathStep], cut: Option<&str>) -> Vec<HopProps> {
    path.iter()
        .map(|h| {
            let signature = format!("{} -[{}]-> {}", h.from, h.relation, h.to);
            HopProps {
                from: NodeKey::short_of(&h.from).to_string(),
                relation: h.relation.clone(),
                to: NodeKey::short_of(&h.to).to_string(),
                structural: is_structural_relation(&h.relation),
                is_cut: cut == Some(signature.as_str()),
            }
        })
        .collect()
}

/// Whether a relation label names a STRUCTURAL substrate edge (runs-as / runs-image /
/// scheduled-on) — these are rendered muted in the hop-list (brief §5). Mirrors
/// [`crate::engine::graph::Relation::is_structural`] over the label string.
fn is_structural_relation(relation: &str) -> bool {
    matches!(relation, "runs-as" | "runs-image" | "scheduled-on")
}

/// A stable DOM/fragment id for a finding, derived from its entry key. Non-alphanumerics
/// collapse to `-` so it is a safe `id`/anchor.
fn finding_id(entry: &str) -> String {
    let slug: String = entry
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("f-{slug}")
}

/// The verbatim model judgement props for an entry, if one was captured in the log. Matches by
/// entry key; the newest judgement for the entry wins.
fn judgement_props(entry: &str, judgements: &[Judgement]) -> JudgementProps {
    match judgements.iter().find(|j| j.entry == entry) {
        Some(j) => JudgementProps {
            prompt: j.prompt.clone(),
            reply: j.reply.clone(),
            verdict: Some(j.verdict.clone()),
        },
        None => JudgementProps::default(),
    }
}

/// Map one [`Finding`] into its presentation props. `judgements` is the newest-first judgement
/// snapshot, used to attach the verbatim prompt/reply for the "show model prompt" disclosure.
pub(super) fn finding_props(f: &Finding, judgements: &[Judgement]) -> FindingProps {
    let posture = posture_of(f.verdict.as_ref());
    let live_tag = live_tag_of(f.verdict.as_ref());
    FindingProps {
        id: finding_id(&f.entry),
        posture,
        live_tag,
        delta: delta_of(f.recency.as_ref()),
        entry_glyph: entry_glyph(&f.entry, f.foothold),
        entry: NodeKey::short_of(&f.entry).to_string(),
        foothold: f.foothold,
        objective: NodeKey::short_of(&f.objective).to_string(),
        fanout: None, // single-objective rows; fan-out is computed in the collapse pass below.
        evidence_summary: evidence_summary(&f.evidence),
        disposition: f.disposition.clone(),
        verdict_summary: f.verdict.as_ref().map(|v| v.summary()),
        path: path_props(&f.path, f.cut.as_deref()),
        cut: f.cut.clone(),
        evidence: evidence_props(&f.evidence),
        judgement: judgement_props(&f.entry, judgements),
    }
}

/// The urgency rank for the sort (lower = MORE urgent). Urgency is NOT severity (ADR-0016): a
/// corroborated-live breach outranks a model-promoted one, which outranks an escalation, which
/// outranks an awaiting row, which outranks a cleared one (the calm tail).
fn urgency_rank(f: &FindingProps) -> u8 {
    match (f.posture, f.live_tag, &f.delta) {
        // Corroborated-live breach — the loudest.
        (Posture::Breach, LiveTag::Live, _) => 0,
        // Model-promoted breach.
        (Posture::Breach, _, _) => 1,
        // An escalation (newly worsened), regardless of decisive posture.
        (_, _, super::props::DeltaProps::Escalated) => 2,
        // Uncertain — not safe, needs a look.
        (Posture::Uncertain, _, _) => 3,
        // Awaiting judgement.
        (Posture::Awaiting, _, _) => 4,
        // Cleared — the calm tail (collapsed group).
        (Posture::Cleared, _, _) => 5,
    }
}

/// Collapse a group of findings that share an entry into one fan-out row when the entry reaches
/// many objectives (argocd → ~120 secrets), framed as reachable-but-cleared (brief §5). A small
/// reachable set is left as individual rows.
fn collapse_fanout(mut rows: Vec<FindingProps>) -> Vec<FindingProps> {
    use std::collections::HashMap;
    let mut counts: HashMap<String, usize> = HashMap::new();
    for r in &rows {
        *counts.entry(r.entry.clone()).or_default() += 1;
    }
    // Entries that fan out beyond the threshold collapse to a single representative row.
    let mut seen: HashMap<String, ()> = HashMap::new();
    rows.retain(|r| {
        let n = counts.get(&r.entry).copied().unwrap_or(1);
        if n > FANOUT_THRESHOLD {
            // Keep only the first row per fanned-out entry.
            seen.insert(r.entry.clone(), ()).is_none()
        } else {
            true
        }
    });
    for r in &mut rows {
        let n = counts.get(&r.entry).copied().unwrap_or(1);
        if n > FANOUT_THRESHOLD {
            r.fanout = Some(n);
        }
    }
    rows
}

/// Map and URGENCY-sort a snapshot of findings into props (brief §5). Only breach-relevant
/// findings are surfaced — the caller passes the breach-relevant set. Fan-out collapse runs
/// first, then the urgency sort (stable within a rank, by entry for determinism).
pub(super) fn map_findings(findings: &[Finding], judgements: &[Judgement]) -> Vec<FindingProps> {
    let mut rows: Vec<FindingProps> = findings
        .iter()
        .filter(|f| f.breach_relevant)
        .map(|f| finding_props(f, judgements))
        .collect();
    rows = collapse_fanout(rows);
    rows.sort_by(|a, b| {
        urgency_rank(a)
            .cmp(&urgency_rank(b))
            .then(a.entry.cmp(&b.entry))
            .then(a.objective.cmp(&b.objective))
    });
    rows
}

#[cfg(test)]
mod tests;
