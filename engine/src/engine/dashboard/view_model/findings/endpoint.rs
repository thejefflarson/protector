//! The per-endpoint findings assembly (JEF-205, ADR-0019): the heavier `Props` builders that
//! coalesce a group of [`Finding`]s for one internet-facing entry into the dense-table row
//! ([`RowProps`]), the expanded detail body ([`DetailProps`]), the collapsed graph
//! ([`GraphProps`]), and the remediation card ([`RemediationProps`]). Split from the
//! `findings` helper module so each file stays under the 1,000-line cap. Pure data only — no
//! maud, no markup.

use super::{
    EvidenceProps, GlyphProps, Posture, RailProps, Tier, evidence_props, glyph_props,
    humanize_relation, is_broad, next_lever_tag, path_aria_label, plural, rail_facts, row_id,
    terminal_reach_clause, verdict_gist, what_to_do,
};
use crate::engine::dashboard::components::graph::{kind, short};
use crate::engine::dashboard::legacy::{EntryEvidence, Finding, relative_time};
use std::collections::{BTreeMap, BTreeSet};

/// One graph edge to draw, in render order. `cut` dashes the severing edge; `aggregate`
/// carries an explicit target label (the "47 secrets" fan-out node) keyed by `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    /// For an aggregate fan-out node, the explicit node label; `None` for a plain node
    /// (labeled by its short name).
    pub to_label: Option<String>,
    pub edge_label: String,
    pub cut: bool,
}

/// One coalesced fan-out group's expander data: the count, the pluralized kind, the relation
/// (untrusted, escaped at render), and the sorted member short-names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanoutGroup {
    pub count: usize,
    pub kind_plural: String,
    pub relation: String,
    pub members: Vec<String>,
}

/// The collapsed-graph data for one endpoint card (JEF-202): the source rows (built into
/// Mermaid by the component), the aria summary, the reach counts the summary names, and the
/// fan-out expanders for coalesced aggregate nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphProps {
    pub entry: String,
    pub entry_short: String,
    pub edges: Vec<GraphEdge>,
    pub aria: String,
    pub objectives: usize,
    pub hops: usize,
    pub broad: bool,
    pub fanouts: Vec<FanoutGroup>,
}

/// What the disposition-derived broad-reach lead reads, and whether the row is the calm
/// "working as intended" case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadLead {
    /// Not a broad endpoint (or broad + breach) — no lead, not calm.
    None,
    /// Broad + Safe — the calm "working as intended" row, no verbose lead.
    Calm,
    /// Broad + Awaiting — the honest one-line "model hasn't finished" note, not calm.
    AwaitingNote,
}

/// The expandable detail-row body data for one endpoint (JEF-202): the verbatim verdict +
/// posture, the broad-reach lead, the certainty rail, both evidence blocks, the collapsed
/// graph, and the disposition "what to do". Plain data; `components::findings::detail`
/// renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailProps {
    pub posture: Posture,
    /// The model's verdict VERBATIM (never paraphrased — ADR-0013); `None` ⇒ awaiting.
    pub verdict: Option<String>,
    pub broad_lead: BroadLead,
    pub rail: RailProps,
    pub evidence: EvidenceProps,
    pub graph: GraphProps,
    /// The disposition-derived "what to do" line (plain text, escaped at render).
    pub todo: String,
}

/// The computed metadata for one endpoint's dense table ROW (JEF-202).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowMeta {
    pub posture: Posture,
    pub objectives: usize,
    /// Whether the model cleared a broad entry → the calm "working as intended" row.
    pub calm: bool,
}

/// The summary-row cell data for one endpoint (JEF-202): the tier chip, the entry → reaches
/// cell, the verdict tag + clause, the evidence glyphs, the next-lever tag, and the row ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowProps {
    pub tier: Tier,
    pub row_id: String,
    pub detail_id: String,
    pub entry_short: String,
    pub reaches: String,
    pub verdict_tag: &'static str,
    pub verdict_tone: &'static str,
    pub verdict_clause: String,
    pub glyphs: GlyphProps,
    pub lever: &'static str,
    /// The pass-age phrase ("as of Nm ago") — already humanized.
    pub age: String,
    pub calm: bool,
}

/// A finding-pair (summary + detail) for one endpoint, the full Props pair the
/// `components::findings::row` + `::detail` renderers consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointProps {
    pub row: RowProps,
    pub detail: DetailProps,
}

/// Build the collapsed-graph + detail-body data for one endpoint (JEF-202), plus its row
/// metadata. Mirrors the legacy `endpoint_card_body`: terminal objectives sharing a (from,
/// relation, kind) are coalesced into one aggregate node; intermediate hops are deduped.
pub fn detail_props(entry: &str, fs: &[&Finding]) -> (DetailProps, RowMeta) {
    let mut seen_intermediate: BTreeSet<String> = BTreeSet::new();
    let mut groups: BTreeMap<(String, String, String), Vec<String>> = BTreeMap::new();
    let mut objectives = 0usize;
    let mut edges: Vec<GraphEdge> = Vec::new();

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
                edges.push(GraphEdge {
                    from: step.from.clone(),
                    to: step.to.clone(),
                    to_label: None,
                    edge_label: humanize_relation(&step.relation),
                    cut: false,
                });
            }
        }
    }

    for ((from, relation, kind), objs) in &groups {
        let label = humanize_relation(relation);
        if objs.len() == 1 {
            edges.push(GraphEdge {
                from: from.clone(),
                to: objs[0].clone(),
                to_label: None,
                edge_label: label,
                cut: false,
            });
        } else {
            let agg_key = format!("{kind}/__agg/{from}/{relation}");
            let agg_label = format!("{} {}", objs.len(), plural(kind, objs.len()));
            edges.push(GraphEdge {
                from: from.clone(),
                to: agg_key,
                to_label: Some(agg_label),
                edge_label: label,
                cut: false,
            });
        }
    }

    let hops = seen_intermediate.len() + groups.len();

    let verdict = fs.iter().find_map(|f| f.verdict.as_deref());
    let posture = Posture::of(verdict);

    let empty_evidence = EntryEvidence::default();
    let entry_evidence = fs.first().map(|f| &f.evidence).unwrap_or(&empty_evidence);

    let rail = rail_facts(entry, fs, entry_evidence);
    let evidence = evidence_props(entry_evidence);

    let broad = is_broad(objectives);
    let (broad_lead, calm) = if broad && posture == Posture::Safe {
        (BroadLead::Calm, true)
    } else if broad && posture == Posture::Awaiting {
        (BroadLead::AwaitingNote, false)
    } else {
        (BroadLead::None, false)
    };

    let todo = fs
        .first()
        .map(|f| what_to_do(f))
        .unwrap_or_else(|| "manual — no automatic cut classified for this path".to_string());

    let aria = path_aria_label(entry, fs);

    let fanouts: Vec<FanoutGroup> = groups
        .iter()
        .filter(|(_, objs)| objs.len() > 1)
        .map(|((_, relation, kind), objs)| {
            let mut members: Vec<String> = objs.iter().map(|o| short(o)).collect();
            members.sort();
            FanoutGroup {
                count: objs.len(),
                kind_plural: plural(kind, objs.len()),
                relation: relation.clone(),
                members,
            }
        })
        .collect();

    let graph = GraphProps {
        entry: entry.to_string(),
        entry_short: short(entry),
        edges,
        aria,
        objectives,
        hops,
        broad,
        fanouts,
    };

    let detail = DetailProps {
        posture,
        verdict: verdict.map(|v| v.to_string()),
        broad_lead,
        rail,
        evidence,
        graph,
        todo,
    };
    (
        detail,
        RowMeta {
            posture,
            objectives,
            calm,
        },
    )
}

/// Build the full summary-row + detail Props pair for one endpoint (JEF-202), at the tier the
/// ranking assigns. Mirrors the legacy `endpoint_row` inputs; `last_pass` drives the row's
/// pass-age cell.
pub fn endpoint_props(
    entry: &str,
    fs: &[&Finding],
    tier: Tier,
    last_pass: Option<std::time::SystemTime>,
) -> EndpointProps {
    let (detail, meta) = detail_props(entry, fs);
    let id = row_id(entry);
    let detail_id = format!("{id}-detail");

    let reaches = terminal_reach_clause(fs).unwrap_or_else(|| {
        format!(
            "{} target{}",
            meta.objectives,
            if meta.objectives == 1 { "" } else { "s" }
        )
    });

    let verdict = fs.iter().find_map(|f| f.verdict.as_deref());
    let empty = EntryEvidence::default();
    let ev = fs.first().map(|f| &f.evidence).unwrap_or(&empty);
    let (tag, clause) = verdict_gist(verdict, ev, fs);

    let awaiting = meta.posture == Posture::Awaiting;
    let corroborated = fs.iter().any(|f| f.corroborated);
    let glyphs = glyph_props(ev, corroborated, awaiting);

    let lever = if meta.calm {
        "working as intended"
    } else {
        fs.first().map_or("manual", |f| next_lever_tag(f))
    };

    let row = RowProps {
        tier,
        row_id: id,
        detail_id,
        entry_short: short(entry),
        reaches,
        verdict_tag: tag,
        verdict_tone: meta.posture.tone(),
        verdict_clause: clause,
        glyphs,
        lever,
        age: relative_time(last_pass),
        calm: meta.calm,
    };
    EndpointProps { row, detail }
}

// ---- remediation card (the auto-eligible cut, with the severing edge dashed) ----------

/// The killchain attack-steps for the remediation card (JEF-176): the plain technique name
/// leads, with the MITRE code tucked into an `<abbr>` tooltip. The foothold half is present
/// when the entry is an exploitable front door. All values come from a closed ATT&CK
/// catalogue, so they are not untrusted free-text (escaped anyway at render).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillchainProps {
    pub foothold: bool,
    pub technique: String,
    pub technique_name: String,
}

/// One remediation card's plain data (JEF-161): the verbatim verdict + posture, the
/// certainty rail, both evidence blocks, the kill-chain caption, the cut-marked graph, and
/// the disposition "what to do". One chain ⇒ the rail/graph are built over that single
/// finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationProps {
    pub posture: Posture,
    pub verdict: Option<String>,
    pub rail: RailProps,
    pub evidence: EvidenceProps,
    pub killchain: KillchainProps,
    pub graph: GraphProps,
    pub todo: String,
    /// Whether the cut is applied (armed) vs proposed (shadow) — the caption's status.
    pub armed: bool,
}

/// Build the remediation card data for one auto-eligible finding (JEF-161). The graph is the
/// single chain's path with the severing edge dashed; `cut` matches the finding's recorded
/// cut signature.
pub fn remediation_props(f: &Finding, armed: bool) -> RemediationProps {
    let one = std::slice::from_ref(&f);
    let mut edges: Vec<GraphEdge> = Vec::new();
    for step in &f.path {
        let sig = format!("{} -[{}]-> {}", step.from, step.relation, step.to);
        let is_cut = f.cut.as_deref() == Some(sig.as_str());
        let label = if is_cut {
            "✂ NetworkPolicy cut".to_string()
        } else {
            humanize_relation(&step.relation)
        };
        edges.push(GraphEdge {
            from: step.from.clone(),
            to: step.to.clone(),
            to_label: None,
            edge_label: label,
            cut: is_cut,
        });
    }
    let graph = GraphProps {
        entry: f.entry.clone(),
        entry_short: short(&f.entry),
        edges,
        aria: path_aria_label(&f.entry, one),
        // The remediation graph is a single chain; reach/hops/fanout are unused by its
        // (non-collapsible) caption, so leave them at the chain's natural values.
        objectives: 1,
        hops: f.path.len(),
        broad: false,
        fanouts: Vec::new(),
    };
    RemediationProps {
        posture: Posture::of(f.verdict.as_deref()),
        verdict: f.verdict.clone(),
        rail: rail_facts(&f.entry, one, &f.evidence),
        evidence: evidence_props(&f.evidence),
        killchain: KillchainProps {
            foothold: f.foothold,
            technique: f.technique.clone(),
            technique_name: f.technique_name.clone(),
        },
        graph,
        todo: what_to_do(f),
        armed,
    }
}
