//! The expand-in-place "why" panel for a finding (brief §5): the verbatim verdict → the proven
//! path as a vertical chain diagram (structural hops muted, the severable edge marked ✂) → the
//! evidence tables → the proposed/applied cut + its self-revert condition → the "show model
//! prompt" disclosure to the raw judgement. Pure component; no domain types; all free-text
//! auto-escaped.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::{FindingProps, HopProps, JudgementProps};

use super::evidence::evidence_tables;

/// Render the full detail panel for a finding.
pub(super) fn detail_panel(f: &FindingProps) -> Markup {
    html! {
        div class={ "detail rail-" (f.posture.token()) } {
            (verdict_block(f))
            (path_block(&f.path))
            (evidence_tables(&f.evidence))
            (cut_block(f))
            (model_prompt(&f.id, &f.judgement))
        }
    }
}

/// The verbatim model verdict — the model's own words first (brief: "why" is one click away).
fn verdict_block(f: &FindingProps) -> Markup {
    html! {
        section.detail-section.verdict-block {
            h3.detail-h { "verdict" }
            @match &f.verdict_summary {
                Some(v) => p.verdict-prose { (v) }
                None => p.verdict-prose.muted { "awaiting judgement \u{2014} the model has not judged this entry yet" }
            }
        }
    }
}

/// The proven path as a **vertical chain diagram** (brief §3): the internet/entry node at the
/// top, each hop flowing down a connector spine to the objective node at the bottom. Each node
/// carries its node-kind glyph + label; the relation is the labelled connector between nodes; the
/// severable edge is marked with a prominent ✂ "cut here". Structural hops are muted; the
/// objective node is emphasized. Honest when no path is recorded.
fn path_block(path: &[HopProps]) -> Markup {
    html! {
        section.detail-section.path-block {
            h3.detail-h { "proven path" }
            @if path.is_empty() {
                p.muted { "no path recorded" }
            } @else {
                ol.chain aria-label="proven attack path, entry to objective" {
                    // The entry node (top of the chain) — the very first hop's `from`.
                    (chain_node(&path[0].from_glyph, &path[0].from, true, false))
                    // Then, for each hop, the labelled connector edge and its `to` node. The last
                    // hop's `to` is the objective node, emphasized.
                    @for (i, hop) in path.iter().enumerate() {
                        (chain_edge(hop))
                        (chain_node(
                            &hop.to_glyph,
                            &hop.to,
                            false,
                            i == path.len() - 1, // the final node is the objective
                        ))
                    }
                }
            }
        }
    }
}

/// One node in the vertical chain: its node-kind glyph + label on its own line, threaded onto the
/// connector spine. The entry node and the objective node are emphasized; intermediate nodes are
/// plain (structural muting rides on the *edge*, not the node).
fn chain_node(glyph: &str, label: &str, is_entry: bool, is_objective: bool) -> Markup {
    let role = if is_entry {
        "chain-node chain-entry"
    } else if is_objective {
        "chain-node chain-objective"
    } else {
        "chain-node"
    };
    html! {
        li class=(role) {
            span.chain-dot aria-hidden="true" {}
            span.chain-glyph { (glyph) }
            span.chain-label { (label) }
            @if is_objective {
                span.chain-tag { "objective" }
            } @else if is_entry {
                span.chain-tag { "entry" }
            }
        }
    }
}

/// The labelled connector edge between two nodes: the relation, riding the spine. A structural
/// (substrate) edge is muted; the severable edge carries the prominent ✂ "cut here" marker in the
/// breach colour — the actionable heart of the diagram (brief §3).
fn chain_edge(hop: &HopProps) -> Markup {
    let cls = if hop.is_cut {
        "chain-edge chain-edge-cut"
    } else if hop.structural {
        "chain-edge chain-edge-structural"
    } else {
        "chain-edge"
    };
    html! {
        li class=(cls) {
            span.chain-rel { span.chain-rel-line aria-hidden="true" { "\u{2500}[" } (hop.relation) span.chain-rel-line aria-hidden="true" { "]\u{2192}" } }
            @if hop.is_cut {
                span.chain-cut title="minimal cut severs this edge" {
                    span.chain-cut-glyph { "\u{2702}" }
                    span.chain-cut-label { "cut here" }
                }
            }
        }
    }
}

/// The proposed/applied cut + its self-revert condition (the safety story). When there is no
/// single-edge cut, that is stated honestly rather than left blank.
fn cut_block(f: &FindingProps) -> Markup {
    html! {
        section.detail-section.cut-block {
            h3.detail-h { "proposed cut" }
            @match &f.cut {
                Some(cut) => {
                    p.cut-sig { code { (cut) } }
                    p.cut-revert.muted {
                        "self-reverts when the breach condition clears \u{2014} the cut persists "
                        "only while the chain \u{2227} its enrichment fingerprint hold (ADR-0017)."
                    }
                }
                None => p.muted { "no single-edge cut \u{2014} this chain is not severable by one network edge" }
            }
        }
    }
}

/// The "show model prompt" disclosure to the raw judgement (prompt + reply). Nested
/// `<details>` so it is collapsed by default; honest about an absent prompt/reply.
fn model_prompt(id: &str, j: &JudgementProps) -> Markup {
    html! {
        // `data-prompt` keys this disclosure so the client can persist its open state across the
        // /fragment poll swap (otherwise it would snap shut every poll while being read).
        details.model-prompt data-prompt=(id) {
            summary.why-toggle role="button" aria-expanded="false" { "show model prompt" }
            div.prompt-body {
                @match &j.verdict {
                    Some(v) => p.prompt-verdict { "final verdict: " span.mono { (v) } }
                    None => p.muted { "no verdict recorded for this entry" }
                }
                h4.detail-h { "prompt" }
                @match &j.prompt {
                    Some(p) => pre.prompt-text { (p) }
                    None => p.muted { "no prompt \u{2014} the deterministic pre-filter decided without asking the model" }
                }
                h4.detail-h { "reply" }
                @match &j.reply {
                    Some(r) => pre.prompt-text { (r) }
                    None => p.muted { "no reply \u{2014} the model was unavailable (timed out)" }
                }
            }
        }
    }
}
