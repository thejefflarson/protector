//! The expand-in-place "why" panel for a finding (brief §5): the verbatim verdict → the proven
//! path as a text hop-list (structural hops muted, the cut point marked) → the evidence tables
//! → the proposed/applied cut + its self-revert condition → the "show model prompt" disclosure
//! to the raw judgement. Pure component; no domain types; all free-text auto-escaped.

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
            (model_prompt(&f.judgement))
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

/// The proven path as a text hop-list: `entry ─relation→ … → objective`. Structural hops are
/// muted; the cut point is marked.
fn path_block(path: &[HopProps]) -> Markup {
    html! {
        section.detail-section.path-block {
            h3.detail-h { "proven path" }
            @if path.is_empty() {
                p.muted { "no path recorded" }
            } @else {
                ol.hop-list {
                    @for hop in path {
                        (hop_item(hop))
                    }
                }
            }
        }
    }
}

/// One hop in the list. A structural (substrate) hop is muted; the cut hop carries the scissors.
fn hop_item(hop: &HopProps) -> Markup {
    let cls = if hop.structural {
        "hop hop-structural"
    } else {
        "hop"
    };
    html! {
        li class=(cls) {
            span.hop-from { (hop.from) }
            span.hop-rel { " \u{2500}[" (hop.relation) "]\u{2192} " }
            span.hop-to { (hop.to) }
            @if hop.is_cut {
                span.hop-cut title="minimal cut severs here" { " \u{2702} cut" }
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
fn model_prompt(j: &JudgementProps) -> Markup {
    html! {
        details.model-prompt {
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
