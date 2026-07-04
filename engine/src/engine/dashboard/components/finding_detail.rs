//! The expand-in-place "why" panel for a finding (brief §5): the verbatim verdict → the proven
//! path as an indented chain staircase (structural hops muted, the severable edge marked ✂) → the
//! evidence tables → the proposed/applied cut signature → the "show model prompt" disclosure to
//! the raw judgement. Pure component; no domain types; all free-text auto-escaped.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::{FindingProps, HopProps, JudgementProps};

use super::evidence::evidence_tables;

/// Render the full detail panel for a finding.
pub(super) fn detail_panel(f: &FindingProps) -> Markup {
    html! {
        div class={ "detail rail-" (f.posture.token()) } {
            (verdict_block(f))
            (path_block(f))
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

/// The deepest indent step the staircase cascades to before it stops stepping further right.
/// Beyond this depth every remaining hop sits at the same (maximum) indent so a very long path
/// never marches off the panel. The matching `.chain-step-0..=MAX` padding rules live in the CSS.
const CHAIN_STEP_MAX: usize = 6;

/// The depth class for a hop at index `step` (entry = 0), capped at `CHAIN_STEP_MAX` so the
/// staircase reads as a cascade without ever overflowing the panel.
fn chain_step_class(step: usize) -> String {
    format!("chain-step-{}", step.min(CHAIN_STEP_MAX))
}

/// The number of proven paths shown OPEN by default before the rest fold into an expandable
/// disclosure (JEF-281). Enough to make redundancy visible immediately (the common no-cut shape
/// is two paths) while a wide objective stays collapsed-by-default but one click from the full set.
const PATHS_SHOWN_OPEN: usize = 3;

/// The proven path(s) as **vertical chain diagrams** (brief §3 / JEF-281). When the objective is
/// reachable ONE way this is a single staircase — the internet/entry node at the top, each hop
/// indented one step deeper, the severable edge marked ✂ "cut here". When it is reachable SEVERAL
/// ways (a wide finding) it renders ALL the proven paths as stacked staircases, edges shared by
/// every path marked so the redundancy is visible — and when no single edge severs the chain, the
/// multiple paths ARE the reason, stated in the header line. Honest when no path is recorded.
fn path_block(f: &FindingProps) -> Markup {
    // The complete proven-path set (the view_model always fills at least the representative path);
    // drop any empty path defensively so a lone empty entry reads as "no path recorded".
    let paths: Vec<&Vec<HopProps>> = f.paths.iter().filter(|p| !p.is_empty()).collect();
    let multi = paths.len() > 1;
    html! {
        section.detail-section.path-block {
            h3.detail-h { (if multi { "proven paths" } else { "proven path" }) }
            @if paths.is_empty() {
                p.muted { "no path recorded" }
            } @else if multi {
                (paths_summary(paths.len(), f.cut.is_some()))
                (stacked_paths(&paths, f.paths_truncated))
            } @else {
                (chain_diagram(paths[0]))
            }
        }
    }
}

/// The one-line legibility header for a multi-path finding (JEF-281): how many proven paths reach
/// the objective, and — the crux — whether any single edge severs them. When there is no
/// single-edge cut, the several redundant paths ARE the explanation, so we say so in words.
fn paths_summary(n: usize, has_cut: bool) -> Markup {
    html! {
        p.paths-summary {
            "reachable via " span.paths-count { (n) } " redundant paths"
            @if has_cut {
                " \u{2014} one shared edge severs all (marked \u{2702})"
            } @else {
                " \u{2014} no single edge severs the objective"
            }
        }
    }
}

/// The stacked proven paths: the first [`PATHS_SHOWN_OPEN`] rendered open, the rest folded into a
/// native `<details>` disclosure (server-rendered, no JS — the fan-out stays collapsed by default
/// but the operator can expand to the full picture, JEF-281). A `truncated` set adds an honest
/// bounded "+more" note rather than an unbounded wall.
fn stacked_paths(paths: &[&Vec<HopProps>], truncated: bool) -> Markup {
    let shown = paths.len().min(PATHS_SHOWN_OPEN);
    html! {
        div.paths {
            @for (i, p) in paths.iter().take(shown).enumerate() {
                (labelled_path(i + 1, p))
            }
            @if paths.len() > shown {
                details.more-paths {
                    summary.why-toggle role="button" aria-expanded="false" {
                        "show " (paths.len() - shown) " more path"
                        @if paths.len() - shown != 1 { "s" }
                    }
                    div.more-paths-body {
                        @for (i, p) in paths.iter().enumerate().skip(shown) {
                            (labelled_path(i + 1, p))
                        }
                        @if truncated {
                            p.muted.more-paths-note { "+ more proven paths exist (bounded)" }
                        }
                    }
                }
            } @else if truncated {
                p.muted.more-paths-note { "+ more proven paths exist (bounded)" }
            }
        }
    }
}

/// One numbered path in the stack — a "path N" label above its chain staircase, so the operator
/// can tell the redundant routes apart.
fn labelled_path(n: usize, path: &[HopProps]) -> Markup {
    html! {
        div.path-alt {
            span.path-alt-label { "path " (n) }
            (chain_diagram(path))
        }
    }
}

/// One proven path as the vertical chain staircase: the entry node at step 0, then each hop's
/// labelled connector edge + its `to` node one indent deeper, cascading to the emphasized
/// objective. The severable edge is marked ✂; edges shared across every path are marked too.
fn chain_diagram(path: &[HopProps]) -> Markup {
    html! {
        ol.chain aria-label="proven attack path, entry to objective" {
            // The entry node (top of the chain, step 0) — the very first hop's `from`.
            (chain_node(&path[0].from_glyph, &path[0].from, 0, true, false))
            // Then, for each hop, the labelled connector edge and its `to` node, each indented one
            // step deeper than the previous so the path cascades; the last hop's `to` is the
            // objective node, emphasized.
            @for (i, hop) in path.iter().enumerate() {
                (chain_edge(hop, i + 1))
                (chain_node(
                    &hop.to_glyph,
                    &hop.to,
                    i + 1,
                    false,
                    i == path.len() - 1, // the final node is the objective
                ))
            }
        }
    }
}

/// One node in the vertical chain: its node-kind glyph + label on its own line, threaded onto the
/// connector spine and indented to its `step` depth (the staircase). The entry node and the
/// objective node are emphasized; intermediate nodes are plain (structural muting rides on the
/// *edge*, not the node).
fn chain_node(glyph: &str, label: &str, step: usize, is_entry: bool, is_objective: bool) -> Markup {
    let depth = chain_step_class(step);
    let role = if is_entry {
        format!("chain-node chain-entry {depth}")
    } else if is_objective {
        format!("chain-node chain-objective {depth}")
    } else {
        format!("chain-node {depth}")
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

/// The labelled connector edge between two nodes: the relation, riding the spine, indented to the
/// `step` of the node it leads into so the staircase reads as one descent. A structural
/// (substrate) edge is muted; the severable edge carries the prominent ✂ "cut here" marker in the
/// breach colour — the actionable heart of the diagram (brief §3).
fn chain_edge(hop: &HopProps, step: usize) -> Markup {
    let depth = chain_step_class(step);
    let mut cls = if hop.is_cut {
        format!("chain-edge chain-edge-cut {depth}")
    } else if hop.structural {
        format!("chain-edge chain-edge-structural {depth}")
    } else {
        format!("chain-edge {depth}")
    };
    // An edge on EVERY proven path is a shared bottleneck — a single-edge-cut candidate (JEF-281).
    if hop.shared {
        cls.push_str(" chain-edge-shared");
    }
    html! {
        li class=(cls) {
            span.chain-rel { span.chain-rel-line aria-hidden="true" { "\u{2500}[" } (hop.relation) span.chain-rel-line aria-hidden="true" { "]\u{2192}" } }
            @if hop.is_cut {
                span.chain-cut title="minimal cut severs this edge" {
                    span.chain-cut-glyph { "\u{2702}" }
                    span.chain-cut-label { "cut here" }
                }
            } @else if hop.shared {
                // Shared-but-not-the-cut: mark it so the operator sees the common bottleneck.
                span.chain-shared title="on every proven path \u{2014} a shared bottleneck" { "shared" }
            }
        }
    }
}

/// The proposed/applied cut signature. When there is no single-edge cut, that is stated honestly
/// rather than left blank.
fn cut_block(f: &FindingProps) -> Markup {
    html! {
        section.detail-section.cut-block {
            h3.detail-h { "proposed cut" }
            @match &f.cut {
                Some(cut) => {
                    p.cut-sig { code { (cut) } }
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
