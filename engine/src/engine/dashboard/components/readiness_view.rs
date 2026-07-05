//! The Readiness view body (brief §6): one row per decision input — its honest
//! Present/Absent/Degraded state (colour + glyph + word, never colour alone), the live detail,
//! why it matters, and the env var to enable it. Inputs that WEAKEN decisions when absent float
//! to the top and carry an amber keyline; an absent weakening input shows its "how to enable"
//! instruction prominently (the per-feed enablement surface the operator asked for). Pure
//! component; no domain types.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::{
    NodeRowProps, ParityReportProps, ReadinessRowProps, ReadinessViewProps,
};

/// Render the Readiness view: the coverage rows and the corroboration-parity panel under the
/// persistent strip (composed by `page`).
pub fn readiness_view(v: &ReadinessViewProps) -> Markup {
    html! {
        main.view.view-readiness {
            section.coverage-detail aria-label="decision-input coverage" {
                h2.section-h.t-h2 { "decision inputs" }
                p.section-sub.t-body.muted {
                    "every input the model leans on to decide \u{2014} its live state, why it matters, \
                     and how to enable it. A weakening input that is absent is shown first."
                }
                ul.cov-rows {
                    @for row in &v.rows {
                        (coverage_row(row))
                    }
                }
            }
            (parity_panel(&v.parity))
        }
    }
}

/// The corroboration-parity panel (JEF-310, Falco-retirement F6): the Falco-vs-agent
/// corroboration split and the HONEST retirement reading. The state chip carries colour + glyph +
/// word (never colour alone); "nothing to compare" renders as its own non-green state so a
/// Falco-silent window never reads as a reassuring "0 uncovered = safe to retire" (ADR-0016). The
/// uncovered workload names are UNTRUSTED — maud auto-escapes them (never `PreEscaped`).
fn parity_panel(p: &ParityReportProps) -> Markup {
    html! {
        section.parity-detail aria-label="Falco-retirement corroboration parity"
            data-state=(p.state.token())
        {
            h2.section-h.t-h2 { "Falco-retirement corroboration parity" }
            p.section-sub.t-body.muted {
                "while both sensors run, each breach-chain corroboration is attributed to its source. \
                 The agent is ready to replace Falco when the agent-uncovered count (Falco saw it, the \
                 agent didn\u{2019}t) holds at 0 over a bake \u{2014} a window with no Falco alerts is \
                 \u{201c}nothing to compare\u{201d}, not a go-signal."
            }
            div.parity-head {
                span class={ "parity-state parity-" (p.state.token()) } {
                    span.parity-state-glyph aria-hidden="true" { (p.state.glyph()) }
                    " "
                    span.parity-state-word { (p.state.word()) }
                }
            }
            p.parity-summary.t-data { (p.summary) }
            ul.parity-counts.t-data {
                li { span.parity-count-label { "agent-uncovered (Falco-only)" } " " span.parity-count-val { (p.agent_uncovered) } }
                li { span.parity-count-label { "corroborated by both" } " " span.parity-count-val { (p.both) } }
                li { span.parity-count-label { "Falco corroborations" } " " span.parity-count-val { (p.falco_corroborated) } }
                li { span.parity-count-label { "agent corroborations" } " " span.parity-count-val { (p.agent_corroborated) } }
            }
            @if !p.uncovered_entries.is_empty() {
                details.parity-uncovered {
                    summary.parity-uncovered-summary.t-micro {
                        (p.uncovered_entries.len())
                        " agent-uncovered workload"
                        (if p.uncovered_entries.len() == 1 { "" } else { "s" })
                    }
                    ul.parity-uncovered-list.t-data {
                        @for entry in &p.uncovered_entries {
                            li.parity-uncovered-item { (entry) }
                        }
                    }
                }
            }
        }
    }
}

/// One coverage row. The state chip carries colour + glyph + word; an absent/degraded WEAKENING
/// input gets an amber keyline (style guide: `weakens_decisions` + absent → amber keyline) and
/// surfaces its enablement instruction. The detail is the live, honest line (a count, "last call
/// ok", or "no signals (quiet, or sensor down)").
fn coverage_row(r: &ReadinessRowProps) -> Markup {
    // A weakening input that isn't present is the attention case (amber keyline + how-to-enable).
    let weak_gap = r.weakens_decisions && !r.state.is_present();
    let li_class = if weak_gap {
        "cov-row cov-row-gap"
    } else {
        "cov-row"
    };
    html! {
        li class=(li_class) data-input=(r.id) data-state=(r.state.token()) {
            div.cov-row-head {
                span class={ "cov-state cov-" (r.state.token()) } {
                    span.cov-state-glyph aria-hidden="true" { (r.state.glyph()) }
                    span.cov-state-word { (r.state.word()) }
                }
                span.cov-row-label.t-data-strong { (r.label) }
                @if r.weakens_decisions {
                    span.cov-weakens.t-micro title="absence weakens the model's decision" {
                        "weakens decisions"
                    }
                }
            }
            p.cov-detail.t-data { (r.detail) }
            p.cov-why.t-body.muted { (r.why) }
            // The per-node runtime-corroboration breakdown (JEF-308) — a server-rendered table
            // inside <details> (NO JS, per the maud/server-render convention). Only the
            // runtime-corroboration row carries nodes; every other row skips this.
            @if !r.nodes.is_empty() {
                (node_breakdown(&r.nodes))
            }
            // The how-to-enable instruction: always shown when there is an env var/mount, and read
            // as an action ("enable with …") when the input is an absent weakening gap.
            @if !r.enable.is_empty() {
                p class={ "cov-enable t-data" @if weak_gap { " cov-enable-action" } } {
                    span.cov-enable-label.t-micro {
                        @if weak_gap { "enable with" } @else { "configured via" }
                    }
                    " "
                    code.cov-enable-var { (r.enable) }
                }
            }
        }
    }
}

/// The per-node runtime-corroboration breakdown (JEF-308): a server-rendered `<table>` inside a
/// `<details>` disclosure — NO client JS (the maud/server-render convention). Each row is a node,
/// its honest state (colour + glyph + word, never colour alone), and a live detail. Node names are
/// UNTRUSTED — maud auto-escapes them (never `PreEscaped`).
fn node_breakdown(nodes: &[NodeRowProps]) -> Markup {
    let blind = nodes.iter().filter(|n| n.state.token() == "blind").count();
    html! {
        details.cov-nodes {
            summary.cov-nodes-summary.t-micro {
                (nodes.len()) " node" (if nodes.len() == 1 { "" } else { "s" })
                @if blind > 0 { " \u{2014} " (blind) " blind" }
            }
            table.cov-nodes-table {
                thead {
                    tr { th { "node" } th { "state" } th { "detail" } }
                }
                tbody {
                    @for n in nodes {
                        tr data-state=(n.state.token()) {
                            td.cov-node-name { (n.node) }
                            td {
                                span class={ "node-state node-" (n.state.token()) } {
                                    span.node-state-glyph aria-hidden="true" { (n.state.glyph()) }
                                    " "
                                    span.node-state-word { (n.state.word()) }
                                }
                            }
                            td.cov-node-detail { (n.detail) }
                        }
                    }
                }
            }
        }
    }
}
