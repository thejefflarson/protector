//! The remediation card (JEF-161): one auto-eligible cut shown as the verbatim verdict, the
//! certainty rail, both evidence blocks, the kill-chain caption + a graph of the path with
//! the severing edge dashed, and the disposition "what to do". Unlike the dense-table detail
//! body, the remediation graph is NOT collapsed (it is the headline of the card). Pure
//! `Props -> Markup`; imports only its props + maud + sibling findings components. NO
//! `engine::` domain type.

use crate::engine::dashboard::components::findings::detail::verdict_line;
use crate::engine::dashboard::components::findings::evidence::evidence;
use crate::engine::dashboard::components::findings::rail::rail;
use crate::engine::dashboard::components::graph::{Mermaid, mermaid_pre};
use crate::engine::dashboard::view_model::findings::{KillchainProps, RemediationProps};
use maud::{Markup, html};

/// The kill-chain attack steps (JEF-176): the plain technique name leads, the MITRE code
/// tucked into an `<abbr>` tooltip; the foothold half is present for an exploitable front
/// door. The technique id/name come from a closed ATT&CK catalogue (not untrusted), escaped
/// anyway by the auto-escaping maud braces (defence in depth).
fn killchain(kc: &KillchainProps) -> Markup {
    html! {
        @if kc.foothold {
            abbr title="T1190 Exploit Public-Facing Application" {
                "break in through an internet-facing service"
            }
            " → "
        }
        abbr title=(format!("{} {}", kc.technique, kc.technique_name)) {
            (kc.technique_name)
        }
    }
}

/// The Mermaid source for the remediation graph: the Internet source, then the chain's hops
/// with the severing edge dashed. Every label is `mm`-sanitized by the builder.
fn source(props: &RemediationProps) -> String {
    let mut m = Mermaid::default();
    m.add_internet(&props.graph.entry);
    for e in &props.graph.edges {
        m.edge(&e.from, &e.to, &e.edge_label, e.cut);
    }
    m.finish()
}

/// One remediation card (JEF-161): verdict-first, the proof rail, both evidence blocks, the
/// attack-steps caption + the cut-marked (non-collapsed) graph, and the "what to do".
pub fn remediation(props: &RemediationProps) -> Markup {
    let src = source(props);
    html! {
        div class="card" {
            (verdict_line(props.posture, props.verdict.as_deref()))
            (rail(&props.rail))
            (evidence(&props.evidence))
            div class="kc2" {
                "the picture of those facts — attack steps: " (killchain(&props.killchain)) "  "
                @if props.armed {
                    span class="applied" { "applied" }
                } @else {
                    span class="proposed" { "would apply (shadow)" }
                }
            }
            (mermaid_pre(&src, &props.graph.aria))
            @if let Some(todo) = &props.todo {
                div class="todo" { b { "what to do:" } " " (todo) }
            }
        }
    }
}
