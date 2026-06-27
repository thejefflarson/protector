//! The findings graph block (JEF-205): turns a [`GraphProps`] into the Mermaid source and
//! the collapsed `<details>` that wraps the `<pre class="mermaid">`. Pure `Props -> Markup`;
//! imports only its props + maud + the `components::graph` builder. NO `engine::` domain type.

use crate::engine::dashboard::components::graph::{Mermaid, mermaid_pre};
use crate::engine::dashboard::view_model::findings::{FanoutGroup, GraphProps};
use maud::{Markup, html};

/// One coalesced fan-out group's `<details>` expander (JEF-202): the members hidden behind a
/// summary naming the count, kind, and (escaped) relation. Rendered AFTER the "what to do"
/// line by the detail/remediation body, so the legacy `<div class="expand">` ordering holds.
pub fn fanout_expanders(groups: &[FanoutGroup]) -> Markup {
    html! {
        @if !groups.is_empty() {
            div class="expand" {
                @for group in groups {
                    (fanout(group))
                }
            }
        }
    }
}

/// Build the Mermaid source for a graph's edges: the Internet source first, then each edge
/// (a plain node, an aggregate fan-out node, or a dashed cut). Every label is `mm`-sanitized
/// by the builder as it is added, so the [`mermaid_pre`] body is the audited `PreEscaped`.
fn source(g: &GraphProps) -> String {
    let mut m = Mermaid::default();
    m.add_internet(&g.entry);
    for e in &g.edges {
        match &e.to_label {
            Some(label) => m.edge_to_labeled(&e.from, &e.to, label, &e.edge_label),
            None => m.edge(&e.from, &e.to, &e.edge_label, e.cut),
        }
    }
    m.finish()
}

/// One coalesced fan-out group's `<details>` expander: the members hidden behind a summary
/// naming the count, kind, and (escaped) relation.
fn fanout(group: &FanoutGroup) -> Markup {
    html! {
        details {
            summary {
                (group.count) " " (group.kind_plural) " "
                span class="muted" { "via " (group.relation) }
            }
            ul {
                @for name in &group.members {
                    li { (name) }
                }
            }
        }
    }
}

/// The collapsed attack-path graph for an endpoint card (JEF-202): the caption, the graph
/// inside a `details.graphwrap` so it stays collapsed-by-default for every tier (open on
/// demand), and the fan-out expanders for coalesced aggregate nodes.
pub fn graph(g: &GraphProps) -> Markup {
    let summary = if g.broad {
        format!(
            "show what it can reach ({} target{})",
            g.objectives,
            if g.objectives == 1 { "" } else { "s" },
        )
    } else {
        format!(
            "show attack path ({} hop{})",
            g.hops,
            if g.hops == 1 { "" } else { "s" },
        )
    };
    let src = source(g);
    html! {
        div class="kc2" {
            "the picture of those facts — "
            span class="muted" {
                (g.entry_short) " (" (g.objectives) " target"
                @if g.objectives != 1 { "s" }
                " reachable)"
            }
        }
        details class="graphwrap" {
            summary { (summary) }
            (mermaid_pre(&src, &g.aria))
        }
    }
}
