//! The attack-path renderer (JEF-255): the proven path as a TEXT hop-list, not a graph (the
//! Mermaid bundle is retired). Pure `HopList -> Markup`; imports no `engine::` domain type
//! (ADR-0019). Every node/relation token is auto-escaped at the maud brace.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::hops::HopList;

/// Render the hop-list as an ordered text ladder:
/// ```text
/// web (internet-reachable)
///  └→ reaches store     ✂ cut here (arm network)
///     └→ can read session-key   ← objective
/// ```
pub fn hops(list: &HopList) -> Markup {
    html! {
        div class="hops" role="group" aria-label="proven attack path" {
            div class="hop hop-entry" {
                b { (list.entry) }
                @if list.internet_reachable {
                    " " span class="hop-net" { "(internet-reachable)" }
                }
            }
            @for (i, hop) in list.hops.iter().enumerate() {
                div class=(format!("hop hop-step depth-{}", (i + 1).min(6))) {
                    span class="hop-arm" aria-hidden="true" { "└→ " }
                    span class="hop-rel" { (hop.relation) } " "
                    span class="hop-node" { (hop.node) }
                    @if hop.is_objective {
                        " " span class="hop-objective" { "← objective" }
                    }
                    @if hop.is_cut {
                        @if let Some(note) = &list.cut_note {
                            " " span class="hop-cut" { (note) }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::view_model::hops::Hop;

    fn list() -> HopList {
        HopList {
            entry: "Pod/web".into(),
            internet_reachable: true,
            hops: vec![
                Hop {
                    relation: "reaches".into(),
                    node: "Pod/store".into(),
                    is_cut: true,
                    is_objective: false,
                },
                Hop {
                    relation: "can read".into(),
                    node: "session-key".into(),
                    is_cut: false,
                    is_objective: true,
                },
            ],
            cut_note: Some("✂ cut here (arm network)".into()),
        }
    }

    #[test]
    fn renders_entry_hops_cut_and_objective() {
        let m = hops(&list()).into_string();
        assert!(m.contains("Pod/web"));
        assert!(m.contains("(internet-reachable)"));
        assert!(m.contains("reaches"));
        assert!(m.contains("✂ cut here (arm network)"));
        assert!(m.contains("← objective"));
        assert!(!m.contains("<svg"), "no graph — text only");
    }

    #[test]
    fn node_names_are_escaped() {
        let mut l = list();
        l.hops[0].node = "<img src=x onerror=alert(1)>".into();
        let m = hops(&l).into_string();
        assert!(!m.contains("<img src=x"));
        assert!(m.contains("&lt;img"));
    }
}
