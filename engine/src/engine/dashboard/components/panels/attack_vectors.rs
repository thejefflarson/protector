//! The attack-vectors panel — "what an attacker could reach" (ADR-0013), migrated to maud
//! (ADR-0019).
//!
//! PRESENTATION ONLY: this renderer takes its [`AttackVectorsProps`] and nothing else. It
//! imports NO `engine::` domain type — only its props (from the `view_model`) and maud.
//! The tactic / technique text goes through auto-escaping `( )` braces, including the
//! `<abbr title>` attribute value (ADR-0019). This is the per-ATT&CK-technique overview that
//! sits above the per-endpoint graphs: how many distinct objectives are reachable, and how
//! many the model affirmed exploitable.

use crate::engine::dashboard::view_model::AttackVectorsProps;
use maud::{Markup, html};

/// The attack-vectors table, or the empty state when nothing reaches a target. Pure
/// `Props -> Markup`.
pub fn attack_vectors(props: &AttackVectorsProps) -> Markup {
    if props.rows.is_empty() {
        return html! { p class="muted" { "no internet-facing service can reach a target" } };
    }
    html! {
        table class="vectors" {
            thead {
                tr {
                    th { "Tactic" } th { "Technique" }
                    th { "Reachable" } th { "Model-flagged" }
                }
            }
            tbody {
                @for row in &props.rows {
                    tr {
                        td { (row.tactic) }
                        td {
                            abbr title=(format!("{} {}", row.technique_id, row.technique_name)) {
                                (row.technique_name)
                            }
                        }
                        td { (row.reachable) }
                        td {
                            @if row.flagged == 0 {
                                span class="muted" { "—" }
                            } @else {
                                span class="flagged" { (row.flagged) }
                            }
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
    use crate::engine::dashboard::model::{EntryEvidence, Finding};
    use crate::engine::dashboard::view_model::attack_vectors_props;

    fn finding(objective: &str, breach_relevant: bool, verdict: Option<&str>) -> Finding {
        Finding {
            entry: "workload/app/Pod/web".into(),
            objective: objective.into(),
            tactic: "TA0006".into(),
            tactic_name: "Credential Access".into(),
            technique: "T1552".into(),
            technique_name: "Unsecured Credentials".into(),
            foothold: false,
            corroborated: false,
            adjudicated: true,
            promoted: false,
            disposition: "no-cut".into(),
            cut: None,
            breach_relevant,
            killchain: String::new(),
            verdict: verdict.map(str::to_string),
            path: Vec::new(),
            evidence: EntryEvidence::default(),
        }
    }

    fn render(findings: &[Finding]) -> String {
        attack_vectors(&attack_vectors_props(findings)).into_string()
    }

    #[test]
    fn empty_state_when_nothing_reaches_a_target() {
        let panel = render(&[finding("secret/app/s", false, None)]);
        assert!(panel.contains("no internet-facing service can reach a target"));
        assert!(!panel.contains("<table"), "no table when there are no rows");
    }

    /// Byte-stability with the legacy `attack_vectors`: a reachable, model-flagged technique
    /// must be byte-for-byte the old string-concat output.
    #[test]
    fn attack_vectors_output_is_byte_stable_with_the_legacy_string_concat() {
        let got = render(&[
            finding("secret/app/a", true, Some("exploitable — RCE")),
            finding("secret/app/b", true, None),
        ]);
        let want = "<table class=\"vectors\"><thead><tr><th>Tactic</th><th>Technique</th>\
            <th>Reachable</th><th>Model-flagged</th></tr></thead><tbody>\
            <tr><td>Credential Access</td>\
            <td><abbr title=\"T1552 Unsecured Credentials\">Unsecured Credentials</abbr></td>\
            <td>2</td><td><span class=\"flagged\">1</span></td></tr></tbody></table>";
        assert_eq!(got, want);
    }

    /// A reachable-but-unflagged technique renders the muted dash, not a flagged count.
    #[test]
    fn unflagged_technique_shows_the_muted_dash() {
        let got = render(&[finding("secret/app/a", true, None)]);
        assert!(got.contains("<td><span class=\"muted\">—</span></td>"));
        assert!(!got.contains("class=\"flagged\""));
    }

    /// ADR-0019 boundary guard: the panel takes only its props.
    #[test]
    fn attack_vectors_imports_no_engine_domain_type() {
        let _: fn(&AttackVectorsProps) -> Markup = attack_vectors;
    }
}
