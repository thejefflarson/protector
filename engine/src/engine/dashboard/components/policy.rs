//! The `/policy` page (JEF-226): the webhook's admission-decision log — a table of the
//! recent signature / mesh / enforce-authz decisions the admission webhook resolved, each
//! row led by the decision chip (deny vs audit) with the policy, the workload subject, the
//! namespace, the reason, and how long ago. The machine-readable form is `/policy.json`.
//!
//! This complements the aggregate `/metrics` counter (`protector_policy_violations_total`):
//! the counter is the rollup, this is the per-event journal.
//!
//! PRESENTATION ONLY: this renderer takes its [`PolicyProps`] and nothing else. It imports NO
//! `engine::` domain type — only its props (from the `view_model`), the shared `chips`
//! primitives, and maud. The `policy_imports_no_engine_domain_type` test documents the
//! boundary (ADR-0019). Every text field (subject / namespace / reason) is attacker-influenced
//! and rendered through an auto-escaping maud brace — an unsigned image ref or a workload name
//! cannot inject markup (JEF-226 AC).

use crate::engine::dashboard::components::chips::{doctype, posture_tag, sep};
use crate::engine::dashboard::view_model::{PolicyDecisionRow, PolicyProps};
use maud::{Markup, html};

/// One `/policy` row: the decision chip (deny/audit), the policy that decided, the workload
/// subject + namespace, the reason prose, and the humanized "when". Every value auto-escapes.
fn row(row: &PolicyDecisionRow) -> Markup {
    html! {
        tr {
            td { (posture_tag(&row.decision, row.decision_tone)) }
            td { code { (row.policy) } }
            td { code { (row.subject) } }
            td {
                @if row.namespace.is_empty() {
                    span class="muted" { "—" }
                } @else {
                    code { (row.namespace) }
                }
            }
            td { (row.reason) }
            td class="muted" { (row.when) }
        }
    }
}

/// The full `/policy` HTML page (JEF-226): the admission-decision table, or the honest-empty
/// state. Self-contained, styled by the shared self-hosted `/assets/dashboard.css` (no inline
/// `<style>`). Pure `Props -> Markup`.
pub fn policy(props: &PolicyProps) -> Markup {
    html! {
        (doctype())
        html {
            head {
                meta charset="utf-8";
                title { "protector — admission decisions" }
                link rel="stylesheet" href="/assets/dashboard.css";
            }
            body {
                h1 { "protector — admission decisions" }
                p class="sum" {
                    "What the admission webhook decided on each matched write — signature, mesh, \
                     and authz scope. A "
                    b { "deny" }
                    " is an enforced rejection; an "
                    b { "audit" }
                    " is a would-deny that was allowed (the discovery signal for what \
                     enforcement would reject). The aggregate counts are at "
                    code { "/metrics" }
                    ". "
                    (sep()) " " a href="/" { "dashboard" } " " (sep()) " "
                    a href="/policy.json" { "json" }
                }
                h2 {
                    "Recent decisions " span class="muted" { "(" (props.rows.len()) ")" }
                }
                @if props.rows.is_empty() {
                    p class="muted" {
                        "no admission decisions recorded yet (a decision is logged when a policy \
                         would deny or audit a write — an all-allowing cluster records nothing)"
                    }
                } @else {
                    table class="policy" {
                        thead {
                            tr {
                                th { "decision" }
                                th { "policy" }
                                th { "subject" }
                                th { "namespace" }
                                th { "reason" }
                                th { "when" }
                            }
                        }
                        tbody {
                            @for r in &props.rows { (row(r)) }
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
    use crate::engine::dashboard::view_model::policy_props;
    use crate::engine::policy_log::PolicyDecisionRecord;

    fn record(
        policy: &str,
        decision: &str,
        subject: &str,
        ns: &str,
        reason: &str,
    ) -> PolicyDecisionRecord {
        PolicyDecisionRecord {
            policy: policy.into(),
            decision: decision.into(),
            subject: subject.into(),
            namespace: ns.into(),
            reason: reason.into(),
            // A fixed epoch so the "when" phrase is deterministic in the byte tests.
            at_ms: 0,
        }
    }

    fn render(rows: &[PolicyDecisionRecord]) -> String {
        policy(&policy_props(rows)).into_string()
    }

    /// A deny row carries the breach-tone chip with the decision word, the policy, the
    /// subject + namespace, and the reason.
    #[test]
    fn deny_row_renders_chip_policy_subject_and_reason() {
        let html = render(&[record(
            "image-signature",
            "deny",
            "Pod/web",
            "payments",
            "unsigned or untrusted image(s): ghcr.io/org/app:1",
        )]);
        assert!(html.contains("<span class=\"chip chip-breach\">deny</span>"));
        assert!(html.contains("<code>image-signature</code>"));
        assert!(html.contains("<code>Pod/web</code>"));
        assert!(html.contains("<code>payments</code>"));
        assert!(html.contains("unsigned or untrusted image(s): ghcr.io/org/app:1"));
    }

    /// An audit row reads as the awaiting tone (a would-deny that was allowed).
    #[test]
    fn audit_row_uses_the_awaiting_tone() {
        let html = render(&[record(
            "mesh-injection",
            "audit",
            "Pod/api",
            "default",
            "not enrolled in the mesh",
        )]);
        assert!(html.contains("<span class=\"chip chip-awaiting\">audit</span>"));
        assert!(html.contains("not enrolled in the mesh"));
    }

    /// The honest-empty state (an all-allowing cluster records nothing).
    #[test]
    fn empty_state_is_honest() {
        let html = render(&[]);
        assert!(html.contains("no admission decisions recorded yet"));
        assert!(html.contains("<span class=\"muted\">(0)</span>"));
        assert!(!html.contains("<table"));
    }

    /// A hostile image ref / workload name is auto-escaped (the reason quotes attacker text).
    #[test]
    fn untrusted_subject_and_reason_are_escaped() {
        let html = render(&[record(
            "image-signature",
            "deny",
            "Pod/<script>alert(1)</script>",
            "ns",
            "unsigned: ghcr.io/<img src=x onerror=alert(1)>/app & more",
        )]);
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "raw subject tag escaped: {html}"
        );
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(
            !html.contains("<img src=x onerror=alert(1)>"),
            "raw reason tag escaped: {html}"
        );
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("&amp; more"));
    }

    /// JEF-176 leak-test: the rendered `/policy` never leaks an `ADR-`/`JEF-` ref.
    #[test]
    fn policy_never_leaks_internal_refs() {
        let rows = vec![
            record("image-signature", "deny", "Pod/web", "ns", "unsigned image"),
            record("mesh-injection", "audit", "Pod/api", "ns", "not meshed"),
        ];
        for surface in [render(&rows), render(&[])] {
            assert!(!surface.contains("ADR-"), "no ADR- leak: {surface}");
            assert!(!surface.contains("JEF-"), "no JEF- leak: {surface}");
        }
    }

    /// ADR-0019 boundary guard: the policy component takes only its props.
    #[test]
    fn policy_imports_no_engine_domain_type() {
        let _: fn(&PolicyProps) -> Markup = policy;
    }
}
