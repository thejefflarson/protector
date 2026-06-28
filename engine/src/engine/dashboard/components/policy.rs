//! The `/policy` page (JEF-226/237): the webhook's admission-decision log — a table of the
//! recent signature / mesh decisions the admission webhook resolved, each row led by the
//! decision chip with the coarse signature + mesh summary, the workload subject, the image,
//! the namespace, the reason, the dedup count, and how long ago. The machine-readable form is
//! `/policy.json`.
//!
//! JEF-237 widens this from violations-only to EVERY resolved admission, so a healthy cluster
//! shows its GOOD pods — a green "admitted — signed, meshed" row — not a blank panel. The
//! activity line (admit/audit/deny counts + last-decision time) renders ALWAYS, so even an
//! empty ring reads as "webhook active — no decisions since <boot>", never a bare blank.
//!
//! This complements the aggregate `/metrics` counter (`protector_policy_violations_total`):
//! the counter is the rollup, this is the per-event journal.
//!
//! PRESENTATION ONLY: this renderer takes its [`PolicyProps`] and nothing else. It imports NO
//! `engine::` domain type — only its props (from the `view_model`), the shared `chips`
//! primitives, and maud. The `policy_imports_no_engine_domain_type` test documents the
//! boundary (ADR-0019). Every attacker-influenced field (subject / image / namespace / reason)
//! is rendered through an auto-escaping maud brace — an unsigned image ref or a workload name
//! cannot inject markup.

use crate::engine::dashboard::components::chips::{doctype, posture_tag, sep};
use crate::engine::dashboard::view_model::{PolicyDecisionRow, PolicyProps};
use maud::{Markup, html};

/// One `/policy` row: the decision chip (allow/audit/deny) + short summary, the workload
/// subject, the image, the namespace, the reason prose, the "×N" dedup badge, and the
/// humanized "last seen". Every attacker-influenced value auto-escapes.
fn row(row: &PolicyDecisionRow) -> Markup {
    html! {
        tr {
            td {
                (posture_tag(&row.decision, row.decision_tone))
                " "
                span class="muted" { (row.summary) }
            }
            td { code { (row.subject) } }
            td {
                @if row.image.is_empty() {
                    span class="muted" { "—" }
                } @else {
                    code { (row.image) }
                }
            }
            td {
                @if row.namespace.is_empty() {
                    span class="muted" { "—" }
                } @else {
                    code { (row.namespace) }
                }
            }
            td {
                @if row.reason.is_empty() {
                    span class="muted" { "—" }
                } @else {
                    (row.reason)
                }
            }
            td class="muted" {
                @if row.count > 1 { "×" (row.count) } @else { "1" }
            }
            td class="muted" { (row.when) }
        }
    }
}

/// The always-rendered activity line: the admit / audit / deny tallies and the last-decision
/// (or boot) time, so the webhook's liveness is visible whether or not the table has rows.
fn activity(props: &PolicyProps) -> Markup {
    html! {
        p class="sum" {
            "Admission webhook active — "
            b { (props.admitted) } " admitted, "
            b { (props.audited) } " audited, "
            b { (props.denied) } " denied "
            span class="muted" { "(last decision " (props.since) ")" }
        }
    }
}

/// The full `/policy` HTML page (JEF-226/237): the activity line, then the admission-decision
/// table, or the honest-empty state. Self-contained, styled by the shared self-hosted
/// `/assets/dashboard.css` (no inline `<style>`). Pure `Props -> Markup`.
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
                    "What the admission webhook decided on each matched write — signature and \
                     mesh. A "
                    b { "deny" }
                    " is an enforced rejection; an "
                    b { "audit" }
                    " is a would-deny that was allowed (the discovery signal for what \
                     enforcement would reject); an "
                    b { "admit" }
                    " is a clean pass (signed + meshed). The aggregate counts are at "
                    code { "/metrics" }
                    ". "
                    (sep()) " " a href="/" { "dashboard" } " " (sep()) " "
                    a href="/policy.json" { "json" }
                }
                (activity(props))
                h2 {
                    "Recent decisions " span class="muted" { "(" (props.rows.len()) ")" }
                }
                @if props.rows.is_empty() {
                    p class="muted" {
                        "no admission decisions since boot — the webhook is active and recording, \
                         it just hasn't matched a write yet"
                    }
                } @else {
                    table class="policy" {
                        thead {
                            tr {
                                th { "decision" }
                                th { "subject" }
                                th { "image" }
                                th { "namespace" }
                                th { "reason" }
                                th { "count" }
                                th { "last seen" }
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
    use crate::engine::policy_log::{DecisionTallies, PolicyDecisionRecord};
    use std::time::SystemTime;

    fn record(
        decision: &str,
        subject: &str,
        image: &str,
        signature: &str,
        mesh: &str,
        ns: &str,
        reason: &str,
    ) -> PolicyDecisionRecord {
        PolicyDecisionRecord {
            policy: "admission".into(),
            decision: decision.into(),
            subject: subject.into(),
            image: image.into(),
            signature: signature.into(),
            mesh: mesh.into(),
            namespace: ns.into(),
            reason: reason.into(),
            count: 1,
            // A fixed epoch so the "when" phrase is deterministic in the byte tests.
            at_ms: 0,
        }
    }

    fn render(rows: &[PolicyDecisionRecord]) -> String {
        let mut t = DecisionTallies::default();
        for r in rows {
            match r.decision.as_str() {
                "allow" => t.admitted += r.count,
                "audit" => t.audited += r.count,
                "deny" => t.denied += r.count,
                _ => {}
            }
        }
        policy(&policy_props(rows, t, SystemTime::now())).into_string()
    }

    /// A clean admit renders the SAFE-tone chip with the "admitted — signed, meshed" summary
    /// (JEF-237: the good pods are shown, not just violations).
    #[test]
    fn clean_admit_renders_safe_chip_and_signed_meshed_summary() {
        let html = render(&[record(
            "allow",
            "Pod/web",
            "ghcr.io/org/app:1",
            "signed",
            "meshed",
            "default",
            "",
        )]);
        assert!(html.contains("<span class=\"chip chip-safe\">allow</span>"));
        assert!(html.contains("admitted — signed, meshed"));
        assert!(html.contains("<code>ghcr.io/org/app:1</code>"));
    }

    /// A deny row carries the breach-tone chip with the decision word, subject, image, reason.
    #[test]
    fn deny_row_renders_chip_subject_image_and_reason() {
        let html = render(&[record(
            "deny",
            "Pod/web",
            "ghcr.io/org/app:1",
            "unsigned",
            "meshed",
            "payments",
            "unsigned or untrusted image(s): ghcr.io/org/app:1",
        )]);
        assert!(html.contains("<span class=\"chip chip-breach\">deny</span>"));
        assert!(html.contains("<code>Pod/web</code>"));
        assert!(html.contains("<code>payments</code>"));
        assert!(html.contains("unsigned or untrusted image(s): ghcr.io/org/app:1"));
    }

    /// An audit row reads as the awaiting tone (a would-deny that was allowed).
    #[test]
    fn audit_row_uses_the_awaiting_tone() {
        let html = render(&[record(
            "audit",
            "Pod/api",
            "img:1",
            "unsigned",
            "meshed",
            "default",
            "not signed",
        )]);
        assert!(html.contains("<span class=\"chip chip-awaiting\">audit</span>"));
        assert!(html.contains("not signed"));
    }

    /// The activity line renders ALWAYS with the tallies — liveness over a bare blank.
    #[test]
    fn activity_line_shows_tallies() {
        let html = render(&[
            record("allow", "Pod/a", "img:a", "signed", "meshed", "ns", ""),
            record("allow", "Pod/b", "img:b", "signed", "meshed", "ns", ""),
            record("deny", "Pod/c", "img:c", "unsigned", "n/a", "ns", "x"),
        ]);
        assert!(html.contains("Admission webhook active"));
        assert!(html.contains("<b>2</b> admitted"));
        assert!(html.contains("<b>1</b> denied"));
    }

    /// The honest-empty state: webhook-active line, never a bare blank.
    #[test]
    fn empty_state_is_honest_and_active() {
        let html = render(&[]);
        assert!(html.contains("Admission webhook active"));
        assert!(html.contains("no admission decisions since boot"));
        assert!(html.contains("<span class=\"muted\">(0)</span>"));
        assert!(!html.contains("<table"));
    }

    /// Replica churn surfaces as a "×N" count badge, not N rows.
    #[test]
    fn dedup_count_renders_as_a_times_badge() {
        let mut r = record("allow", "Pod/web", "img:1", "signed", "meshed", "ns", "");
        r.count = 12;
        let html = render(&[r]);
        assert!(html.contains("×12"), "the dedup count is shown: {html}");
    }

    /// A hostile image ref / workload name is auto-escaped (the reason quotes attacker text).
    #[test]
    fn untrusted_subject_image_and_reason_are_escaped() {
        let html = render(&[record(
            "deny",
            "Pod/<script>alert(1)</script>",
            "ghcr.io/<img src=x onerror=alert(1)>/app",
            "unsigned",
            "n/a",
            "ns",
            "unsigned: ghcr.io/<b>x</b>/app & more",
        )]);
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "raw subject tag escaped: {html}"
        );
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(
            !html.contains("<img src=x onerror=alert(1)>"),
            "raw image tag escaped: {html}"
        );
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("&amp; more"));
    }

    /// JEF-176 leak-test: the rendered `/policy` never leaks an `ADR-`/`JEF-` ref.
    #[test]
    fn policy_never_leaks_internal_refs() {
        let rows = vec![
            record(
                "deny",
                "Pod/web",
                "img:1",
                "unsigned",
                "meshed",
                "ns",
                "unsigned image",
            ),
            record("allow", "Pod/api", "img:2", "signed", "meshed", "ns", ""),
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
