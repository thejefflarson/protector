//! The Admission/policy view body (brief §6 — the webhook floor): the decision-tallies header
//! (admitted / audited / denied, so a healthy cluster is never a blank screen — counts honest even
//! at zero) + the deduped decision rows (subject/image · namespace · signature status · mesh status
//! · the decision · the "if enforced" what-if). Light-theme, calm by default; meaning never by
//! colour alone (colour + glyph + word). Honest empty state when no decisions are recorded. Pure
//! component; no domain types; all free-text auto-escaped.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::{
    AdmissionViewProps, DecisionRowProps, GateStatus,
};

/// Render the Admission view: the tallies header, then the deduped decision rows, with an honest
/// empty state when no decisions have been recorded.
pub fn admission_view(v: &AdmissionViewProps) -> Markup {
    html! {
        main.view.view-admission {
            (tallies_header(v))
            @if v.rows.is_empty() {
                (empty_state())
            } @else {
                (decision_rows(v))
            }
        }
    }
}

/// The tallies header: admitted / audited / denied counts so a healthy cluster is never blank.
/// Each count carries colour + glyph + word, and the counts are honest at zero (rendered, not
/// hidden) — the operator can always see the webhook is being asked, even with no flagged rows.
fn tallies_header(v: &AdmissionViewProps) -> Markup {
    html! {
        section.admission-summary aria-label="admission decision tallies" {
            h2.section-h.t-h2 { "admission \u{2014} the webhook floor" }
            p.section-sub.t-body.muted {
                "every admission the webhook resolved: clean admits, would-deny-but-allowed audits, \
                 and enforced denials. In shadow the gates only PROPOSE \u{2014} the 'if enforced' \
                 column is the what-if, never the live decision."
            }
            div.admission-tallies {
                span.tally.tally-admitted.t-data-strong {
                    span.glyph aria-hidden="true" { "\u{2713}" }
                    " " (v.admitted) " admitted"
                }
                span.tally.tally-audited.t-data-strong {
                    span.glyph aria-hidden="true" { "\u{25D0}" }
                    " " (v.audited) " audited"
                }
                span.tally.tally-denied.t-data-strong {
                    span.glyph aria-hidden="true" { "\u{25CF}" }
                    " " (v.denied) " denied"
                }
                span.tally.tally-total.t-data.muted { (v.total) " total" }
            }
        }
    }
}

/// The deduped decision rows as a real table (keyboard/semantics gate: machine data in a `<table>`
/// so columns align). One row per distinct `(subject, image, decision)`.
fn decision_rows(v: &AdmissionViewProps) -> Markup {
    html! {
        section.admission-rows aria-label="admission decisions" {
            h3.col-h.t-h2 { "decisions" }
            table.decisions {
                thead {
                    tr {
                        th.t-micro { "decision" }
                        th.t-micro { "workload" }
                        th.t-micro { "signature" }
                        th.t-micro { "mesh" }
                        th.t-micro { "if enforced" }
                    }
                }
                tbody {
                    @for row in &v.rows {
                        (decision_row(row))
                    }
                }
            }
        }
    }
}

/// One decision row: the decision chip · the subject/image/namespace · the signature + mesh shadow
/// status · the "if enforced" what-if. A `would-fail` gate or a `would-deny` what-if is the
/// attention case (a denied keyline). All free-text (subject/image/namespace/reason) auto-escaped.
fn decision_row(r: &DecisionRowProps) -> Markup {
    // A row the engine would have rejected if enforced is the attention case — keyline it.
    let attention = !r.would_admit;
    let tr_class = if attention {
        "decision-row decision-row-attention"
    } else {
        "decision-row"
    };
    html! {
        tr class=(tr_class) data-decision=(r.decision.token()) {
            td.cell-decision {
                span class={ "decision-chip decision-" (r.decision.token()) } {
                    span.glyph aria-hidden="true" { (r.decision.glyph()) }
                    span.decision-word { (r.decision.word()) }
                }
                @if r.count > 1 {
                    span.decision-count.t-micro.muted title="distinct workloads + image + outcome seen this many times" {
                        "\u{00D7}" (r.count)
                    }
                }
            }
            td.cell-workload {
                span.workload-subject.t-data-strong { (r.subject) }
                @if !r.image.is_empty() {
                    span.workload-image.t-data.muted { (r.image) }
                }
                span.workload-ns.t-micro.muted {
                    @if r.namespace.is_empty() {
                        "cluster-scoped"
                    } @else {
                        "ns " (r.namespace)
                    }
                }
                @if !r.reason.is_empty() {
                    p.decision-reason.t-data { (r.reason) }
                }
            }
            td.cell-gate { (gate_chip(r.signature)) }
            td.cell-gate { (gate_chip(r.mesh)) }
            td.cell-enforced { (if_enforced(r.would_admit)) }
        }
    }
}

/// A per-gate shadow-status chip (signature / mesh): colour + glyph + word, never colour alone.
fn gate_chip(g: GateStatus) -> Markup {
    html! {
        span class={ "gate-chip gate-" (g.token()) } {
            span.glyph aria-hidden="true" { (g.glyph()) }
            span.gate-word { (g.word()) }
        }
    }
}

/// The "if enforced" net what-if (JEF-246): would-admit / would-deny. Colour + glyph + word; a
/// would-deny is the loud channel (the request would be rejected if the gates were armed).
fn if_enforced(would_admit: bool) -> Markup {
    html! {
        @if would_admit {
            span.enforced-chip.enforced-admit {
                span.glyph aria-hidden="true" { "\u{2713}" }
                span.enforced-word { "would admit" }
            }
        } @else {
            span.enforced-chip.enforced-deny {
                span.glyph aria-hidden="true" { "\u{2715}" }
                span.enforced-word { "would deny" }
            }
        }
    }
}

/// The honest empty state: no admission decisions recorded — never read as "all clear". Names the
/// two honest reasons (webhook not wired / none in window) rather than implying safety.
fn empty_state() -> Markup {
    html! {
        div.empty.admission-empty {
            p.empty-head.t-h2 { "no admission decisions recorded yet" }
            p.empty-sub.t-body.muted {
                "the webhook may not be receiving admission requests, or none have landed in this \
                 window. This is not an all-clear \u{2014} wire the admission webhook to populate \
                 the decision floor."
            }
        }
    }
}
