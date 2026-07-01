//! The Admission/policy view body (brief §6 — the webhook floor): the decision-tallies header
//! (admitted / audited / denied, so a healthy cluster is never a blank screen — counts honest even
//! at zero) + the per-image signing inventory (JEF-262 / ADR-0020) + the deduped decision rows
//! (subject/image · namespace · mesh status · the decision · the "if enforced" what-if). The
//! signature posture now lives in the signing inventory, so the decision log no longer carries a
//! signature gate column. Light-theme, calm by default; meaning never by colour alone (colour +
//! glyph + word). Honest empty states throughout. Pure component; no domain types; all free-text
//! auto-escaped.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::{
    AdmissionViewProps, DecisionRowProps, GateStatus, RepoStrength, SigningPosture,
    SigningRegressionProps, SigningRepoProps, SigningRowProps,
};

/// Render the Admission view: the tallies header, then the per-image signing inventory, then the
/// deduped decision rows — each with its own honest empty state.
pub fn admission_view(v: &AdmissionViewProps) -> Markup {
    html! {
        main.view.view-admission {
            (tallies_header(v))
            (signing_inventory(v))
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

/// The per-image signing inventory (JEF-262 / ADR-0020): the observed signing posture of EVERY
/// image, grouped under its repo, sitting between the tallies header and the decision log. Two hard
/// rules the operator set: the posture is always signed / invalid signature / not signed (or the
/// transient checking) — never n/a; and the "if enforced" cell is always the binary would-admit /
/// would-block. Honest empty ("no images observed yet") — explicitly NOT an all-clear.
fn signing_inventory(v: &AdmissionViewProps) -> Markup {
    html! {
        section.signing-inventory aria-label="signing inventory" {
            h3.col-h.t-h2 { "signing inventory" }
            p.section-sub.t-body.muted {
                "the observed signing posture of every image \u{2014} signed, invalid signature, or \
                 not signed (or a transient check while a registry is unreachable). This is \
                 observation, not a gate; the 'if enforced' column is the binary what-if a \
                 signature gate would apply (only a verifying signature would admit)."
            }
            @if v.signing.is_empty() {
                (signing_empty())
            } @else {
                @for repo in &v.signing {
                    (signing_repo(repo))
                }
            }
        }
    }
}

/// One repo group: the registry/repo header + (when the repo's signed history has drifted) a loud
/// signing-regression banner + a real `<table>` of the images observed under it (so the machine
/// columns align — the keyboard/semantics gate). The table is omitted when the regressed image has
/// aged out of the observation window, so a standing regression still surfaces on its own.
fn signing_repo(g: &SigningRepoProps) -> Markup {
    html! {
        div.signing-repo {
            div.signing-repo-head {
                h4.signing-repo-h.t-data-strong { (g.repo) }
                @if g.strength != RepoStrength::Unknown {
                    span.signing-strength.t-micro.muted data-strength=(g.strength.token())
                        title="whether the public transparency log corroborates this repo's signing history (JEF-266)" {
                        (g.strength.word())
                    }
                }
            }
            @if let Some(regression) = &g.regression {
                (signing_regression(regression))
            }
            @if !g.images.is_empty() {
                table.signing {
                    thead {
                        tr {
                            th.t-micro { "image" }
                            th.t-micro { "signature" }
                            th.t-micro { "if enforced" }
                        }
                    }
                    tbody {
                        @for img in &g.images {
                            (signing_row(img))
                        }
                    }
                }
            }
        }
    }
}

/// The loud signing-regression banner (JEF-264, ADR-0020 §3): a repo's signed history drifted —
/// now unsigned/invalid, or signed by a new identity. The breach-rail channel (glyph + word,
/// distinct from calm "not signed"), stating before→after with BOTH identities in FULL. An
/// established baseline reads as the strong signal; a cold baseline is honestly flagged a weak lead.
///
/// Security: every identity/issuer is UNTRUSTED Fulcio SAN, emitted ONLY via maud interpolation
/// `(x)` (auto-escaped) — never `PreEscaped`, never concatenated into markup, and never used to
/// derive a `class=`/CSS value (the `data-regression` attribute is the fixed low-cardinality kind
/// token, not identity text).
fn signing_regression(r: &SigningRegressionProps) -> Markup {
    let strength = if r.established {
        "established baseline"
    } else {
        "weak baseline \u{2014} treat as a lead"
    };
    html! {
        div.signing-regression.signing-row-attention data-regression=(r.kind.token()) role="alert" {
            div.signing-regression-head {
                span.glyph aria-hidden="true" { "\u{25CF}" }
                span.signing-regression-word.t-data-strong { (r.kind.word()) }
                span.signing-regression-strength.t-micro.muted { "(" (strength) ")" }
            }
            div.signing-regression-detail {
                p.t-data { "image: " span.mono { (r.image) } }
                @if r.before_identities.is_empty() {
                    p.t-data.muted { "before: baseline signer not recorded" }
                } @else {
                    p.t-data {
                        "before \u{2014} baseline signer"
                        @if r.before_identities.len() != 1 { "s" }
                        ":"
                    }
                    ul.signing-regression-before {
                        @for identity in &r.before_identities {
                            li.t-data { span.mono { (identity) } }
                        }
                    }
                }
                @match &r.after_identity {
                    Some(identity) => {
                        p.t-data { "after \u{2014} now signed by:" }
                        p.t-data { span.mono { (identity) } }
                        @if let Some(issuer) = &r.after_issuer {
                            p.t-data.muted { "issuer: " span.mono { (issuer) } }
                        }
                    }
                    None => {
                        p.t-data { "after \u{2014} " (r.kind.after_word()) }
                    }
                }
            }
        }
    }
}

/// One image row: the ref (expand-in-place for the full ref + signer/issuer detail) · the signing
/// posture chip · the binary "if enforced". An invalid signature is the loud attention case (a
/// breach keyline). The signer identity (untrusted Fulcio SAN) truncates in-row and is auto-escaped;
/// its full value lives in the expand panel + `title=`.
fn signing_row(r: &SigningRowProps) -> Markup {
    let attention = r.posture == SigningPosture::Invalid;
    let tr_class = if attention {
        "signing-row signing-row-attention"
    } else {
        "signing-row"
    };
    html! {
        tr class=(tr_class) data-posture=(r.posture.token()) {
            td.cell-image {
                details.signing-detail {
                    summary.why-toggle role="button" aria-expanded="false" {
                        span.signing-ref.t-data-strong title=(r.image) { (r.label) }
                        @if r.count > 1 {
                            span.signing-count.t-micro.muted title="distinct image observed this many times" {
                                "\u{00D7}" (r.count)
                            }
                        }
                        @if let Some(signer) = &r.signer {
                            span.signing-by.t-micro.muted title=(signer.identity_full) {
                                "signed by " (signer.identity_short)
                                @if !signer.issuer_badge.is_empty() {
                                    " \u{00B7} " span.issuer-badge { (signer.issuer_badge) }
                                }
                            }
                        }
                    }
                    div.signing-detail-body {
                        p.t-data { "image: " span.mono { (r.image) } }
                        @match &r.signer {
                            Some(signer) => {
                                p.t-data { "identity: " span.mono { (signer.identity_full) } }
                                @match &signer.issuer_full {
                                    Some(issuer) => p.t-data { "issuer: " span.mono { (issuer) } }
                                    None => p.t-data.muted { "issuer: none recorded" }
                                }
                            }
                            None => {
                                @if r.detail.is_empty() {
                                    p.t-data.muted { "no signature artifact present for this image" }
                                } @else {
                                    p.t-data { (r.detail) }
                                }
                            }
                        }
                    }
                }
            }
            td.cell-gate { (signing_chip(r.posture)) }
            td.cell-enforced { (if_enforced_signing(r.posture.would_admit())) }
        }
    }
}

/// A signing-posture chip: colour + glyph + word, never colour alone. Reuses the `gate-chip`
/// vocabulary with the `sign-*` colour tokens; `invalid` is the loud channel, `not signed` calm.
fn signing_chip(p: SigningPosture) -> Markup {
    html! {
        span class={ "gate-chip sign-" (p.token()) } {
            span.glyph aria-hidden="true" { (p.glyph()) }
            span.gate-word { (p.word()) }
        }
    }
}

/// The binary "if enforced" for a signing posture: would admit / would block (never n/a). Colour +
/// glyph + word; a would-block is the loud channel (a signature gate would reject the image).
fn if_enforced_signing(would_admit: bool) -> Markup {
    html! {
        @if would_admit {
            span.enforced-chip.enforced-admit {
                span.glyph aria-hidden="true" { "\u{2713}" }
                span.enforced-word { "would admit" }
            }
        } @else {
            span.enforced-chip.enforced-block {
                span.glyph aria-hidden="true" { "\u{2715}" }
                span.enforced-word { "would block" }
            }
        }
    }
}

/// The honest empty inventory: no images observed yet — explicitly NOT an all-clear (nothing has
/// been inspected, not "everything is signed").
fn signing_empty() -> Markup {
    html! {
        div.empty.signing-empty {
            p.empty-head.t-h2 { "no images observed yet" }
            p.empty-sub.t-body.muted {
                "the signing sweep has not recorded any image postures in this window. This is not \
                 an all-clear \u{2014} it means nothing has been inspected yet, not that every \
                 image is signed."
            }
        }
    }
}

/// The deduped decision rows as a real table (keyboard/semantics gate: machine data in a `<table>`
/// so columns align). One row per distinct `(subject, image, decision)`. The signature posture
/// lives in the signing inventory above, so this table carries only the mesh gate.
fn decision_rows(v: &AdmissionViewProps) -> Markup {
    html! {
        section.admission-rows aria-label="admission decisions" {
            h3.col-h.t-h2 { "decisions" }
            table.decisions {
                thead {
                    tr {
                        th.t-micro { "decision" }
                        th.t-micro { "workload" }
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

/// One decision row: the decision chip · the subject/image/namespace · the mesh shadow status · the
/// "if enforced" what-if. A `would-fail` gate or a `would-deny` what-if is the attention case (a
/// denied keyline). All free-text (subject/image/namespace/reason) auto-escaped.
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
