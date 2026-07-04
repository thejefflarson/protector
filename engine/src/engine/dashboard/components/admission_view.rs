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
    AdmissionViewProps, DecisionRowProps, ExceptionAcceptedProps, GateStatus,
    ProvenanceChangeProps, ProvenancePosture, RepoStrength, SigningEnforcement, SigningPosture,
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
/// image, as ONE aligned `<table>` for the whole inventory (so the machine columns line up across
/// every repo — the operator's core complaint against the old per-repo mini-tables), grouped under
/// repo group-header rows and expandable exactly like the Findings table. Two hard rules the
/// operator set: the posture is always signed / invalid signature / not signed (or the transient
/// checking) — never n/a; and the "if enforced" cell is always a definite continuity verdict —
/// would-admit / would-block / uncertain (JEF-297, ADR-0020). Honest empty ("no images observed
/// yet") — explicitly NOT an all-clear.
fn signing_inventory(v: &AdmissionViewProps) -> Markup {
    html! {
        section.signing-inventory aria-label="signing inventory" {
            h3.col-h.t-h2 { "signing inventory" }
            p.section-sub.t-body.muted {
                "the observed signing posture of every image \u{2014} signed, invalid signature, or \
                 not signed (or a transient check while a registry is unreachable). This is \
                 observation, not a gate; the 'if enforced' column is the what-if a signature-\
                 continuity gate would apply \u{2014} a calm, consistent posture would admit, only a \
                 regression against the repo's established baseline would block (a cold-baseline \
                 regression reads uncertain, not blocked)."
            }
            @if v.signing.is_empty() {
                (signing_empty())
            } @else {
                table.signing {
                    thead {
                        tr {
                            th.col-expand.t-micro {}
                            th.t-micro { "signature" }
                            th.t-micro { "image" }
                            th.t-micro { "signer" }
                            th.t-micro { "provenance" }
                            th.t-micro { "baseline" }
                            th.t-micro { "if enforced" }
                        }
                    }
                    tbody {
                        @for repo in &v.signing {
                            (signing_group(repo))
                        }
                    }
                }
            }
        }
    }
}

/// One repo group inside the single table: a spanning group-header row carrying the registry/repo,
/// then (when the repo's signed history drifted) the loud regression row, then the repo's image rows
/// sorted loud-first. The repo stays visible without breaking the whole-table column alignment.
fn signing_group(g: &SigningRepoProps) -> Markup {
    html! {
        tr.signing-group {
            th.signing-group-head.t-data-strong colspan="7" scope="colgroup" { (g.repo) }
        }
        @if let Some(regression) = &g.regression {
            (signing_regression_row(regression))
        }
        @if let Some(exception) = &g.exception {
            (signing_exception_row(exception))
        }
        @if let Some(change) = &g.provenance_change {
            (provenance_change_row(change))
        }
        @for img in &g.images {
            (signing_row(img, g.strength))
        }
    }
}

/// One image row: a findings-style summary `<tr.row>` (a `+/-` expander · posture chip · image ·
/// signer · baseline strength · the continuity "if enforced") paired with a hidden full-width
/// `<tr.row-detail>` the client toggles open in place. An invalid signature is the loud attention
/// case (a breach keyline on the row). Every untrusted field (image/label/signer identity+issuer)
/// is emitted ONLY via maud interpolation (auto-escaped) — never `PreEscaped`; the `data-signing`
/// id and `data-posture` token are fixed `[a-z0-9-]`, never derived from untrusted text.
fn signing_row(r: &SigningRowProps, strength: RepoStrength) -> Markup {
    let attention = r.posture == SigningPosture::Invalid;
    let tr_class = if attention {
        "row signing-row signing-row-attention"
    } else {
        "row signing-row"
    };
    let detail_id = format!("detail-{}", r.dom_id);
    html! {
        tr class=(tr_class) id=(r.dom_id) data-signing=(r.dom_id) data-posture=(r.posture.token()) {
            td.cell.cell-expand {
                button.expander
                    type="button"
                    aria-expanded="false"
                    aria-controls=(detail_id)
                    aria-label="expand image signing detail" {
                    span.expander-glyph aria-hidden="true" { "+" }
                }
            }
            td.cell.cell-gate { (signing_chip(r.posture)) }
            td.cell.cell-image {
                span.signing-ref.t-data-strong title=(r.image) { (r.label) }
                @if r.count > 1 {
                    span.signing-count.t-micro.muted title="distinct image observed this many times" {
                        "\u{00D7}" (r.count)
                    }
                }
            }
            td.cell.cell-signer {
                @match &r.signer {
                    Some(signer) => {
                        span.signing-by.t-micro title=(signer.identity_full) {
                            (signer.identity_short)
                            @if !signer.issuer_badge.is_empty() {
                                " \u{00B7} " span.issuer-badge { (signer.issuer_badge) }
                            }
                        }
                    }
                    None => span.t-micro.muted title="no trusted signer for this image" { "\u{2014}" }
                }
            }
            td.cell.cell-provenance data-provenance=(r.provenance.token()) {
                (provenance_chip(r.provenance))
                @if let Some(prov) = &r.provenance_info {
                    span.provenance-by.t-micro title=(prov.builder_full) {
                        " \u{00B7} " (prov.builder_short)
                    }
                }
            }
            td.cell.cell-baseline {
                @if strength == RepoStrength::Unknown {
                    span.t-micro.muted title="no signing baseline learned for this repo yet" {
                        "\u{2014}"
                    }
                } @else {
                    span.signing-strength.t-micro.muted data-strength=(strength.token())
                        title="whether the public transparency log corroborates this repo's signing history (JEF-266)" {
                        (strength.word())
                    }
                }
            }
            td.cell.cell-enforced { (if_enforced_signing(r.enforcement)) }
        }
        tr.row-detail id=(detail_id) data-detail-for=(r.dom_id) {
            td.detail-host colspan="7" {
                (signing_detail(r, strength))
            }
        }
    }
}

/// The expand-in-place detail for an image row: the FULL image ref, the FULL Fulcio SAN identity +
/// issuer (or the posture prose for a non-signed image), and the repo's baseline detail. Every
/// identity/issuer/image is UNTRUSTED — emitted only via maud interpolation (auto-escaped, never
/// `PreEscaped`). The detail rail class is the fixed posture token, never untrusted text.
fn signing_detail(r: &SigningRowProps, strength: RepoStrength) -> Markup {
    html! {
        div class={ "detail detail-sign-" (r.posture.token()) } {
            section.detail-section {
                h3.detail-h { "image" }
                p.t-data { span.mono { (r.image) } }
            }
            section.detail-section {
                h3.detail-h { "signer" }
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
            section.detail-section {
                h3.detail-h { "build provenance" }
                @match &r.provenance_info {
                    Some(prov) => {
                        p.t-data { "source: " span.mono { (prov.source_full) } }
                        p.t-data { "builder: " span.mono { (prov.builder_full) } }
                    }
                    None => @match r.provenance {
                        ProvenancePosture::Absent => p.t-data.muted {
                            "no SLSA build-provenance attestation for this image \u{2014} calm, not \
                             an alarm, but not a verified build either"
                        },
                        ProvenancePosture::Unverifiable => p.t-data.muted {
                            "a provenance attestation is present but was not verified against our \
                             trust root (or carried no builder identity) \u{2014} not a trusted build"
                        },
                        _ => p.t-data.muted { "build provenance not yet known (registry/log unreachable)" },
                    }
                }
            }
            section.detail-section {
                h3.detail-h { "baseline" }
                p.t-data.muted { (strength.detail()) }
            }
        }
    }
}

/// The loud signing-regression row (JEF-264, ADR-0020 §3): a repo's signed history drifted — now
/// unsigned/invalid, or signed by a new identity. It stays PROMINENT — a findings-style expander
/// row with a breach keyline, a filled glyph + the loud "signing regression" word (lexically
/// distinct from calm "not signed"), spanning the machine columns (a repo-level alert, not an image
/// posture, so it carries no per-image if-enforced). The FULL before→after identities live in its
/// pulldown. An established baseline reads as the strong signal; a cold baseline a weak lead.
///
/// Security: every identity/issuer is UNTRUSTED Fulcio SAN, emitted ONLY via maud interpolation
/// `(x)` (auto-escaped) — never `PreEscaped`, never concatenated into markup, and never used to
/// derive a `class=`/CSS value (the `data-regression` attribute is the fixed low-cardinality kind
/// token, not identity text).
fn signing_regression_row(r: &SigningRegressionProps) -> Markup {
    let strength = if r.established {
        "established baseline"
    } else {
        "weak baseline \u{2014} treat as a lead"
    };
    let detail_id = format!("detail-{}", r.dom_id);
    html! {
        tr.row.signing-row.signing-row-attention id=(r.dom_id) data-signing=(r.dom_id)
            data-regression=(r.kind.token()) role="alert" {
            td.cell.cell-expand {
                button.expander
                    type="button"
                    aria-expanded="false"
                    aria-controls=(detail_id)
                    aria-label="expand signing regression detail" {
                    span.expander-glyph aria-hidden="true" { "+" }
                }
            }
            td.cell.cell-regression colspan="6" {
                span.signing-regression-head {
                    span.glyph aria-hidden="true" { "\u{25CF}" }
                    span.signing-regression-word.t-data-strong { (r.kind.word()) }
                    span.signing-regression-strength.t-micro.muted { "(" (strength) ")" }
                }
                span.signing-regression-image.t-data { " image: " span.mono { (r.image) } }
            }
        }
        tr.row-detail id=(detail_id) data-detail-for=(r.dom_id) {
            td.detail-host colspan="7" {
                (signing_regression_detail(r))
            }
        }
    }
}

/// The expand-in-place detail for a regression row: the before→after with BOTH identities in FULL
/// and the reason. Every identity/issuer is UNTRUSTED — emitted only via maud interpolation
/// (auto-escaped, never `PreEscaped`). Kept prominent (its own breach-railed panel).
fn signing_regression_detail(r: &SigningRegressionProps) -> Markup {
    html! {
        div.detail.detail-sign-regression {
            section.detail-section {
                h3.detail-h { "what changed" }
                p.t-data { "image: " span.mono { (r.image) } }
                p.t-data { (r.kind.word()) }
            }
            section.detail-section {
                @if r.before_identities.is_empty() {
                    h3.detail-h { "before \u{2014} baseline signer" }
                    p.t-data.muted { "baseline signer not recorded" }
                } @else {
                    h3.detail-h {
                        "before \u{2014} baseline signer"
                        @if r.before_identities.len() != 1 { "s" }
                    }
                    ul.signing-regression-before {
                        @for identity in &r.before_identities {
                            li.t-data { span.mono { (identity) } }
                        }
                    }
                }
            }
            section.detail-section {
                h3.detail-h { "after" }
                @match &r.after_identity {
                    Some(identity) => {
                        p.t-data { "now signed by:" }
                        p.t-data { span.mono { (identity) } }
                        @if let Some(issuer) = &r.after_issuer {
                            p.t-data.muted { "issuer: " span.mono { (issuer) } }
                        }
                    }
                    None => {
                        p.t-data { (r.kind.after_word()) }
                    }
                }
            }
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

/// A build-provenance-posture chip (JEF-275): colour + glyph + word, never colour alone. `verified`
/// is the one trusted-build state; `no provenance` (the common case) is calm, `unverifiable` is the
/// honest "present, not trusted here". The `prov-*` colour tokens are fixed, never untrusted text.
fn provenance_chip(p: ProvenancePosture) -> Markup {
    html! {
        span class={ "gate-chip prov-" (p.token()) } {
            span.glyph aria-hidden="true" { (p.glyph()) }
            span.gate-word { (p.word()) }
        }
    }
}

/// The loud build-provenance-change row (JEF-275, ADR-0020 §5): a repo's established provenance
/// identity drifted — an image was built by an unexpected builder or from an unexpected source. Like
/// the signing-regression row it stays PROMINENT (a breach keyline, filled glyph, the loud "build
/// provenance change" word), spans the machine columns, and carries the FULL before→after builders in
/// its pulldown. Audit-only (the image is still admitted).
///
/// Security: every builder/source is UNTRUSTED predicate text, emitted ONLY via maud interpolation
/// `(x)` (auto-escaped) — never `PreEscaped`, never concatenated into markup, never a `class=` value
/// (the `data-provenance` attribute is the fixed `changed` token, not identity text).
fn provenance_change_row(r: &ProvenanceChangeProps) -> Markup {
    let strength = if r.established {
        "established baseline"
    } else {
        "weak baseline \u{2014} treat as a lead"
    };
    let detail_id = format!("detail-{}", r.dom_id);
    html! {
        tr.row.signing-row.signing-row-attention id=(r.dom_id) data-signing=(r.dom_id)
            data-provenance="changed" role="alert" {
            td.cell.cell-expand {
                button.expander
                    type="button"
                    aria-expanded="false"
                    aria-controls=(detail_id)
                    aria-label="expand build-provenance change detail" {
                    span.expander-glyph aria-hidden="true" { "+" }
                }
            }
            td.cell.cell-regression colspan="6" {
                span.signing-regression-head {
                    span.glyph aria-hidden="true" { "\u{25CF}" }
                    span.signing-regression-word.t-data-strong {
                        "build provenance change \u{2014} unexpected builder/source"
                    }
                    span.signing-regression-strength.t-micro.muted { "(" (strength) ")" }
                }
                span.signing-regression-image.t-data { " image: " span.mono { (r.image) } }
            }
        }
        tr.row-detail id=(detail_id) data-detail-for=(r.dom_id) {
            td.detail-host colspan="7" {
                (provenance_change_detail(r))
            }
        }
    }
}

/// The expand-in-place detail for a provenance-change row: the before→after builders in FULL + the
/// deviating source. Every builder/source is UNTRUSTED — emitted only via maud interpolation
/// (auto-escaped, never `PreEscaped`).
fn provenance_change_detail(r: &ProvenanceChangeProps) -> Markup {
    html! {
        div.detail.detail-sign-regression {
            section.detail-section {
                h3.detail-h { "what changed" }
                p.t-data { "image: " span.mono { (r.image) } }
                p.t-data { "built by an unexpected builder / from an unexpected source" }
            }
            section.detail-section {
                @if r.before_builders.is_empty() {
                    h3.detail-h { "before \u{2014} baseline builder" }
                    p.t-data.muted { "baseline builder not recorded" }
                } @else {
                    h3.detail-h {
                        "before \u{2014} baseline builder"
                        @if r.before_builders.len() != 1 { "s" }
                    }
                    ul.signing-regression-before {
                        @for builder in &r.before_builders {
                            li.t-data { span.mono { (builder) } }
                        }
                    }
                }
            }
            section.detail-section {
                h3.detail-h { "after" }
                p.t-data { "now built by:" }
                p.t-data { span.mono { (r.after_builder) } }
                p.t-data.muted { "source: " span.mono { (r.after_source) } }
            }
        }
    }
}

/// The baseline-relative "if enforced" continuity verdict for a signing posture (JEF-297): would
/// admit / would block / uncertain (never n/a). Colour + glyph + word, so meaning never rides on
/// colour alone. A would-block is the loud channel (a genuine regression, or a genuinely-invalid
/// signature, a continuity gate would reject); uncertain is the honest non-green weak lead for a
/// cold-baseline regression — never a hard block. The `enforced-{token}` class is a fixed
/// low-cardinality token, never untrusted text.
/// The CALM "exception accepted" row (JEF-265, ADR-0020 Stage 3): a signing regression the operator
/// has opted out of via a scoped, recorded exception. Deliberately NOT the loud breach-rail
/// regression channel — a muted expander row with a distinct glyph + the distinct word "exception
/// accepted" (never "signed"/cleared-green) — yet it stays VISIBLE so the opt-out is never hidden,
/// and it does not count toward breach. The FULL before→after identities live in its pulldown.
///
/// Security: every identity is UNTRUSTED Fulcio SAN, emitted ONLY via maud interpolation
/// (auto-escaped) — never `PreEscaped`, never a `class=`/CSS value (`data-exception` is the fixed
/// low-cardinality kind token, not identity text).
fn signing_exception_row(r: &ExceptionAcceptedProps) -> Markup {
    let strength = if r.established {
        "established baseline"
    } else {
        "weak baseline \u{2014} treat as a lead"
    };
    let detail_id = format!("detail-{}", r.dom_id);
    html! {
        tr.row.signing-row id=(r.dom_id) data-signing=(r.dom_id)
            data-exception=(r.kind.token()) {
            td.cell.cell-expand {
                button.expander
                    type="button"
                    aria-expanded="false"
                    aria-controls=(detail_id)
                    aria-label="expand exception-accepted detail" {
                    span.expander-glyph aria-hidden="true" { "+" }
                }
            }
            td.cell.cell-regression colspan="6" {
                span.signing-exception-head {
                    span.glyph aria-hidden="true" { "\u{25C8}" }
                    span.signing-exception-word.t-data-strong { "exception accepted \u{2014} " (r.kind.word()) }
                    span.signing-exception-strength.t-micro.muted { "(" (strength) ")" }
                }
                span.signing-exception-image.t-data { " image: " span.mono { (r.image) } }
            }
        }
        tr.row-detail id=(detail_id) data-detail-for=(r.dom_id) {
            td.detail-host colspan="7" {
                (signing_exception_detail(r))
            }
        }
    }
}

/// The expand-in-place detail for an exception-accepted row: what was accepted, with BOTH the
/// before baseline signer(s) and (for an identity change) the accepted new identity in FULL. Every
/// identity is UNTRUSTED — emitted only via maud interpolation (auto-escaped, never `PreEscaped`).
fn signing_exception_detail(r: &ExceptionAcceptedProps) -> Markup {
    html! {
        div.detail {
            section.detail-section {
                h3.detail-h { "accepted exception" }
                p.t-data { "image: " span.mono { (r.image) } }
                p.t-data.muted {
                    "a scoped, recorded exception admits this drift for THIS repo/image only; a \
                     different subsequent change re-flags."
                }
            }
            section.detail-section {
                @if r.before_identities.is_empty() {
                    h3.detail-h { "before \u{2014} baseline signer" }
                    p.t-data.muted { "baseline signer not recorded" }
                } @else {
                    h3.detail-h {
                        "before \u{2014} baseline signer"
                        @if r.before_identities.len() != 1 { "s" }
                    }
                    ul.signing-regression-before {
                        @for identity in &r.before_identities {
                            li.t-data { span.mono { (identity) } }
                        }
                    }
                }
            }
            @if let Some(after) = &r.after_identity {
                section.detail-section {
                    h3.detail-h { "accepted \u{2014} new signer" }
                    p.t-data { span.mono { (after) } }
                }
            }
        }
    }
}

fn if_enforced_signing(v: SigningEnforcement) -> Markup {
    let class = match v {
        SigningEnforcement::WouldAdmit => "enforced-chip enforced-admit",
        SigningEnforcement::WouldBlock => "enforced-chip enforced-block",
        SigningEnforcement::Uncertain => "enforced-chip enforced-uncertain",
        SigningEnforcement::ExceptionAccepted => "enforced-chip enforced-exception",
    };
    html! {
        span class=(class) {
            span.glyph aria-hidden="true" { (v.glyph()) }
            span.enforced-word { (v.word()) }
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
