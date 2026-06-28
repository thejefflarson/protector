//! The ADMISSION strip renderer (JEF-255): the compact `signed X/Y · meshed Y/Y` summary of
//! the webhook's recent admission decisions, with the audit/deny tallies. Pure
//! `AdmissionProps -> Markup`; no `engine::` domain type (ADR-0019). A clear seam is left for
//! the JEF-246 "if enforced" what-if (the `audited` count) — not built here, just surfaced.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::admission::AdmissionProps;

/// Render the one-line admission strip.
pub fn admission(p: &AdmissionProps) -> Markup {
    html! {
        p class="admission" {
            b { "admission: " }
            @if p.empty {
                span class="muted" { "no admission decisions yet" }
            } @else {
                "signed " b { (p.signed) "/" (p.signed_of) }
                " · meshed " b { (p.meshed) "/" (p.meshed_of) }
                " · " (p.admitted) " admitted"
                @if p.audited > 0 {
                    " · " span class="would-deny" { (p.audited) " would-deny (audit)" }
                }
                @if p.denied > 0 {
                    " · " span class="denied" { (p.denied) " denied" }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_strip_is_honest() {
        let m = admission(&AdmissionProps {
            signed: 0,
            signed_of: 0,
            meshed: 0,
            meshed_of: 0,
            admitted: 0,
            audited: 0,
            denied: 0,
            empty: true,
        })
        .into_string();
        assert!(m.contains("no admission decisions yet"));
    }

    #[test]
    fn shows_fractions_and_the_audit_what_if_seam() {
        let m = admission(&AdmissionProps {
            signed: 3,
            signed_of: 4,
            meshed: 4,
            meshed_of: 4,
            admitted: 4,
            audited: 1,
            denied: 0,
            empty: false,
        })
        .into_string();
        assert!(m.contains("signed <b>3/4</b>"));
        assert!(m.contains("meshed <b>4/4</b>"));
        assert!(m.contains("would-deny (audit)"));
    }
}
