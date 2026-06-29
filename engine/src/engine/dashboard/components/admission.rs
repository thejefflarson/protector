//! The ADMISSION strip renderer (JEF-255, extended JEF-246): the compact
//! `signed X/Y · meshed Y/Y` summary of the webhook's recent admission decisions, with the
//! audit/deny tallies AND the shadow "if enforced" what-if. Pure `AdmissionProps -> Markup`; no
//! `engine::` domain type (ADR-0019).
//!
//! The actual-decision line stays honest (the real admitted/audit/denied tallies — what the API
//! did). Below it, the "if enforced" line surfaces the counterfactual (JEF-246): the would-be
//! signed + meshed fractions (counted over every shadow-evaluated image, even out of scope) and
//! the net would-DENY count — what protector WOULD do if every gate were enforced. The two are
//! deliberately separated so the operator can read the truth and the preview side by side.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::admission::AdmissionProps;

/// Render the admission strip: the actual decision tallies, then the "if enforced" what-if line.
pub fn admission(p: &AdmissionProps) -> Markup {
    html! {
        p class="admission" {
            b { "admission: " }
            @if p.empty {
                span class="muted" { "no admission decisions yet" }
            } @else {
                (p.admitted) " admitted"
                @if p.audited > 0 {
                    " · " span class="would-deny" { (p.audited) " would-deny (audit)" }
                }
                @if p.denied > 0 {
                    " · " span class="denied" { (p.denied) " denied" }
                }
            }
        }
        @if !p.empty {
            p class="admission admission-whatif" {
                b { "if enforced: " }
                "signed " b { (p.signed) "/" (p.signed_of) }
                " · meshed " b { (p.meshed) "/" (p.meshed_of) }
                @if p.would_deny > 0 {
                    " · " span class="would-deny" { (p.would_deny) " would-DENY" }
                } @else {
                    " · " span class="ok" { "all would-ADMIT" }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn props(would_deny: u32, signed: u32, signed_of: u32) -> AdmissionProps {
        AdmissionProps {
            signed,
            signed_of,
            meshed: 4,
            meshed_of: 4,
            admitted: 4,
            audited: 0,
            denied: 0,
            would_deny,
            empty: false,
        }
    }

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
            would_deny: 0,
            empty: true,
        })
        .into_string();
        assert!(m.contains("no admission decisions yet"));
        // No what-if line in the empty state.
        assert!(!m.contains("if enforced"));
    }

    #[test]
    fn surfaces_the_if_enforced_what_if_fractions() {
        let m = admission(&props(0, 3, 4)).into_string();
        assert!(m.contains("if enforced"));
        assert!(m.contains("signed <b>3/4</b>"));
        assert!(m.contains("meshed <b>4/4</b>"));
        assert!(m.contains("4 admitted"), "actual tally stays honest");
    }

    #[test]
    fn net_would_deny_is_shown_when_any_image_would_fail() {
        let m = admission(&props(2, 2, 4)).into_string();
        assert!(m.contains("2 would-DENY"));
        assert!(!m.contains("all would-ADMIT"));
    }

    #[test]
    fn net_all_would_admit_when_nothing_would_fail() {
        let m = admission(&props(0, 4, 4)).into_string();
        assert!(m.contains("all would-ADMIT"));
    }
}
