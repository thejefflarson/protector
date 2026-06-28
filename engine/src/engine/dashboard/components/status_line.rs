//! The status-line renderer (JEF-255): the dashboard's one-line headline answer. Pure
//! `StatusProps -> Markup`; imports no `engine::` domain type (ADR-0019). Meaning is always in
//! the text; the lead dot's color only reinforces the tone.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::status::{StatusProps, StatusTone};

/// Render the status line:
/// `● N BREACH · M endpoints · K awaiting · model live (pass <age>) · coverage X%`.
pub fn status_line(p: &StatusProps) -> Markup {
    html! {
        p class=(format!("status {}", p.tone.css())) role="status" {
            span class="status-dot" aria-hidden="true" { "●" }
            " "
            (lead(p))
            " · " b { (p.endpoints) } " endpoint" (plural(p.endpoints))
            " · " b { (p.awaiting) } " awaiting"
            " · " (p.model_clause) " (pass " (p.pass_age) ")"
            " · coverage " b { (p.coverage_pct) "%" }
        }
    }
}

/// The lead clause keys on tone — a breach leads with the count loud; a blind state names the
/// gap; an all-clear says so. The screen-reader summary is the same words (no color reliance).
fn lead(p: &StatusProps) -> Markup {
    match p.tone {
        StatusTone::Breach => html! { b class="lead-breach" { (p.breach) " BREACH" } },
        StatusTone::Blind => html! { b class="lead-blind" { "0 breach (blind — see coverage)" } },
        StatusTone::Clear => html! { b class="lead-clear" { "all clear" } },
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn props(tone: StatusTone) -> StatusProps {
        StatusProps {
            tone,
            breach: 2,
            endpoints: 5,
            awaiting: 1,
            model_clause: "model live".into(),
            pass_age: "12s ago".into(),
            coverage_pct: 100,
        }
    }

    #[test]
    fn renders_the_one_line_with_all_counts() {
        let m = status_line(&props(StatusTone::Breach)).into_string();
        assert!(m.contains("2 BREACH"));
        assert!(m.contains("<b>5</b> endpoints"));
        assert!(m.contains("<b>1</b> awaiting"));
        assert!(m.contains("model live"));
        assert!(m.contains("pass 12s ago"));
        assert!(m.contains("coverage <b>100%</b>"));
        assert!(m.contains("status s-breach"));
    }

    #[test]
    fn blind_state_does_not_read_calm() {
        let mut p = props(StatusTone::Blind);
        p.breach = 0;
        p.coverage_pct = 40;
        let m = status_line(&p).into_string();
        assert!(m.contains("s-blind"));
        assert!(m.contains("blind"));
        assert!(!m.contains("all clear"));
    }

    #[test]
    fn clear_state_says_all_clear() {
        let m = status_line(&props(StatusTone::Clear)).into_string();
        assert!(m.contains("all clear"));
        assert!(m.contains("s-clear"));
    }
}
