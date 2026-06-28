//! Shared presentational primitives (ADR-0019, JEF-255): the small reusable chips/badges the
//! v2 components compose — the posture chip, the evidence glyph, the severity/KEV badge — plus
//! the two byte-stable structural constants (`<!doctype html>`, `&nbsp;`).
//!
//! These are presentation only: they take plain data (`&str`/`bool`), never an `engine::`
//! domain type, so they can be reused from any component without pulling the domain layer in.
//! Every value interpolation is a maud `{ }` brace, so chip text is auto-escaped — the XSS
//! surface is the brace, not a hand-written `format!`. The only `PreEscaped` here are the
//! compile-time structural/entity constants (ADR-0019 `PreEscaped` allowance #3).

use maud::{Markup, PreEscaped, html};

/// The HTML5 doctype in the project's lowercase spelling — a compile-time structural constant
/// (ADR-0019 `PreEscaped` allowance #3), no untrusted input.
pub fn doctype() -> Markup {
    PreEscaped("<!doctype html>".to_string())
}

/// A literal non-breaking space — a compile-time entity constant (allowance #3).
pub fn nbsp() -> Markup {
    PreEscaped("&nbsp;".to_string())
}

/// The model posture chip: the BREACH / SAFE / awaiting word + its tone class. Meaning is
/// carried by the WORD, never color alone (accessibility).
pub fn posture_chip(label: &str, tone: &str) -> Markup {
    html! { span class=(format!("chip {tone}")) { (label) } }
}

/// A small evidence glyph (cvss/epss/kev/secret/runtime) — the text token IS the meaning.
pub fn glyph(text: &str, tone: &str) -> Markup {
    html! { span class=(format!("glyph {tone}")) { (text) } }
}

/// A CVE severity / KEV badge: the severity word with a `KEV` marker appended when the CVE is
/// in a known-exploited catalogue (the stronger-than-severity exploitation signal).
pub fn severity_badge(severity: &str, kev: bool, tone: &str) -> Markup {
    html! {
        span class=(format!("badge {tone}")) {
            (severity)
            @if kev { " " span class="badge-kev" { "KEV" } }
        }
    }
}

/// The CSS tone class for a severity word.
pub fn severity_tone(severity: &str) -> &'static str {
    match severity {
        "critical" => "sev-critical",
        "high" => "sev-high",
        "medium" => "sev-medium",
        _ => "sev-low",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_chip_carries_word_and_tone() {
        let m = posture_chip("BREACH", "p-breach").into_string();
        assert_eq!(m, "<span class=\"chip p-breach\">BREACH</span>");
    }

    #[test]
    fn severity_badge_appends_kev_only_when_known_exploited() {
        let plain = severity_badge("high", false, "sev-high").into_string();
        assert_eq!(plain, "<span class=\"badge sev-high\">high</span>");
        let kev = severity_badge("critical", true, "sev-critical").into_string();
        assert!(kev.contains("<span class=\"badge-kev\">KEV</span>"));
    }

    #[test]
    fn chip_text_is_auto_escaped() {
        let m = posture_chip("<script>", "p-safe").into_string();
        assert!(!m.contains("<script>"));
        assert!(m.contains("&lt;script&gt;"));
    }
}
