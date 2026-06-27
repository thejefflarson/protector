//! Shared presentational primitives — the small reusable chips/badges the dashboard's
//! components compose: the posture tag, the attention-tier chip, and the CVE
//! severity/KEV badge (see ADR-0019 for the component split). Each is a pure
//! `data -> Markup` helper; tickets 3–5 migrate the findings table / cards / report
//! onto these instead of re-emitting the chip markup by hand.
//!
//! These primitives are **presentation only**: they take plain data (`&str`/`bool`),
//! never an `engine::` domain type, so they can be reused from any component without
//! pulling the domain layer into the view. Every interpolation is a maud `{ }` brace,
//! so the chip text is auto-escaped — the XSS surface is the auto-escaped brace, not a
//! hand-written `format!` (ADR-0019, the `PreEscaped` allowlist).

use maud::{Markup, PreEscaped, html};

/// A literal non-breaking space (`&nbsp;`), the byte-stable building block the read-only
/// pages depend on for their layout. It is the canonical home for the migrated tree's
/// non-breaking space: the panels and report compose `chips::nbsp()` rather than emitting a
/// raw entity or a literal U+00A0 char, so the rendered bytes stay identical to the pre-maud
/// output (`to&nbsp;do`, `&nbsp;|&nbsp;`). This is a `PreEscaped` of a compile-time HTML
/// constant with no untrusted input — ADR-0019 `PreEscaped` allowance #3 (constant
/// structural/entity markup), not a value brace.
pub fn nbsp() -> Markup {
    PreEscaped("&nbsp;".to_string())
}

/// The page-header nav separator (`&nbsp;|&nbsp;`) the read-only pages put between the
/// preamble sentence and the per-page links (e.g. "… | dashboard | json"), composed from
/// [`nbsp`] around a literal pipe so the bytes match the pre-maud output. ADR-0019
/// `PreEscaped` allowance #3 — a compile-time entity constant, no untrusted input.
pub fn sep() -> Markup {
    html! { (nbsp()) "|" (nbsp()) }
}

/// The HTML5 doctype the read-only pages open with, in the project's lowercase
/// `<!doctype html>` spelling (maud's built-in `DOCTYPE` is uppercase, which would change
/// the rendered bytes). A `PreEscaped` of a compile-time structural constant with no
/// untrusted input — ADR-0019 `PreEscaped` allowance #3.
pub fn doctype() -> Markup {
    PreEscaped("<!doctype html>".to_string())
}

/// The model's posture as a chip — the `[BREACH]` / `[SAFE]` / `[awaiting judgement]`
/// tag that leads a finding (JEF-161). `tone` is the CSS tone class
/// (`chip-breach` / `chip-safe` / `chip-awaiting`); meaning is carried by the WORD in
/// `label`, never color alone (accessibility).
pub fn posture_tag(label: &str, tone: &str) -> Markup {
    html! { span class=(format!("chip {tone}")) { (label) } }
}

/// The attention-tier chip (JEF-163): `flagged` / `watch` / `context`. `tone` is the
/// tier tone class (`tier-flagged` / `tier-watch` / `tier-context`). A presentation-only
/// "look at this first" key — it never gates a decision (ADR-0016).
pub fn tier_chip(label: &str, tone: &str) -> Markup {
    html! { span class=(format!("chip {tone}")) { (label) } }
}

/// A CVE severity / KEV badge: the severity word (`low`/`medium`/`high`/`critical`),
/// with a `KEV` marker appended when the CVE is in a known-exploited catalogue (the
/// stronger-than-severity exploitation signal). `tone` is the severity tone class.
pub fn severity_badge(severity: &str, kev: bool, tone: &str) -> Markup {
    html! {
        span class=(format!("badge {tone}")) {
            (severity)
            @if kev { " " span class="badge-kev" { "KEV" } }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_tag_carries_word_and_tone() {
        let m = posture_tag("[BREACH]", "chip-breach").into_string();
        assert_eq!(m, "<span class=\"chip chip-breach\">[BREACH]</span>");
    }

    #[test]
    fn tier_chip_carries_word_and_tone() {
        let m = tier_chip("flagged", "tier-flagged").into_string();
        assert_eq!(m, "<span class=\"chip tier-flagged\">flagged</span>");
    }

    #[test]
    fn severity_badge_appends_kev_only_when_known_exploited() {
        let plain = severity_badge("high", false, "sev-high").into_string();
        assert_eq!(plain, "<span class=\"badge sev-high\">high</span>");

        let kev = severity_badge("critical", true, "sev-critical").into_string();
        assert!(kev.contains("critical"));
        assert!(
            kev.contains("<span class=\"badge-kev\">KEV</span>"),
            "KEV marker present: {kev}"
        );
    }

    #[test]
    fn chip_text_is_auto_escaped() {
        // Defence in depth: a chip label is auto-escaped by the maud brace, so even a
        // hostile label can't inject markup (ADR-0019 — the XSS surface is the brace).
        let m = posture_tag("<script>", "chip-safe").into_string();
        assert!(!m.contains("<script>"), "raw tag must be escaped: {m}");
        assert!(m.contains("&lt;script&gt;"), "escaped form present: {m}");
    }
}
