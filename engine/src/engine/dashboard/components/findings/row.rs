//! The dense findings table's SUMMARY row (JEF-202): one `<tr>` of decisive cells whose
//! tier cell is the row-expand control. Pure `Props -> Markup`; imports only its props +
//! maud + `components::chips`. NO `engine::` domain type.

use crate::engine::dashboard::components::chips::tier_chip;
use crate::engine::dashboard::view_model::findings::{GlyphProps, RowProps};
use maud::{Markup, html};

/// The compact evidence-glyph cell (JEF-202): `N CVE`, a `K·KEV` badge, a `crit` count, and
/// `◆live` when runtime-corroborated. `—` when there is no evidence; `unjudged` when the
/// model hasn't reached the entry yet (an honest awaiting state). Counts only — nothing
/// untrusted is emitted. The parts are space-joined exactly like the legacy
/// `parts.join(" ")`.
fn glyphs(g: &GlyphProps) -> Markup {
    let mut parts: Vec<Markup> = Vec::new();
    if g.cves > 0 {
        parts.push(html! { (g.cves) " CVE" });
    }
    if g.kev > 0 {
        parts.push(html! { span class="kev" { (g.kev) "·KEV" } });
    }
    if g.crit > 0 {
        parts.push(html! { span class="ev-crit" { (g.crit) " crit" } });
    }
    if g.live {
        parts.push(html! { span class="ev-live" { "◆live" } });
    }
    html! {
        @if !parts.is_empty() {
            @for (i, part) in parts.iter().enumerate() {
                @if i > 0 { " " }
                (part)
            }
        } @else if g.awaiting {
            span class="muted" { "unjudged" }
        } @else {
            span class="muted" { "—" }
        }
    }
}

/// One endpoint's SUMMARY row (JEF-202): the tier cell doubles as the row-expand
/// `<button aria-expanded aria-controls>`; then entry → reaches, the verdict tag + clause,
/// the evidence glyphs, the next lever, and the pass-age. The row class carries `f-calm` for
/// a model-cleared broad entry. `aria-controls` / the detail id wire the hidden detail row.
pub fn row(props: &RowProps) -> Markup {
    let base = if props.calm { "f-row f-calm" } else { "f-row" };
    // A context-group row (JEF-202) renders `hidden` and prepends `ctx-row` so the single
    // `ctx-summary` toggle reveals the group; a standalone attention/watch row does neither.
    let row_class = if props.context {
        format!("ctx-row {base}")
    } else {
        base.to_string()
    };
    html! {
        tr hidden[props.context] class=(row_class) {
            td class="c-tier" {
                button class="row-toggle" aria-expanded="false"
                    aria-controls=(props.detail_id) {
                    (tier_chip(props.tier.label(), props.tier.chip_class()))
                }
            }
            td class="c-entry" {
                code { (props.entry_short) } " "
                span class="r-arrow" { "→" } " "
                span class="muted" { (props.reaches) }
            }
            td class="c-verdict" {
                span class=(format!("chip {}", props.verdict_tone)) { (props.verdict_tag) }
                @if !props.verdict_clause.is_empty() {
                    " " span class="v-clause" { (props.verdict_clause) }
                }
            }
            td class="c-ev" { (glyphs(&props.glyphs)) }
            td class="c-lever" { span class="lever" { (props.lever) } }
            td class="c-age" { "as of " (props.age) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::view_model::findings::GlyphProps;

    #[test]
    fn evidence_glyphs_render_compact_badges() {
        let g = glyphs(&GlyphProps {
            cves: 2,
            kev: 1,
            crit: 1,
            live: true,
            awaiting: false,
        })
        .into_string();
        assert!(g.contains("2 CVE"), "CVE count: {g}");
        assert!(g.contains("1·KEV"), "KEV badge: {g}");
        assert!(g.contains("1 crit"), "crit count: {g}");
        assert!(g.contains("◆live"), "live glyph: {g}");
        // Space-joined, exactly like the legacy `parts.join(" ")`.
        assert!(
            g.contains("2 CVE <span class=\"kev\">1·KEV</span>"),
            "parts space-joined: {g}"
        );
    }

    #[test]
    fn evidence_glyphs_dash_when_none_unjudged_when_awaiting() {
        let dash = glyphs(&GlyphProps {
            cves: 0,
            kev: 0,
            crit: 0,
            live: false,
            awaiting: false,
        })
        .into_string();
        assert!(dash.contains("—") && !dash.contains("CVE"), "dash: {dash}");

        let unjudged = glyphs(&GlyphProps {
            cves: 0,
            kev: 0,
            crit: 0,
            live: false,
            awaiting: true,
        })
        .into_string();
        assert!(
            unjudged.contains("unjudged"),
            "awaiting reads unjudged: {unjudged}"
        );
    }

    /// ADR-0019 boundary guard: the row component takes only its props.
    #[test]
    fn row_imports_no_engine_domain_type() {
        let _: fn(&RowProps) -> Markup = row;
    }
}
