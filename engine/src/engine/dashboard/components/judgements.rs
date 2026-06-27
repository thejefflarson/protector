//! The `/judgements` page (JEF-161), migrated to maud (ADR-0019): the human "why" view —
//! one card per recent judgement, led by the posture chip + the model's prose, the three
//! honest meta-states surfaced, and the raw prompt+reply tucked behind a `<details>`
//! expander. The prompt is the injection surface (JEF-106); operators read the verdict, not
//! the prompt — so the raw text is a power-user diagnostic, never something to grade.
//!
//! PRESENTATION ONLY: this renderer takes its [`JudgementsProps`] and nothing else. It
//! imports NO `engine::` domain type — only its props (from the `view_model`), the shared
//! `chips` primitives, and maud. The page CSS is the shared self-hosted
//! `/assets/dashboard.css` (JEF-203); there is NO inline `<style>` block. The
//! `judgements_imports_no_engine_domain_type` test documents the boundary (ADR-0019); the
//! byte-stability tests pin the output to the pre-maud string-concat render.

use crate::engine::dashboard::components::chips::{doctype, posture_tag, sep};
use crate::engine::dashboard::view_model::{JudgementCardProps, JudgementLead, JudgementsProps};
use maud::{Markup, html};

/// The honest meta-state line a card leads with (JEF-161 AC #3): the pre-filter / timeout
/// meta note, or the model's prose verdict VERBATIM (auto-escaped — the LLM is the judge).
fn lead(lead: &JudgementLead) -> Markup {
    html! {
        @match lead {
            JudgementLead::PreFilter => {
                span class="meta" { "decided without the model (pre-filter)" }
            }
            JudgementLead::Timeout => {
                span class="meta" { "model timed out — safe fallback" }
            }
            JudgementLead::Verdict(words) => {
                span class="vwords" { (words) }
            }
        }
    }
}

/// The raw prompt+reply behind the `<details>` expander — the injection surface kept a
/// diagnostic, not something operators are asked to grade (JEF-106). Both texts auto-escape.
fn raw(card: &JudgementCardProps) -> Markup {
    html! {
        details class="raw" {
            summary { "show full prompt" }
            div class="raw-cap" { "prompt sent to the model" }
            pre { (card.prompt) }
            div class="raw-cap" { "raw model reply" }
            pre { (card.reply) }
        }
    }
}

/// One `/judgements` card: the posture chip + the model's prose (or a meta-state), the
/// short workload key and how many targets it weighed, and the raw prompt behind the
/// expander.
fn card(card: &JudgementCardProps) -> Markup {
    html! {
        div class="card" {
            div class="vline" {
                (posture_tag(card.posture_label, card.posture_tone)) " " (lead(&card.lead))
            }
            div class="kc2" {
                code { (card.entry) } " "
                span class="muted" {
                    "· " (card.objectives) " target"
                    @if card.objectives != 1 { "s" }
                    " it can reach weighed"
                }
            }
            (raw(card))
        }
    }
}

/// The full `/judgements` HTML page (JEF-161): the human "why" view — one card per recent
/// judgement, or the honest-empty state. Self-contained, styled by the shared self-hosted
/// `/assets/dashboard.css` (no inline `<style>`). Pure `Props -> Markup`.
pub fn judgements(props: &JudgementsProps) -> Markup {
    html! {
        (doctype())
        html {
            head {
                meta charset="utf-8";
                title { "protector — judgements" }
                link rel="stylesheet" href="/assets/dashboard.css";
            }
            body {
                h1 { "protector — judgements" }
                p class="sum" {
                    "Why the model called each internet-facing service the way it did — the \
                     posture and the model's own words first. The raw prompt+reply is behind "
                    i { "show full prompt" }
                    " (a power-user diagnostic; the prompt is the part an attacker could try \
                     to poison). "
                    (sep()) " " a href="/" { "dashboard" } " " (sep()) " "
                    a href="/judgements.json" { "json" }
                }
                h2 {
                    "Recent judgements " span class="muted" { "(" (props.cards.len()) ")" }
                }
                @if props.cards.is_empty() {
                    p class="muted" {
                        "no model judgements yet (the model hasn't reached an internet-facing \
                         service — a slow CPU model takes a few passes after a restart)"
                    }
                } @else {
                    @for c in &props.cards { (card(c)) }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::model::Judgement;
    use crate::engine::dashboard::view_model::judgements_props;

    fn full(entry: &str, verdict: &str, prompt: Option<&str>, reply: Option<&str>) -> Judgement {
        Judgement {
            entry: entry.to_string(),
            objectives: 3,
            verdict: verdict.to_string(),
            prompt: prompt.map(str::to_string),
            reply: reply.map(str::to_string),
        }
    }

    fn render(rows: &[Judgement]) -> String {
        judgements(&judgements_props(rows)).into_string()
    }

    /// JEF-207: one normal card is byte-for-byte the pre-maud `judgement_card` — the
    /// posture chip + the prose verdict, the short key + target count, the raw prompt+reply
    /// behind the expander.
    #[test]
    fn normal_card_is_byte_stable() {
        let rows = vec![full(
            "workload/app/Pod/web",
            "exploitable — RCE reaches the secret",
            Some("PROMPT TEXT the injection surface"),
            Some("the model raw reply"),
        )];
        let got = render(&rows);
        let want_card = "<div class=\"card\"><div class=\"vline\">\
             <span class=\"chip chip-breach\">[BREACH]</span> \
             <span class=\"vwords\">exploitable — RCE reaches the secret</span></div>\
             <div class=\"kc2\"><code>app/Pod/web</code> \
             <span class=\"muted\">· 3 targets it can reach weighed</span></div>\
             <details class=\"raw\"><summary>show full prompt</summary>\
             <div class=\"raw-cap\">prompt sent to the model</div>\
             <pre>PROMPT TEXT the injection surface</pre>\
             <div class=\"raw-cap\">raw model reply</div>\
             <pre>the model raw reply</pre></details></div>";
        assert!(got.contains(want_card), "card byte-stable: {got}");
    }

    /// The full page wrapper (head/title/link, preamble, recent-count header) is byte-stable.
    #[test]
    fn page_wrapper_is_byte_stable() {
        let got = render(&[]);
        let want = "<!doctype html><html><head><meta charset=\"utf-8\">\
             <title>protector — judgements</title>\
             <link rel=\"stylesheet\" href=\"/assets/dashboard.css\">\
             </head><body>\
             <h1>protector — judgements</h1>\
             <p class=\"sum\">Why the model called each internet-facing service the way it did — \
             the posture and the model's own words first. The raw prompt+reply is behind \
             <i>show full prompt</i> (a power-user diagnostic; the prompt is the part an attacker \
             could try to poison). &nbsp;|&nbsp; <a href=\"/\">dashboard</a> &nbsp;|&nbsp; \
             <a href=\"/judgements.json\">json</a></p>\
             <h2>Recent judgements <span class=\"muted\">(0)</span></h2>\
             <p class=\"muted\">no model judgements yet (the model hasn't reached an \
             internet-facing service — a slow CPU model takes a few passes after a restart)</p>\
             </body></html>";
        assert_eq!(got, want);
    }

    /// AC: prose-led, three honest meta-states, raw behind an expander.
    #[test]
    fn three_meta_states_render_prose_first() {
        let rows = vec![
            // Normal: model answered → its prose verdict.
            full(
                "workload/app/Pod/web",
                "exploitable — RCE reaches the secret",
                Some("PROMPT TEXT the injection surface"),
                Some("the model raw reply"),
            ),
            // Pre-filter: prompt None → decided without the model.
            full(
                "workload/app/Pod/api",
                "Refuted(\"no promotion ground\")",
                None,
                None,
            ),
            // Timeout: reply None → safe fallback.
            full(
                "workload/app/Pod/cache",
                "Uncertain(\"model timed out\")",
                Some("PROMPT TEXT"),
                None,
            ),
        ];
        let html = render(&rows);
        assert!(html.contains("exploitable — RCE reaches the secret"));
        assert!(html.contains("[BREACH]"));
        assert!(html.contains("decided without the model (pre-filter)"));
        assert!(html.contains("model timed out — safe fallback"));
        // The pre-filter / timeout default raw text is surfaced behind the expander.
        assert!(html.contains("<pre>(none — pre-filter decided)</pre>"));
        assert!(html.contains("<pre>(none — model timed out)</pre>"));
        // The raw prompt is behind an expander, after the prose verdict.
        assert!(html.contains("show full prompt"));
        let prompt_at = html.find("PROMPT TEXT the injection surface").unwrap();
        let prose_at = html.find("exploitable — RCE reaches the secret").unwrap();
        assert!(
            prose_at < prompt_at,
            "the prose verdict precedes the raw prompt"
        );
        assert!(html.contains("/judgements.json"));
    }

    /// The honest-empty state.
    #[test]
    fn empty_state_is_honest() {
        let html = render(&[]);
        assert!(html.contains("no model judgements yet"));
        assert!(html.contains("hasn't reached"));
    }

    /// One target reads singular ("1 target", no plural `s`).
    #[test]
    fn single_target_is_singular() {
        let j = Judgement {
            entry: "workload/app/Pod/web".into(),
            objectives: 1,
            verdict: "not exploitable — denied".into(),
            prompt: Some("p".into()),
            reply: Some("r".into()),
        };
        let html = render(&[j]);
        assert!(html.contains("· 1 target it can reach weighed"));
        assert!(!html.contains("1 targets"));
    }

    /// A hostile prompt/verdict is auto-escaped (the prompt is the injection surface).
    #[test]
    fn untrusted_prompt_and_verdict_are_escaped() {
        let j = full(
            "workload/app/Pod/web",
            "exploitable — <b>spoof</b>",
            Some("<script>alert(1)</script> & <img>"),
            Some("ok"),
        );
        let html = render(&[j]);
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "raw tag escaped"
        );
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp; &lt;img&gt;"));
        assert!(html.contains("exploitable — &lt;b&gt;spoof&lt;/b&gt;"));
    }

    /// JEF-176: the rendered `/judgements` never leaks an `ADR-`/`JEF-` ref.
    #[test]
    fn judgements_never_leaks_internal_refs() {
        let rows = vec![
            full(
                "workload/app/Pod/web",
                "Exploitable(\"RCE\")",
                Some("system: judge this chain"),
                Some("exploitable"),
            ),
            full("workload/api/Pod/svc", "Refuted(..)", None, None),
        ];
        for surface in [render(&rows), render(&[])] {
            assert!(!surface.contains("ADR-"), "no ADR- leak: {surface}");
            assert!(!surface.contains("JEF-"), "no JEF- leak: {surface}");
        }
    }

    /// ADR-0019 boundary guard: the judgements component takes only its props.
    #[test]
    fn judgements_imports_no_engine_domain_type() {
        let _: fn(&JudgementsProps) -> Markup = judgements;
    }
}
