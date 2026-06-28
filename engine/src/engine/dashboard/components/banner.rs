//! The full-width status banner (JEF-159), migrated to maud as the proof-of-pattern for
//! ADR-0019. `role="status"` + `aria-live="polite"` so a screen reader announces a change;
//! the meaning is in the WORD + glyph + subtitle, never color alone.
//!
//! PRESENTATION ONLY: this renderer takes its [`BannerProps`] and nothing else. It imports
//! NO `engine::` domain type — only its props (from the `view_model`), the `ClusterStatus`
//! presentation enum, and maud. The `banner_imports_no_engine_domain_type` test documents
//! that boundary (ADR-0019).

use crate::engine::dashboard::view_model::{BannerProps, ClusterStatus};
use maud::{Markup, html};

/// Pluralize a noun phrase: the empty suffix for one, `s` otherwise.
fn plural_suffix(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// The banner's detail line — the count plus, for a breach, the anchor to the cards. The
/// only `<a>` here is rendered through maud (not `PreEscaped`), so it is part of the
/// auto-escaped tree, not a hand-written markup string. The "cleared" claim appears ONLY
/// in `Watching` (a live-model clearance), never in any non-judged state (JEF-174 AC #4).
fn detail(props: &BannerProps) -> Markup {
    let exposed = props.exposed;
    let flagged = props.flagged;
    html! {
        @match props.status {
            ClusterStatus::WarmingUp => {
                "first pass not yet complete — verdicts loading"
            }
            ClusterStatus::Isolated => {
                (flagged) " exploitable path" (plural_suffix(flagged)) " — "
                a href="#attack-paths" { "cut applied, contained" }
            }
            ClusterStatus::BreachLive => {
                (flagged) " exploitable path" (plural_suffix(flagged)) " — "
                a href="#attack-paths" { "needs attention now" }
            }
            ClusterStatus::Unjudged => {
                (exposed) " exposed path" (plural_suffix(exposed)) " — "
                a href="#coverage" {
                    "the model isn't judging right now, so none are confirmed safe"
                }
            }
            ClusterStatus::Watching => {
                (exposed) " exposed path" (plural_suffix(exposed))
                " watched, none exploitable — the model cleared them"
            }
            ClusterStatus::Quiet => {
                "no internet-facing service can reach a target"
            }
        }
    }
}

/// The full-width status banner: the first child of `<body>`, above `<h1>`. Pure
/// `Props -> Markup`. Auto-escapes the freshness phrase; the detail anchor is part of the
/// maud tree (no `PreEscaped`).
pub fn banner(props: &BannerProps) -> Markup {
    let status = props.status;
    // The arm-state half of the subtitle: shadow (proposing only) vs live (acting).
    let arm = if props.armed {
        "armed (acting)"
    } else {
        "shadow mode (proposing only)"
    };
    html! {
        div class=(format!("banner banner-{}", status.tone()))
            role="status" aria-live="polite" {
            div class="banner-head" {
                span class="banner-glyph" aria-hidden="true" { (status.glyph()) }
                span class="banner-word" { (status.word()) }
            }
            div class="banner-detail" { (detail(props)) }
            div class="banner-sub" {
                "last scan " (props.freshness) " · auto-refresh 30s · " (arm)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::model::Finding;
    use crate::engine::dashboard::view_model::banner_props;
    use std::time::SystemTime;

    /// A breach-relevant finding for one entry, optionally judged exploitable + auto-cut.
    fn finding(entry: &str, verdict: Option<&str>, auto: bool) -> Finding {
        Finding {
            entry: entry.into(),
            objective: "secret/app/session-key".into(),
            tactic: "TA0006".into(),
            tactic_name: "Credential Access".into(),
            technique: "T1552".into(),
            technique_name: "Unsecured Credentials".into(),
            foothold: true,
            corroborated: false,
            adjudicated: verdict.is_some(),
            promoted: false,
            disposition: if auto {
                crate::engine::dashboard::model::AUTO_ELIGIBLE.to_string()
            } else {
                "latent foothold".to_string()
            },
            cut: None,
            breach_relevant: true,
            killchain: String::new(),
            verdict: verdict.map(|v| v.to_string()),
            path: Vec::new(),
            evidence: Default::default(),
            recency: None,
        }
    }

    fn render(
        findings: &[Finding],
        armed: bool,
        last_pass: Option<SystemTime>,
        freshness: &str,
        judging: bool,
    ) -> String {
        banner(&banner_props(
            findings, armed, last_pass, freshness, judging,
        ))
        .into_string()
    }

    #[test]
    fn every_state_carries_the_aria_contract() {
        let now = Some(SystemTime::now());
        let states = [
            render(&[], false, None, "x", true), // WarmingUp
            render(&[], false, now, "x", true),  // Quiet
            render(
                &[finding("e", Some("not exploitable"), false)],
                false,
                now,
                "x",
                true,
            ), // Watching
            render(
                &[finding("e", Some("not exploitable"), false)],
                false,
                now,
                "x",
                false,
            ), // Unjudged
            render(
                &[finding("e", Some("exploitable — RCE"), false)],
                false,
                now,
                "x",
                true,
            ), // BreachLive
            render(
                &[finding("e", Some("exploitable — RCE"), true)],
                true,
                now,
                "x",
                true,
            ), // Isolated
        ];
        for b in &states {
            assert!(b.contains("role=\"status\""), "role on every banner: {b}");
            assert!(
                b.contains("aria-live=\"polite\""),
                "aria-live on every banner: {b}"
            );
        }
    }

    #[test]
    fn warming_up_state() {
        let b = render(&[], false, None, "waiting for first pass", true);
        assert!(b.contains("Warming up"));
        assert!(b.contains("banner-warming"));
        assert!(b.contains("◌"), "warming glyph");
        assert!(
            !b.contains("Quiet") && !b.contains("Watching"),
            "never claims OK"
        );
        assert!(!b.contains("cleared"), "never a clearance claim");
    }

    #[test]
    fn quiet_state() {
        let b = render(&[], false, Some(SystemTime::now()), "5s ago", true);
        assert!(b.contains("Quiet"));
        assert!(b.contains("banner-ok"), "calm/green tone");
        assert!(b.contains("no internet-facing service can reach a target"));
        assert!(!b.contains("cleared"));
    }

    #[test]
    fn watching_state() {
        let b = render(
            &[finding(
                "workload/app/Pod/web",
                Some("not exploitable — denied"),
                false,
            )],
            false,
            Some(SystemTime::now()),
            "5s ago",
            true,
        );
        assert!(b.contains("Watching"));
        assert!(b.contains("banner-ok"), "calm/green tone");
        assert!(b.contains("1 exposed path"), "states paths watched");
        assert!(
            b.contains("the model cleared them"),
            "live-model clearance stated"
        );
        assert!(
            b.contains("shadow mode (proposing only)"),
            "arm-state in subtitle"
        );
        assert!(b.contains("last scan 5s ago"), "freshness in subtitle");
        assert!(b.contains("auto-refresh 30s"), "refresh cadence noted");
    }

    #[test]
    fn breach_live_state() {
        let b = render(
            &[finding(
                "workload/app/Pod/web",
                Some("exploitable — RCE"),
                false,
            )],
            false,
            Some(SystemTime::now()),
            "5s ago",
            true,
        );
        assert!(b.contains("Breach — live"));
        assert!(b.contains("banner-breach"));
        assert!(b.contains("▲"), "breach glyph");
        assert!(b.contains("1 exploitable path"), "names the count");
        assert!(
            b.contains("href=\"#attack-paths\""),
            "anchors to the card(s)"
        );
        assert!(b.contains("needs attention now"));
    }

    #[test]
    fn isolated_state() {
        let b = render(
            &[finding(
                "workload/app/Pod/web",
                Some("exploitable — RCE"),
                true,
            )],
            true,
            Some(SystemTime::now()),
            "5s ago",
            true,
        );
        assert!(b.contains("Isolated"));
        assert!(b.contains("banner-isolated"));
        assert!(b.contains("armed (acting)"));
        assert!(b.contains("cut applied, contained"));
    }

    #[test]
    fn unjudged_state_is_non_green_and_states_the_reason_in_text() {
        let b = render(
            &[finding(
                "workload/app/Pod/web",
                Some("not exploitable — denied"),
                false,
            )],
            false,
            Some(SystemTime::now()),
            "5s ago",
            false,
        );
        assert!(b.contains("Unjudged"), "leads with the word");
        assert!(
            b.contains("banner-unjudged") && !b.contains("banner-ok"),
            "non-green amber tone, never the green/ok token: {b}"
        );
        assert!(
            b.contains("the model isn't judging right now"),
            "the meaning is in the text, not color alone"
        );
        assert!(b.contains("1 exposed path"), "states the count");
        assert!(!b.contains("cleared"), "no clearance without a live model");
    }

    /// JEF-174 AC #4: no non-judged state ever claims the model cleared anything.
    #[test]
    fn detail_never_claims_clearance_without_a_live_verdict() {
        let exposed = vec![finding("e", Some("not exploitable"), false)];
        let now = Some(SystemTime::now());
        assert!(!render(&exposed, false, now, "x", false).contains("cleared")); // Unjudged
        assert!(!render(&exposed, false, None, "x", false).contains("cleared")); // WarmingUp
        assert!(!render(&[], false, now, "x", false).contains("cleared")); // Quiet
        assert!(render(&exposed, false, now, "x", true).contains("the model cleared them"));
    }

    /// Byte-stability with the pre-maud `status_banner` (JEF-204 AC): the full Watching
    /// banner must be byte-for-byte the old string-concat output.
    #[test]
    fn banner_output_is_byte_stable_with_the_legacy_string_concat() {
        let got = render(
            &[finding(
                "workload/app/Pod/web",
                Some("not exploitable — denied"),
                false,
            )],
            false,
            Some(SystemTime::now()),
            "5s ago",
            true,
        );
        let want = "<div class=\"banner banner-ok\" role=\"status\" aria-live=\"polite\">\
            <div class=\"banner-head\">\
            <span class=\"banner-glyph\" aria-hidden=\"true\">●</span>\
            <span class=\"banner-word\">Watching</span></div>\
            <div class=\"banner-detail\">1 exposed path watched, none exploitable — \
            the model cleared them</div>\
            <div class=\"banner-sub\">last scan 5s ago · auto-refresh 30s · \
            shadow mode (proposing only)</div></div>";
        assert_eq!(got, want);
    }

    /// And the breach detail's anchor is byte-stable too (the `PreEscaped`-free anchor path).
    #[test]
    fn breach_banner_detail_is_byte_stable() {
        let got = render(
            &[finding("e", Some("exploitable — RCE"), false)],
            false,
            Some(SystemTime::now()),
            "1m ago",
            true,
        );
        assert!(
            got.contains(
                "<div class=\"banner-detail\">1 exploitable path — \
             <a href=\"#attack-paths\">needs attention now</a></div>"
            ),
            "{got}"
        );
    }

    /// ADR-0019 boundary guard: the banner component takes only its props.
    #[test]
    fn banner_imports_no_engine_domain_type() {
        let _: fn(&BannerProps) -> Markup = banner;
    }
}
