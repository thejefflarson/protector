//! Serialization contract tests for the view-model props (ADR-0025 — the JSON-props boundary).
//!
//! These pin the wire format the Preact client consumes: the STABLE enum string tags (a silent
//! rename would break the client's exhaustive switch — it must break a test first), the
//! SERVER-DERIVED honesty tokens (`all-clear` / `watching` / per-row `posture` / `is-cleared`,
//! the blind caveat) that the client must NOT re-derive, the reconcile-key ids, and the
//! untrusted-text-ships-RAW guarantee (escaping is the render layer's single job; the JSON carries
//! the verbatim string). They assert on the exact bytes the client receives — the honesty guard
//! relocated from the maud-render boundary to the JSON-props boundary (ADR-0025).

use serde_json::json;

use super::*;

/// A calm, fully-covered strip with nothing outstanding — the ONLY honest all-clear.
fn all_clear_strip() -> StatusStripProps {
    StatusStripProps {
        cluster: "prod-east".into(),
        armed: false,
        model_judging: true,
        warming_up: false,
        model_attached: true,
        coverage: vec![CoverageChip {
            label: "kev".into(),
            present: true,
            degraded: false,
            blind: false,
            stalled: false,
        }],
        coverage_alert: None,
        last_pass: Some("12s ago".into()),
        breach_count: 0,
        awaiting_count: 0,
        uncertain_count: 0,
        cleared_count: 3,
        escalated_count: 0,
        signing_regression_breach: 0,
        signing_regression_uncertain: 0,
    }
}

// ---------------------------------------------------------------------------
// Enum string tags — the stable wire vocabulary. A rename breaks these, not
// the client's switch silently.
// ---------------------------------------------------------------------------

#[test]
fn posture_serializes_to_stable_string_tags() {
    assert_eq!(
        serde_json::to_value(Posture::Breach).unwrap(),
        json!("breach")
    );
    assert_eq!(
        serde_json::to_value(Posture::Cleared).unwrap(),
        json!("cleared")
    );
    assert_eq!(
        serde_json::to_value(Posture::Uncertain).unwrap(),
        json!("uncertain")
    );
    assert_eq!(
        serde_json::to_value(Posture::Awaiting).unwrap(),
        json!("awaiting")
    );
}

#[test]
fn live_tag_and_tab_serialize_to_stable_string_tags() {
    assert_eq!(serde_json::to_value(LiveTag::Live).unwrap(), json!("live"));
    assert_eq!(
        serde_json::to_value(LiveTag::Judged).unwrap(),
        json!("judged")
    );
    assert_eq!(serde_json::to_value(LiveTag::None).unwrap(), json!("none"));

    assert_eq!(
        serde_json::to_value(Tab::Findings).unwrap(),
        json!("findings")
    );
    assert_eq!(serde_json::to_value(Tab::Alerts).unwrap(), json!("alerts"));
    assert_eq!(
        serde_json::to_value(Tab::Admission).unwrap(),
        json!("admission")
    );
}

#[test]
fn gate_and_decision_enums_serialize_to_stable_string_tags() {
    assert_eq!(
        serde_json::to_value(GateStatus::WouldFail).unwrap(),
        json!("would-fail")
    );
    assert_eq!(
        serde_json::to_value(GateStatus::WouldPass).unwrap(),
        json!("would-pass")
    );
    assert_eq!(
        serde_json::to_value(GateStatus::NotApplicable).unwrap(),
        json!("not-applicable")
    );
    assert_eq!(
        serde_json::to_value(AdmissionDecision::Deny).unwrap(),
        json!("deny")
    );
    assert_eq!(
        serde_json::to_value(AdmissionDecision::Allow).unwrap(),
        json!("allow")
    );
}

#[test]
fn delta_props_serialize_as_internally_tagged_kinds() {
    assert_eq!(
        serde_json::to_value(DeltaProps::New).unwrap(),
        json!({ "kind": "new" })
    );
    assert_eq!(
        serde_json::to_value(DeltaProps::DeEscalated).unwrap(),
        json!({ "kind": "de-escalated" })
    );
    // The steady case carries its human age alongside the tag.
    assert_eq!(
        serde_json::to_value(DeltaProps::Unchanged {
            age: Some("4m".into())
        })
        .unwrap(),
        json!({ "kind": "unchanged", "age": "4m" })
    );
}

// ---------------------------------------------------------------------------
// Server-derived honesty tokens carried in the JSON (ADR-0025). The client
// performs ZERO honesty derivation — the wire carries the DECIDED answer.
// ---------------------------------------------------------------------------

#[test]
fn all_clear_strip_serializes_the_green_honesty_token() {
    let v = serde_json::to_value(all_clear_strip()).unwrap();
    // Case X = affirmatively cleared: `all-clear` true, `watching` false.
    assert_eq!(
        v["all-clear"],
        json!(true),
        "an honest all-clear ships green"
    );
    assert_eq!(v["watching"], json!(false));
}

#[test]
fn awaiting_strip_never_ships_green_and_reads_watching() {
    // Case X = something still awaiting the model: NEVER green, reads the calm "watching" token.
    let mut strip = all_clear_strip();
    strip.awaiting_count = 1;
    let v = serde_json::to_value(strip).unwrap();
    assert_eq!(
        v["all-clear"],
        json!(false),
        "an awaiting entry can never ship the green token"
    );
    assert_eq!(
        v["watching"],
        json!(true),
        "it reads the calm watching token"
    );
}

#[test]
fn blind_strip_never_ships_green_or_watching() {
    // Case X = model down / warming (blind): neither honesty token is set — never a false green.
    let mut strip = all_clear_strip();
    strip.model_judging = false;
    let v = serde_json::to_value(strip).unwrap();
    assert_eq!(v["all-clear"], json!(false));
    assert_eq!(
        v["watching"],
        json!(false),
        "a blind strip is neither all-clear nor watching"
    );
}

#[test]
fn standing_signing_regression_forbids_the_green_token() {
    // Case X = a standing established-baseline signing regression (JEF-264): never green.
    let strip = all_clear_strip().with_signing_regressions(1, 0);
    let v = serde_json::to_value(strip).unwrap();
    assert_eq!(v["all-clear"], json!(false));
    assert_eq!(
        v["watching"],
        json!(false),
        "an established regression is louder than watching"
    );
    assert_eq!(v["signing-regression-breach"], json!(1));
}

// ---------------------------------------------------------------------------
// The coverage-stall register (JEF-421): the loud, server-derived was-covering
// → now-silent edge. `stalled` is DISTINCT from `absent`/`degraded`, forbids the
// green all-clear, and ships a `coverage-alert` banner ONLY when a feed stalled.
// ---------------------------------------------------------------------------

/// An all-clear strip whose ONLY coverage chip is a live Runtime feed — the baseline the stall
/// overlay flips to loud.
fn runtime_covered_strip() -> StatusStripProps {
    let mut strip = all_clear_strip();
    strip.coverage = vec![CoverageChip {
        label: "Runtime".into(),
        present: true,
        degraded: false,
        blind: false,
        stalled: false,
    }];
    strip
}

/// The stall alert payload for the `Runtime` feed.
fn runtime_alert() -> StripCoverageAlert {
    StripCoverageAlert {
        feed_label: "Runtime".into(),
        last_observation: Some("2m ago".into()),
        message: "runtime corroboration stalled — all 2 sensor nodes went dark".into(),
    }
}

#[test]
fn input_state_stalled_serializes_distinctly() {
    // The row-level state tag: `stalled` is its OWN string, never collapsing into absent/degraded.
    assert_eq!(
        serde_json::to_value(InputStateProps::Stalled).unwrap(),
        json!("stalled")
    );
    assert_ne!(
        serde_json::to_value(InputStateProps::Stalled).unwrap(),
        serde_json::to_value(InputStateProps::Absent).unwrap()
    );
    assert_ne!(
        serde_json::to_value(InputStateProps::Stalled).unwrap(),
        serde_json::to_value(InputStateProps::Degraded).unwrap()
    );
}

#[test]
fn a_stalled_feed_forbids_the_green_token_and_ships_the_alert() {
    // A covering Runtime feed that stalled: the chip goes `stalled`, green is forbidden, and the
    // strip-level `coverage-alert` banner ships (present ONLY because a covering feed stalled).
    let strip = runtime_covered_strip().with_coverage_stall(Some(runtime_alert()));
    let v = serde_json::to_value(&strip).unwrap();
    assert_eq!(
        v["all-clear"],
        json!(false),
        "a stalled feed can never ship the green all-clear"
    );
    let chip = &v["coverage"][0];
    assert_eq!(chip["stalled"], json!(true), "the chip reads stalled");
    assert_eq!(
        chip["present"],
        json!(false),
        "a stalled feed is not present"
    );
    assert_eq!(chip["degraded"], json!(false), "stalled is not degraded");
    // The banner is present with its feed label + last-observation + message.
    assert_eq!(v["coverage-alert"]["feed-label"], json!("Runtime"));
    assert_eq!(v["coverage-alert"]["last-observation"], json!("2m ago"));
    assert!(
        v["coverage-alert"]["message"]
            .as_str()
            .unwrap()
            .contains("stalled")
    );
}

#[test]
fn no_stall_ships_a_null_coverage_alert() {
    // The common case: no feed stalled ⇒ the additive `coverage-alert` is `null` (never synthesized).
    let v = serde_json::to_value(runtime_covered_strip()).unwrap();
    assert_eq!(
        v["coverage-alert"],
        json!(null),
        "no stall means no banner — the client never synthesizes one"
    );
}

#[test]
fn a_wholly_blind_expected_feed_forbids_the_green_token() {
    // The cold-start / crash-loop hole the security audit found: an EXPECTED runtime fleet that is
    // wholly dark this pass (never `was_covering`, so no stall edge fires) must NOT read green. It is
    // DISTINCT from an `absent` feed (never enabled), which is an honest known-absence that may stay
    // green. Before the fix, both collapsed to `present:false` and `fully_covered` ignored it → green.
    let mut blind = all_clear_strip();
    blind.coverage = vec![CoverageChip {
        label: "Runtime".into(),
        present: false,
        degraded: false,
        blind: true,
        stalled: false,
    }];
    assert!(
        !blind.all_clear(),
        "a wholly-blind EXPECTED feed must forbid the green all-clear"
    );
    assert_ne!(
        blind.judging_state(),
        "all-clear",
        "and its judging token is not the green one"
    );
    let v = serde_json::to_value(&blind).unwrap();
    assert_eq!(
        v["coverage"][0]["blind"],
        json!(true),
        "the chip reads blind on the wire"
    );
    assert_eq!(v["all-clear"], json!(false));

    // Contrast — an `absent` feed (never enabled, expected==0) is an honest known-absence and DOES
    // NOT block the all-clear: the exact distinction the fix preserves.
    let mut absent = all_clear_strip();
    absent.coverage = vec![CoverageChip {
        label: "Runtime".into(),
        present: false,
        degraded: false,
        blind: false,
        stalled: false,
    }];
    assert!(
        absent.all_clear(),
        "an absent (never-enabled) feed is an honest known-absence — it does not block the all-clear"
    );
}

// ---------------------------------------------------------------------------
// The single judging-axis token `judging-state` (JEF-408): the ONE string the
// client strip switches on to pick the whole axis. It is server-derived from
// the SAME branch logic as `all-clear`/`watching`, so it can never disagree.
// ---------------------------------------------------------------------------

#[test]
fn judging_state_all_clear_ships_the_green_token() {
    let v = serde_json::to_value(all_clear_strip()).unwrap();
    assert_eq!(
        v["judging-state"],
        json!("all-clear"),
        "an affirmatively-cleared strip ships the green judging token"
    );
}

#[test]
fn judging_state_reads_watching_when_something_is_outstanding() {
    // Model up but an entry still awaiting / uncertain — the calm, NON-green watching token.
    let mut awaiting = all_clear_strip();
    awaiting.awaiting_count = 1;
    assert_eq!(
        serde_json::to_value(&awaiting).unwrap()["judging-state"],
        json!("watching")
    );

    let mut uncertain = all_clear_strip();
    uncertain.uncertain_count = 1;
    assert_eq!(
        serde_json::to_value(&uncertain).unwrap()["judging-state"],
        json!("watching")
    );

    // A COLD-baseline signing regression is a weak lead — still up, reads watching (not breach-loud).
    let cold = all_clear_strip().with_signing_regressions(0, 1);
    assert_eq!(
        serde_json::to_value(&cold).unwrap()["judging-state"],
        json!("watching"),
        "a cold regression reads the calm watching token"
    );
}

#[test]
fn judging_state_reads_judging_when_up_with_a_breach() {
    // Model up with a loud breach: the axis is the calm "judging" (the breach is loud in the
    // headline, not the axis) — NOT watching, NOT green.
    let mut breach = all_clear_strip();
    breach.breach_count = 1;
    assert_eq!(
        serde_json::to_value(&breach).unwrap()["judging-state"],
        json!("judging")
    );
}

#[test]
fn judging_state_reads_warming_when_warming_up() {
    // A completed pass has not landed — verdicts still loading. Non-green.
    let mut warming = all_clear_strip();
    warming.warming_up = true;
    let v = serde_json::to_value(&warming).unwrap();
    assert_eq!(v["judging-state"], json!("warming"));
    assert_eq!(v["all-clear"], json!(false), "warming is never green");
    assert_eq!(v["watching"], json!(false));
}

#[test]
fn judging_state_reads_no_model_when_none_attached() {
    let mut none = all_clear_strip();
    none.model_judging = false;
    none.model_attached = false;
    assert_eq!(
        serde_json::to_value(&none).unwrap()["judging-state"],
        json!("no-model")
    );
}

#[test]
fn judging_state_reads_blind_when_the_model_is_down() {
    // Attached but not answering — the honest blind register (non-green).
    let mut down = all_clear_strip();
    down.model_judging = false;
    let v = serde_json::to_value(&down).unwrap();
    assert_eq!(v["judging-state"], json!("blind"));
    assert_eq!(v["all-clear"], json!(false));
}

#[test]
fn judging_state_is_all_clear_iff_the_green_token_is() {
    // The safety-critical alignment: the judging token reads `all-clear` EXACTLY when the `all-clear`
    // boolean is true — never a green judging axis over a non-green strip. Sweep the honesty states.
    let cases: Vec<StatusStripProps> = vec![
        all_clear_strip(),
        {
            let mut s = all_clear_strip();
            s.awaiting_count = 1;
            s
        },
        {
            let mut s = all_clear_strip();
            s.breach_count = 2;
            s
        },
        {
            let mut s = all_clear_strip();
            s.warming_up = true;
            s
        },
        {
            let mut s = all_clear_strip();
            s.model_judging = false;
            s
        },
        all_clear_strip().with_signing_regressions(1, 0),
    ];
    for strip in cases {
        let all_clear = strip.all_clear();
        let v = serde_json::to_value(&strip).unwrap();
        assert_eq!(
            v["judging-state"] == json!("all-clear"),
            all_clear,
            "judging-state may read all-clear IFF the strip is all_clear() ({strip:?})"
        );
    }
}

#[test]
fn cleared_posture_is_the_only_green_row_token() {
    // The per-row honesty token: `is_cleared` — asserted at the JSON boundary via the enum tag the
    // client switches on. Only `cleared` is the green path.
    for (posture, cleared) in [
        (Posture::Cleared, true),
        (Posture::Breach, false),
        (Posture::Uncertain, false),
        (Posture::Awaiting, false),
    ] {
        assert_eq!(
            posture.is_cleared(),
            cleared,
            "{posture:?} greenness must match the honesty gate"
        );
    }
}

#[test]
fn alerts_view_carries_the_blind_caveat_token() {
    // Case X = a blind node while the Alerts view is quiet: the server-decided caveat ships in the
    // JSON so the client renders the honest "absence is not safety" state without deriving it.
    let view = AlertsViewProps {
        strip: all_clear_strip(),
        alerts: vec![],
        blind_caveat: Some("web-1 has no live sensor".into()),
    };
    let v = serde_json::to_value(view).unwrap();
    assert_eq!(v["blind-caveat"], json!("web-1 has no live sensor"));
    assert!(v["alerts"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Reconcile-key ids (ADR-0025): FindingProps.id / ReadinessRowProps.id
// serialize; AlertProps / DecisionRowProps carry no id by design.
// ---------------------------------------------------------------------------

#[test]
fn finding_and_readiness_ids_serialize_as_reconcile_keys() {
    let finding = sample_finding("web-to-db-creds", Posture::Awaiting, None);
    let v = serde_json::to_value(&finding).unwrap();
    assert_eq!(
        v["id"],
        json!("web-to-db-creds"),
        "the finding id is the client key"
    );

    let row = ReadinessRowProps {
        id: "runtime-corroboration".into(),
        label: "runtime".into(),
        state: InputStateProps::Present,
        why: "corroborates".into(),
        enable: String::new(),
        detail: "3 nodes".into(),
        weakens_decisions: true,
        nodes: vec![],
    };
    let rv = serde_json::to_value(row).unwrap();
    assert_eq!(rv["id"], json!("runtime-corroboration"));

    // AlertProps carries NO id field by design (a current-window observation, not a reconcile row).
    let alert = AlertProps {
        signal: "notable exec".into(),
        kind: "exec".into(),
        workload: "web".into(),
        recency: "this pass".into(),
        on_chain: None,
    };
    let av = serde_json::to_value(alert).unwrap();
    assert!(
        av.get("id").is_none(),
        "an alert row must not fabricate an id"
    );
}

// ---------------------------------------------------------------------------
// Untrusted text ships RAW (NOT pre-escaped). Escaping is the render layer's
// single job; a `<script>` payload must survive VERBATIM in the JSON.
// ---------------------------------------------------------------------------

#[test]
fn untrusted_script_text_survives_verbatim_unescaped_in_the_json() {
    let xss = "<script>alert('pwn')</script>";
    let finding = sample_finding("evil", Posture::Breach, Some(xss.to_string()));
    let v = serde_json::to_value(&finding).unwrap();
    // The JSON string is the RAW payload — serde does not HTML-escape; double-escaping would be
    // the bug (ADR-0025). The client escapes at render.
    assert_eq!(
        v["verdict-summary"],
        json!(xss),
        "the verdict prose ships raw, byte-for-byte"
    );
    // And it is present verbatim in the serialized text — byte-for-byte, no `&lt;` HTML-entity
    // mangling and no forward-slash escaping (serde_json does neither). The client escapes at
    // render; the JSON must carry the raw payload (ADR-0025).
    let text = serde_json::to_string(&finding).unwrap();
    assert!(
        text.contains("<script>alert('pwn')</script>"),
        "the raw <script> survives verbatim (never HTML-escaped): {text}"
    );
    assert!(
        !text.contains("&lt;script&gt;"),
        "must NOT be HTML pre-escaped"
    );
}

#[test]
fn untrusted_alert_signal_survives_verbatim_in_the_json() {
    let xss = "drop-and-execute: <img src=x onerror=alert(1)>";
    let alert = AlertProps {
        signal: xss.into(),
        kind: "exec".into(),
        workload: "<b>web</b>".into(),
        recency: "this pass".into(),
        on_chain: None,
    };
    let v = serde_json::to_value(alert).unwrap();
    assert_eq!(v["signal"], json!(xss), "the untrusted signal ships raw");
    assert_eq!(v["workload"], json!("<b>web</b>"), "the workload ships raw");
}

// ---------------------------------------------------------------------------
// The top-level view shape — the client's tab endpoints get the whole tree.
// ---------------------------------------------------------------------------

#[test]
fn findings_view_serializes_strip_plus_keyed_rows() {
    let view = FindingsViewProps {
        strip: all_clear_strip(),
        findings: vec![sample_finding("a", Posture::Cleared, Some("safe".into()))],
    };
    let v = serde_json::to_value(view).unwrap();
    assert!(v["strip"].is_object(), "the persistent strip is nested");
    assert_eq!(v["strip"]["all-clear"], json!(true));
    let rows = v["findings"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], json!("a"));
    assert_eq!(rows[0]["posture"], json!("cleared"));
}

/// A minimal FindingProps fixture — enough to pin the wire shape without the engine.
fn sample_finding(id: &str, posture: Posture, verdict: Option<String>) -> FindingProps {
    FindingProps {
        id: id.into(),
        posture,
        live_tag: LiveTag::None,
        delta: DeltaProps::New,
        entry_glyph: "\u{1F310}".into(),
        entry: "web".into(),
        foothold: true,
        objective: "db-creds".into(),
        fanout: None,
        replicas: None,
        evidence_summary: EvidenceSummary::default(),
        disposition: "propose".into(),
        verdict_summary: verdict,
        path: vec![],
        paths: vec![],
        paths_truncated: false,
        cut: None,
        evidence: EvidenceProps::default(),
        judgement: JudgementProps::default(),
        blind_node_caveat: None,
        alerts: vec![],
    }
}
