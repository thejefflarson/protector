//! Tests for the Activity view_model mapping: the reversion/judgement snapshots → Props shaping,
//! the age formatting, and the honest absent prompt/reply preservation.

use super::*;
use crate::engine::state::{Judgement, ReversionRecord};

fn strip() -> StatusStripProps {
    StatusStripProps {
        cluster: "prod".into(),
        armed: false,
        model_judging: true,
        warming_up: false,
        model_attached: true,
        coverage: vec![],
        last_pass: None,
        breach_count: 0,
        awaiting_count: 0,
        uncertain_count: 0,
        cleared_count: 0,
        escalated_count: 0,
    }
}

#[test]
fn reversion_age_is_formatted_relative_to_now() {
    let now_ms = 10_000_000u64;
    let reversions = vec![ReversionRecord {
        cut: "web -[reaches]-> db".into(),
        reason: "breach condition cleared".into(),
        at_ms: now_ms - 90_000, // 90s ago
    }];
    let v = build_at(strip(), &reversions, &[], now_ms);
    assert_eq!(v.reversions.len(), 1);
    assert_eq!(v.reversions[0].age, "1m"); // 90s ⇒ 1m bucket
    assert_eq!(v.reversions[0].reason, "breach condition cleared");
}

#[test]
fn a_future_or_skewed_reversion_clamps_to_zero_age() {
    let now_ms = 1_000u64;
    let reversions = vec![ReversionRecord {
        cut: "web -[reaches]-> db".into(),
        reason: "skew".into(),
        at_ms: now_ms + 5_000, // "in the future" — clock skew
    }];
    let v = build_at(strip(), &reversions, &[], now_ms);
    assert_eq!(v.reversions[0].age, "0s");
}

#[test]
fn judgement_preserves_absent_prompt_and_reply_honestly() {
    let judgements = vec![
        Judgement {
            entry: "web".into(),
            objectives: 1,
            verdict: "Exploitable".into(),
            prompt: Some("the prompt".into()),
            reply: Some("the reply".into()),
        },
        Judgement {
            entry: "api".into(),
            objectives: 3,
            verdict: "Uncertain".into(),
            prompt: None, // pre-filter decided
            reply: None,  // timed out
        },
    ];
    let v = build_at(strip(), &[], &judgements, 0);
    assert_eq!(v.judgements.len(), 2);
    assert_eq!(v.judgements[0].prompt.as_deref(), Some("the prompt"));
    assert_eq!(v.judgements[0].reply.as_deref(), Some("the reply"));
    // The absent prompt/reply stay None so the component can render the honest "no prompt"/"no
    // reply" lines (never a blank).
    assert!(v.judgements[1].prompt.is_none());
    assert!(v.judgements[1].reply.is_none());
    assert_eq!(v.judgements[1].objectives, 3);
}

#[test]
fn empty_logs_yield_empty_vecs() {
    let v = build_at(strip(), &[], &[], 0);
    assert!(v.reversions.is_empty());
    assert!(v.judgements.is_empty());
}
