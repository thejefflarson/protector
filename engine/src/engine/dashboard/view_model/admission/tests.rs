//! Tests for the Admission view_model mapping: the tallies → header counts, the deduped rows
//! shaping, the shadow what-if (`verified` / `would-pass` / `would-fail`) parse, and the honest
//! all-zero / empty-rows case.

use super::*;
use crate::engine::policy_log::PolicyDecisionRecord;

fn strip() -> StatusStripProps {
    // A minimal strip; the admission mapper does not inspect it, just carries it.
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

#[allow(clippy::too_many_arguments)]
fn rec(
    decision: &str,
    subject: &str,
    image: &str,
    signature: &str,
    mesh: &str,
    ns: &str,
    reason: &str,
    would_admit: bool,
) -> PolicyDecisionRecord {
    PolicyDecisionRecord::now(
        "admission",
        decision,
        subject,
        image,
        signature,
        mesh,
        ns,
        reason,
    )
    .with_would_admit(would_admit)
}

#[test]
fn tallies_drive_the_header_counts() {
    let tallies = DecisionTallies {
        admitted: 12,
        audited: 3,
        denied: 1,
    };
    let v = build(strip(), tallies, &[]);
    assert_eq!(v.admitted, 12);
    assert_eq!(v.audited, 3);
    assert_eq!(v.denied, 1);
    assert_eq!(v.total, 16, "total sums every outcome");
}

#[test]
fn rows_carry_the_subject_image_namespace_and_count() {
    let rows = vec![rec(
        "allow",
        "Pod/web",
        "ghcr.io/org/app:1",
        "verified",
        "verified",
        "payments",
        "",
        true,
    )];
    let v = build(strip(), DecisionTallies::default(), &rows);
    assert_eq!(v.rows.len(), 1);
    let row = &v.rows[0];
    assert_eq!(row.subject, "Pod/web");
    assert_eq!(row.image, "ghcr.io/org/app:1");
    assert_eq!(row.namespace, "payments");
    assert_eq!(row.decision, AdmissionDecision::Allow);
    assert!(row.would_admit);
}

#[test]
fn the_shadow_what_if_words_map_to_the_gate_states() {
    let rows = vec![
        rec(
            "deny",
            "Pod/a",
            "img:a",
            "would-fail",
            "verified",
            "ns",
            "unsigned image",
            false,
        ),
        rec(
            "audit",
            "Pod/b",
            "img:b",
            "would-pass",
            "would-fail",
            "ns",
            "not mesh-injected",
            false,
        ),
        // An empty / unknown legacy status word reads as not-applicable, never a false pass.
        rec("allow", "Pod/c", "img:c", "", "signed", "ns", "", true),
    ];
    let v = build(strip(), DecisionTallies::default(), &rows);
    assert_eq!(v.rows[0].signature, GateStatus::WouldFail);
    assert_eq!(v.rows[0].mesh, GateStatus::Verified);
    assert!(
        !v.rows[0].would_admit,
        "a would-fail gate flips would_admit"
    );

    assert_eq!(v.rows[1].signature, GateStatus::WouldPass);
    assert_eq!(v.rows[1].mesh, GateStatus::WouldFail);

    assert_eq!(
        v.rows[2].signature,
        GateStatus::NotApplicable,
        "an empty status word is not-applicable"
    );
    assert_eq!(
        v.rows[2].mesh,
        GateStatus::NotApplicable,
        "an unknown legacy word (`signed`) is not-applicable, not a false pass"
    );
}

#[test]
fn empty_log_renders_zero_tallies_and_no_rows() {
    // The honest-empty case: no admission decisions recorded. Counts are honest at zero (never
    // blank) and there are no rows.
    let v = build(strip(), DecisionTallies::default(), &[]);
    assert_eq!(v.admitted, 0);
    assert_eq!(v.audited, 0);
    assert_eq!(v.denied, 0);
    assert_eq!(v.total, 0);
    assert!(v.rows.is_empty());
}

#[test]
fn dedup_count_passes_through() {
    let mut r = rec(
        "allow", "Pod/web", "img:1", "verified", "verified", "ns", "", true,
    );
    r.count = 50;
    let v = build(strip(), DecisionTallies::default(), &[r]);
    assert_eq!(
        v.rows[0].count, 50,
        "the replica-churn dedup count is carried"
    );
}
