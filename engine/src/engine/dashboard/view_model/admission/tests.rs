//! Tests for the Admission view_model mapping: the tallies (derived from the DECISION rows, so the
//! signing sweep's observation rows never inflate them), the deduped rows shaping, the mesh
//! shadow-status parse, and the honest all-zero / empty-rows case. The per-image signing inventory
//! mapping is tested in `super::super::signing_inventory`.

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
        coverage_alert: None,
        last_pass: None,
        breach_count: 0,
        awaiting_count: 0,
        uncertain_count: 0,
        cleared_count: 0,
        escalated_count: 0,
        signing_regression_breach: 0,
        signing_regression_uncertain: 0,
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
fn tallies_are_summed_from_the_decision_rows() {
    // The header counts are derived from the deduped DECISION rows' counts (summing them equals the
    // log's own tallies), so a healthy view is never blank and observation rows don't inflate them.
    let mut admits = rec(
        "allow", "Pod/web", "img:1", "verified", "verified", "ns", "", true,
    );
    admits.count = 12;
    let mut audits = rec(
        "audit",
        "Pod/legacy",
        "img:2",
        "would-fail",
        "verified",
        "ns",
        "x",
        false,
    );
    audits.count = 3;
    let deny = rec(
        "deny",
        "Pod/dbg",
        "img:3",
        "would-pass",
        "would-fail",
        "ns",
        "y",
        false,
    );
    let v = build(strip(), &[admits, audits, deny]);
    assert_eq!(v.admitted, 12);
    assert_eq!(v.audited, 3);
    assert_eq!(v.denied, 1);
    assert_eq!(v.total, 16, "total sums every outcome");
}

#[test]
fn observation_rows_feed_the_inventory_not_the_tallies() {
    // A signing-sweep observation row (subject `Image/<ref>`, decision `allow`) belongs to the
    // signing inventory and must NOT be counted as an admission admit.
    let admit = rec(
        "allow", "Pod/web", "img:1", "verified", "verified", "ns", "", true,
    );
    let observation = PolicyDecisionRecord::now(
        "image-signature",
        "allow",
        "Image/ghcr.io/org/app:1",
        "ghcr.io/org/app:1",
        "not-signed",
        "",
        "",
        "",
    );
    let v = build(strip(), &[admit, observation]);
    assert_eq!(v.admitted, 1, "only the real admission decision is counted");
    assert_eq!(v.rows.len(), 1, "the observation row is not a decision row");
    assert_eq!(
        v.signing.len(),
        1,
        "the observation row is in the inventory"
    );
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
    let v = build(strip(), &rows);
    assert_eq!(v.rows.len(), 1);
    let row = &v.rows[0];
    assert_eq!(row.subject, "Pod/web");
    assert_eq!(row.image, "ghcr.io/org/app:1");
    assert_eq!(row.namespace, "payments");
    assert_eq!(row.decision, AdmissionDecision::Allow);
    assert!(row.would_admit);
}

#[test]
fn the_mesh_shadow_what_if_words_map_to_the_gate_states() {
    let rows = vec![
        rec(
            "deny",
            "Pod/a",
            "img:a",
            "would-fail",
            "verified",
            "ns",
            "r",
            false,
        ),
        rec(
            "audit",
            "Pod/b",
            "img:b",
            "would-pass",
            "would-fail",
            "ns",
            "r",
            false,
        ),
        // An empty / unknown legacy mesh word reads as not-applicable, never a false pass.
        rec("allow", "Pod/c", "img:c", "", "signed", "ns", "", true),
    ];
    let v = build(strip(), &rows);
    assert_eq!(v.rows[0].mesh, GateStatus::Verified);
    assert_eq!(v.rows[1].mesh, GateStatus::WouldFail);
    assert_eq!(
        v.rows[2].mesh,
        GateStatus::NotApplicable,
        "an unknown legacy word (`signed`) is not-applicable, not a false pass"
    );
}

#[test]
fn empty_log_renders_zero_tallies_no_rows_and_no_inventory() {
    // The honest-empty case: no decisions recorded. Counts are honest at zero and there are no rows.
    let v = build(strip(), &[]);
    assert_eq!(v.admitted, 0);
    assert_eq!(v.audited, 0);
    assert_eq!(v.denied, 0);
    assert_eq!(v.total, 0);
    assert!(v.rows.is_empty());
    assert!(v.signing.is_empty());
}

#[test]
fn dedup_count_passes_through() {
    let mut r = rec(
        "allow", "Pod/web", "img:1", "verified", "verified", "ns", "", true,
    );
    r.count = 50;
    let v = build(strip(), &[r]);
    assert_eq!(
        v.rows[0].count, 50,
        "the replica-churn dedup count is carried"
    );
}
