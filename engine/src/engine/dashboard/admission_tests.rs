//! Render-level tests for the Admission/policy view (the webhook floor, brief §6): the tallies
//! header (never blank, honest at zero), the deduped decision rows + the "if enforced" what-if, the
//! honest-empty case, the real fourth nav tab, and escaping of the untrusted image/subject/reason
//! text. These drive the view_model + component directly (no HTTP, no engine), so they are fast and
//! pure. Kept in their own file so `tests.rs` stays under the 1,000-line cap (CLAUDE.md).

use std::time::SystemTime;

use crate::engine::policy_log::{DecisionTallies, PolicyDecisionRecord};
use crate::engine::state::{BakeStats, Finding, ModelHealth, ReadinessConfig, derive_readiness};

use super::page;
use super::view_model::{build_admission_view, build_status_strip};

/// A readiness snapshot for a fully-covered, actively-judging model (mirrors `tests::judging_readiness`).
fn judging_readiness() -> crate::engine::state::Readiness {
    let config = ReadinessConfig {
        model_attached: true,
        kev_count: 5,
        epss_count: 5,
        journal_durable: true,
        armed: false,
    };
    let mut bake = BakeStats::default();
    bake.signals_by_variant.insert("alert".into(), 1);
    derive_readiness(&config, ModelHealth::Ok, &bake, Some(SystemTime::now()))
}

/// Build the persistent strip from a given findings snapshot (the strip the Admission view carries).
fn strip_from(findings: &[Finding]) -> super::view_model::props::StatusStripProps {
    build_status_strip(
        "prod".into(),
        findings,
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    )
}

#[allow(clippy::too_many_arguments)]
fn admission_rec(
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
fn admission_nav_tab_is_a_real_fourth_surface() {
    // The four tabs are all reachable; the Admission tab links to its real route. The merged
    // Action tab replaces the former Trust + Activity pair.
    let v = build_admission_view(strip_from(&[]), DecisionTallies::default(), &[]);
    let html = page::admission_page(&v).into_string();
    for tab in ["Findings", "Action", "Readiness", "Admission"] {
        assert!(html.contains(tab), "the nav offers the {tab} tab");
    }
    // The retired tabs are gone from the nav.
    assert!(!html.contains(">Trust<"), "no Trust nav label remains");
    assert!(
        !html.contains(">Activity<"),
        "no Activity nav label remains"
    );
    assert!(
        html.contains("?tab=admission"),
        "the Admission tab links to its real route"
    );
}

#[test]
fn admission_tallies_header_is_never_blank_even_at_zero() {
    // The webhook floor's headline: counts honest at zero, so a healthy cluster is never blank.
    let v = build_admission_view(strip_from(&[]), DecisionTallies::default(), &[]);
    let html = page::admission_page(&v).into_string();
    assert!(html.contains("admitted"), "the admitted tally is rendered");
    assert!(html.contains("audited"), "the audited tally is rendered");
    assert!(html.contains("denied"), "the denied tally is rendered");
    // And the honest-empty body, never read as all-clear.
    assert!(
        html.contains("no admission decisions recorded yet"),
        "an empty log reads as no-decisions, not all-clear"
    );
    assert!(html.contains("not an all-clear"));
}

#[test]
fn admission_renders_deduped_rows_with_the_if_enforced_what_if() {
    let tallies = DecisionTallies {
        admitted: 42,
        audited: 2,
        denied: 1,
    };
    let rows = vec![
        // A clean admit — verified on both gates, would admit.
        admission_rec(
            "allow",
            "Deployment/web",
            "ghcr.io/org/web:1",
            "verified",
            "verified",
            "default",
            "",
            true,
        ),
        // A would-fail signature gate → the "if enforced" what-if is would-deny.
        admission_rec(
            "audit",
            "Deployment/legacy",
            "docker.io/legacy:old",
            "would-fail",
            "would-pass",
            "payments",
            "unsigned or untrusted image",
            false,
        ),
    ];
    let html =
        page::admission_page(&build_admission_view(strip_from(&[]), tallies, &rows)).into_string();
    // The counts surface.
    assert!(html.contains("42"), "the admitted count");
    // The per-gate shadow status words ride alongside their glyphs (meaning never by colour alone).
    assert!(html.contains("verified"), "a verified gate");
    assert!(html.contains("would-fail"), "a would-fail gate");
    assert!(html.contains("would-pass"), "a would-pass gate");
    // The "if enforced" what-if for both directions.
    assert!(html.contains("would admit"), "the admit what-if");
    assert!(html.contains("would deny"), "the would-deny what-if");
    // The subject + image surface (untrusted, escaped by maud).
    assert!(html.contains("Deployment/web"));
    assert!(html.contains("ghcr.io/org/web:1"));
}

#[test]
fn admission_dedup_count_shows_when_above_one() {
    let mut r = admission_rec(
        "allow", "Pod/web", "img:1", "verified", "verified", "ns", "", true,
    );
    r.count = 50;
    let html = page::admission_page(&build_admission_view(
        strip_from(&[]),
        DecisionTallies::default(),
        &[r],
    ))
    .into_string();
    assert!(
        html.contains("\u{00D7}50"),
        "the replica-churn dedup count (×50) is shown"
    );
}

#[test]
fn admission_untrusted_image_and_reason_are_escaped() {
    let evil = "<script>alert('x')</script>";
    let rows = vec![admission_rec(
        "deny",
        format!("Pod/{evil}").as_str(),
        format!("img/{evil}").as_str(),
        "would-fail",
        "verified",
        evil,
        format!("unsigned {evil}").as_str(),
        false,
    )];
    let html = page::admission_page(&build_admission_view(
        strip_from(&[]),
        DecisionTallies::default(),
        &rows,
    ))
    .into_string();
    assert!(
        !html.contains("<script>alert"),
        "raw script must not reach output"
    );
    assert!(html.contains("&lt;script&gt;"), "it is escaped");
}

#[test]
fn admission_fragment_has_no_document_shell() {
    let v = build_admission_view(strip_from(&[]), DecisionTallies::default(), &[]);
    let frag = page::admission_fragment(&v).into_string();
    assert!(!frag.contains("<!DOCTYPE"), "a fragment carries no doctype");
    assert!(!frag.contains("<html"), "nor a document element");
    // It carries the persistent strip (a poll refreshes coverage/freshness on this tab too).
    assert!(frag.contains("strip"));
}
