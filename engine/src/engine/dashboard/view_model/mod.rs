//! The **view_model** layer (ADR-0019): the ONLY layer that touches `engine::`/`state::`
//! domain types. It shapes the engine's read-only output state into the plain [`props`] the
//! pure components render — the React-like data layer. The components import these props and
//! nothing from `engine::`, a boundary the guard tests enforce (invariant #4).
//!
//! Nothing here makes a decision: it is a view, never a gate (ADR-0016). The honesty rules
//! (Uncertain/Awaiting never green; calm only while judging) are encoded in the mapping
//! (`posture`/`strip`) and tested at this boundary.

pub mod props;

mod access;
mod action;
mod admission;
mod alerts;
mod findings;
mod posture;
mod readiness;
mod signing_inventory;
mod strip;

use std::time::SystemTime;

use crate::engine::dashboard::auth::claims::Tier;
use crate::engine::mcp::AccessRecord;
use crate::engine::policy_log::PolicyDecisionRecord;
use crate::engine::state::{CoverageState, Finding, Judgement, Readiness, Report, ReversionRecord};

use props::{
    AccessViewProps, ActionViewProps, AdmissionViewProps, AlertsViewProps, FindingProps,
    FindingsViewProps, Posture, ReadinessViewProps, StatusStripProps, StripCoverageAlert,
};

/// Build the persistent status strip with the TRUE findings headline counts (brief §3/§4). The
/// strip is carried on EVERY view (Findings, Action, Readiness, Admission), and its honesty reading
/// (all-clear / watching / blind) depends on the real breach/awaiting/uncertain counts — so a
/// secondary tab must not zero them, or the strip would falsely read "all clear" while Findings
/// holds a breach. The mapped findings rows are returned alongside so the Findings view reuses
/// them without re-mapping.
fn strip_from_findings(
    cluster: String,
    findings: &[Finding],
    judgements: &[Judgement],
    readiness: &Readiness,
    last_pass: Option<SystemTime>,
) -> (StatusStripProps, Vec<FindingProps>) {
    // Blind nodes (JEF-308) come from the readiness runtime-corroboration breakdown, so a finding
    // on a node with no live sensor carries its caveat.
    let blind_nodes = findings::blind_nodes_of(readiness);
    let rows = findings::map_findings(findings, judgements, &blind_nodes);
    let breach = rows.iter().filter(|r| r.posture == Posture::Breach).count();
    let awaiting = rows
        .iter()
        .filter(|r| r.posture == Posture::Awaiting)
        .count();
    let uncertain = rows
        .iter()
        .filter(|r| r.posture == Posture::Uncertain)
        .count();
    let cleared = rows
        .iter()
        .filter(|r| r.posture == Posture::Cleared)
        .count();
    let escalated = rows
        .iter()
        .filter(|r| matches!(r.delta, props::DeltaProps::Escalated))
        .count();
    let strip = strip::status_strip(
        cluster, readiness, last_pass, breach, awaiting, uncertain, cleared, escalated,
    );
    (strip, rows)
}

/// Build the whole Findings view's props from the engine's read-only state. `findings` is a
/// findings snapshot (verdicts already resolved), `judgements` the newest-first judgement ring
/// (for the verbatim "show model prompt" disclosure), `readiness` the coverage snapshot, and
/// `last_pass` the freshness stamp. Pure given its inputs — driveable in tests with no engine.
pub fn build_findings_view(
    cluster: String,
    findings: &[Finding],
    judgements: &[Judgement],
    readiness: &Readiness,
    last_pass: Option<SystemTime>,
) -> FindingsViewProps {
    let (strip, findings) =
        strip_from_findings(cluster, findings, judgements, readiness, last_pass);
    FindingsViewProps { strip, findings }
}

/// Build the persistent status strip carrying the TRUE findings counts (brief §3/§4) — the strip
/// a secondary view (Action / Readiness / Admission) shows, so its honesty reading reflects the real
/// cluster posture, not a falsely-empty one. The mapped findings drive the counts but are
/// discarded; the secondary view supplies its own body.
pub fn build_status_strip(
    cluster: String,
    findings: &[Finding],
    judgements: &[Judgement],
    readiness: &Readiness,
    last_pass: Option<SystemTime>,
) -> StatusStripProps {
    strip_from_findings(cluster, findings, judgements, readiness, last_pass).0
}

/// Build the whole Alerts view's props (JEF-323): the persistent strip + the current-window
/// "alarming-now" activity events across every finding's entry this pass, plus the calm
/// blind-node caveat for the quiet state. A CURRENT-WINDOW view (runtime signals live one pass),
/// NOT a persisted audit log. Derived from the SAME per-pass findings snapshot the Findings view
/// reads, so the Alerts tab and the findings-view "alarming activity observed" line never disagree.
/// Pure given its inputs.
pub fn build_alerts_view(
    strip: StatusStripProps,
    findings: &[Finding],
    readiness: &Readiness,
) -> AlertsViewProps {
    alerts::build(strip, findings, readiness)
}

/// Build the whole Readiness view's props (brief §6): the persistent strip + one coverage row per
/// decision input, weakening-when-absent inputs first. Pure given its inputs.
pub fn build_readiness_view(strip: StatusStripProps, readiness: &Readiness) -> ReadinessViewProps {
    readiness::build(strip, readiness)
}

/// Build the whole Action view's props (brief §4/§6) — the merged Trust + Activity story in
/// lifecycle order: the persistent strip + the proposed cuts (would-act proposals + self-reverted
/// cuts) + the left-alone (cleared) paths + the judgement audit. Pure given its inputs.
pub fn build_action_view(
    strip: StatusStripProps,
    report: &Report,
    reversions: &[ReversionRecord],
    judgements: &[Judgement],
) -> ActionViewProps {
    action::build(strip, report, reversions, judgements)
}

/// Build the whole Admission/policy (webhook floor) view's props (brief §6): the persistent strip +
/// the decision tallies header (so a healthy view is never blank) + the per-image signing inventory
/// (JEF-262) + the deduped decision rows. The tallies are derived from the webhook DECISION rows
/// alone — the signing sweep's observation rows (`Image/<ref>`) feed the inventory, never the
/// admitted/audited/denied counts — so pure observation can't inflate the decision totals. Pure
/// given its inputs.
pub fn build_admission_view(
    strip: StatusStripProps,
    rows: &[PolicyDecisionRecord],
) -> AdmissionViewProps {
    admission::build(strip, rows)
}

/// Build the whole "Access" view's props (JEF-490): the persistent strip + the caller's OWN tier
/// chip + the per-tier reveal list + the newest-first forensic/raw disclosure pulls, each redacted
/// to the CALLER's own tier (a lower-tier viewer never sees a higher-tier pull's target). `records`
/// are newest-first; `durable` selects the honest empty-state caveat. Pure given its inputs.
pub fn build_access_view(
    strip: StatusStripProps,
    caller_tier: Tier,
    records: &[AccessRecord],
    durable: bool,
) -> AccessViewProps {
    access::build(strip, caller_tier, records, durable)
}

/// The standing signing-regression counts `(established, cold)` derived from the admission-decision
/// log's regression rows (`SigningRegression/<repo>`, JEF-264) — established-baseline regressions
/// count toward breach, cold-baseline ones toward uncertain. The caller folds these into the
/// persistent strip (via [`StatusStripProps::with_signing_regressions`]) so a standing regression
/// keeps the strip non-green on EVERY tab, WITHOUT routing through the reachability findings
/// pipeline. Pure given its input.
pub fn signing_regression_counts(rows: &[PolicyDecisionRecord]) -> (usize, usize) {
    signing_inventory::counts(rows)
}

/// Map the server-derived coverage-stall register (JEF-421) into the strip-level `coverage-alert`
/// banner payload — `Some` ONLY for [`CoverageState::Stalled`] (a covering feed went dark past the
/// debounce). Every other register (`Covered`/`Degraded`/`Absent`) yields `None`: the stall banner
/// is exclusively the loud was-covering → now-silent edge, never the honest known-absence. The caller
/// folds the result into the strip via [`StatusStripProps::with_coverage_stall`], which also marks the
/// matching coverage chip stalled so the strip can never read green while a feed is dark.
pub fn coverage_stall_alert(state: &CoverageState) -> Option<StripCoverageAlert> {
    match state {
        CoverageState::Stalled(alert) => Some(StripCoverageAlert {
            feed_label: alert.feed_label.clone(),
            last_observation: alert.last_observation.clone(),
            message: alert.message.clone(),
        }),
        CoverageState::Covered | CoverageState::Degraded | CoverageState::Absent => None,
    }
}
