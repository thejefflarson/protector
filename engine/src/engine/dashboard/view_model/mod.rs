//! The **view_model** layer (ADR-0019): the ONLY layer that touches `engine::`/`state::`
//! domain types. It shapes the engine's read-only output state into the plain [`props`] the
//! pure components render — the React-like data layer. The components import these props and
//! nothing from `engine::`, a boundary the guard tests enforce (invariant #4).
//!
//! Nothing here makes a decision: it is a view, never a gate (ADR-0016). The honesty rules
//! (Uncertain/Awaiting never green; calm only while judging) are encoded in the mapping
//! (`posture`/`strip`) and tested at this boundary.

pub mod props;

mod activity;
mod admission;
mod findings;
mod posture;
mod readiness;
mod strip;
mod trust;

use std::time::SystemTime;

use crate::engine::policy_log::{DecisionTallies, PolicyDecisionRecord};
use crate::engine::state::{Finding, Judgement, Readiness, Report, ReversionRecord};

use props::{
    ActivityViewProps, AdmissionViewProps, FindingProps, FindingsViewProps, Posture,
    ReadinessViewProps, StatusStripProps, TrustViewProps,
};

/// Build the persistent status strip with the TRUE findings headline counts (brief §3/§4). The
/// strip is carried on EVERY view (Findings, Trust, Readiness, Activity), and its honesty reading
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
    let rows = findings::map_findings(findings, judgements);
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
/// a secondary view (Trust / Readiness / Activity) shows, so its honesty reading reflects the real
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

/// Build the whole Readiness view's props (brief §6): the persistent strip + one coverage row per
/// decision input, weakening-when-absent inputs first. Pure given its inputs.
pub fn build_readiness_view(strip: StatusStripProps, readiness: &Readiness) -> ReadinessViewProps {
    readiness::build(strip, readiness)
}

/// Build the whole Trust (would-have-acted) view's props (brief §6): the persistent strip + the
/// would-cut / left-alone diff from the report. Pure given its inputs.
pub fn build_trust_view(strip: StatusStripProps, report: &Report) -> TrustViewProps {
    trust::build(strip, report)
}

/// Build the whole Activity (audit) view's props (brief §6): the persistent strip + the
/// self-reverted-cuts log + the judgement ring (both newest-first). Pure given its inputs.
pub fn build_activity_view(
    strip: StatusStripProps,
    reversions: &[ReversionRecord],
    judgements: &[Judgement],
) -> ActivityViewProps {
    activity::build(strip, reversions, judgements)
}

/// Build the whole Admission/policy (webhook floor) view's props (brief §6): the persistent strip +
/// the decision tallies header (so a healthy view is never blank) + the deduped decision rows.
/// Pure given its inputs.
pub fn build_admission_view(
    strip: StatusStripProps,
    tallies: DecisionTallies,
    rows: &[PolicyDecisionRecord],
) -> AdmissionViewProps {
    admission::build(strip, tallies, rows)
}
