//! The **view_model** layer (ADR-0019): the ONLY layer that touches `engine::`/`state::`
//! domain types. It shapes the engine's read-only output state into the plain [`props`] the
//! pure components render — the React-like data layer. The components import these props and
//! nothing from `engine::`, a boundary the guard tests enforce (invariant #4).
//!
//! Nothing here makes a decision: it is a view, never a gate (ADR-0016). The honesty rules
//! (Uncertain/Awaiting never green; calm only while judging) are encoded in the mapping
//! (`posture`/`strip`) and tested at this boundary.

pub mod props;

mod findings;
mod posture;
mod strip;

use std::time::SystemTime;

use crate::engine::state::{Finding, Judgement, Readiness};

use props::{FindingsViewProps, Posture, StatusStripProps};

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
    let rows = findings::map_findings(findings, judgements);
    let breach = rows.iter().filter(|r| r.posture == Posture::Breach).count();
    let awaiting = rows
        .iter()
        .filter(|r| r.posture == Posture::Awaiting)
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
        cluster, readiness, last_pass, breach, awaiting, cleared, escalated,
    );
    FindingsViewProps {
        strip,
        findings: rows,
    }
}

/// Build only the status strip (for views that don't list findings — the phase-2 stubs still
/// carry the persistent strip). The headline counts are zeroed; a stub view shows no findings.
pub fn build_status_strip(
    cluster: String,
    readiness: &Readiness,
    last_pass: Option<SystemTime>,
) -> StatusStripProps {
    strip::status_strip(cluster, readiness, last_pass, 0, 0, 0, 0)
}
