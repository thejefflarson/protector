//! Map the webhook's admission-decision log into the [`AdmissionViewProps`] the Admission view
//! renders (brief §6 — the webhook floor): the [`DecisionTallies`] header (admitted/audited/denied,
//! so a healthy view is never blank) + the deduped decision rows (signature/mesh/decision + the
//! JEF-246 "if enforced" what-if). The per-gate shadow status (`verified` / `would-pass` /
//! `would-fail`) is parsed into the presentation enum here so the components never see a raw status
//! word. Data layer: touches `engine::`; the components never do.

use crate::engine::policy_log::{DecisionTallies, PolicyDecisionRecord};

use super::props::{
    AdmissionDecision, AdmissionViewProps, DecisionRowProps, GateStatus, StatusStripProps,
};

/// Project one engine [`PolicyDecisionRecord`] into its presentation row. The coarse decision and
/// per-gate status words are parsed into the presentation enums; the untrusted free-text fields
/// (subject / image / namespace / reason) pass through and are escaped by the component at render.
fn decision_row(r: &PolicyDecisionRecord) -> DecisionRowProps {
    DecisionRowProps {
        decision: AdmissionDecision::parse(&r.decision),
        subject: r.subject.clone(),
        image: r.image.clone(),
        namespace: r.namespace.clone(),
        signature: GateStatus::parse(&r.signature),
        mesh: GateStatus::parse(&r.mesh),
        would_admit: r.would_admit,
        reason: r.reason.clone(),
        count: r.count,
    }
}

/// Build the whole Admission view's props from the webhook's decision tallies + the deduped row
/// snapshot (newest-first) + the persistent strip the caller supplies. The tallies carry liveness
/// even when the (deduped) row set is short, so a healthy cluster never renders blank. Pure given
/// its inputs — driveable in tests with no engine.
pub(super) fn build(
    strip: StatusStripProps,
    tallies: DecisionTallies,
    rows: &[PolicyDecisionRecord],
) -> AdmissionViewProps {
    AdmissionViewProps {
        strip,
        admitted: tallies.admitted,
        audited: tallies.audited,
        denied: tallies.denied,
        total: tallies.total(),
        rows: rows.iter().map(decision_row).collect(),
    }
}

#[cfg(test)]
mod tests;
