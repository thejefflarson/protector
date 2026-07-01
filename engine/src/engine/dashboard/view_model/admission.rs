//! Map the webhook's admission-decision log into the [`AdmissionViewProps`] the Admission view
//! renders (brief §6 — the webhook floor): the tallies header (admitted/audited/denied, so a
//! healthy view is never blank) + the per-image signing inventory (JEF-262) + the deduped decision
//! rows (mesh/decision + the JEF-246 "if enforced" what-if). The mesh shadow status
//! (`verified` / `would-pass` / `would-fail`) is parsed into the presentation enum here so the
//! components never see a raw status word; the signature posture now lives in the signing inventory
//! ([`signing_inventory`](super::signing_inventory)). Data layer: touches `engine::`; the
//! components never do.

use crate::engine::policy_log::PolicyDecisionRecord;

use super::props::{
    AdmissionDecision, AdmissionViewProps, DecisionRowProps, GateStatus, StatusStripProps,
};
use super::signing_inventory;

/// Project one engine [`PolicyDecisionRecord`] into its presentation row. The coarse decision and
/// mesh status words are parsed into the presentation enums; the untrusted free-text fields
/// (subject / image / namespace / reason) pass through and are escaped by the component at render.
fn decision_row(r: &PolicyDecisionRecord) -> DecisionRowProps {
    DecisionRowProps {
        decision: AdmissionDecision::parse(&r.decision),
        subject: r.subject.clone(),
        image: r.image.clone(),
        namespace: r.namespace.clone(),
        mesh: GateStatus::parse(&r.mesh),
        would_admit: r.would_admit,
        reason: r.reason.clone(),
        count: r.count,
    }
}

/// Build the whole Admission view's props from the deduped decision-log snapshot (newest-first) +
/// the persistent strip the caller supplies. The snapshot carries both the webhook's workload
/// decision rows and the signing sweep's per-image observation rows (`Image/<ref>`); this splits
/// them — the observation rows feed the signing inventory, the decision rows feed the tallies +
/// decision log. The tallies are summed from the DECISION rows alone (summing the deduped counts
/// equals the log's own tallies), so pure observation never inflates the admitted/audited/denied
/// counts. Pure given its inputs — driveable in tests with no engine.
pub(super) fn build(strip: StatusStripProps, rows: &[PolicyDecisionRecord]) -> AdmissionViewProps {
    let signing = signing_inventory::build(rows);
    let (mut admitted, mut audited, mut denied) = (0u64, 0u64, 0u64);
    let mut decisions = Vec::new();
    for r in rows
        .iter()
        .filter(|r| !signing_inventory::is_inventory_row(r))
    {
        let row = decision_row(r);
        match row.decision {
            AdmissionDecision::Allow => admitted += r.count,
            AdmissionDecision::Audit => audited += r.count,
            AdmissionDecision::Deny => denied += r.count,
            AdmissionDecision::Other => {}
        }
        decisions.push(row);
    }

    AdmissionViewProps {
        strip,
        admitted,
        audited,
        denied,
        total: admitted + audited + denied,
        signing,
        rows: decisions,
    }
}

#[cfg(test)]
mod tests;
