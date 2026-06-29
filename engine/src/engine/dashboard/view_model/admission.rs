//! The ADMISSION strip view-model (JEF-255): the compact `signed X/Y · meshed Y/Y` summary of
//! the webhook's recent admission decisions, plus the audit/deny tallies. Shaped from the
//! decision log's [`DecisionTallies`] and its deduped records.
//!
//! A clear seam is left for the JEF-246 "if enforced" what-if (the `audited` count is the
//! would-deny-but-allowed set); this ticket does not build that, but the strip surfaces the
//! number so the future panel has its anchor. Pure data; the renderer takes only these props.

use crate::engine::policy_log::{DecisionTallies, PolicyDecisionRecord};

/// The compact admission strip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionProps {
    /// Workloads admitted with a verified signature, over those evaluated for signature.
    pub signed: u32,
    pub signed_of: u32,
    /// Workloads admitted into the mesh, over those evaluated for mesh.
    pub meshed: u32,
    pub meshed_of: u32,
    /// Clean admits / would-deny-but-allowed (audit) / enforced denies — the activity tallies.
    pub admitted: u64,
    pub audited: u64,
    pub denied: u64,
    /// No decisions seen yet — the honest empty state ("no admission decisions yet").
    pub empty: bool,
}

/// Build the admission strip from the decision log snapshot + tallies (JEF-255). The
/// signed/meshed fractions are counted over the deduped records that were actually evaluated
/// for that gate (status is non-empty and not `n/a`).
pub fn admission_props(
    records: &[PolicyDecisionRecord],
    tallies: DecisionTallies,
) -> AdmissionProps {
    let mut signed = 0u32;
    let mut signed_of = 0u32;
    let mut meshed = 0u32;
    let mut meshed_of = 0u32;
    for r in records {
        match r.signature.as_str() {
            "signed" => {
                signed += 1;
                signed_of += 1;
            }
            "unsigned" => signed_of += 1,
            _ => {}
        }
        match r.mesh.as_str() {
            "meshed" => {
                meshed += 1;
                meshed_of += 1;
            }
            "unmeshed" => meshed_of += 1,
            _ => {}
        }
    }
    AdmissionProps {
        signed,
        signed_of,
        meshed,
        meshed_of,
        admitted: tallies.admitted,
        audited: tallies.audited,
        denied: tallies.denied,
        empty: records.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(signature: &str, mesh: &str) -> PolicyDecisionRecord {
        PolicyDecisionRecord::now(
            "admission",
            "allow",
            "Deployment/web",
            "img@sha",
            signature,
            mesh,
            "app",
            "ok",
        )
    }

    #[test]
    fn counts_signed_and_meshed_over_evaluated() {
        let records = vec![
            rec("signed", "meshed"),
            rec("unsigned", "meshed"),
            rec("not-gated", "n/a"),
        ];
        let t = DecisionTallies {
            admitted: 3,
            audited: 1,
            denied: 0,
        };
        let p = admission_props(&records, t);
        assert_eq!((p.signed, p.signed_of), (1, 2));
        assert_eq!((p.meshed, p.meshed_of), (2, 2));
        assert_eq!(p.admitted, 3);
        assert_eq!(p.audited, 1);
        assert!(!p.empty);
    }

    #[test]
    fn no_records_is_the_honest_empty_state() {
        let p = admission_props(&[], DecisionTallies::default());
        assert!(p.empty);
        assert_eq!((p.signed, p.signed_of), (0, 0));
    }
}
