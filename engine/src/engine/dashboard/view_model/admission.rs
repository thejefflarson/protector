//! The ADMISSION strip view-model (JEF-255, extended JEF-246): the compact
//! `signed X/Y · meshed Y/Y` summary of the webhook's recent admission decisions, plus the
//! audit/deny tallies AND the shadow what-if — what protector WOULD do if every gate were
//! enforced. Shaped from the decision log's [`DecisionTallies`] and its deduped records.
//!
//! The JEF-246 what-if is the headline change: each record now carries a THREE-state per-gate
//! shadow status (`verified` / `would-pass` / `would-fail`, computed for EVERY image even out of
//! scope) plus the net `would_admit`. The strip surfaces the would-be signed + meshed fractions
//! (counted over every shadow-evaluated record, not only the in-scope ones) and the net
//! would-DENY count — so a green status can no longer hide an unchecked image, and the operator
//! can answer "if I enforced this namespace, what would happen?". Pure data; the renderer takes
//! only these props (ADR-0019).

use crate::engine::policy_log::{DecisionTallies, PolicyDecisionRecord};

/// The compact admission strip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionProps {
    /// Workloads whose signature shadow-verdict would PASS (`verified` or `would-pass`), over
    /// those the signature gate has an opinion on (any non-empty status). The what-if fraction:
    /// counts out-of-scope would-passes too, not only in-scope verifications.
    pub signed: u32,
    pub signed_of: u32,
    /// Workloads whose mesh shadow-verdict would PASS, over those the mesh gate has an opinion
    /// on. Same what-if semantics as [`signed`](Self::signed).
    pub meshed: u32,
    pub meshed_of: u32,
    /// Clean admits / would-deny-but-allowed (audit) / enforced denies — the ACTUAL activity
    /// tallies (unchanged by the what-if; the honest record of what the API did).
    pub admitted: u64,
    pub audited: u64,
    pub denied: u64,
    /// The shadow what-if net (JEF-246): how many distinct admitted workloads WOULD be denied if
    /// every gate were enforced (`would_admit == false`). Distinct from `denied` (which is the
    /// actual enforced rejections) — this is the counterfactual for the rest.
    pub would_deny: u32,
    /// No decisions seen yet — the honest empty state ("no admission decisions yet").
    pub empty: bool,
}

/// Build the admission strip from the decision log snapshot + tallies (JEF-255/246). The
/// signed/meshed fractions are counted over the deduped records the gate shadow-evaluated (a
/// non-empty three-state status); the what-if net counts the records that would be denied under
/// enforcement.
pub fn admission_props(
    records: &[PolicyDecisionRecord],
    tallies: DecisionTallies,
) -> AdmissionProps {
    let mut signed = 0u32;
    let mut signed_of = 0u32;
    let mut meshed = 0u32;
    let mut meshed_of = 0u32;
    let mut would_deny = 0u32;
    for r in records {
        if let Some(passed) = gate_passes(&r.signature) {
            signed_of += 1;
            if passed {
                signed += 1;
            }
        }
        if let Some(passed) = gate_passes(&r.mesh) {
            meshed_of += 1;
            if passed {
                meshed += 1;
            }
        }
        if !r.would_admit {
            would_deny += 1;
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
        would_deny,
        empty: records.is_empty(),
    }
}

/// Interpret a three-state shadow status (JEF-246): `Some(true)` for a would-pass (`verified` /
/// `would-pass`), `Some(false)` for a would-fail (`would-fail`), `None` when the gate has no
/// opinion (empty status). The pre-JEF-246 coarse words are mapped for back-compat with replayed
/// journal lines so an old log still tallies: `signed`/`meshed` → pass, `unsigned`/`unmeshed` →
/// fail, `not-gated`/`n/a` → no opinion.
fn gate_passes(status: &str) -> Option<bool> {
    match status {
        "verified" | "would-pass" | "signed" | "meshed" => Some(true),
        "would-fail" | "unsigned" | "unmeshed" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(signature: &str, mesh: &str, would_admit: bool) -> PolicyDecisionRecord {
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
        .with_would_admit(would_admit)
    }

    #[test]
    fn counts_would_pass_over_every_shadow_evaluated_record() {
        // The what-if fraction counts out-of-scope would-passes too, not only in-scope
        // verifications — a verified and a would-pass both count toward `signed`.
        let records = vec![
            rec("verified", "verified", true),
            rec("would-pass", "would-fail", false),
            rec("would-fail", "would-pass", false),
            rec("", "", true), // no opinion either gate — excluded from both fractions
        ];
        let t = DecisionTallies {
            admitted: 4,
            audited: 0,
            denied: 0,
        };
        let p = admission_props(&records, t);
        // signature: verified + would-pass pass (2), of three evaluated.
        assert_eq!((p.signed, p.signed_of), (2, 3));
        // mesh: verified + would-pass pass (2), of three evaluated.
        assert_eq!((p.meshed, p.meshed_of), (2, 3));
    }

    #[test]
    fn would_deny_counts_the_counterfactual_denies() {
        let records = vec![
            rec("verified", "verified", true),
            rec("would-fail", "verified", false),
            rec("verified", "would-fail", false),
        ];
        let p = admission_props(&records, DecisionTallies::default());
        assert_eq!(p.would_deny, 2, "two records would be denied if enforced");
    }

    #[test]
    fn legacy_coarse_words_still_tally_for_replayed_journal_lines() {
        // A pre-JEF-246 journal line carries `signed`/`unsigned`/`meshed`/`unmeshed`; they must
        // still count so an old log isn't blank after a restart.
        let records = vec![
            rec("signed", "meshed", true),
            rec("unsigned", "unmeshed", true),
        ];
        let p = admission_props(&records, DecisionTallies::default());
        assert_eq!((p.signed, p.signed_of), (1, 2));
        assert_eq!((p.meshed, p.meshed_of), (1, 2));
    }

    #[test]
    fn no_records_is_the_honest_empty_state() {
        let p = admission_props(&[], DecisionTallies::default());
        assert!(p.empty);
        assert_eq!((p.signed, p.signed_of), (0, 0));
        assert_eq!(p.would_deny, 0);
    }
}
