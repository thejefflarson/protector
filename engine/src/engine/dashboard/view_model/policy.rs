//! The `/policy` view-model (ADR-0019, the DATA layer): a pure function mapping the webhook's
//! admission-decision records (JEF-226) into the plain `Props` the `components::policy`
//! renderer consumes. No maud, no markup — only the mapping from the engine's policy-decision
//! ring into presentation-shaped data: the decision chip label + tone, and the resolved
//! relative-time phrase. Escaping + layout are the renderer's job.
//!
//! The decision-tone mapping is the only logic here: a `deny` is an enforced rejection (breach
//! tone), an `audit` is a would-deny the engine allowed (the discovery signal, awaiting tone),
//! and any other word (an `allow`, defensively) is the safe tone. The policy name and the
//! subject / namespace / reason pass through verbatim for the component to auto-escape — the
//! image ref / workload name in those fields is attacker-influenced (JEF-226 AC).

use crate::engine::dashboard::model::relative_time;
use crate::engine::policy_log::PolicyDecisionRecord;
use std::time::{Duration, SystemTime};

/// One `/policy` row, fully resolved for rendering: the policy name, the decision chip
/// (label + tone), the workload subject, the namespace, the reason prose, and the humanized
/// "when". Every text field renders through an auto-escaping brace in the component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecisionRow {
    /// The policy that decided (`image-signature` / `mesh-injection`). Auto-escaped at render.
    pub policy: String,
    /// The decision word as recorded (`deny` / `audit` / `allow`), shown in the chip.
    pub decision: String,
    /// The decision chip tone class: `chip-breach` (deny), `chip-awaiting` (audit), or
    /// `chip-safe` (allow / anything else, defensively).
    pub decision_tone: &'static str,
    /// The workload the decision was about (`kind/name`). Auto-escaped at render.
    pub subject: String,
    /// The request's namespace (empty for cluster-scoped). Auto-escaped at render.
    pub namespace: String,
    /// The human-actionable reason — UNTRUSTED (it can quote an attacker-chosen image ref),
    /// auto-escaped at render. Empty for a plain allow.
    pub reason: String,
    /// The humanized "when" (`just now` / `NNs ago` / …).
    pub when: String,
}

/// The plain-data props for the `/policy` page (ADR-0019 view-model): the resolved decision
/// rows, newest first (as the ring snapshots them). The component renders the honest-empty
/// state when this is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyProps {
    /// The recent admission-decision rows, in display order (newest first).
    pub rows: Vec<PolicyDecisionRow>,
}

/// Map a recorded decision word to its chip tone class. `deny` is an enforced rejection
/// (breach), `audit` is a would-deny that was allowed (the discovery signal, awaiting), and
/// anything else (an `allow`, defensively) reads as the safe tone. Meaning is carried by the
/// WORD shown in the chip, never color alone (accessibility).
fn decision_tone(decision: &str) -> &'static str {
    match decision {
        "deny" => "chip-breach",
        "audit" => "chip-awaiting",
        _ => "chip-safe",
    }
}

/// Build the `/policy` props from the admission-decision records — the pure mapping from the
/// webhook's decision ring to the data the policy component renders. Resolves each record's
/// decision tone and relative-time phrase; leaves escaping + layout to the renderer.
pub fn policy_props(decisions: &[PolicyDecisionRecord]) -> PolicyProps {
    let rows = decisions
        .iter()
        .map(|d| PolicyDecisionRow {
            policy: d.policy.clone(),
            decision: d.decision.clone(),
            decision_tone: decision_tone(&d.decision),
            subject: d.subject.clone(),
            namespace: d.namespace.clone(),
            reason: d.reason.clone(),
            when: relative_time(Some(
                SystemTime::UNIX_EPOCH + Duration::from_millis(d.at_ms),
            )),
        })
        .collect();
    PolicyProps { rows }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix_now_ms() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn record(
        policy: &str,
        decision: &str,
        subject: &str,
        ns: &str,
        reason: &str,
    ) -> PolicyDecisionRecord {
        PolicyDecisionRecord {
            policy: policy.into(),
            decision: decision.into(),
            subject: subject.into(),
            namespace: ns.into(),
            reason: reason.into(),
            at_ms: unix_now_ms(),
        }
    }

    #[test]
    fn empty_decisions_have_no_rows() {
        assert!(policy_props(&[]).rows.is_empty());
    }

    #[test]
    fn props_resolve_every_field_and_the_when() {
        let props = policy_props(&[record(
            "image-signature",
            "deny",
            "Pod/web",
            "payments",
            "unsigned or untrusted image(s): ghcr.io/org/app:1",
        )]);
        assert_eq!(props.rows.len(), 1);
        let row = &props.rows[0];
        assert_eq!(row.policy, "image-signature");
        assert_eq!(row.decision, "deny");
        assert_eq!(row.subject, "Pod/web");
        assert_eq!(row.namespace, "payments");
        assert_eq!(
            row.reason,
            "unsigned or untrusted image(s): ghcr.io/org/app:1"
        );
        assert_eq!(row.when, "just now");
    }

    #[test]
    fn decision_tone_distinguishes_deny_audit_allow() {
        assert_eq!(decision_tone("deny"), "chip-breach");
        assert_eq!(decision_tone("audit"), "chip-awaiting");
        assert_eq!(decision_tone("allow"), "chip-safe");
        // Anything unexpected reads as the safe tone, never as a breach.
        assert_eq!(decision_tone("???"), "chip-safe");
    }

    #[test]
    fn tone_is_resolved_per_row() {
        let props = policy_props(&[
            record(
                "mesh-injection",
                "audit",
                "Pod/a",
                "ns",
                "not enrolled in the mesh",
            ),
            record("image-signature", "deny", "Pod/b", "ns", "unsigned"),
        ]);
        assert_eq!(props.rows[0].decision_tone, "chip-awaiting");
        assert_eq!(props.rows[1].decision_tone, "chip-breach");
    }
}
