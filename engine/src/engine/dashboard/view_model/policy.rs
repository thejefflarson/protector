//! The `/policy` view-model (ADR-0019, the DATA layer): a pure function mapping the webhook's
//! admission-decision records (JEF-226/237) into the plain `Props` the `components::policy`
//! renderer consumes. No maud, no markup — only the mapping from the engine's policy-decision
//! ring into presentation-shaped data: the decision chip label + tone, the coarse
//! signature/mesh status, the dedup count, and the resolved relative-time phrase. Escaping +
//! layout are the renderer's job.
//!
//! JEF-237 widens this from violations-only to EVERY resolved admission: a clean admit
//! (`allow`) reads as the SAFE tone with a "signed + meshed" summary, an `audit` (would-deny,
//! allowed) reads AWAITING, and a `deny` reads BREACH. The policy name and the subject / image
//! / namespace / reason pass through verbatim for the component to auto-escape — the image ref
//! / workload name in those fields is attacker-influenced.

use crate::engine::dashboard::model::relative_time;
use crate::engine::policy_log::{DecisionTallies, PolicyDecisionRecord};
use std::time::{Duration, SystemTime};

/// One `/policy` row, fully resolved for rendering: the decision chip (label + tone), a short
/// human admit/flag summary, the workload subject, the image, the namespace, the reason prose,
/// the dedup count, and the humanized "last seen". Every text field renders through an
/// auto-escaping brace in the component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecisionRow {
    /// The decision word as recorded (`allow` / `audit` / `deny`), shown in the chip.
    pub decision: String,
    /// The decision chip tone class: `chip-safe` (allow — a clean admit), `chip-awaiting`
    /// (audit — a would-deny that was allowed), or `chip-breach` (deny).
    pub decision_tone: &'static str,
    /// A short, human one-line summary of the outcome — e.g. "admitted — signed, meshed" for a
    /// clean admit, or "would-deny — unsigned" for a flagged one. Trusted (engine-built from
    /// the fixed status vocabulary), so it is NOT untrusted prose; it carries no attacker text.
    pub summary: String,
    /// The workload the decision was about (`kind/name`). Auto-escaped at render.
    pub subject: String,
    /// The (representative) image ref. Auto-escaped at render (attacker-influenced). Empty when
    /// the decision isn't image-scoped.
    pub image: String,
    /// The request's namespace (empty for cluster-scoped). Auto-escaped at render.
    pub namespace: String,
    /// The human-actionable reason — UNTRUSTED (it can quote an attacker-chosen image ref),
    /// auto-escaped at render. Empty for a clean admit.
    pub reason: String,
    /// How many times this exact `(subject, image, decision)` recurred (replica/CronJob churn),
    /// for the "×N" badge. 1 for a single occurrence.
    pub count: u64,
    /// The humanized "last seen" (`just now` / `NNs ago` / …).
    pub when: String,
}

/// The plain-data props for the `/policy` page (ADR-0019 view-model): the resolved decision
/// rows (newest first), the activity tallies (admit/audit/deny counts), and the boot-time
/// phrase for the honest-empty state. The component renders the activity line always — so
/// liveness ("webhook active, no decisions since <boot>") is visible even when `rows` is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyProps {
    /// The recent admission-decision rows, in display order (newest first).
    pub rows: Vec<PolicyDecisionRow>,
    /// Clean-admit count (sum of `allow` rows' dedup counts).
    pub admitted: u64,
    /// Would-deny-but-allowed count (sum of `audit` rows' dedup counts).
    pub audited: u64,
    /// Enforced-rejection count (sum of `deny` rows' dedup counts).
    pub denied: u64,
    /// The humanized "since" phrase for the activity line — the boot time when the ring is
    /// empty (so "no decisions since <boot>" is honest), or the newest decision's time
    /// otherwise.
    pub since: String,
}

/// Map a recorded decision word to its chip tone class. `allow` is a clean admit (safe),
/// `audit` is a would-deny that was allowed (the discovery signal, awaiting), and `deny` is an
/// enforced rejection (breach). Anything unexpected reads as the safe tone, never as a breach.
/// Meaning is carried by the WORD shown in the chip, never color alone (accessibility).
fn decision_tone(decision: &str) -> &'static str {
    match decision {
        "deny" => "chip-breach",
        "audit" => "chip-awaiting",
        _ => "chip-safe",
    }
}

/// A short human summary of one decision from its coarse signature/mesh status. For a clean
/// admit this is the operator-facing "admitted — signed, meshed"; for a flagged one it leads
/// with the outcome word. Built only from the engine's fixed status vocabulary (no attacker
/// text), so the component renders it as trusted, markup-free text.
fn summarize(decision: &str, signature: &str, mesh: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    match signature {
        "signed" => parts.push("signed"),
        "unsigned" => parts.push("unsigned"),
        "not-gated" => parts.push("not gated"),
        _ => {}
    }
    if mesh == "meshed" {
        parts.push("meshed");
    } else if mesh == "unmeshed" {
        parts.push("unmeshed");
    }
    let lead = match decision {
        "allow" => "admitted",
        "audit" => "would-deny",
        "deny" => "denied",
        other => other,
    };
    if parts.is_empty() {
        lead.to_string()
    } else {
        format!("{lead} — {}", parts.join(", "))
    }
}

/// Build the `/policy` props from the admission-decision records + tallies + a boot time — the
/// pure mapping from the webhook's decision ring to the data the policy component renders.
/// Resolves each record's tone, summary, and relative-time phrase; leaves escaping + layout to
/// the renderer. `boot` seeds the honest-empty "no decisions since <boot>" line.
pub fn policy_props(
    decisions: &[PolicyDecisionRecord],
    tallies: DecisionTallies,
    boot: SystemTime,
) -> PolicyProps {
    let rows: Vec<PolicyDecisionRow> = decisions
        .iter()
        .map(|d| PolicyDecisionRow {
            decision: d.decision.clone(),
            decision_tone: decision_tone(&d.decision),
            summary: summarize(&d.decision, &d.signature, &d.mesh),
            subject: d.subject.clone(),
            image: d.image.clone(),
            namespace: d.namespace.clone(),
            reason: d.reason.clone(),
            count: d.count,
            when: relative_time(Some(
                SystemTime::UNIX_EPOCH + Duration::from_millis(d.at_ms),
            )),
        })
        .collect();
    // The activity line's "since": the newest decision's time when there is one (records are
    // newest-first), else the boot time so the empty state reads honestly.
    let since_time = decisions
        .first()
        .map(|d| SystemTime::UNIX_EPOCH + Duration::from_millis(d.at_ms))
        .unwrap_or(boot);
    PolicyProps {
        rows,
        admitted: tallies.admitted,
        audited: tallies.audited,
        denied: tallies.denied,
        since: relative_time(Some(since_time)),
    }
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
        decision: &str,
        subject: &str,
        image: &str,
        signature: &str,
        mesh: &str,
        ns: &str,
        reason: &str,
    ) -> PolicyDecisionRecord {
        PolicyDecisionRecord {
            policy: "admission".into(),
            decision: decision.into(),
            subject: subject.into(),
            image: image.into(),
            signature: signature.into(),
            mesh: mesh.into(),
            namespace: ns.into(),
            reason: reason.into(),
            count: 1,
            at_ms: unix_now_ms(),
        }
    }

    fn props(records: &[PolicyDecisionRecord]) -> PolicyProps {
        let mut t = DecisionTallies::default();
        for r in records {
            match r.decision.as_str() {
                "allow" => t.admitted += r.count,
                "audit" => t.audited += r.count,
                "deny" => t.denied += r.count,
                _ => {}
            }
        }
        policy_props(records, t, SystemTime::now())
    }

    #[test]
    fn empty_decisions_have_no_rows_but_carry_a_since() {
        let p = policy_props(&[], DecisionTallies::default(), SystemTime::now());
        assert!(p.rows.is_empty());
        assert_eq!(p.admitted, 0);
        assert_eq!(
            p.since, "just now",
            "empty state still reports a since-boot time"
        );
    }

    #[test]
    fn props_resolve_every_field_and_the_when() {
        let p = props(&[record(
            "deny",
            "Pod/web",
            "ghcr.io/org/app:1",
            "unsigned",
            "meshed",
            "payments",
            "unsigned or untrusted image(s): ghcr.io/org/app:1",
        )]);
        assert_eq!(p.rows.len(), 1);
        let row = &p.rows[0];
        assert_eq!(row.decision, "deny");
        assert_eq!(row.subject, "Pod/web");
        assert_eq!(row.image, "ghcr.io/org/app:1");
        assert_eq!(row.namespace, "payments");
        assert_eq!(
            row.reason,
            "unsigned or untrusted image(s): ghcr.io/org/app:1"
        );
        assert_eq!(row.when, "just now");
    }

    #[test]
    fn clean_admit_reads_safe_with_signed_meshed_summary() {
        // JEF-237: a good pod is SAFE-toned and summarized as "admitted — signed, meshed".
        let p = props(&[record(
            "allow", "Pod/web", "img:1", "signed", "meshed", "default", "",
        )]);
        let row = &p.rows[0];
        assert_eq!(row.decision_tone, "chip-safe");
        assert_eq!(row.summary, "admitted — signed, meshed");
        assert_eq!(p.admitted, 1);
    }

    #[test]
    fn decision_tone_distinguishes_allow_audit_deny() {
        assert_eq!(decision_tone("allow"), "chip-safe");
        assert_eq!(decision_tone("audit"), "chip-awaiting");
        assert_eq!(decision_tone("deny"), "chip-breach");
        // Anything unexpected reads as the safe tone, never as a breach.
        assert_eq!(decision_tone("???"), "chip-safe");
    }

    #[test]
    fn summary_leads_with_the_outcome_word() {
        assert_eq!(
            summarize("audit", "unsigned", "meshed"),
            "would-deny — unsigned, meshed"
        );
        assert_eq!(
            summarize("deny", "unsigned", "unmeshed"),
            "denied — unsigned, unmeshed"
        );
        // An out-of-mesh-scope (n/a) clean admit drops the mesh clause.
        assert_eq!(summarize("allow", "signed", "n/a"), "admitted — signed");
    }

    #[test]
    fn tone_and_summary_are_resolved_per_row() {
        let p = props(&[
            record(
                "audit",
                "Pod/a",
                "img:a",
                "unsigned",
                "meshed",
                "ns",
                "not signed",
            ),
            record("allow", "Pod/b", "img:b", "signed", "meshed", "ns", ""),
        ]);
        assert_eq!(p.rows[0].decision_tone, "chip-awaiting");
        assert_eq!(p.rows[1].decision_tone, "chip-safe");
        assert_eq!(p.rows[1].summary, "admitted — signed, meshed");
    }

    #[test]
    fn tallies_pass_through_to_props() {
        let p = props(&[
            record("allow", "Pod/a", "img:a", "signed", "meshed", "ns", ""),
            record("allow", "Pod/b", "img:b", "signed", "meshed", "ns", ""),
            record("deny", "Pod/c", "img:c", "unsigned", "n/a", "ns", "x"),
        ]);
        assert_eq!(p.admitted, 2);
        assert_eq!(p.denied, 1);
        assert_eq!(p.audited, 0);
    }
}
