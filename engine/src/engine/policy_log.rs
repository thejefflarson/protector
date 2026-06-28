//! The admission-decision log (JEF-226): a bounded, in-memory ring of the webhook's
//! per-event policy decisions — the signature / mesh / enforce-authz allow/audit/deny
//! verdicts the admission webhook resolves on each `AdmissionReview`.
//!
//! Today those decisions are only stdout `tracing` logs plus the aggregate
//! `protector_policy_violations_total` counter (`metrics.rs`); there is no queryable
//! per-event record (the durable decision journal records only the engine's breach side).
//! This module adds one, deliberately mirroring [`dashboard::JudgementLog`]: a `Mutex`-guarded
//! `VecDeque` capped at a small constant, written by the webhook [`Engine`](crate::policy::Engine)
//! (the single recording chokepoint) and read by the dashboard's `/policy` view.
//!
//! The webhook process holds zero cluster access by design, so this ring lives in the same
//! process as both the webhook server and the (separately-spawned) dashboard: the write handle
//! is shared into the webhook engine, the read handle into the dashboard — the two halves of
//! one `Arc`. It is in-memory only this PR (it does not survive a restart); durable persistence
//! to the decision journal is a noted follow-up.
//!
//! Payloads are deliberately LOW-CARDINALITY and carry NO secret values: the policy name, the
//! coarse decision word, the workload subject (`kind/name`), the namespace, and the same
//! human-actionable reason text the deny/audit log already carries. The reason is operator-facing
//! prose (e.g. "unsigned or untrusted image(s): …"); it is auto-escaped at render (the dashboard
//! component treats it as untrusted), never trusted as markup.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// One admission decision the webhook resolved, captured for the `/policy` view. Diagnostic /
/// audit only — it complements (never replaces) the aggregate `/metrics` counter.
///
/// `Serialize` is the `/policy.json` contract. Every text field is operator-facing and rendered
/// through an auto-escaping maud brace; an attacker-controlled image ref or workload name cannot
/// inject markup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyDecisionRecord {
    /// The policy that rendered the verdict — its stable name
    /// (`image-signature` / `mesh-injection`). Low-cardinality.
    pub policy: String,
    /// The coarse decision word: `deny` (enforced — the request is rejected),
    /// `audit` (would-deny, but allowed — the discovery signal), or `allow`.
    pub decision: String,
    /// The workload the decision was about: `kind/name` (e.g. `Pod/web`). The image ref(s),
    /// when relevant, live in `reason`, not here, to keep this field low-cardinality.
    pub subject: String,
    /// The request's namespace (empty for a cluster-scoped object).
    pub namespace: String,
    /// The human-actionable reason — the same prose the deny/audit log carries. Empty for a
    /// plain `allow`. UNTRUSTED at render (it can quote an attacker-chosen image ref).
    pub reason: String,
    /// When the decision was recorded, Unix epoch milliseconds (so the JSON view is
    /// self-contained and the HTML can render "NNs ago").
    pub at_ms: u64,
}

impl PolicyDecisionRecord {
    /// Build a record stamped with the current wall-clock time. `policy`/`decision` are the
    /// stable engine strings; `subject`/`namespace`/`reason` come from the admission request.
    pub fn now(
        policy: impl Into<String>,
        decision: impl Into<String>,
        subject: impl Into<String>,
        namespace: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            policy: policy.into(),
            decision: decision.into(),
            subject: subject.into(),
            namespace: namespace.into(),
            reason: reason.into(),
            at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or_default(),
        }
    }
}

/// A bounded, newest-last ring of recent [`PolicyDecisionRecord`]s, shared between the webhook
/// engine (writer) and the dashboard's `/policy` view (reader). Mirrors
/// [`JudgementLog`](crate::engine::dashboard::JudgementLog): a handful of admission decisions
/// happen per workload write, so the cap comfortably holds the recent window without growing
/// unbounded. In-memory only — it does not survive a restart.
#[derive(Default)]
pub struct PolicyDecisionLog {
    rows: Mutex<VecDeque<PolicyDecisionRecord>>,
}

impl PolicyDecisionLog {
    /// How many recent decisions the ring retains. A workload write fans out to a few
    /// policies, so this holds a comfortable recent window without growing unbounded.
    pub(crate) const CAP: usize = 256;

    pub fn new() -> Self {
        Self::default()
    }

    /// Append a decision, evicting the oldest once at capacity.
    pub fn record(&self, decision: PolicyDecisionRecord) {
        let mut rows = self
            .rows
            .lock()
            .expect("policy decision log mutex poisoned");
        if rows.len() >= Self::CAP {
            rows.pop_front();
        }
        rows.push_back(decision);
    }

    /// Snapshot newest-first for display.
    pub fn snapshot(&self) -> Vec<PolicyDecisionRecord> {
        self.rows
            .lock()
            .expect("policy decision log mutex poisoned")
            .iter()
            .rev()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(
        policy: &str,
        decision: &str,
        subject: &str,
        ns: &str,
        reason: &str,
    ) -> PolicyDecisionRecord {
        PolicyDecisionRecord::now(policy, decision, subject, ns, reason)
    }

    #[test]
    fn now_captures_every_field() {
        let r = rec(
            "image-signature",
            "deny",
            "Pod/web",
            "payments",
            "unsigned or untrusted image(s): ghcr.io/org/app:1",
        );
        assert_eq!(r.policy, "image-signature");
        assert_eq!(r.decision, "deny");
        assert_eq!(r.subject, "Pod/web");
        assert_eq!(r.namespace, "payments");
        assert_eq!(
            r.reason,
            "unsigned or untrusted image(s): ghcr.io/org/app:1"
        );
        assert!(r.at_ms > 0, "timestamp is stamped");
    }

    #[test]
    fn snapshot_is_newest_first() {
        let log = PolicyDecisionLog::new();
        log.record(rec("image-signature", "audit", "Pod/a", "ns", "older"));
        log.record(rec("mesh-injection", "deny", "Pod/b", "ns", "newer"));
        let snap = log.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].reason, "newer", "newest decision is first");
        assert_eq!(snap[1].reason, "older");
    }

    #[test]
    fn ring_is_bounded_and_evicts_oldest() {
        let log = PolicyDecisionLog::new();
        for i in 0..(PolicyDecisionLog::CAP + 10) {
            log.record(rec(
                "mesh-injection",
                "audit",
                "Pod/x",
                "ns",
                &format!("r{i}"),
            ));
        }
        let snap = log.snapshot();
        assert_eq!(snap.len(), PolicyDecisionLog::CAP, "capped at CAP");
        // The newest entry is retained; the oldest ten were evicted.
        assert_eq!(snap[0].reason, format!("r{}", PolicyDecisionLog::CAP + 9));
        assert!(
            !snap.iter().any(|r| r.reason == "r0"),
            "the oldest entry was evicted"
        );
    }

    #[test]
    fn allow_decisions_carry_an_empty_reason() {
        let r = rec("image-signature", "allow", "Pod/web", "default", "");
        assert_eq!(r.decision, "allow");
        assert!(r.reason.is_empty());
    }
}
