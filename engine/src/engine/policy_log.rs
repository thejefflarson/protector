//! The admission-decision log (JEF-226, extended JEF-237): a bounded, deduped, in-memory
//! ring of the webhook's per-event policy decisions — the signature / mesh allow / audit /
//! deny verdicts the admission webhook resolves on each `AdmissionReview`.
//!
//! JEF-226 recorded ONLY violations (audit/deny), so a healthy cluster's `/policy` view was
//! blank and read as broken. JEF-237 records EVERY resolved admission — including clean
//! admits (signed + meshed) — so the operator sees the full picture: the good pods, not just
//! the flagged ones. Each row carries the workload subject, the image ref, the coarse
//! signature + mesh status, the namespace, the coarse decision word, the reason, and the time.
//!
//! Volume is the reason JEF-226 stayed violations-only: a Deployment's N replicas and a
//! CronJob's repeated runs would flood an admit-everything log. JEF-237 bounds it two ways:
//! **dedup** by `(subject, image, decision)` — one row per distinct workload + image +
//! outcome, carrying a `count` and the `last_seen` time — and a **ring cap** on the number of
//! distinct rows. So replica/CronJob churn coalesces into a single counted row instead of
//! flooding the ring.
//!
//! This module mirrors [`dashboard::JudgementLog`]: a `Mutex`-guarded `VecDeque` written by
//! the webhook [`Engine`](crate::policy::Engine) (the single recording chokepoint) and read
//! by the dashboard's `/policy` view. Both the webhook server and the dashboard live in the
//! same process, so the write handle is shared into the webhook engine and the read handle
//! into the dashboard — the two halves of one `Arc`.
//!
//! Persistence (JEF-237): the webhook engine ALSO mirrors each recorded decision into the
//! durable decision journal (JEF-141) so the log survives a restart. On boot the engine
//! replays the journal's admission lines back into this ring (parallel to `restored_verdicts`),
//! so the `/policy` view repopulates immediately rather than going blank for ~20 min.
//!
//! Payloads are deliberately LOW-CARDINALITY and carry NO secret values: the policy name, the
//! coarse decision word, the workload subject (`kind/name`), the image ref, the coarse
//! signature/mesh status, the namespace, and the same human-actionable reason text the
//! deny/audit log already carries. Every text field is auto-escaped at render (the dashboard
//! component treats it as untrusted), never trusted as markup.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// One admission decision the webhook resolved, captured for the `/policy` view. Diagnostic /
/// audit only — it complements (never replaces) the aggregate `/metrics` counter.
///
/// `Serialize`/`Deserialize` are the `/policy.json` contract AND the durable-journal shape:
/// every field that post-dates JEF-226 uses `#[serde(default)]` so an older journal line still
/// parses. Every text field is operator-facing and rendered through an auto-escaping maud
/// brace; an attacker-controlled image ref or workload name cannot inject markup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecisionRecord {
    /// The policy that rendered the verdict — its stable name
    /// (`image-signature` / `mesh-injection`), or `admission` for the holistic engine
    /// summary row. Low-cardinality.
    pub policy: String,
    /// The coarse decision word: `deny` (enforced — the request is rejected),
    /// `audit` (would-deny, but allowed — the discovery signal), or `allow` (a clean admit).
    pub decision: String,
    /// The workload the decision was about: `kind/name` (e.g. `Pod/web`).
    pub subject: String,
    /// The (representative) image ref the decision concerns. Empty when the decision isn't
    /// image-scoped. Part of the dedup key with `subject` + `decision`. UNTRUSTED at render.
    #[serde(default)]
    pub image: String,
    /// Coarse signature status: `signed` (gated + verified), `unsigned` (gated + not trusted),
    /// or `not-gated` (out of signature scope). Empty when not evaluated. Low-cardinality.
    #[serde(default)]
    pub signature: String,
    /// Coarse mesh status: `meshed`, `unmeshed`, or `n/a` (out of mesh scope — a one-shot/Job
    /// pod). Empty when not evaluated. Low-cardinality.
    #[serde(default)]
    pub mesh: String,
    /// The request's namespace (empty for a cluster-scoped object).
    pub namespace: String,
    /// The human-actionable reason — the same prose the deny/audit log carries. Empty for a
    /// plain `allow`. UNTRUSTED at render (it can quote an attacker-chosen image ref).
    pub reason: String,
    /// How many times this exact `(subject, image, decision)` was seen (dedup count). Starts
    /// at 1; bumped each time the same decision recurs (replica/CronJob churn).
    #[serde(default = "one")]
    pub count: u64,
    /// When the decision was LAST seen, Unix epoch milliseconds (so the JSON view is
    /// self-contained and the HTML can render "NNs ago"). Updated on each dedup bump.
    pub at_ms: u64,
}

/// `serde` default for `count` on lines that predate the field (treat an old line as one hit).
fn one() -> u64 {
    1
}

impl PolicyDecisionRecord {
    /// Build a record stamped with the current wall-clock time, `count = 1`. The
    /// `policy`/`decision`/`signature`/`mesh` fields are the stable engine strings;
    /// `subject`/`image`/`namespace`/`reason` come from the admission request.
    #[allow(clippy::too_many_arguments)]
    pub fn now(
        policy: impl Into<String>,
        decision: impl Into<String>,
        subject: impl Into<String>,
        image: impl Into<String>,
        signature: impl Into<String>,
        mesh: impl Into<String>,
        namespace: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            policy: policy.into(),
            decision: decision.into(),
            subject: subject.into(),
            image: image.into(),
            signature: signature.into(),
            mesh: mesh.into(),
            namespace: namespace.into(),
            reason: reason.into(),
            count: 1,
            at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or_default(),
        }
    }

    /// The dedup identity: a distinct row is one `(subject, image, decision)` triple. Replica
    /// and CronJob churn share an identity and coalesce into a single counted row.
    fn dedup_key(&self) -> (&str, &str, &str) {
        (&self.subject, &self.image, &self.decision)
    }
}

/// A bounded, deduped, newest-last ring of [`PolicyDecisionRecord`]s, shared between the
/// webhook engine (writer) and the dashboard's `/policy` view (reader). Mirrors
/// [`JudgementLog`](crate::engine::dashboard::JudgementLog), but with **dedup**: recording a
/// decision whose `(subject, image, decision)` already exists bumps that row's `count` and
/// `last_seen` and moves it to the newest position, instead of appending — so a Deployment's
/// replicas or a CronJob's runs can't flood the ring. The cap bounds the number of *distinct*
/// rows.
#[derive(Default)]
pub struct PolicyDecisionLog {
    rows: Mutex<VecDeque<PolicyDecisionRecord>>,
}

impl PolicyDecisionLog {
    /// How many DISTINCT decision rows the ring retains. With dedup folding churn into a single
    /// counted row per `(subject, image, decision)`, this comfortably holds the recent window
    /// of distinct admissions without growing unbounded.
    pub(crate) const CAP: usize = 256;

    pub fn new() -> Self {
        Self::default()
    }

    /// Record a decision, deduping by `(subject, image, decision)`. If a matching row already
    /// exists, its `count` is incremented, its `at_ms` advanced to the new (later) time, and it
    /// is moved to the newest position. Otherwise the record is appended, evicting the oldest
    /// distinct row once at capacity.
    pub fn record(&self, decision: PolicyDecisionRecord) {
        let mut rows = self
            .rows
            .lock()
            .expect("policy decision log mutex poisoned");
        if let Some(pos) = rows
            .iter()
            .position(|r| r.dedup_key() == decision.dedup_key())
        {
            // Fold the recurrence into the existing row: bump the count, keep the latest time,
            // refresh reason / status (they only grow more specific), re-seat as newest.
            let mut existing = rows.remove(pos).expect("position is valid");
            existing.count = existing.count.saturating_add(1);
            existing.at_ms = existing.at_ms.max(decision.at_ms);
            existing.reason = decision.reason;
            existing.signature = decision.signature;
            existing.mesh = decision.mesh;
            rows.push_back(existing);
            return;
        }
        if rows.len() >= Self::CAP {
            rows.pop_front();
        }
        rows.push_back(decision);
    }

    /// Restore a record from the durable journal (JEF-237), preserving its `count` and
    /// `last_seen` rather than resetting to 1. Deduped like [`record`](Self::record): a replayed
    /// line whose identity is already present folds its count in (so a journal that logged the
    /// same decision across rotations still totals correctly).
    pub fn restore(&self, decision: PolicyDecisionRecord) {
        let mut rows = self
            .rows
            .lock()
            .expect("policy decision log mutex poisoned");
        if let Some(pos) = rows
            .iter()
            .position(|r| r.dedup_key() == decision.dedup_key())
        {
            let mut existing = rows.remove(pos).expect("position is valid");
            existing.count = existing.count.saturating_add(decision.count);
            existing.at_ms = existing.at_ms.max(decision.at_ms);
            rows.push_back(existing);
            return;
        }
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

    /// Aggregate counts by coarse decision word — `(allow, audit, deny)` — summing each row's
    /// dedup `count`. Drives the `/policy` activity header so liveness is visible even when the
    /// (deduped) table is short.
    pub fn tallies(&self) -> DecisionTallies {
        let rows = self
            .rows
            .lock()
            .expect("policy decision log mutex poisoned");
        let mut t = DecisionTallies::default();
        for r in rows.iter() {
            match r.decision.as_str() {
                "allow" => t.admitted += r.count,
                "audit" => t.audited += r.count,
                "deny" => t.denied += r.count,
                _ => {}
            }
        }
        t
    }
}

/// Coarse decision tallies for the `/policy` activity header (JEF-237): how many admissions
/// the webhook admitted / audited / denied, summed over the deduped rows' counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecisionTallies {
    /// Clean admits (`allow`).
    pub admitted: u64,
    /// Would-deny-but-allowed (`audit`).
    pub audited: u64,
    /// Enforced rejections (`deny`).
    pub denied: u64,
}

impl DecisionTallies {
    /// Total decisions across all outcomes.
    pub fn total(&self) -> u64 {
        self.admitted + self.audited + self.denied
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn rec(
        policy: &str,
        decision: &str,
        subject: &str,
        image: &str,
        signature: &str,
        mesh: &str,
        ns: &str,
        reason: &str,
    ) -> PolicyDecisionRecord {
        PolicyDecisionRecord::now(
            policy, decision, subject, image, signature, mesh, ns, reason,
        )
    }

    #[test]
    fn now_captures_every_field() {
        let r = rec(
            "image-signature",
            "deny",
            "Pod/web",
            "ghcr.io/org/app:1",
            "unsigned",
            "meshed",
            "payments",
            "unsigned or untrusted image(s): ghcr.io/org/app:1",
        );
        assert_eq!(r.policy, "image-signature");
        assert_eq!(r.decision, "deny");
        assert_eq!(r.subject, "Pod/web");
        assert_eq!(r.image, "ghcr.io/org/app:1");
        assert_eq!(r.signature, "unsigned");
        assert_eq!(r.mesh, "meshed");
        assert_eq!(r.namespace, "payments");
        assert_eq!(r.count, 1);
        assert!(r.at_ms > 0, "timestamp is stamped");
    }

    #[test]
    fn snapshot_is_newest_first() {
        let log = PolicyDecisionLog::new();
        log.record(rec(
            "image-signature",
            "audit",
            "Pod/a",
            "img:1",
            "unsigned",
            "n/a",
            "ns",
            "older",
        ));
        log.record(rec(
            "mesh-injection",
            "deny",
            "Pod/b",
            "img:2",
            "not-gated",
            "unmeshed",
            "ns",
            "newer",
        ));
        let snap = log.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].reason, "newer", "newest decision is first");
        assert_eq!(snap[1].reason, "older");
    }

    #[test]
    fn clean_admits_are_recorded() {
        // JEF-237: an `allow` (clean admit) is a first-class row, not dropped.
        let log = PolicyDecisionLog::new();
        log.record(rec(
            "admission",
            "allow",
            "Pod/web",
            "ghcr.io/org/app:1",
            "signed",
            "meshed",
            "default",
            "",
        ));
        let snap = log.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].decision, "allow");
        assert_eq!(snap[0].signature, "signed");
        assert_eq!(snap[0].mesh, "meshed");
    }

    #[test]
    fn replica_churn_dedups_into_a_single_counted_row() {
        // The whole point of JEF-237's bounding: a Deployment's N replicas (same subject +
        // image + outcome) coalesce into ONE row with count == N, not N rows.
        let log = PolicyDecisionLog::new();
        for _ in 0..50 {
            log.record(rec(
                "admission",
                "allow",
                "Pod/web",
                "ghcr.io/org/app:1",
                "signed",
                "meshed",
                "default",
                "",
            ));
        }
        let snap = log.snapshot();
        assert_eq!(snap.len(), 1, "replica churn folds into one row");
        assert_eq!(snap[0].count, 50, "the dedup count totals the replicas");
    }

    #[test]
    fn distinct_image_or_decision_is_a_distinct_row() {
        let log = PolicyDecisionLog::new();
        log.record(rec(
            "admission",
            "allow",
            "Pod/web",
            "img:1",
            "signed",
            "meshed",
            "ns",
            "",
        ));
        // Different image → distinct row.
        log.record(rec(
            "admission",
            "allow",
            "Pod/web",
            "img:2",
            "signed",
            "meshed",
            "ns",
            "",
        ));
        // Same subject+image but a different outcome → distinct row.
        log.record(rec(
            "admission",
            "audit",
            "Pod/web",
            "img:1",
            "unsigned",
            "meshed",
            "ns",
            "x",
        ));
        assert_eq!(log.snapshot().len(), 3);
    }

    #[test]
    fn dedup_advances_last_seen_and_reseats_as_newest() {
        let log = PolicyDecisionLog::new();
        log.record(rec(
            "admission",
            "audit",
            "Pod/a",
            "img:a",
            "unsigned",
            "n/a",
            "ns",
            "a",
        ));
        log.record(rec(
            "admission",
            "allow",
            "Pod/b",
            "img:b",
            "signed",
            "meshed",
            "ns",
            "",
        ));
        // Re-record A: it should move to the front (newest) with count 2.
        log.record(rec(
            "admission",
            "audit",
            "Pod/a",
            "img:a",
            "unsigned",
            "n/a",
            "ns",
            "a",
        ));
        let snap = log.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].subject, "Pod/a", "the re-seen row is newest");
        assert_eq!(snap[0].count, 2);
    }

    #[test]
    fn ring_is_bounded_by_distinct_rows_and_evicts_oldest() {
        let log = PolicyDecisionLog::new();
        for i in 0..(PolicyDecisionLog::CAP + 10) {
            log.record(rec(
                "admission",
                "audit",
                &format!("Pod/x{i}"),
                "img:1",
                "unsigned",
                "n/a",
                "ns",
                "r",
            ));
        }
        let snap = log.snapshot();
        assert_eq!(
            snap.len(),
            PolicyDecisionLog::CAP,
            "capped at CAP distinct rows"
        );
        assert_eq!(
            snap[0].subject,
            format!("Pod/x{}", PolicyDecisionLog::CAP + 9)
        );
        assert!(
            !snap.iter().any(|r| r.subject == "Pod/x0"),
            "the oldest distinct row was evicted"
        );
    }

    #[test]
    fn tallies_sum_dedup_counts_by_outcome() {
        let log = PolicyDecisionLog::new();
        for _ in 0..3 {
            log.record(rec(
                "admission",
                "allow",
                "Pod/a",
                "img:a",
                "signed",
                "meshed",
                "ns",
                "",
            ));
        }
        log.record(rec(
            "admission",
            "audit",
            "Pod/b",
            "img:b",
            "unsigned",
            "meshed",
            "ns",
            "x",
        ));
        log.record(rec(
            "image-signature",
            "deny",
            "Pod/c",
            "img:c",
            "unsigned",
            "n/a",
            "ns",
            "y",
        ));
        let t = log.tallies();
        assert_eq!(t.admitted, 3, "three admits folded into one counted row");
        assert_eq!(t.audited, 1);
        assert_eq!(t.denied, 1);
        assert_eq!(t.total(), 5);
    }

    #[test]
    fn restore_preserves_count_and_last_seen() {
        // JEF-237 persistence: a replayed journal line keeps its count, it isn't reset to 1.
        let log = PolicyDecisionLog::new();
        let mut r = rec(
            "admission",
            "allow",
            "Pod/web",
            "img:1",
            "signed",
            "meshed",
            "ns",
            "",
        );
        r.count = 7;
        r.at_ms = 1_000;
        log.restore(r);
        let snap = log.snapshot();
        assert_eq!(snap[0].count, 7, "restored count is preserved");
        assert_eq!(snap[0].at_ms, 1_000, "restored last-seen is preserved");
    }

    #[test]
    fn restore_then_record_folds_live_hits_onto_restored_count() {
        let log = PolicyDecisionLog::new();
        let mut restored = rec(
            "admission",
            "allow",
            "Pod/web",
            "img:1",
            "signed",
            "meshed",
            "ns",
            "",
        );
        restored.count = 5;
        log.restore(restored);
        // A fresh live admit of the same workload bumps the restored row, not a new one.
        log.record(rec(
            "admission",
            "allow",
            "Pod/web",
            "img:1",
            "signed",
            "meshed",
            "ns",
            "",
        ));
        let snap = log.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].count, 6);
    }

    #[test]
    fn allow_decisions_carry_an_empty_reason() {
        let r = rec(
            "admission",
            "allow",
            "Pod/web",
            "img:1",
            "signed",
            "meshed",
            "default",
            "",
        );
        assert_eq!(r.decision, "allow");
        assert!(r.reason.is_empty());
    }

    #[test]
    fn record_round_trips_through_json_with_back_compat_defaults() {
        // The /policy.json + journal contract: a record serializes and a JEF-226-era line
        // (no image/signature/mesh/count) still deserializes via #[serde(default)].
        let r = rec(
            "admission",
            "allow",
            "Pod/web",
            "img:1",
            "signed",
            "meshed",
            "ns",
            "",
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: PolicyDecisionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);

        let legacy = r#"{"policy":"image-signature","decision":"deny","subject":"Pod/x","namespace":"ns","reason":"unsigned","at_ms":5}"#;
        let parsed: PolicyDecisionRecord = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.image, "", "absent image defaults to empty");
        assert_eq!(parsed.signature, "");
        assert_eq!(parsed.mesh, "");
        assert_eq!(parsed.count, 1, "absent count defaults to one");
    }
}
