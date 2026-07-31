//! Tests for the entry-scoped corroboration shape — privilege escalation on the
//! foothold — kept in its own `*_tests.rs` file (repo CLAUDE.md: tests count toward the
//! 1,000-line cap). `super` resolves to the proof module, so these exercise the `pub(super)`
//! `corroborate` seam directly.
//!
//! The shape closes the Falco-parity gap: Falco fires critical on setuid→root, but the flat
//! `corroborates(PrivilegeChange, _)` relation stays non-corroborating everywhere (ADR-0011:
//! legit entrypoints/inits escalate to root on ordinary pods constantly). This shape is
//! scoped to a proven internet-facing foothold entry ONLY, so an ordinary pod's routine
//! setuid still never corroborates — it is shadow-gated (only sets `corroborated`, never
//! actuates) like every arm here.

use std::time::{Duration, SystemTime};

use super::corroborate::{EntryContext, corroborated_for, privilege_escalation_on_foothold};
use crate::engine::graph::Provenance;
use crate::engine::graph::attack::{AttackRef, CREDENTIAL_ACCESS, ESCAPE_TO_HOST};
use crate::engine::graph::{Behavior, RuntimeSignal};

/// A base time all `at()` offsets are relative to, so timing is exact regardless of clock.
fn base() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

/// A `RuntimeSignal` for `behavior` observed `secs` after [`base`].
fn sig(behavior: Behavior, secs: u64) -> RuntimeSignal {
    RuntimeSignal {
        behavior,
        provenance: Provenance::new("test", base() + Duration::from_secs(secs)),
    }
}

fn priv_change(from_uid: u32, to_uid: u32) -> Behavior {
    Behavior::PrivilegeChange { from_uid, to_uid }
}

/// The entry is a proven internet-facing foothold in namespace `ns`.
fn foothold_entry(ns: &str) -> EntryContext<'_> {
    EntryContext {
        source_ns: ns,
        is_foothold: true,
    }
}

/// The entry is an ordinary (non-foothold) workload in namespace `ns`.
fn ordinary_entry(ns: &str) -> EntryContext<'_> {
    EntryContext {
        source_ns: ns,
        is_foothold: false,
    }
}

/// The objective for these tests: a PrivilegeEscalation-tactic chain (T1611 Escape to Host).
fn priv_esc_objective() -> AttackRef {
    ESCAPE_TO_HOST
}

// ---- Positive: root escalation on the foothold entry — end to end -----------------------

#[test]
fn root_escalation_on_the_foothold_entry_corroborates_priv_esc() {
    // setuid non-root -> root on the proven internet-facing foothold IS the Falco-parity
    // signal: the attacker who owns the front door escalating on that same workload.
    let runtime = [sig(priv_change(1000, 0), 0)];
    assert!(corroborated_for(
        &runtime,
        &priv_esc_objective(),
        None,
        foothold_entry("frontend"),
    ));
    // And the predicate directly.
    assert!(privilege_escalation_on_foothold(
        &runtime,
        &priv_esc_objective(),
        foothold_entry("frontend"),
    ));
}

// ---- Negative: same escalation, non-foothold entry ---------------------------------------

#[test]
fn root_escalation_on_a_non_foothold_entry_does_not_corroborate() {
    // The SAME setuid, but the entry is an ordinary pod — a legit entrypoint/init dropping
    // privileges (or escalating) on an unrelated workload must NOT corroborate (ADR-0011).
    let runtime = [sig(priv_change(1000, 0), 0)];
    assert!(!corroborated_for(
        &runtime,
        &priv_esc_objective(),
        None,
        ordinary_entry("frontend"),
    ));
    assert!(!privilege_escalation_on_foothold(
        &runtime,
        &priv_esc_objective(),
        ordinary_entry("frontend"),
    ));
}

// ---- Regression guards: don't widen past root escalation / past PrivilegeEscalation ------

#[test]
fn non_root_privilege_change_on_the_foothold_does_not_corroborate() {
    // A privilege change that does NOT land on uid 0 (e.g. dropping from root to a service
    // account, or moving between two non-root uids) is not the setuid-to-root signal Falco
    // fires on, even on the foothold entry.
    let runtime = [
        sig(priv_change(0, 1000), 0),
        sig(priv_change(1000, 1001), 5),
    ];
    assert!(!privilege_escalation_on_foothold(
        &runtime,
        &priv_esc_objective(),
        foothold_entry("frontend"),
    ));
}

#[test]
fn root_escalation_on_the_foothold_does_not_corroborate_an_unrelated_objective() {
    // The shape only lights up a PrivilegeEscalation-tactic objective — it must not blanket-
    // corroborate a CredentialAccess chain just because the entry is a foothold.
    let runtime = [sig(priv_change(1000, 0), 0)];
    assert!(!corroborated_for(
        &runtime,
        &CREDENTIAL_ACCESS,
        None,
        foothold_entry("frontend"),
    ));
    assert!(!privilege_escalation_on_foothold(
        &runtime,
        &CREDENTIAL_ACCESS,
        foothold_entry("frontend"),
    ));
}
