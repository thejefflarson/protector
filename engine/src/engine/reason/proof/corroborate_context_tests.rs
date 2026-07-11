//! Tests for the JEF-319 entry-scoped corroboration shape — cross-tenant lateral — kept in
//! its own `*_tests.rs` file (repo CLAUDE.md: tests count toward the 1,000-line cap).
//! `super` resolves to the proof module, so these exercise the `pub(super)` `corroborate`
//! seam directly.
//!
//! The shape is shadow-gated (it only sets `corroborated`, never actuates) and scoped to a
//! proven internet-facing foothold entry, so a legit cross-namespace call from an ordinary
//! pod must NOT corroborate. It is tested BOTH ways — end-to-end through `corroborated_for`
//! (a bare in-cluster `NetworkConnection` does not blanket-corroborate, so the cross-tenant
//! shape is the only thing that can flip `corroborated_for`, a real end-to-end assertion) and
//! on the `cross_tenant_lateral` predicate directly — plus regression guards that ordinary
//! egress / ordinary in-cluster traffic still corroborate only via the unchanged flat arms.
//!
//! (The reverse-shell shape considered in JEF-319 was dropped at integration: it was
//! redundant-by-construction under the blanket notable-exec arm (JEF-117) — a notable exec
//! already corroborates ANY objective, so the narrower exec+egress-timing shape could not
//! flip `corroborated_for` today. It lands load-bearing only WHEN that blanket exec arm is
//! narrowed; a follow-up ticket tracks implementing it then, so it arrives with a test that
//! can actually fail rather than dead-on-arrival.)

use std::time::{Duration, SystemTime};

use super::corroborate::{EntryContext, corroborated_for, cross_tenant_lateral};
use crate::engine::graph::Provenance;
use crate::engine::graph::attack::{AttackRef, CREDENTIAL_ACCESS, EXFILTRATION};
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

fn conn(peer: &str, internet: bool) -> Behavior {
    Behavior::NetworkConnection {
        peer: peer.into(),
        internet,
    }
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

/// The objective for the CROSS-TENANT `corroborated_for` tests: EXFILTRATION fires (flat arm)
/// only on an `internet` egress, and those tests use an in-cluster peer, so with `foothold:
/// None` a positive is attributable to the cross-tenant shape alone.
fn cross_tenant_objective() -> AttackRef {
    EXFILTRATION
}

// ---- Cross-tenant lateral — end-to-end through corroborated_for ------------------------

#[test]
fn cross_tenant_from_the_foothold_entry_corroborates() {
    // A connection from the entry (namespace `frontend`) to a pod in ANOTHER namespace
    // (`backend`) is lateral movement — corroborates when the entry is a proven foothold.
    let runtime = [sig(conn("backend/api:8080 (10.42.3.9)", false), 0)];
    assert!(corroborated_for(
        &runtime,
        &cross_tenant_objective(),
        None,
        foothold_entry("frontend"),
    ));
    // And the predicate directly.
    assert!(cross_tenant_lateral(&runtime, foothold_entry("frontend")));
}

#[test]
fn same_namespace_call_does_not_corroborate() {
    // A connection to a peer in the SAME namespace is ordinary in-namespace traffic.
    let runtime = [sig(conn("frontend/cache:6379 (10.42.1.4)", false), 0)];
    assert!(!corroborated_for(
        &runtime,
        &cross_tenant_objective(),
        None,
        foothold_entry("frontend"),
    ));
    assert!(!cross_tenant_lateral(&runtime, foothold_entry("frontend")));
}

#[test]
fn cross_tenant_from_a_non_foothold_entry_does_not_corroborate() {
    // The SAME cross-namespace connection, but the entry is an ordinary pod — a legit
    // cross-ns service call from a non-entry workload must NOT corroborate.
    let runtime = [sig(conn("backend/api:8080 (10.42.3.9)", false), 0)];
    assert!(!corroborated_for(
        &runtime,
        &cross_tenant_objective(),
        None,
        ordinary_entry("frontend"),
    ));
    assert!(!cross_tenant_lateral(&runtime, ordinary_entry("frontend")));
}

// ---- Regression guard: don't widen the flat egress predicate --------------------------

#[test]
fn ordinary_in_cluster_traffic_does_not_corroborate() {
    // From a proven foothold entry with NO cross-tenant peer: ordinary same-namespace and
    // unresolved in-cluster traffic must STILL corroborate nothing. The objective is
    // EXFILTRATION, which the UNCHANGED flat arm only fires on for *internet* egress (absent
    // here), so any positive would mean the cross-tenant shape wrongly widened.
    let runtime = [
        sig(conn("frontend/cache:6379 (10.42.1.4)", false), 0), // same-ns in-cluster
        sig(conn("10.42.1.159:8086", false), 5),                // unresolved in-cluster IP
    ];
    assert!(!corroborated_for(
        &runtime,
        &cross_tenant_objective(),
        None,
        foothold_entry("frontend"),
    ));
    assert!(!cross_tenant_lateral(&runtime, foothold_entry("frontend")));
}

#[test]
fn ordinary_internet_egress_still_corroborates_only_via_the_unchanged_flat_arm() {
    // Ordinary internet egress from the foothold entry still corroborates the EXFILTRATION
    // objective — via the UNCHANGED flat arm, not a new shape (no cross-tenant peer). Proven
    // by: it corroborates EXFILTRATION, but the SAME egress does NOT corroborate a
    // CredentialAccess objective — so no entry-scoped shape (which would corroborate BOTH
    // objectives) fired.
    let runtime = [sig(conn("203.0.113.7:443", true), 0)];
    assert!(corroborated_for(
        &runtime,
        &EXFILTRATION,
        None,
        foothold_entry("frontend"),
    ));
    assert!(!corroborated_for(
        &runtime,
        &CREDENTIAL_ACCESS,
        None,
        foothold_entry("frontend"),
    ));
    // And directly: the cross-tenant shape does not fire on a bare outbound egress.
    assert!(!cross_tenant_lateral(&runtime, foothold_entry("frontend")));
}
