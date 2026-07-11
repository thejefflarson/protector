//! Tests for the JEF-319 entry-scoped corroboration shapes — cross-tenant lateral and
//! reverse-shell — kept in their own `*_tests.rs` file (repo CLAUDE.md: tests count toward
//! the 1,000-line cap). `super` resolves to the proof module, so these exercise the
//! `pub(super)` `corroborate` seam directly.
//!
//! Both shapes are shadow-gated (they only set `corroborated`, never actuate) and scoped to a
//! proven internet-facing foothold entry, so a legit cross-namespace call from an ordinary pod
//! or an ordinary egress from a non-entry pod must NOT corroborate. Each shape is tested BOTH
//! ways, plus a regression guard that ordinary egress / ordinary in-cluster traffic stays
//! non-corroborating.
//!
//! Why cross-tenant goes through `corroborated_for` but reverse-shell tests its predicate
//! directly: a bare in-cluster `NetworkConnection` does NOT blanket-corroborate, so the
//! cross-tenant shape is the only thing that can flip `corroborated_for` — a real end-to-end
//! assertion. A *notable exec*, however, already blanket-corroborates ANY objective via the
//! flat arm (JEF-117), which masks the narrower reverse-shell shape inside `corroborated_for`;
//! so we assert the reverse-shell shape on its `reverse_shell_shape` predicate directly (both
//! ways), and separately confirm the flat arms it must not widen still behave.

use std::time::{Duration, SystemTime};

use super::corroborate::{
    EntryContext, corroborated_for, cross_tenant_lateral, reverse_shell_shape,
};
use crate::engine::graph::Provenance;
use crate::engine::graph::attack::{AttackRef, CREDENTIAL_ACCESS, EXFILTRATION};
use crate::engine::graph::{Behavior, RuntimeSignal};

/// A base time all `at()` offsets are relative to, so windows are exact regardless of clock.
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

fn exec(path: &str) -> Behavior {
    Behavior::ProcessExec { path: path.into() }
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

// ---- Cross-tenant lateral (shape 1) — end-to-end through corroborated_for --------------

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

// ---- Reverse-shell (shape 2) — on the predicate directly (see module note) -------------

#[test]
fn notable_exec_then_egress_in_window_from_the_foothold_entry_is_a_reverse_shell() {
    // A shell exec at t=0 followed by outbound internet egress 10s later, from a foothold
    // entry — the reverse-shell signature.
    let runtime = [
        sig(exec("/bin/bash"), 0),
        sig(conn("203.0.113.7:4444", true), 10),
    ];
    assert!(reverse_shell_shape(&runtime, foothold_entry("frontend")));
}

#[test]
fn egress_with_no_preceding_notable_exec_is_not_a_reverse_shell() {
    // Outbound egress with NO notable exec before it — an ordinary (non-notable) exec does
    // not count, and egress alone must not match the reverse-shell shape.
    let runtime = [
        sig(exec("/app/server"), 0), // not a shell / pkg manager → not notable
        sig(conn("203.0.113.7:4444", true), 10),
    ];
    assert!(!reverse_shell_shape(&runtime, foothold_entry("frontend")));
}

#[test]
fn notable_exec_long_before_egress_is_outside_the_window() {
    // A shell exec at t=0 but egress 5 minutes later — well outside the tight 60s window, so
    // this is the ordinary "container execs, then later egresses" case, not a reverse shell.
    let runtime = [
        sig(exec("/bin/bash"), 0),
        sig(conn("203.0.113.7:4444", true), 300),
    ];
    assert!(!reverse_shell_shape(&runtime, foothold_entry("frontend")));
}

#[test]
fn egress_before_the_exec_is_not_a_reverse_shell() {
    // Egress FIRST, then the shell exec — wrong order; a reverse shell dials out AFTER the
    // shell starts, so this must not match.
    let runtime = [
        sig(conn("203.0.113.7:4444", true), 0),
        sig(exec("/bin/bash"), 10),
    ];
    assert!(!reverse_shell_shape(&runtime, foothold_entry("frontend")));
}

#[test]
fn reverse_shell_from_a_non_foothold_entry_does_not_match() {
    // The exact reverse-shell shape but the entry is an ordinary pod — scoped to a foothold
    // entry, so it must NOT match.
    let runtime = [
        sig(exec("/bin/bash"), 0),
        sig(conn("203.0.113.7:4444", true), 10),
    ];
    assert!(!reverse_shell_shape(&runtime, ordinary_entry("frontend")));
}

#[test]
fn in_cluster_egress_after_a_notable_exec_is_not_a_reverse_shell() {
    // A notable exec followed by an IN-CLUSTER (`internet: false`) connection is not a
    // dial-out — the shape requires outbound internet egress. Guards against widening to
    // ordinary in-cluster traffic.
    let runtime = [
        sig(exec("/bin/bash"), 0),
        sig(conn("frontend/cache:6379 (10.42.1.4)", false), 10),
    ];
    assert!(!reverse_shell_shape(&runtime, foothold_entry("frontend")));
}

// ---- Regression guard: don't widen the flat egress predicate --------------------------

#[test]
fn ordinary_in_cluster_traffic_does_not_trigger_the_new_shapes() {
    // From a proven foothold entry with NO notable exec and NO cross-tenant peer: ordinary
    // same-namespace and unresolved in-cluster traffic must STILL corroborate nothing. The
    // objective is EXFILTRATION, which the UNCHANGED flat arm only fires on for *internet*
    // egress (absent here), so any positive would mean a new shape wrongly widened.
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
    // Neither new shape fires on this traffic either.
    assert!(!cross_tenant_lateral(&runtime, foothold_entry("frontend")));
    assert!(!reverse_shell_shape(&runtime, foothold_entry("frontend")));
}

#[test]
fn ordinary_internet_egress_still_corroborates_only_via_the_unchanged_flat_arm() {
    // Ordinary internet egress from the foothold entry still corroborates the EXFILTRATION
    // objective — via the UNCHANGED flat arm, not a new shape (no notable exec precedes it,
    // no cross-tenant peer). Proven by: it corroborates EXFILTRATION, but the SAME egress does
    // NOT corroborate a CredentialAccess objective — so no entry-scoped shape (which would
    // corroborate BOTH objectives) fired.
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
    // And directly: neither new shape fires on a bare outbound egress.
    assert!(!cross_tenant_lateral(&runtime, foothold_entry("frontend")));
    assert!(!reverse_shell_shape(&runtime, foothold_entry("frontend")));
}
