//! Tests for the entry-scoped corroboration shape — kernel-module load on the
//! foothold — kept in its own `*_tests.rs` file (repo CLAUDE.md: tests count toward the
//! 1,000-line file cap). `super` resolves to the proof module, so these exercise the
//! `pub(super)` `corroborate` seam directly.
//!
//! The shape closes the Falco-parity gap: Falco fires critical on `init_module`/
//! `finit_module`, but the flat `corroborates(ModuleLoad, _)` relation stays
//! non-corroborating everywhere (ADR-0011: a legitimate driver-loading DaemonSet — a CNI/CSI
//! plugin, a kernel-module operator — loads modules on ordinary pods). This shape is scoped
//! to a proven internet-facing foothold entry ONLY, mirroring
//! [`corroborate_ptrace_tests`](super::corroborate_ptrace_tests) — it is shadow-gated (only
//! sets `corroborated`, never actuates) like every arm here.

use std::time::{Duration, SystemTime};

use super::corroborate::{EntryContext, corroborated_for, module_load_on_foothold};
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

/// The objective for these tests: a PrivilegeEscalation-tactic chain (T1611 Escape to Host) —
/// the same tactic `module_load_on_foothold` gates on (a kernel module load from
/// inside a container IS host compromise, see the predicate's doc comment).
fn priv_esc_objective() -> AttackRef {
    ESCAPE_TO_HOST
}

// ---- Positive: module load on the foothold entry — end to end -----------------------------

#[test]
fn module_load_on_the_foothold_entry_corroborates_priv_esc() {
    let runtime = [sig(Behavior::ModuleLoad, 0)];
    assert!(corroborated_for(
        &runtime,
        &priv_esc_objective(),
        None,
        foothold_entry("frontend"),
    ));
    // And the predicate directly.
    assert!(module_load_on_foothold(
        &runtime,
        &priv_esc_objective(),
        foothold_entry("frontend"),
    ));
}

// ---- Negative: same load, non-foothold entry -----------------------------------------------

#[test]
fn module_load_on_a_non_foothold_entry_does_not_corroborate() {
    // The SAME module load, but the entry is an ordinary pod — a legit driver-loading
    // DaemonSet on an unrelated workload must NOT corroborate (ADR-0011).
    let runtime = [sig(Behavior::ModuleLoad, 0)];
    assert!(!corroborated_for(
        &runtime,
        &priv_esc_objective(),
        None,
        ordinary_entry("frontend"),
    ));
    assert!(!module_load_on_foothold(
        &runtime,
        &priv_esc_objective(),
        ordinary_entry("frontend"),
    ));
}

// ---- Regression guard: don't widen past PrivilegeEscalation --------------------------------

#[test]
fn module_load_on_the_foothold_does_not_corroborate_an_unrelated_objective() {
    // The shape only lights up a PrivilegeEscalation-tactic objective — it must not blanket-
    // corroborate a CredentialAccess chain just because the entry is a foothold.
    let runtime = [sig(Behavior::ModuleLoad, 0)];
    assert!(!corroborated_for(
        &runtime,
        &CREDENTIAL_ACCESS,
        None,
        foothold_entry("frontend"),
    ));
    assert!(!module_load_on_foothold(
        &runtime,
        &CREDENTIAL_ACCESS,
        foothold_entry("frontend"),
    ));
}

#[test]
fn other_behaviors_on_the_foothold_do_not_trigger_this_shape() {
    // A PtraceAttach ('s OTHER new shape) and an ordinary ProcessExec on the same
    // foothold entry must not be mistaken for a module load.
    let runtime = [
        sig(Behavior::PtraceAttach, 0),
        sig(
            Behavior::ProcessExec {
                path: "/app/server".into(),
                exe_anon_inode: false,
            },
            1,
        ),
    ];
    assert!(!module_load_on_foothold(
        &runtime,
        &priv_esc_objective(),
        foothold_entry("frontend"),
    ));
}
