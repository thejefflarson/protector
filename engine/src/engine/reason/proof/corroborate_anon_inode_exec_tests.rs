//! Tests for the JEF-317 (Route A) entry-scoped corroboration shape — anon-inode exec on
//! the foothold — kept in its own `*_tests.rs` file (repo CLAUDE.md: tests count toward the
//! 1,000-line cap). `super` resolves to the proof module, so these exercise the
//! `pub(super)` `corroborate` seam directly, mirroring `corroborate_privesc_tests.rs`.
//!
//! Route A replaces a WITHDRAWN v1 approach (a security review caught it): v1 classified
//! the exec *path shape* (`/dev/fd/<n>` etc.) and fed it into the flat, blanket
//! `corroborates` gate, forging corroboration on routine `fexecve()`/runc-memfd-reexec
//! behavior. This shape instead reads the real (agent-supplied, kernel-observed)
//! `exe_anon_inode` inode fact, and is scoped BOTH to a proven internet-facing foothold
//! entry AND to an Execution-tactic objective — never the "corroborates any objective"
//! blanket gate a shell/package-manager exec gets.

use std::time::{Duration, SystemTime};

use super::corroborate::{EntryContext, anon_inode_exec_on_foothold, corroborated_for};
use crate::engine::graph::Provenance;
use crate::engine::graph::attack::{
    AttackRef, CONTAINER_ADMIN_COMMAND, CREDENTIAL_ACCESS, ESCAPE_TO_HOST,
};
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

fn exec(path: &str, exe_anon_inode: bool, secs: u64) -> RuntimeSignal {
    sig(
        Behavior::ProcessExec {
            path: path.into(),
            exe_anon_inode,
        },
        secs,
    )
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

/// The objective for these tests: an Execution-tactic chain (T1609 Container
/// Administration Command).
fn execution_objective() -> AttackRef {
    CONTAINER_ADMIN_COMMAND
}

// ---- Positive: anon-inode exec on the foothold entry — end to end ------------------------

#[test]
fn anon_inode_exec_on_the_foothold_entry_corroborates_execution() {
    // A memfd/unlinked-backed exec on the proven internet-facing foothold IS the
    // Falco-parity signal (JEF-317): the attacker who owns the front door running a
    // fileless payload on that same workload.
    let runtime = [exec("/tmp/payload", true, 0)];
    assert!(corroborated_for(
        &runtime,
        &execution_objective(),
        None,
        foothold_entry("frontend"),
    ));
    // And the predicate directly.
    assert!(anon_inode_exec_on_foothold(
        &runtime,
        &execution_objective(),
        foothold_entry("frontend"),
    ));
}

// ---- Negative: same exec, non-foothold entry ----------------------------------------------

#[test]
fn anon_inode_exec_on_a_non_foothold_entry_does_not_corroborate() {
    // The SAME anon-inode exec, but the entry is an ordinary pod — must NOT corroborate
    // (ADR-0011): this is exactly where an unmeasured runc-memfd-reexec false positive
    // would land if it attributed to an arbitrary workload rather than a proven foothold.
    let runtime = [exec("/tmp/payload", true, 0)];
    assert!(!corroborated_for(
        &runtime,
        &execution_objective(),
        None,
        ordinary_entry("frontend"),
    ));
    assert!(!anon_inode_exec_on_foothold(
        &runtime,
        &execution_objective(),
        ordinary_entry("frontend"),
    ));
}

// ---- Regression guards: don't widen past exe_anon_inode / past Execution -----------------

#[test]
fn a_normal_exec_on_the_foothold_does_not_corroborate() {
    // exe_anon_inode: false — an ordinary on-disk exec, even on the proven foothold — is
    // not the fileless-exec signal Falco fires on.
    let runtime = [exec("/app/server", false, 0)];
    assert!(!anon_inode_exec_on_foothold(
        &runtime,
        &execution_objective(),
        foothold_entry("frontend"),
    ));
}

#[test]
fn anon_inode_exec_on_the_foothold_does_not_corroborate_an_unrelated_objective() {
    // The shape only lights up an Execution-tactic objective — it must not blanket-
    // corroborate a CredentialAccess or PrivilegeEscalation chain just because the entry
    // is a foothold. This is the conservative-scoping guard the withdrawn v1 approach
    // lacked entirely (it corroborated ANY objective).
    let runtime = [exec("/tmp/payload", true, 0)];
    for objective in [CREDENTIAL_ACCESS, ESCAPE_TO_HOST] {
        assert!(
            !corroborated_for(&runtime, &objective, None, foothold_entry("frontend")),
            "{objective:?}"
        );
        assert!(
            !anon_inode_exec_on_foothold(&runtime, &objective, foothold_entry("frontend")),
            "{objective:?}"
        );
    }
}
