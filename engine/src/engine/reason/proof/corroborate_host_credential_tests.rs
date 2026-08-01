//! Tests for the security-rework entry-scoped corroboration shape — an on-host
//! credential-path `SecretRead` on the foothold — kept in its own `*_tests.rs` file (repo
//! CLAUDE.md: tests count toward the 1,000-line cap). `super` resolves to the proof module,
//! so these exercise the `pub(super)` `corroborate` seam directly.
//!
//! Finding 4 (MEDIUM, broken access control) from the HELD security review: unlike its
//! siblings [`cross_tenant_lateral`](super::corroborate::cross_tenant_lateral) /
//! [`privilege_escalation_on_foothold`](super::corroborate::privilege_escalation_on_foothold)
//! / [`drop_then_execute`](super::corroborate::drop_then_execute), the `SecretRead { source:
//! HostPath, .. }` arm was NOT gated on `entry.is_foothold` — it corroborated on ANY
//! workload. This module tests the fix both ways: the flat `corroborates()` relation must
//! now stay silent for a `HostPath` read (only `Mounted`/`Api` stay context-free), and the
//! new entry-scoped shape must fire ONLY on a proven foothold.

use std::time::{Duration, SystemTime};

use super::corroborate::{
    EntryContext, corroborated_for, corroborates, host_credential_read_on_foothold,
};
use crate::engine::graph::Provenance;
use crate::engine::graph::attack::{CREDENTIAL_ACCESS, EXFILTRATION};
use crate::engine::graph::{Behavior, RuntimeSignal, SecretReadSource};

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

fn host_path_read(path: &str) -> Behavior {
    Behavior::SecretRead {
        secret: path.into(),
        source: SecretReadSource::HostPath,
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

// ---- Positive: on-host credential read on the foothold entry — end to end ----------------

#[test]
fn on_host_credential_read_on_the_foothold_entry_corroborates_credential_access() {
    let runtime = [sig(host_path_read("/etc/shadow"), 0)];
    assert!(corroborated_for(
        &runtime,
        &CREDENTIAL_ACCESS,
        None,
        foothold_entry("frontend"),
    ));
    // And the predicate directly.
    assert!(host_credential_read_on_foothold(
        &runtime,
        &CREDENTIAL_ACCESS,
        foothold_entry("frontend"),
    ));
}

// ---- Negative: same read, non-foothold entry (the security-review finding) ---------------

#[test]
fn on_host_credential_read_on_a_non_foothold_entry_does_not_corroborate() {
    // MEDIUM finding (broken access control, security rework): the SAME read, but the
    // entry is an ordinary pod — a bastion pod's own `sshd` reading its own `/etc/shadow`
    // for PAM must NOT corroborate on an unrelated, non-foothold workload (ADR-0011).
    let runtime = [sig(host_path_read("/etc/shadow"), 0)];
    assert!(!corroborated_for(
        &runtime,
        &CREDENTIAL_ACCESS,
        None,
        ordinary_entry("frontend"),
    ));
    assert!(!host_credential_read_on_foothold(
        &runtime,
        &CREDENTIAL_ACCESS,
        ordinary_entry("frontend"),
    ));
}

// ---- Regression guard: the flat, context-free relation must NOT corroborate HostPath -----

#[test]
fn host_path_secret_read_does_not_flatly_corroborate_without_the_foothold_gate() {
    // The context-free `corroborates()` seam must stay silent for a `HostPath` read — only
    // the entry-scoped, foothold-gated shape above may promote it. A `Mounted`/`Api` read
    // (the pod's OWN declared k8s Secret) is unambiguous and stays context-free — see
    // `corroborate_objective_tests::secret_read_corroborates_credential_access`.
    let behavior = host_path_read("/etc/shadow");
    assert!(!corroborates(&behavior, &CREDENTIAL_ACCESS));
}

// ---- Regression guard: doesn't widen past CredentialAccess or corroborate an unrelated ---

#[test]
fn on_host_credential_read_on_the_foothold_does_not_corroborate_an_unrelated_objective() {
    let runtime = [sig(host_path_read("/etc/shadow"), 0)];
    assert!(!corroborated_for(
        &runtime,
        &EXFILTRATION,
        None,
        foothold_entry("frontend"),
    ));
    assert!(!host_credential_read_on_foothold(
        &runtime,
        &EXFILTRATION,
        foothold_entry("frontend"),
    ));
}

#[test]
fn a_mounted_secret_read_on_the_foothold_still_corroborates_via_the_flat_relation() {
    // Sanity: this fix must not regress the unrelated, unchanged Mounted/Api path — those
    // stay context-free and corroborate even without invoking the new entry-scoped shape.
    let runtime = [sig(
        Behavior::SecretRead {
            secret: "db-creds".into(),
            source: SecretReadSource::Mounted,
        },
        0,
    )];
    assert!(corroborated_for(
        &runtime,
        &CREDENTIAL_ACCESS,
        None,
        ordinary_entry("frontend"),
    ));
}
