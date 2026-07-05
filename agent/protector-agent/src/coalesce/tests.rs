//! Unit tests for the agent-side debounce/coalescer (JEF-296).

use super::*;
use protector_behavior::{Behavior, SecretReadSource};

/// A mundane observation attributed to `pod_uid`, stamped at `at_ms`.
fn obs(pod_uid: &str, behavior: Behavior, at_ms: u64) -> RuntimeObservation {
    RuntimeObservation {
        attribution: Attribution::by_pod_uid(pod_uid),
        source: Some("protector-agent".into()),
        observed_at_ms: Some(at_ms),
        node: None,
        behavior,
    }
}

fn connect(peer: &str, internet: bool) -> Behavior {
    Behavior::NetworkConnection {
        peer: peer.into(),
        internet,
    }
}

/// Identical coarse signals within a window collapse to a single observation.
#[test]
fn coalesces_identical_signals_within_a_window() {
    let mut c = Coalescer::new(1024);
    // The same workload hitting three *different* internet peers is the same coarse fact
    // (`egress:internet`) — the exact per-peer churn the engine's verdict cache coarsens.
    assert!(
        c.offer(obs("p1", connect("1.1.1.1:443", true), 10))
            .is_empty()
    );
    assert!(
        c.offer(obs("p1", connect("2.2.2.2:443", true), 20))
            .is_empty()
    );
    assert!(
        c.offer(obs("p1", connect("3.3.3.3:80", true), 30))
            .is_empty()
    );

    let flushed = c.drain();
    assert_eq!(flushed.len(), 1, "three egress:internet churn → one row");
    assert!(c.is_empty(), "drain empties the buffer");
}

/// The first-seen observation (and its freshness stamp) is the one kept; later identical
/// signals are dropped, not the earlier one.
#[test]
fn keeps_the_first_seen_observation_per_key() {
    let mut c = Coalescer::new(1024);
    c.offer(obs("p1", connect("1.1.1.1:443", true), 100));
    c.offer(obs("p1", connect("9.9.9.9:443", true), 200));
    let flushed = c.drain();
    assert_eq!(flushed.len(), 1);
    // First-seen timestamp preserved (freshness is the sensor's first observation, ADR-0002).
    assert_eq!(flushed[0].observed_at_ms, Some(100));
    // And it's the first peer that's carried.
    assert_eq!(
        flushed[0].behavior,
        connect("1.1.1.1:443", true),
        "the first-seen concrete observation is kept"
    );
}

/// Distinct coarse behaviors all survive — nothing distinct is ever dropped.
#[test]
fn distinct_behaviors_all_survive() {
    let mut c = Coalescer::new(1024);
    // Each of these has a DISTINCT fingerprint_key, so none may coalesce into another.
    c.offer(obs("p1", connect("1.1.1.1:443", true), 1)); // egress:internet
    c.offer(obs("p1", connect("10.0.0.5:443", false), 2)); // egress:cluster
    c.offer(obs(
        "p1",
        Behavior::ProcessExec {
            path: "/bin/bash".into(),
        },
        3,
    )); // exec:bash
    c.offer(obs(
        "p1",
        Behavior::ProcessExec {
            path: "/usr/bin/python".into(),
        },
        4,
    )); // exec:python
    c.offer(obs(
        "p1",
        Behavior::SecretRead {
            secret: "app/a".into(),
            source: SecretReadSource::Mounted,
        },
        5,
    )); // read:app/a
    c.offer(obs(
        "p1",
        Behavior::SecretRead {
            secret: "app/b".into(),
            source: SecretReadSource::Mounted,
        },
        6,
    )); // read:app/b
    c.offer(obs(
        "p1",
        Behavior::LibraryLoaded {
            name: "libssl.so.3".into(),
        },
        7,
    )); // lib:...

    let flushed = c.drain();
    assert_eq!(flushed.len(), 7, "all distinct fingerprints survive");
}

/// The same coarse behavior from DIFFERENT workloads is not coalesced — attribution is part
/// of the identity, so one pod's egress never masks another's.
#[test]
fn distinct_attributions_do_not_coalesce() {
    let mut c = Coalescer::new(1024);
    c.offer(obs("pod-a", connect("1.1.1.1:443", true), 1));
    c.offer(obs("pod-b", connect("1.1.1.1:443", true), 2));
    assert_eq!(c.drain().len(), 2, "same behavior, two pods → two rows");
}

/// exec churn: repeated execs of the same binary from different absolute paths collapse to
/// the shared `exec:<basename>` key, mirroring the engine's fingerprint.
#[test]
fn exec_churn_collapses_by_basename() {
    let mut c = Coalescer::new(1024);
    c.offer(obs(
        "p1",
        Behavior::ProcessExec {
            path: "/usr/bin/bash".into(),
        },
        1,
    ));
    c.offer(obs(
        "p1",
        Behavior::ProcessExec {
            path: "/bin/bash".into(),
        },
        2,
    ));
    assert_eq!(c.drain().len(), 1, "same basename → one row");
}

/// Alerts bypass the debounce entirely: each is returned for an immediate POST and is never
/// buffered — live corroboration must not eat the window latency.
#[test]
fn alerts_bypass_the_debounce_immediately() {
    let mut c = Coalescer::new(1024);
    let alert = obs(
        "p1",
        Behavior::Alert {
            rule: "Terminal shell in container".into(),
        },
        1,
    );
    let immediate = c.offer(alert.clone());
    assert_eq!(immediate, vec![alert], "the alert flushes immediately");
    assert!(c.is_empty(), "the alert was NOT buffered");

    // Two alerts, even with the same rule, each flush now (never coalesced) — urgency over
    // dedup for the corroboration path.
    let a2 = obs(
        "p1",
        Behavior::Alert {
            rule: "same".into(),
        },
        2,
    );
    let a3 = obs(
        "p1",
        Behavior::Alert {
            rule: "same".into(),
        },
        3,
    );
    assert_eq!(c.offer(a2.clone()), vec![a2]);
    assert_eq!(c.offer(a3.clone()), vec![a3]);
    assert!(c.is_empty());
}

/// An alert flushes immediately even while a mundane buffer is filling — and it does not
/// disturb that buffer (the window flush still delivers the buffered mundane signals).
#[test]
fn alert_does_not_disturb_the_mundane_buffer() {
    let mut c = Coalescer::new(1024);
    assert!(
        c.offer(obs("p1", connect("1.1.1.1:443", true), 1))
            .is_empty()
    );
    let alert = obs("p1", Behavior::Alert { rule: "x".into() }, 2);
    assert_eq!(c.offer(alert.clone()), vec![alert]);
    // The buffered egress is still pending and comes out on the window drain.
    assert_eq!(c.drain().len(), 1);
}

/// The max-size trigger: admitting a new distinct key past the cap drains the buffer and
/// returns it (memory bound), then starts the next window with the new observation.
#[test]
fn max_size_forces_a_flush() {
    let mut c = Coalescer::new(3);
    // Fill to capacity with three distinct signals — none triggers a flush yet.
    assert!(
        c.offer(obs("p1", connect("10.0.0.1:80", false), 1))
            .is_empty()
    ); // egress:cluster
    assert!(
        c.offer(obs("p1", connect("1.1.1.1:443", true), 2))
            .is_empty()
    ); // egress:internet
    assert!(
        c.offer(obs(
            "p1",
            Behavior::ProcessExec {
                path: "/bin/sh".into()
            },
            3
        ))
        .is_empty()
    ); // exec:sh

    // A fourth distinct key would exceed max_size → the buffer is drained and returned.
    let flushed = c.offer(obs(
        "p1",
        Behavior::LibraryLoaded {
            name: "libc.so.6".into(),
        },
        4,
    ));
    assert_eq!(flushed.len(), 3, "the full buffer is flushed at the cap");
    // …and the fourth observation now sits alone in the fresh buffer.
    assert_eq!(c.drain().len(), 1);
}

/// A duplicate at capacity coalesces (drops) rather than forcing a flush — only a genuinely
/// new distinct key trips the max-size trigger.
#[test]
fn duplicate_at_capacity_coalesces_without_flushing() {
    let mut c = Coalescer::new(2);
    c.offer(obs("p1", connect("1.1.1.1:443", true), 1)); // egress:internet
    c.offer(obs("p1", connect("10.0.0.1:80", false), 2)); // egress:cluster (buffer now full)
    // Another egress:internet is a duplicate of a buffered key — coalesced, no flush.
    let flushed = c.offer(obs("p1", connect("2.2.2.2:443", true), 3));
    assert!(
        flushed.is_empty(),
        "a duplicate at cap coalesces, not flushes"
    );
    assert_eq!(
        c.drain().len(),
        2,
        "buffer still holds the two distinct keys"
    );
}

/// The window-elapsed flush on an empty buffer yields nothing (the caller skips the POST).
#[test]
fn draining_an_empty_buffer_is_empty() {
    let mut c = Coalescer::new(1024);
    assert!(c.drain().is_empty());
    assert!(c.is_empty());
}
