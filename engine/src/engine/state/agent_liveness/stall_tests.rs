//! Tests for the coverage-stall edge (JEF-421): the loud `Stalled` register fires only on a
//! WAS-COVERING → now-fully-blind transition held past the debounce; a never-enabled fleet stays
//! honestly `Absent`; a DaemonSet roll (a pass or two of blindness that recovers) never trips it.

use std::time::{Duration, SystemTime};

use super::super::{BlindReason, NodeCoverage, NodeState, RuntimeCoverage};
use super::{CoverageState, STALL_HOLD_PASSES};

/// A coverage snapshot from `(node, state)` pairs.
fn coverage(nodes: &[(&str, NodeState)]) -> RuntimeCoverage {
    RuntimeCoverage {
        nodes: nodes
            .iter()
            .map(|(n, s)| NodeCoverage {
                node: (*n).to_string(),
                state: *s,
            })
            .collect(),
    }
}

fn healthy(node: &str) -> (&str, NodeState) {
    (node, NodeState::Healthy { signals: 3 })
}

fn blind(node: &str) -> (&str, NodeState) {
    (
        node,
        NodeState::Blind {
            reason: BlindReason::NotReporting,
        },
    )
}

/// The edge fires on a healthy → fully-blind transition once held for the debounce window, and NOT
/// before — a normal roll that recovers within the window never strobes.
#[test]
fn stall_fires_on_healthy_to_all_blind_after_hold() {
    let mut t = super::CoverageStallTracker::default();
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);

    // Covering: both nodes healthy.
    let cov = coverage(&[healthy("a"), healthy("b")]);
    assert_eq!(t.observe(&cov, t0), CoverageState::Covered);

    // Now fully blind — but held only a pass or two: still degraded, NOT stalled yet (debounce).
    let dark = coverage(&[blind("a"), blind("b")]);
    for i in 1..STALL_HOLD_PASSES {
        let s = t.observe(&dark, t0 + Duration::from_secs(60 * i as u64));
        assert_eq!(
            s,
            CoverageState::Degraded,
            "pass {i}: within the debounce window it is loud-but-not-yet-stalled"
        );
    }

    // The STALL_HOLD_PASSES-th consecutive fully-blind pass trips the loud edge.
    let s = t.observe(
        &dark,
        t0 + Duration::from_secs(60 * STALL_HOLD_PASSES as u64),
    );
    match s {
        CoverageState::Stalled(alert) => {
            assert_eq!(alert.feed_label, "Runtime");
            assert!(alert.message.contains("stalled"));
            assert!(
                alert.last_observation.is_some(),
                "a stall carries the last-observed-live time"
            );
        }
        other => panic!("expected Stalled after the hold window, got {other:?}"),
    }
}

/// A brief DaemonSet roll (blind for fewer than the hold, then recovers) NEVER stalls — the streak
/// resets the moment a node reports healthy again.
#[test]
fn a_recovering_roll_does_not_stall() {
    let mut t = super::CoverageStallTracker::default();
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let cov = coverage(&[healthy("a"), healthy("b")]);
    let dark = coverage(&[blind("a"), blind("b")]);

    assert_eq!(t.observe(&cov, t0), CoverageState::Covered);
    // Blind for one pass shy of the hold, then recover.
    for i in 1..STALL_HOLD_PASSES {
        assert_eq!(
            t.observe(&dark, t0 + Duration::from_secs(60 * i as u64)),
            CoverageState::Degraded
        );
    }
    assert_eq!(
        t.observe(&cov, t0 + Duration::from_secs(600)),
        CoverageState::Covered,
        "recovery clears the streak"
    );
    // Now a fresh single blind pass is only degraded again — the streak restarted from zero.
    assert_eq!(
        t.observe(&dark, t0 + Duration::from_secs(660)),
        CoverageState::Degraded
    );
}

/// A fleet that was NEVER corroborating stays honestly `Absent` (muted), never `Stalled` — a cold
/// start that never came up is not a stall.
#[test]
fn never_covering_is_absent_not_stalled() {
    let mut t = super::CoverageStallTracker::default();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let dark = coverage(&[blind("a"), blind("b")]);
    // Many fully-blind passes without ever having been healthy.
    for i in 0..(STALL_HOLD_PASSES + 5) {
        assert_eq!(
            t.observe(&dark, now + Duration::from_secs(60 * i as u64)),
            CoverageState::Absent,
            "a never-covering fleet is absent, not stalled"
        );
    }
}

/// No expected nodes (coverage not enabled in scope) is `Absent` and never advances the debounce.
#[test]
fn no_expected_nodes_is_absent() {
    let mut t = super::CoverageStallTracker::default();
    let now = SystemTime::UNIX_EPOCH;
    assert_eq!(
        t.observe(&RuntimeCoverage::default(), now),
        CoverageState::Absent
    );
}

/// A partial fleet (some healthy, some blind) is `Degraded`, never a stall — corroboration is still
/// live on the healthy nodes.
#[test]
fn partial_is_degraded_not_stalled() {
    let mut t = super::CoverageStallTracker::default();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let cov = coverage(&[healthy("a"), blind("b")]);
    // Even repeated, a partial fleet never trips the stall (one node keeps reporting).
    for i in 0..(STALL_HOLD_PASSES + 2) {
        assert_eq!(
            t.observe(&cov, now + Duration::from_secs(60 * i as u64)),
            CoverageState::Degraded
        );
    }
}
