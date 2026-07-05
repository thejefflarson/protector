//! Tests for the JEF-309 "alarming-now" file-write corroboration arm, kept in their own
//! `*_tests.rs` file (repo CLAUDE.md: tests count toward the 1,000-line cap, and `tests.rs`
//! is already near it). `super` resolves to the proof module, so these exercise the
//! `pub(super)` seam directly (`corroborate::corroborates`) plus the full `prove` path.

use serde_json::json;

use super::corroborate::corroborates;
use super::{ProvenChain, QuarantineReason, prove};
use crate::engine::graph::attack::{
    CREDENTIAL_ACCESS, ESCAPE_TO_HOST, EXFILTRATION, EXPLOIT_PUBLIC_FACING,
};
use crate::engine::graph::{Behavior, Provenance, Severity, Vulnerability};
use crate::engine::observe::adapter::{build_graph, default_adapters};
use crate::engine::observe::{
    Attribution, ImageVulnerabilities, RuntimeObservation, SecretMeta, Snapshot,
};

/// An *alarming* file write — a sensitive-path / drop-and-execute drift — corroborates ANY
/// objective, exactly like an Alert or a notable exec (JEF-309). This is the blanket
/// tamper-now gate: Falco's "Write below etc / binary dir" and drop-and-execute criticals,
/// restored engine-side.
#[test]
fn sensitive_write_corroborates_any_objective() {
    // One representative from each sensitive class the F3 policy promotes.
    for path in [
        "/usr/bin/dropper",           // drop-and-execute into PATH
        "/etc/cron.d/persist",        // cron persistence
        "/etc/ld.so.preload",         // config tamper below /etc
        "/root/.ssh/authorized_keys", // SSH persistence
        "/var/run/secrets/kubernetes.io/serviceaccount/token", // SA-token tamper
    ] {
        let write = Behavior::FileWrite { path: path.into() };
        assert!(
            crate::engine::observe::alarm_class::alarming_write(&write).is_some(),
            "{path:?} should classify as an alarming write"
        );
        // Blanket: corroborates every objective tactic, like an alert.
        assert!(corroborates(&write, &CREDENTIAL_ACCESS), "{path:?}");
        assert!(corroborates(&write, &EXFILTRATION), "{path:?}");
        assert!(corroborates(&write, &ESCAPE_TO_HOST), "{path:?}");
        assert!(corroborates(&write, &EXPLOIT_PUBLIC_FACING), "{path:?}");
    }
}

/// NEGATIVE (ADR-0011): a *benign* write — an app writing its own data / tmp / logs, the
/// common case — stays NON-corroborating for every objective. This is the false-positive the
/// classifier must never produce.
#[test]
fn benign_write_does_not_corroborate() {
    for path in ["/data/app.db", "/tmp/scratch", "/var/log/app.log"] {
        let write = Behavior::FileWrite { path: path.into() };
        assert!(
            crate::engine::observe::alarm_class::alarming_write(&write).is_none(),
            "{path:?} should be a benign write"
        );
        assert!(!corroborates(&write, &CREDENTIAL_ACCESS), "{path:?}");
        assert!(!corroborates(&write, &EXFILTRATION), "{path:?}");
        assert!(!corroborates(&write, &ESCAPE_TO_HOST), "{path:?}");
        assert!(!corroborates(&write, &EXPLOIT_PUBLIC_FACING), "{path:?}");
    }
}

/// The internet-exposed, critical-CVE `web` entry with one runtime signal — its `behavior` is
/// the caller's to vary. Shared by the end-to-end drop-and-execute tests so they differ only
/// in the write path under test.
fn web_entry_with_signal(behavior: Behavior) -> Vec<ProvenChain> {
    let web: k8s_openapi::api::core::v1::Pod = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{
            "name": "web", "image": "web:1",
            "envFrom": [{"secretRef": {"name": "session-key"}}]
        }]}
    }))
    .unwrap();
    let lb: k8s_openapi::api::core::v1::Service = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
    }))
    .unwrap();
    let snap = Snapshot {
        pods: vec![web],
        services: vec![lb],
        secrets: vec![SecretMeta {
            namespace: "app".into(),
            name: "session-key".into(),
        }],
        image_vulns: vec![ImageVulnerabilities {
            image: "web:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2026-9999".into(),
                severity: Severity::Critical,
                exploited_in_wild: true,
                epss: None,
                sources: vec![Provenance::new("trivy", std::time::SystemTime::UNIX_EPOCH)],
                ..Default::default()
            }],
        }],
        runtime_events: vec![RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: None,
            observed_at_ms: None,
            node: None,
            behavior,
        }],
        ..Default::default()
    };
    prove(&build_graph(&snap, &default_adapters()))
}

/// End-to-end (JEF-309 + JEF-284): a drop-and-execute write on an exposed, exploitable entry
/// (a) corroborates its credential-access chain (blanket), and (b) marks the entry
/// **actively exploited** — the condition-2 quarantine now fires on a drop-and-execute, not
/// only on an alert / shell. Still shadow-gated for actuation.
#[test]
fn drop_and_execute_corroborates_and_marks_actively_exploited() {
    let chains = web_entry_with_signal(Behavior::FileWrite {
        path: "/usr/bin/dropper".into(),
    });
    let chain = chains
        .iter()
        .find(|c| c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/session-key")
        .expect("web → secret chain");
    assert!(
        chain.corroborated,
        "a drop-and-execute write corroborates the objective (blanket)"
    );
    assert_eq!(
        chain.entry_quarantine_reason(),
        Some(QuarantineReason::ActivelyExploited),
        "a drop-and-execute makes the entry actively exploited (JEF-284 condition 2)"
    );
}

/// NEGATIVE end-to-end (ADR-0011): the SAME exposed, exploitable entry with a *benign* write
/// (its own log) is neither corroborated nor actively exploited — the write is model evidence
/// only. Proves the false-positive direction is closed through the full `prove` path.
#[test]
fn benign_write_neither_corroborates_nor_quarantines() {
    let chains = web_entry_with_signal(Behavior::FileWrite {
        path: "/var/log/app.log".into(),
    });
    let chain = chains
        .iter()
        .find(|c| c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/session-key")
        .expect("web → secret chain");
    assert!(
        !chain.corroborated,
        "a benign log write must NOT corroborate the objective"
    );
    assert_eq!(
        chain.entry_quarantine_reason(),
        None,
        "a benign write must NOT mark the entry actively exploited"
    );
}
