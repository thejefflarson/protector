//! Unit tests for the behavioral wire contract. Moved out of `lib.rs`'s
//! `#[cfg(test)] mod tests` block into its own file per the repo's 1,000-line
//! file cap — `lib.rs` was approaching it. `use super::*` resolves to `lib.rs`, exactly
//! as the inline `mod tests` block did. No test content changed by the move.

use super::*;

#[test]
fn behavior_serializes_to_the_kind_tagged_contract() {
    let v = serde_json::to_value(Behavior::NetworkConnection {
        peer: "1.2.3.4:443".into(),
        internet: true,
    })
    .unwrap();
    assert_eq!(
        v,
        serde_json::json!({"kind": "network_connection", "peer": "1.2.3.4:443", "internet": true})
    );
}

#[test]
fn resolves_in_applies_the_attribution_resolution_rule() {
    // A namespace/name attribution always resolves — even when the lookup
    // would reject everything.
    assert!(Attribution::by_namespaced_name("app", "web").resolves_in(|_| false));
    // A cgroup-UID attribution (the eBPF agent) resolves iff the UID is known.
    assert!(Attribution::by_pod_uid("uid-1").resolves_in(|uid| uid == "uid-1"));
    assert!(!Attribution::by_pod_uid("uid-unknown").resolves_in(|uid| uid == "uid-1"));
}

#[test]
fn observation_roundtrips_and_omits_absent_optionals() {
    // An eBPF-agent observation: attributed by uid, source + time set.
    let obs = RuntimeObservation {
        attribution: Attribution::by_pod_uid("uid"),
        source: Some("protector-agent".into()),
        observed_at_ms: Some(1_710_000_000_000),
        node: None,
        behavior: Behavior::SecretRead {
            secret: "app/session-key".into(),
            source: SecretReadSource::Mounted,
        },
    };
    let v = serde_json::to_value(&obs).unwrap();
    assert_eq!(
        v,
        serde_json::json!({
            "pod_uid": "uid",
            "source": "protector-agent",
            "observed_at_ms": 1_710_000_000_000u64,
            "behavior": {"kind": "secret_read", "secret": "app/session-key"}
        })
    );
    assert_eq!(
        serde_json::from_value::<RuntimeObservation>(v).unwrap(),
        obs
    );
}

#[test]
fn secret_read_source_distinguishes_mounted_from_api() {
    // Mounted is the default and is OMITTED on the wire, so the eBPF agent's existing
    // `{"kind":"secret_read","secret":"..."}` contract is byte-for-byte unchanged.
    let mounted = Behavior::SecretRead {
        secret: "app/db".into(),
        source: SecretReadSource::Mounted,
    };
    assert_eq!(
        serde_json::to_value(&mounted).unwrap(),
        serde_json::json!({"kind": "secret_read", "secret": "app/db"})
    );
    // An absent `source` deserializes back to Mounted (older sensors).
    let from_legacy: Behavior =
        serde_json::from_value(serde_json::json!({"kind": "secret_read", "secret": "app/db"}))
            .unwrap();
    assert_eq!(from_legacy, mounted);

    // An API read serializes its source explicitly and round-trips.
    let api = Behavior::SecretRead {
        secret: "app/db".into(),
        source: SecretReadSource::Api,
    };
    let v = serde_json::to_value(&api).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"kind": "secret_read", "secret": "app/db", "source": "api"})
    );
    assert_eq!(serde_json::from_value::<Behavior>(v).unwrap(), api);

    // The two are distinguishable everywhere it matters: summary prose and the
    // verdict-cache fingerprint. The metric label stays the coarse shared token.
    assert_eq!(mounted.summary(), "reads secret app/db");
    assert_eq!(api.summary(), "reads secret app/db (via Kubernetes API)");
    assert_eq!(mounted.fingerprint_key(), "read:app/db");
    assert_eq!(api.fingerprint_key(), "read-api:app/db");
    assert_ne!(mounted.fingerprint_key(), api.fingerprint_key());
    assert_eq!(mounted.variant_label(), api.variant_label());
}

#[test]
fn secret_read_source_distinguishes_host_path_from_mounted_and_api() {
    // An on-host credential read serializes its source explicitly, just like
    // `Api`, and round-trips — it is a genuinely distinct runtime fact from a k8s
    // Secret-mount read even though both reach the same `Behavior::SecretRead` shape.
    let host = Behavior::SecretRead {
        secret: "/etc/shadow".into(),
        source: SecretReadSource::HostPath,
    };
    let v = serde_json::to_value(&host).unwrap();
    assert_eq!(
        v,
        serde_json::json!({
            "kind": "secret_read",
            "secret": "/etc/shadow",
            "source": "host_path"
        })
    );
    assert_eq!(serde_json::from_value::<Behavior>(v).unwrap(), host);

    // Distinguishable everywhere it matters: summary prose and the verdict-cache
    // fingerprint, distinct from BOTH other sources. The metric label stays the coarse
    // shared token across all three.
    let mounted = Behavior::SecretRead {
        secret: "/etc/shadow".into(),
        source: SecretReadSource::Mounted,
    };
    assert_eq!(
        host.summary(),
        "reads secret /etc/shadow (on-host filesystem)"
    );
    assert_eq!(host.fingerprint_key(), "read-host:/etc/shadow");
    assert_ne!(host.fingerprint_key(), mounted.fingerprint_key());
    assert_eq!(host.variant_label(), mounted.variant_label());
}

#[test]
fn namespaced_observation_deserializes_from_namespace_pod() {
    // A metadata-attributed observation: ns/pod set, no uid/source/time.
    let obs: RuntimeObservation = serde_json::from_value(serde_json::json!({
        "namespace": "app", "pod": "web",
        "behavior": {"kind": "alert", "rule": "Terminal shell in container"}
    }))
    .unwrap();
    assert_eq!(
        obs.attribution,
        Attribution::by_namespaced_name("app", "web")
    );
    assert!(obs.behavior.is_alert());
}

#[test]
fn process_exec_fingerprint_coarsens_to_basename() {
    // Different absolute paths to the same binary must collapse to one stable key so
    // exec churn doesn't bust the verdict cache (mirrors LibraryLoaded's basename key).
    let a = Behavior::ProcessExec {
        path: "/usr/bin/bash".into(),
        exe_anon_inode: false,
    };
    let b = Behavior::ProcessExec {
        path: "/bin/bash".into(),
        exe_anon_inode: false,
    };
    assert_eq!(a.fingerprint_key(), "exec:bash");
    assert_eq!(a.fingerprint_key(), b.fingerprint_key());
    // The wire type's summary is the bare path; *classification* of a notable exec
    // (shell / package manager) is engine policy (engine::observe::exec_class),
    // so it's not annotated here.
    assert_eq!(a.summary(), "executed /usr/bin/bash");
}

#[test]
fn process_exec_summary_is_the_bare_path() {
    // The shared wire type emits only the path — engine policy decides if it's notable
    // (a shell / package manager) and annotates the prompt/output line.
    let shell = Behavior::ProcessExec {
        path: "/bin/bash".into(),
        exe_anon_inode: false,
    };
    let normal = Behavior::ProcessExec {
        path: "/app/server".into(),
        exe_anon_inode: false,
    };
    assert_eq!(shell.summary(), "executed /bin/bash");
    assert_eq!(normal.summary(), "executed /app/server");
    // Classification is engine evidence, NOT action-bar corroboration — only Alerts
    // corroborate from the wire type's perspective.
    assert!(!shell.is_alert());
}

#[test]
fn exe_anon_inode_is_a_raw_fact_distinct_from_path_shape_classification() {
    //  (Route A): `exe_anon_inode` is a kernel-observed inode fact, independent
    // of the path — a `/bin/bash`-looking exec can still be anon-inode-backed (the
    // path is whatever `bprm->filename` resolved to; the flag is a separate read).
    let anon = Behavior::ProcessExec {
        path: "/bin/bash".into(),
        exe_anon_inode: true,
    };
    let normal = Behavior::ProcessExec {
        path: "/bin/bash".into(),
        exe_anon_inode: false,
    };
    // The bare summary carries the raw fact (a kernel-computed bool, not a curated
    // classification — unlike shell/package-manager it is NOT engine-annotated).
    assert_eq!(
        anon.summary(),
        "executed /bin/bash (anonymous-inode: memfd/unlinked backing, no on-disk file)"
    );
    assert_eq!(normal.summary(), "executed /bin/bash");
    // The verdict-cache fingerprint distinguishes the two — a genuinely different fact
    // about the same-named binary must not collapse into one cache entry.
    assert_ne!(anon.fingerprint_key(), normal.fingerprint_key());
    assert_eq!(anon.fingerprint_key(), "exec:bash:anon-inode");
    assert_eq!(normal.fingerprint_key(), "exec:bash");
    // Neither is an Alert-style blanket corroboration source from the wire type's own
    // view — only Alerts corroborate here; scoped corroboration is engine policy.
    assert!(!anon.is_alert());
}

#[test]
fn exe_anon_inode_serializes_only_when_true() {
    // the common (non-anonymous) exec omits the field entirely, keeping the
    // JSON byte-identical to before this field existed (mirrors SecretReadSource's
    // `Mounted`-is-omitted convention). A `true` flag serializes explicitly and both
    // round-trip; an older sensor's JSON with the field absent defaults to `false`.
    let normal = Behavior::ProcessExec {
        path: "/bin/bash".into(),
        exe_anon_inode: false,
    };
    let v = serde_json::to_value(&normal).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"kind": "process_exec", "path": "/bin/bash"})
    );
    assert_eq!(serde_json::from_value::<Behavior>(v).unwrap(), normal);

    let anon = Behavior::ProcessExec {
        path: "/bin/bash".into(),
        exe_anon_inode: true,
    };
    let v = serde_json::to_value(&anon).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"kind": "process_exec", "path": "/bin/bash", "exe_anon_inode": true})
    );
    assert_eq!(serde_json::from_value::<Behavior>(v).unwrap(), anon);

    // A legacy `process_exec` with no `exe_anon_inode` key deserializes to `false`.
    let legacy: Behavior =
        serde_json::from_value(serde_json::json!({"kind": "process_exec", "path": "/bin/bash"}))
            .unwrap();
    assert_eq!(legacy, normal);
}

#[test]
fn variant_label_is_a_stable_low_cardinality_token() {
    // Each variant maps to a fixed token carrying NO per-instance payload (no peer,
    // path, or secret name) — so it's safe as a metric label without cardinality blow-up.
    let cases: [(Behavior, &str); 9] = [
        (Behavior::Alert { rule: "x".into() }, "alert"),
        (
            Behavior::NetworkConnection {
                peer: "1.2.3.4:443".into(),
                internet: true,
            },
            "connection",
        ),
        (
            Behavior::SecretRead {
                secret: "s".into(),
                source: SecretReadSource::Mounted,
            },
            "secret-read",
        ),
        (Behavior::LibraryLoaded { name: "l".into() }, "library-load"),
        (Behavior::FileRead { path: "/p".into() }, "file-read"),
        (
            Behavior::PrivilegeChange {
                from_uid: 1000,
                to_uid: 0,
            },
            "priv-change",
        ),
        (
            Behavior::ProcessExec {
                path: "/bin/bash".into(),
                exe_anon_inode: false,
            },
            "exec",
        ),
        (
            Behavior::FileWrite {
                path: "/etc/cron.d/x".into(),
            },
            "file-write",
        ),
        (
            Behavior::ImageLinkage {
                static_linkage: true,
            },
            "image-linkage",
        ),
    ];
    for (behavior, want) in cases {
        assert_eq!(behavior.variant_label(), want, "{behavior:?}");
    }
}

#[test]
fn file_write_fingerprint_coarsens_to_the_dirname() {
    // Per-file write churn within a directory must collapse to one stable key so a
    // burst of writes (drop-and-execute, a config dir rewritten file-by-file) doesn't
    // bust the verdict cache — the write signal is high-frequency.
    let a = Behavior::FileWrite {
        path: "/etc/cron.d/dropper".into(),
    };
    let b = Behavior::FileWrite {
        path: "/etc/cron.d/other".into(),
    };
    assert_eq!(a.fingerprint_key(), "write:/etc/cron.d");
    assert_eq!(a.fingerprint_key(), b.fingerprint_key());
    // A top-level path and a bare filename coarsen to `/` (low cardinality, never panics).
    assert_eq!(
        Behavior::FileWrite {
            path: "/passwd".into()
        }
        .fingerprint_key(),
        "write:/"
    );
    assert_eq!(
        Behavior::FileWrite {
            path: "relative".into()
        }
        .fingerprint_key(),
        "write:/"
    );
}

#[test]
fn file_write_summary_is_the_bare_path_and_never_corroborates() {
    // The shared wire type emits only the path — whether the write is *sensitive*
    // (container drift / config tampering) is engine corroboration policy (F3),
    // so it's pure data here and, like other mundane behaviors, never an alert.
    let w = Behavior::FileWrite {
        path: "/etc/ssh/sshd_config".into(),
    };
    assert_eq!(w.summary(), "wrote file /etc/ssh/sshd_config");
    assert!(!w.is_alert());
}

#[test]
fn file_write_serializes_to_the_kind_tagged_contract() {
    // Pure-data wire shape: `{"kind":"file_write","path":"..."}`, round-trips.
    let w = Behavior::FileWrite {
        path: "/etc/cron.d/x".into(),
    };
    let v = serde_json::to_value(&w).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"kind": "file_write", "path": "/etc/cron.d/x"})
    );
    assert_eq!(serde_json::from_value::<Behavior>(v).unwrap(), w);
}

#[test]
fn observation_carries_the_node_and_omits_it_when_absent() {
    // the agent stamps its node so coverage is derivable PER NODE. When present it
    // rides the wire; when absent (a node-agnostic sensor, older agents) it is omitted — never guessed.
    let with_node = RuntimeObservation {
        attribution: Attribution::by_pod_uid("uid"),
        source: Some("protector-agent".into()),
        observed_at_ms: None,
        node: Some("node-a".into()),
        behavior: Behavior::ProcessExec {
            path: "/bin/sh".into(),
            exe_anon_inode: false,
        },
    };
    let v = serde_json::to_value(&with_node).unwrap();
    assert_eq!(v["node"], serde_json::json!("node-a"));
    assert_eq!(
        serde_json::from_value::<RuntimeObservation>(v).unwrap(),
        with_node
    );

    // Absent node ⇒ the key is omitted (byte-stable for node-agnostic sensors), and a legacy
    // observation with no `node` deserializes back to `None`.
    let no_node: RuntimeObservation = serde_json::from_value(serde_json::json!({
        "namespace": "app", "pod": "web",
        "behavior": {"kind": "alert", "rule": "shell"}
    }))
    .unwrap();
    assert_eq!(no_node.node, None);
    let reser = serde_json::to_value(&no_node).unwrap();
    assert!(
        reser.get("node").is_none(),
        "absent node is omitted on the wire"
    );
}

#[test]
fn agent_report_round_trips_and_classifies_blind_vs_partial() {
    // A healthy report: all probes loaded, some signals — round-trips.
    let healthy = AgentReport {
        node: "node-a".into(),
        probes_loaded: 6,
        probes_total: 6,
        signals_emitted: 12,
        observed_at_ms: Some(1_710_000_000_000),
    };
    let v = serde_json::to_value(&healthy).unwrap();
    assert_eq!(serde_json::from_value::<AgentReport>(v).unwrap(), healthy);
    assert!(!healthy.is_blind());
    assert!(!healthy.is_partial());

    // Quiet but healthy: probes loaded, zero signals — NOT blind, NOT partial (quiet≠blind).
    let quiet = AgentReport {
        signals_emitted: 0,
        ..healthy.clone()
    };
    assert!(
        !quiet.is_blind(),
        "a quiet node with probes loaded is not blind"
    );
    assert!(!quiet.is_partial());

    // Ready but blind: the agent is up but no probe attached — blind despite pod-Ready.
    let blind = AgentReport {
        probes_loaded: 0,
        ..healthy.clone()
    };
    assert!(blind.is_blind());
    assert!(
        !blind.is_partial(),
        "zero probes reads as blind, not partial"
    );

    // Partial: some but not all probes attached — degraded coverage.
    let partial = AgentReport {
        probes_loaded: 4,
        ..healthy
    };
    assert!(!partial.is_blind());
    assert!(partial.is_partial());
}

#[test]
fn agent_report_observed_at_ms_is_omitted_when_absent() {
    let report = AgentReport {
        node: "n".into(),
        probes_loaded: 1,
        probes_total: 1,
        signals_emitted: 0,
        observed_at_ms: None,
    };
    let v = serde_json::to_value(&report).unwrap();
    assert!(v.get("observed_at_ms").is_none());
    assert_eq!(serde_json::from_value::<AgentReport>(v).unwrap(), report);
}

#[test]
fn runtime_report_round_trips_with_observations_and_liveness() {
    // the unified envelope carries the window's observations AND the per-node
    // liveness beacon in one shape, and round-trips byte-for-byte.
    let report = RuntimeReport {
        observations: vec![RuntimeObservation {
            attribution: Attribution::by_pod_uid("uid"),
            source: Some("protector-agent".into()),
            observed_at_ms: None,
            node: Some("node-a".into()),
            behavior: Behavior::Alert {
                rule: "Terminal shell in container".into(),
            },
        }],
        liveness: Some(AgentReport {
            node: "node-a".into(),
            probes_loaded: 6,
            probes_total: 6,
            signals_emitted: 1,
            observed_at_ms: None,
        }),
    };
    let v = serde_json::to_value(&report).unwrap();
    assert!(v.get("observations").is_some());
    assert_eq!(v["liveness"]["node"], serde_json::json!("node-a"));
    assert_eq!(serde_json::from_value::<RuntimeReport>(v).unwrap(), report);
}

#[test]
fn runtime_report_omits_empty_observations_and_absent_liveness() {
    // A quiet node's envelope: no observations, liveness present — `observations` is omitted
    // (skip_serializing_if empty) so the wire is just `{"liveness":{...}}`.
    let quiet = RuntimeReport {
        observations: Vec::new(),
        liveness: Some(AgentReport {
            node: "node-a".into(),
            probes_loaded: 6,
            probes_total: 6,
            signals_emitted: 0,
            observed_at_ms: None,
        }),
    };
    let v = serde_json::to_value(&quiet).unwrap();
    assert!(
        v.get("observations").is_none(),
        "empty observations omitted from the wire"
    );
    assert!(v.get("liveness").is_some());
    assert_eq!(serde_json::from_value::<RuntimeReport>(v).unwrap(), quiet);

    // A third-party observations-only envelope: liveness absent → `liveness` omitted, and it
    // deserializes back with `liveness: None` (the ADR-0003 tool-agnostic path).
    let obs_only = RuntimeReport {
        observations: vec![RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: None,
            observed_at_ms: None,
            node: None,
            behavior: Behavior::LibraryLoaded {
                name: "openssl".into(),
            },
        }],
        liveness: None,
    };
    let v = serde_json::to_value(&obs_only).unwrap();
    assert!(
        v.get("liveness").is_none(),
        "absent liveness omitted from the wire"
    );
    assert_eq!(
        serde_json::from_value::<RuntimeReport>(v).unwrap(),
        obs_only
    );
}

#[test]
fn image_linkage_serializes_to_the_kind_tagged_contract_and_round_trips() {
    // the linkage signal rides the same `{"kind": "...", ...}` behavioral wire.
    // A static-linkage report and a dynamic one both round-trip byte-for-byte.
    let stat = Behavior::ImageLinkage {
        static_linkage: true,
    };
    let v = serde_json::to_value(&stat).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"kind": "image_linkage", "static_linkage": true})
    );
    assert_eq!(serde_json::from_value::<Behavior>(v).unwrap(), stat);

    let dynm = Behavior::ImageLinkage {
        static_linkage: false,
    };
    let v = serde_json::to_value(&dynm).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"kind": "image_linkage", "static_linkage": false})
    );
    assert_eq!(serde_json::from_value::<Behavior>(v).unwrap(), dynm);
}

#[test]
fn image_linkage_is_context_not_corroboration() {
    // A structural fact about the image, never an "attack is happening now" signal —
    // only Alerts corroborate the action bar (else linkage would fire it, which is wrong).
    assert!(
        !Behavior::ImageLinkage {
            static_linkage: true
        }
        .is_alert()
    );
    // Distinct summaries and fingerprints for the two linkage states.
    assert_eq!(
        Behavior::ImageLinkage {
            static_linkage: true
        }
        .summary(),
        "entrypoint is a statically linked binary"
    );
    assert_eq!(
        Behavior::ImageLinkage {
            static_linkage: false
        }
        .summary(),
        "entrypoint is a dynamically linked binary"
    );
    assert_ne!(
        Behavior::ImageLinkage {
            static_linkage: true
        }
        .fingerprint_key(),
        Behavior::ImageLinkage {
            static_linkage: false
        }
        .fingerprint_key()
    );
}

#[test]
fn image_linkage_observation_round_trips_over_the_wire() {
    // The full RuntimeObservation the agent POSTs for a static entrypoint — attributed by
    // pod UID (the eBPF agent's path), source + node stamped — round-trips.
    let obs = RuntimeObservation {
        attribution: Attribution::by_pod_uid("uid"),
        source: Some("protector-agent".into()),
        observed_at_ms: None,
        node: Some("node-a".into()),
        behavior: Behavior::ImageLinkage {
            static_linkage: true,
        },
    };
    let v = serde_json::to_value(&obs).unwrap();
    assert_eq!(
        v["behavior"],
        serde_json::json!({"kind": "image_linkage", "static_linkage": true})
    );
    assert_eq!(
        serde_json::from_value::<RuntimeObservation>(v).unwrap(),
        obs
    );
}

#[test]
fn only_alert_corroborates() {
    assert!(Behavior::Alert { rule: "x".into() }.is_alert());
    assert!(
        !Behavior::NetworkConnection {
            peer: "p".into(),
            internet: true
        }
        .is_alert()
    );
}
