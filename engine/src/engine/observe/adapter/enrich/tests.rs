use super::*;
use serde_json::json;

fn pod(value: serde_json::Value) -> k8s_openapi::api::core::v1::Pod {
    serde_json::from_value(value).expect("valid Pod fixture")
}

/// A pod that mounts Secret `db-creds` at /etc/creds and ConfigMap `cfg` at /etc/cfg.
fn fixture() -> k8s_openapi::api::core::v1::Pod {
    pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app"},
        "spec": {
            "containers": [{
                "name": "web", "image": "web:1",
                "volumeMounts": [
                    {"name": "creds", "mountPath": "/etc/creds", "readOnly": true},
                    {"name": "cfg", "mountPath": "/etc/cfg"}
                ]
            }],
            "volumes": [
                {"name": "creds", "secret": {"secretName": "db-creds"}},
                {"name": "cfg", "configMap": {"name": "cfg"}}
            ]
        }
    }))
}

#[test]
fn secret_read_under_a_secret_mount_is_named() {
    let p = fixture();
    assert_eq!(
        secret_for_path(&p, "/etc/creds/password"),
        Some("db-creds/password".into())
    );
    // The mount path itself (no sub-key) → just the secret name.
    assert_eq!(secret_for_path(&p, "/etc/creds"), Some("db-creds".into()));
}

#[test]
fn non_secret_tmpfs_reads_are_dropped() {
    let p = fixture();
    // ConfigMap mount — tmpfs, but not a Secret.
    assert_eq!(secret_for_path(&p, "/etc/cfg/app.conf"), None);
    // Unrelated tmpfs read (/tmp), and a path that only prefixes a mount.
    assert_eq!(secret_for_path(&p, "/tmp/scratch"), None);
    assert_eq!(secret_for_path(&p, "/etc/credentials/x"), None);
}

#[test]
fn longest_mount_path_wins_for_nested_secret_mounts() {
    let p = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app"},
        "spec": {
            "containers": [{
                "name": "web", "image": "web:1",
                "volumeMounts": [
                    {"name": "outer", "mountPath": "/etc"},
                    {"name": "inner", "mountPath": "/etc/creds"}
                ]
            }],
            "volumes": [
                {"name": "outer", "secret": {"secretName": "outer-sec"}},
                {"name": "inner", "secret": {"secretName": "inner-sec"}}
            ]
        }
    }));
    assert_eq!(
        secret_for_path(&p, "/etc/creds/key"),
        Some("inner-sec/key".into())
    );
}

#[test]
fn secret_read_under_a_projected_secret_source_is_named() {
    // A projected volume mounting a secret source (plus a non-secret SA-token source)
    // at /var/run/secrets/proj. Reads under it map to the secret; the SA token does
    // not contribute a name.
    let p = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app"},
        "spec": {
            "containers": [{
                "name": "web", "image": "web:1",
                "volumeMounts": [
                    {"name": "proj", "mountPath": "/var/run/secrets/proj", "readOnly": true}
                ]
            }],
            "volumes": [{
                "name": "proj",
                "projected": {
                    "sources": [
                        {"serviceAccountToken": {"path": "token"}},
                        {"secret": {"name": "proj-sec"}}
                    ]
                }
            }]
        }
    }));
    assert_eq!(
        secret_for_path(&p, "/var/run/secrets/proj/api-key"),
        Some("proj-sec/api-key".into())
    );
    // The mount path itself (no sub-key) → just the secret name.
    assert_eq!(
        secret_for_path(&p, "/var/run/secrets/proj"),
        Some("proj-sec".into())
    );
}

#[test]
fn projected_volume_without_a_secret_source_is_not_a_secret() {
    // A projected volume whose only sources are a configMap and an SA token — no
    // secret source, so reads under it must NOT be classified as a SecretRead.
    let p = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app"},
        "spec": {
            "containers": [{
                "name": "web", "image": "web:1",
                "volumeMounts": [
                    {"name": "proj", "mountPath": "/var/run/proj", "readOnly": true}
                ]
            }],
            "volumes": [{
                "name": "proj",
                "projected": {
                    "sources": [
                        {"configMap": {"name": "cfg"}},
                        {"serviceAccountToken": {"path": "token"}}
                    ]
                }
            }]
        }
    }));
    assert_eq!(secret_for_path(&p, "/var/run/proj/ca.crt"), None);
    assert_eq!(secret_for_path(&p, "/var/run/proj/token"), None);
}

// --- JEF-51: the library-name matcher ---------------------------------------

#[test]
fn library_matcher_table() {
    // (loaded library as the agent sees it, scanner pkg_name, should_match)
    let cases = [
        // The issue's two canonical fuzzy cases.
        ("log4j-core-2.14.jar", "log4j-core", true),
        ("libssl.so.3", "openssl", true),
        ("libssl.so.3", "libssl", true),
        ("libssl.so.3", "ssl", true),
        // Plain names, prefixes, paths, case.
        ("libcrypto.so.3", "libcrypto", true),
        ("/usr/lib/x86_64-linux-gnu/libssl.so.1.1", "openssl", true),
        ("LibSSL.so", "openssl", true),
        ("zlib1g", "zlib1g", true),
        // Negatives — the critical false-positive guards.
        ("libc.so.6", "openssl", false),
        ("libc.so.6", "libc", true),
        ("libc.so.6", "glibc", false),
        ("libssl.so.3", "libcrypto", false),
        ("log4j-core-2.14.jar", "log4j-api", false),
        ("libpng.so", "libjpeg", false),
        // Substring containment must NOT match (precision over recall).
        ("libsslextra.so", "openssl", false),
    ];
    for (loaded, pkg, want) in cases {
        assert_eq!(
            library_matches(loaded, pkg),
            want,
            "library_matches({loaded:?}, {pkg:?}) should be {want}"
        );
    }
}

// --- JEF-51: the end-to-end correlation pass --------------------------------

use crate::engine::graph::Vulnerability;
use crate::engine::observe::{ImageVulnerabilities, RuntimeObservation, Snapshot};

/// Build a graph for an image carrying a single CVE on `pkg`, run by a workload
/// that optionally loaded `loaded_lib` at runtime, and return that CVE's
/// reachability after the full adapter pipeline (incl. CveReachabilityAdapter).
fn reachability_for(pkg: &str, loaded_lib: Option<&str>) -> Reachability {
    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{"name": "web", "image": "web:1"}]}
    }));
    let runtime_events = loaded_lib
        .map(|name| {
            vec![RuntimeObservation {
                attribution: Attribution::by_namespaced_name("app", "web"),
                source: None,
                observed_at_ms: None,
                node: None,
                behavior: Behavior::LibraryLoaded { name: name.into() },
            }]
        })
        .unwrap_or_default();
    let snap = Snapshot {
        pods: vec![web],
        image_vulns: vec![ImageVulnerabilities {
            image: "web:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2021-44228".into(),
                severity: crate::engine::graph::Severity::Critical,
                pkg_name: Some(pkg.into()),
                ..Default::default()
            }],
        }],
        runtime_events,
        ..Default::default()
    };
    let graph = super::super::build_graph(&snap, &super::super::default_adapters());
    let img_key = NodeKey::image(&canonical_image("web:1"));
    let idx = graph.index_of(&img_key).expect("image node exists");
    match graph.node(idx) {
        Some(Node::Image(img)) => img.vulnerabilities[0].reachability,
        _ => panic!("expected image node"),
    }
}

#[test]
fn loaded_matching_library_is_loaded_at_runtime() {
    // log4j-core CVE + a workload that loaded log4j-core-2.14.jar → LoadedAtRuntime.
    assert_eq!(
        reachability_for("log4j-core", Some("log4j-core-2.14.jar")),
        Reachability::LoadedAtRuntime
    );
}

/// As [`reachability_for`], but the image's main binary is statically linked (JEF-404).
/// Builds the graph (structural adapters set `static_binary: None`), flips the Image's
/// `static_binary` flag on, then re-runs ONLY the [`CveReachabilityAdapter`] so the static
/// case is exercised through the real correlation code, not a reimplementation.
fn reachability_for_static(pkg: &str, loaded_lib: Option<&str>) -> Reachability {
    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{"name": "web", "image": "web:1"}]}
    }));
    let runtime_events = loaded_lib.map(|name| vec![lib(name)]).unwrap_or_default();
    let snap = Snapshot {
        pods: vec![web],
        image_vulns: vec![ImageVulnerabilities {
            image: "web:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2021-44228".into(),
                severity: crate::engine::graph::Severity::Critical,
                pkg_name: Some(pkg.into()),
                ..Default::default()
            }],
        }],
        runtime_events,
        ..Default::default()
    };
    let mut graph = super::super::build_graph(&snap, &super::super::default_adapters());
    let img_key = NodeKey::image(&canonical_image("web:1"));
    // Mark the image's main binary statically linked — the signal an ELF classification
    // (engine::observe::elf) would carry — then re-run the reachability correlation.
    graph.update_node(&img_key, |node| {
        if let Node::Image(img) = node {
            img.static_binary = Some(true);
        }
    });
    CveReachabilityAdapter.contribute(&snap, &mut graph);
    let idx = graph.index_of(&img_key).expect("image node exists");
    match graph.node(idx) {
        Some(Node::Image(img)) => img.vulnerabilities[0].reachability,
        _ => panic!("expected image node"),
    }
}

#[test]
fn static_binary_cve_without_a_load_is_present_static_binary_not_not_observed() {
    // JEF-404: a Go / musl-static image whose vulnerable package can never emit a per-`.so`
    // load must NOT read as observed-absent — it is indeterminate (PresentStaticBinary).
    assert_eq!(
        reachability_for_static("openssl", None),
        Reachability::PresentStaticBinary
    );
    // And the SAME image if it were dynamically linked stays NotObserved — the two cases
    // classify differently, which is the whole point of the new state.
    assert_eq!(reachability_for("openssl", None), Reachability::NotObserved);
}

#[test]
fn static_binary_still_yields_loaded_at_runtime_on_a_real_load() {
    // Some static binaries dlopen a plugin: an actual matching load still wins over the
    // static-indeterminate tag — real exploitation evidence is never downgraded (JEF-405).
    assert_eq!(
        reachability_for_static("log4j-core", Some("log4j-core-2.14.jar")),
        Reachability::LoadedAtRuntime
    );
}

/// JEF-407 end-to-end: build the graph for an image carrying a critical CVE on `pkg`, run
/// by pod app/web, where the AGENT reported the entrypoint's linkage over the behavioral
/// wire (an `ImageLinkage` observation, `static_linkage`) — no manual `static_binary` flip.
/// The full pipeline runs: the RuntimeAdapter maps the linkage report onto `Image::static_binary`,
/// then the CveReachabilityAdapter reads it. Returns the CVE's resulting reachability, so a
/// static report → `PresentStaticBinary` while a dynamic report → `NotObserved`, activating the
/// dormant JEF-404 machinery from a real prod-shaped signal source.
fn reachability_via_agent_linkage(
    pkg: &str,
    static_linkage: bool,
    loaded_lib: Option<&str>,
) -> Reachability {
    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{"name": "web", "image": "web:1"}]}
    }));
    let mut runtime_events = vec![RuntimeObservation {
        attribution: Attribution::by_namespaced_name("app", "web"),
        source: Some("protector-agent".into()),
        observed_at_ms: None,
        node: Some("node-a".into()),
        behavior: Behavior::ImageLinkage { static_linkage },
    }];
    runtime_events.extend(loaded_lib.map(lib));
    let snap = Snapshot {
        pods: vec![web],
        image_vulns: vec![ImageVulnerabilities {
            image: "web:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2021-44228".into(),
                severity: crate::engine::graph::Severity::Critical,
                pkg_name: Some(pkg.into()),
                ..Default::default()
            }],
        }],
        runtime_events,
        ..Default::default()
    };
    let graph = super::super::build_graph(&snap, &super::super::default_adapters());
    let img_key = NodeKey::image(&canonical_image("web:1"));
    let idx = graph.index_of(&img_key).expect("image node exists");
    match graph.node(idx) {
        Some(Node::Image(img)) => {
            // The linkage report must have landed on the Image — this is the plumbing JEF-407
            // adds. A static report sets Some(true); a dynamic one Some(false).
            assert_eq!(
                img.static_binary,
                Some(static_linkage),
                "the agent's ImageLinkage report should populate Image::static_binary"
            );
            img.vulnerabilities[0].reachability
        }
        _ => panic!("expected image node"),
    }
}

#[test]
fn agent_static_linkage_report_activates_present_static_binary() {
    // JEF-407: a static-linkage report from the agent (the prod byte source) makes a
    // would-be `not-observed` critical CVE render `present-static-binary` — the JEF-404
    // feature that was dormant because Image::static_binary was always None in prod.
    assert_eq!(
        reachability_via_agent_linkage("openssl", true, None),
        Reachability::PresentStaticBinary
    );
}

#[test]
fn agent_dynamic_linkage_report_keeps_not_observed() {
    // A dynamic-linkage report is honestly observed-absent: a dynamically linked workload
    // WOULD have emitted a `.so` load if the vulnerable code ran, so no load → NotObserved.
    assert_eq!(
        reachability_via_agent_linkage("openssl", false, None),
        Reachability::NotObserved
    );
}

#[test]
fn agent_linkage_report_never_downgrades_a_real_load() {
    // Even on a static-linkage report, an actual matching library load still wins — real
    // exploitation evidence (LoadedAtRuntime) is never downgraded (JEF-405).
    assert_eq!(
        reachability_via_agent_linkage("log4j-core", true, Some("log4j-core-2.14.jar")),
        Reachability::LoadedAtRuntime
    );
}

#[test]
fn image_linkage_report_is_not_pushed_onto_workload_runtime() {
    // The linkage signal is a structural per-image fact, not runtime prompt evidence — it
    // must be diverted to Image::static_binary and NEVER land on the workload's `runtime`
    // (it would otherwise pollute the adjudication prompt and the corroboration path).
    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{"name": "web", "image": "web:1"}]}
    }));
    let snap = Snapshot {
        pods: vec![web],
        runtime_events: vec![RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: Some("protector-agent".into()),
            observed_at_ms: None,
            node: None,
            behavior: Behavior::ImageLinkage {
                static_linkage: true,
            },
        }],
        ..Default::default()
    };
    let graph = super::super::build_graph(&snap, &super::super::default_adapters());
    let wl_key = NodeKey::workload("app", "Pod", "web");
    let idx = graph.index_of(&wl_key).expect("workload node exists");
    match graph.node(idx) {
        Some(Node::Workload(w)) => assert!(
            w.runtime
                .iter()
                .all(|s| !matches!(s.behavior, Behavior::ImageLinkage { .. })),
            "ImageLinkage must not land on workload runtime — it is diverted to the Image"
        ),
        _ => panic!("expected workload node"),
    }
}

/// A `LibraryLoaded` observation on pod app/web (the fixture these tests use).
fn lib(name: &str) -> RuntimeObservation {
    RuntimeObservation {
        attribution: Attribution::by_namespaced_name("app", "web"),
        source: None,
        observed_at_ms: None,
        node: None,
        behavior: Behavior::LibraryLoaded { name: name.into() },
    }
}

/// The `LibraryLoaded` names surviving on the (single) workload after the full
/// adapter pipeline — i.e. what's left after the JEF-75 prune.
fn surviving_libs(snap: Snapshot) -> Vec<String> {
    let graph = super::super::build_graph(&snap, &super::super::default_adapters());
    graph
        .inner()
        .node_weights()
        .find_map(|n| match n {
            Node::Workload(w) => Some(
                w.runtime
                    .iter()
                    .filter_map(|o| match &o.behavior {
                        Behavior::LibraryLoaded { name } => Some(name.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .expect("workload node exists")
}

#[test]
fn non_cve_library_loads_are_pruned_from_runtime() {
    // libssl matches the openssl CVE; libpthread matches nothing → only the
    // vulnerable-library load survives, so the noise never reaches the prompt or the
    // verdict fingerprint (JEF-75).
    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{"name": "web", "image": "web:1"}]}
    }));
    let snap = Snapshot {
        pods: vec![web],
        image_vulns: vec![ImageVulnerabilities {
            image: "web:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2022-0001".into(),
                severity: crate::engine::graph::Severity::Critical,
                pkg_name: Some("openssl".into()),
                ..Default::default()
            }],
        }],
        runtime_events: vec![lib("libssl.so.3"), lib("libpthread.so.0")],
        ..Default::default()
    };
    assert_eq!(surviving_libs(snap), vec!["libssl.so.3".to_string()]);
}

#[test]
fn library_load_matching_any_of_a_workloads_images_survives() {
    // Multi-image workload (app + sidecar): a load matching the SECOND image's CVE
    // must survive even though the first image carries a different CVE — proving the
    // prune unions CVE packages across ALL RunsImage edges before deciding (the
    // false-drop path that would silently weaken reachability).
    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [
            {"name": "web", "image": "web:1"},
            {"name": "sidecar", "image": "sidecar:1"}
        ]}
    }));
    let cve = |id: &str, pkg: &str| Vulnerability {
        id: id.into(),
        severity: crate::engine::graph::Severity::Critical,
        pkg_name: Some(pkg.into()),
        ..Default::default()
    };
    let snap = Snapshot {
        pods: vec![web],
        image_vulns: vec![
            ImageVulnerabilities {
                image: "web:1".into(),
                vulnerabilities: vec![cve("CVE-A", "openssl")],
            },
            ImageVulnerabilities {
                image: "sidecar:1".into(),
                vulnerabilities: vec![cve("CVE-B", "log4j-core")],
            },
        ],
        runtime_events: vec![
            lib("libssl.so.3"),
            lib("log4j-core-2.14.jar"),
            lib("libpthread.so.0"),
        ],
        ..Default::default()
    };
    let mut got = surviving_libs(snap);
    got.sort();
    assert_eq!(
        got,
        vec!["libssl.so.3".to_string(), "log4j-core-2.14.jar".to_string()],
        "loads matching EITHER image's CVE survive; the unrelated load is pruned"
    );
}

#[test]
fn workload_with_no_cve_packages_drops_all_loads() {
    // A CVE with no pkg_name can't be correlated → no load can match → all pruned
    // (the `pkgs.is_none()` branch of the prune).
    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{"name": "web", "image": "web:1"}]}
    }));
    let snap = Snapshot {
        pods: vec![web],
        image_vulns: vec![ImageVulnerabilities {
            image: "web:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2022-0002".into(),
                severity: crate::engine::graph::Severity::Critical,
                pkg_name: None,
                ..Default::default()
            }],
        }],
        runtime_events: vec![lib("libssl.so.3")],
        ..Default::default()
    };
    assert!(
        surviving_libs(snap).is_empty(),
        "no correlatable CVE package → every library load pruned"
    );
}

#[test]
fn no_load_is_not_observed() {
    // The image is scanned but nothing loaded → NotObserved (distinct from Unknown).
    assert_eq!(
        reachability_for("log4j-core", None),
        Reachability::NotObserved
    );
}

#[test]
fn wrong_library_is_not_observed() {
    // A loaded but UNRELATED library must not mark an openssl CVE as reachable.
    assert_eq!(
        reachability_for("openssl", Some("libc.so.6")),
        Reachability::NotObserved
    );
}

/// The `NetworkConnection` behaviors attached to the (single) workload in `graph` —
/// i.e. the peer strings as `Behavior::summary()` (the prompt + dashboard) render them.
fn peers_of(graph: &crate::engine::graph::SecurityGraph) -> Vec<(String, bool)> {
    graph
        .inner()
        .node_weights()
        .find_map(|n| match n {
            Node::Workload(w) => Some(
                w.runtime
                    .iter()
                    .filter_map(|o| match &o.behavior {
                        Behavior::NetworkConnection { peer, internet } => {
                            Some((peer.clone(), *internet))
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .expect("workload node exists")
}

/// As [`peers_of`], but running the full pipeline once over `snap`.
fn connection_peers(snap: Snapshot) -> Vec<(String, bool)> {
    peers_of(&super::super::build_graph(
        &snap,
        &super::super::default_adapters(),
    ))
}

/// An `app/web` workload pod and an `analytics/influxdb-0` peer pod at 10.42.1.159 —
/// the fixtures for the peer-resolution tests.
fn web_pod() -> Pod {
    pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{"name": "web", "image": "web:1"}]}
    }))
}

fn influx_pod() -> Pod {
    pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "influxdb-0", "namespace": "analytics"},
        "spec": {"containers": [{"name": "influxdb", "image": "influxdb:2"}]},
        "status": {"podIP": "10.42.1.159"}
    }))
}

/// A connection from `app/web` to the given peer.
fn web_conn(peer: &str, internet: bool) -> RuntimeObservation {
    RuntimeObservation {
        attribution: Attribution::by_namespaced_name("app", "web"),
        source: None,
        observed_at_ms: None,
        node: None,
        behavior: Behavior::NetworkConnection {
            peer: peer.into(),
            internet,
        },
    }
}

#[test]
fn runtime_adapter_keeps_a_cluster_peer_stable_across_a_transient_informer_miss() {
    // JEF-375: the SAME cluster peer must render the SAME token on two consecutive
    // passes even when the informer index transiently MISSES the peer pod on the
    // second pass. Without the memo it would flip
    //   analytics/influxdb-0:8086 (10.42.1.159)  ->  10.42.1.159:8086
    // churning the adjudicator prompt hash into a spurious verdict-cache re-judge.
    //
    // The adapter set is built ONCE and reused across both passes, so RuntimeAdapter's
    // peer memo persists exactly as it does in the live engine (`self.adapters`).
    let adapters = super::super::default_adapters();
    let resolved = ("analytics/influxdb-0:8086 (10.42.1.159)".to_string(), false);

    // Pass 1: the peer pod is present → resolves to its name (and is memoized).
    let snap1 = Snapshot {
        pods: vec![web_pod(), influx_pod()],
        runtime_events: vec![web_conn("10.42.1.159:8086", false)],
        ..Default::default()
    };
    let g1 = super::super::build_graph(&snap1, &adapters);
    assert_eq!(peers_of(&g1), vec![resolved.clone()]);

    // Pass 2: the peer pod is transiently ABSENT (informer miss) but app/web still
    // reports the same connection → the memo bridges the gap, no flip to raw IP.
    let snap2 = Snapshot {
        pods: vec![web_pod()],
        runtime_events: vec![web_conn("10.42.1.159:8086", false)],
        ..Default::default()
    };
    let g2 = super::super::build_graph(&snap2, &adapters);
    assert_eq!(
        peers_of(&g2),
        vec![resolved],
        "a transient informer miss must not flip a known cluster peer's rendering"
    );
}

#[test]
fn runtime_adapter_renders_a_never_seen_peer_raw_even_across_passes() {
    // A genuinely NEW peer the index has never resolved renders raw — the memo must
    // not fabricate a name (ticket non-goal: new peers must still appear/re-judge).
    let adapters = super::super::default_adapters();
    let snap = Snapshot {
        pods: vec![web_pod()],
        runtime_events: vec![web_conn("10.42.7.7:9200", false)],
        ..Default::default()
    };
    assert_eq!(
        peers_of(&super::super::build_graph(&snap, &adapters)),
        vec![("10.42.7.7:9200".to_string(), false)]
    );
    // A second pass with the peer still unknown stays raw too — nothing to reuse.
    assert_eq!(
        peers_of(&super::super::build_graph(&snap, &adapters)),
        vec![("10.42.7.7:9200".to_string(), false)]
    );
}

#[test]
fn runtime_adapter_resolves_cluster_connection_peers_to_names() {
    // app/web connects to a cluster pod (analytics/influxdb-0), a cluster service
    // (analytics/influxdb), an unknown cluster IP, and the internet. After the
    // pipeline the pod/service peers are resolved to ns/name:port (raw-ip); the
    // unknown IP stays raw; the internet peer stays raw (egress, not resolved).
    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{"name": "web", "image": "web:1"}]}
    }));
    let influx_pod = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "influxdb-0", "namespace": "analytics"},
        "spec": {"containers": [{"name": "influxdb", "image": "influxdb:2"}]},
        "status": {"podIP": "10.42.1.159"}
    }));
    let influx_svc: k8s_openapi::api::core::v1::Service = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "influxdb", "namespace": "analytics"},
        "spec": {"clusterIP": "10.43.0.10"}
    }))
    .expect("valid Service");
    let conn = |peer: &str, internet: bool| RuntimeObservation {
        attribution: Attribution::by_namespaced_name("app", "web"),
        source: None,
        observed_at_ms: None,
        node: None,
        behavior: Behavior::NetworkConnection {
            peer: peer.into(),
            internet,
        },
    };
    let snap = Snapshot {
        pods: vec![web, influx_pod],
        services: vec![influx_svc],
        runtime_events: vec![
            conn("10.42.1.159:8086", false), // a cluster pod
            conn("10.43.0.10:8086", false),  // a cluster service ClusterIP
            conn("10.99.0.1:443", false),    // an unresolvable cluster IP
            conn("1.2.3.4:443", true),       // internet egress
        ],
        ..Default::default()
    };
    let mut peers = connection_peers(snap);
    peers.sort();
    assert_eq!(
        peers,
        vec![
            ("1.2.3.4:443".to_string(), true),
            ("10.99.0.1:443".to_string(), false),
            ("analytics/influxdb-0:8086 (10.42.1.159)".to_string(), false),
            ("analytics/influxdb:8086 (10.43.0.10)".to_string(), false),
        ]
    );
}

#[test]
fn cve_without_pkg_name_stays_unknown() {
    // No package name to correlate against → the CVE keeps Unknown even with a load.
    let web = pod(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{"name": "web", "image": "web:1"}]}
    }));
    let snap = Snapshot {
        pods: vec![web],
        image_vulns: vec![ImageVulnerabilities {
            image: "web:1".into(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-0000-0000".into(),
                pkg_name: None,
                ..Default::default()
            }],
        }],
        runtime_events: vec![RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: None,
            observed_at_ms: None,
            node: None,
            behavior: Behavior::LibraryLoaded {
                name: "anything.so".into(),
            },
        }],
        ..Default::default()
    };
    let graph = super::super::build_graph(&snap, &super::super::default_adapters());
    let img_key = NodeKey::image(&canonical_image("web:1"));
    let idx = graph.index_of(&img_key).expect("image node exists");
    let Some(Node::Image(img)) = graph.node(idx) else {
        panic!("expected image node");
    };
    assert_eq!(img.vulnerabilities[0].reachability, Reachability::Unknown);
}
