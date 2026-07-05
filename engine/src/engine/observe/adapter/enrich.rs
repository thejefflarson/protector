use petgraph::visit::EdgeRef;

use super::*;
use crate::engine::graph::{Behavior, Reachability};
use crate::engine::observe::Attribution;
use crate::engine::observe::ip_index::IpIndex;

/// Annotates Image nodes with vulnerability findings (Vulnerability port). Like
/// [`ExposureAdapter`], it enriches existing Image nodes, so it runs after the
/// structural adapters. The live scanner source is wired in the Observer; this
/// adapter just maps normalized findings onto the matching Image node.
pub struct VulnerabilityAdapter;

impl Adapter for VulnerabilityAdapter {
    fn name(&self) -> &'static str {
        "vulnerability"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for finding in &snapshot.image_vulns {
            // Canonicalize the finding's ref to match the Image node the workload
            // adapter keyed (a short pod ref vs a scanner's fully-qualified one) —
            // without this the CVE silently fails to attach (security fix [15]).
            let key = NodeKey::image(&canonical_image(&finding.image));
            graph.update_node(&key, |node| {
                if let Node::Image(img) = node {
                    img.vulnerabilities = finding.vulnerabilities.clone();
                }
            });
        }
    }
}

/// Live runtime signals (RuntimeEvidence port): annotate a Workload with the
/// runtime events observed against it — the "is it happening now" corroboration
/// that completes the action bar. Enriches existing Workload nodes, so it runs
/// after the structural adapters.
pub struct RuntimeAdapter;

impl Adapter for RuntimeAdapter {
    fn name(&self) -> &'static str {
        "runtime"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        if snapshot.runtime_events.is_empty() {
            return;
        }
        // IP → cluster-object index, built once per pass from the SAME Pod/Service
        // objects the reflector stores already hold (JEF: resolve-connection-peers). It
        // turns a raw `IP:port` connection peer into the workload/service it belongs to
        // (`analytics/influxdb:8086 (10.42.1.159)`) so the dashboard AND the adjudicator
        // prompt — which both render `Behavior::summary()` — show *what* a pod connects
        // to, not a bare IP, with NO change to either rendering site. A pure in-memory
        // lookup: zero outbound calls, so the zero-egress invariant holds (we explicitly
        // do NOT do reverse DNS; cluster pod IPs aren't in external DNS and a PTR lookup
        // would leave the cluster).
        let ip_index = IpIndex::from_snapshot(snapshot);
        // UID → the Pod from the watch, so events a sensor attributed by cgroup UID (the
        // eBPF agent) resolve to a workload without the agent ever touching the cluster
        // API (ADR-0014). The full Pod (not just ns/name) is needed to refine a raw
        // FileRead into a SecretRead via its volumeMounts. Observations attributed by
        // namespace/pod directly need no UID map, so only build it when something needs
        // UID resolution.
        let by_uid: std::collections::HashMap<String, &Pod> = if snapshot
            .runtime_events
            .iter()
            .any(|e| matches!(e.attribution, Attribution::ByPodUid { .. }))
        {
            snapshot
                .pods
                .iter()
                .filter_map(|p| Some((p.metadata.uid.clone()?, p)))
                .collect()
        } else {
            std::collections::HashMap::new()
        };

        let (mut attached, mut unresolved, mut filtered) = (0usize, 0usize, 0usize);
        for event in &snapshot.runtime_events {
            // The resolution rule (a namespace/name attribution always resolves; a cgroup
            // UID resolves iff a pod with that UID is observed) lives on `Attribution`,
            // shared with the engine's attribution-outcome metric so the two can't drift.
            if !event
                .attribution
                .resolves_in(|uid| by_uid.contains_key(uid))
            {
                // Unknown UID (pod gone / not yet observed) — drop, don't guess.
                unresolved += 1;
                continue;
            }
            let (ns, name, pod): (String, String, Option<&Pod>) = match &event.attribution {
                Attribution::ByPodUid { pod_uid } => {
                    // resolves_in above guarantees the UID is present.
                    let p = by_uid[pod_uid];
                    (
                        pod_namespace(p),
                        p.metadata.name.clone().unwrap_or_default(),
                        Some(p),
                    )
                }
                Attribution::ByNamespacedName { namespace, pod } => {
                    (namespace.clone(), pod.clone(), None)
                }
            };
            // Refine a raw FileRead (a tmpfs open the credential-free agent couldn't
            // classify) into a SecretRead using the pod's secret volumeMounts — or drop
            // it if the path isn't under a Secret mount (most tmpfs reads aren't). Other
            // behaviors pass through unchanged.
            let behavior = match &event.behavior {
                Behavior::FileRead { path } => match pod.and_then(|p| secret_for_path(p, path)) {
                    Some(secret) => {
                        // Real secret reads are sparse — log each at info (operability +
                        // confirms the secret-read probe end-to-end on the nodes).
                        tracing::info!(%secret, namespace = %ns, pod = %name, "secret read");
                        // A refined FileRead is always a mounted-file read — the only kind
                        // eBPF observes. The API secret-read path is the audit adapter's
                        // (JEF-269), never this one.
                        Behavior::SecretRead {
                            secret,
                            source: crate::engine::graph::SecretReadSource::Mounted,
                        }
                    }
                    None => {
                        filtered += 1;
                        continue;
                    }
                },
                // Resolve a connection peer's cluster IP to the workload/service it
                // belongs to (JEF: resolve-connection-peers). `resolve_peer` keeps an
                // internet/unknown/unresolvable peer exactly as the raw `IP:port`, so
                // this only ever *enriches* a same-cluster pod/service peer; the resolved
                // name then flows through `Behavior::summary()` to both the prompt and the
                // dashboard unchanged.
                Behavior::NetworkConnection { peer, internet } => Behavior::NetworkConnection {
                    peer: ip_index.resolve_peer(peer, *internet),
                    internet: *internet,
                },
                other => other.clone(),
            };
            // Carry the sensor's identity and observation time into the provenance:
            // which sensor (so two sensors agreeing is corroboration, not one opaque
            // "runtime" source) and *when it observed* (not when this pass ran, which
            // lags by a batch interval + a judging pass). Both fall back gracefully for
            // older agents that omit the fields (ADR-0014).
            let source = event.source.as_deref().unwrap_or(self.name());
            let observed_at = event
                .observed_at_ms
                .map(|ms| SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms))
                .unwrap_or_else(SystemTime::now);
            let key = NodeKey::workload(&ns, "Pod", &name);
            graph.update_node(&key, |node| {
                if let Node::Workload(w) = node {
                    w.runtime.push(RuntimeSignal {
                        behavior: behavior.clone(),
                        provenance: Provenance::new(source, observed_at),
                    });
                    attached += 1;
                }
            });
        }
        // One line per pass so the behavioral pipeline is observable: signals attached,
        // UIDs that didn't resolve (a persistent nonzero means the agent's cgroup UIDs
        // aren't matching pod metadata.uid), and FileReads dropped as non-secret tmpfs.
        tracing::info!(
            attached,
            unresolved,
            filtered,
            events = snapshot.runtime_events.len(),
            "runtime behavioral signals"
        );
    }
}

/// Correlates each Image's CVEs against the runtime libraries loaded by the workloads
/// running it (JEF-51 v1 — *dynamic* reachability). It reads the `LibraryLoaded`
/// signals the [`RuntimeAdapter`] already attached, so it MUST run after both the
/// [`VulnerabilityAdapter`] (which puts the CVEs on the Image) and the
/// [`RuntimeAdapter`] (which puts the loads on the Workload).
///
/// For each vulnerability with a known `pkg_name`, reachability becomes
/// [`Reachability::LoadedAtRuntime`] when a loaded library's basename matches the
/// package, else [`Reachability::NotObserved`]. CVEs with no `pkg_name` stay
/// [`Reachability::Unknown`] — we can't correlate what the scanner didn't name. This
/// is evidence for the model only; it never gates or suppresses anything in v1.
pub struct CveReachabilityAdapter;

impl Adapter for CveReachabilityAdapter {
    fn name(&self) -> &'static str {
        "reachability"
    }

    fn contribute(&self, _snapshot: &Snapshot, graph: &mut SecurityGraph) {
        // Pass 1 (immutable borrow): for every Image, gather the library names loaded by
        // the workloads that run it, walking the `RunsImage` edges. Keyed by the Image
        // key's String (NodeKey is not Hash) so pass 2 can mutate without the borrow.
        let mut loads_by_image: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        let g = graph.inner();
        for idx in g.node_indices() {
            let Some(Node::Workload(w)) = g.node_weight(idx) else {
                continue;
            };
            let loaded: Vec<String> = w
                .runtime
                .iter()
                .filter_map(|s| match &s.behavior {
                    Behavior::LibraryLoaded { name } => Some(name.clone()),
                    _ => None,
                })
                .collect();
            if loaded.is_empty() {
                continue;
            }
            for edge in g.edges(idx) {
                if matches!(edge.weight().relation, Relation::RunsImage)
                    && let Some(img_key) = g.node_weight(edge.target()).map(Node::key)
                {
                    loads_by_image
                        .entry(img_key.0)
                        .or_default()
                        .extend(loaded.iter().cloned());
                }
            }
        }

        // Pass 2: collect the Image keys, then update each. Every Image with CVEs is
        // visited (even those with no loads) so a scanned-but-not-running image's CVEs
        // flip from Unknown to NotObserved — that distinction is itself model evidence.
        let image_keys: Vec<NodeKey> = graph
            .inner()
            .node_indices()
            .filter_map(|idx| match graph.inner().node_weight(idx) {
                Some(node @ Node::Image(_)) => Some(node.key()),
                _ => None,
            })
            .collect();
        for key in image_keys {
            let loads = loads_by_image.get(&key.0).cloned().unwrap_or_default();
            graph.update_node(&key, |node| {
                if let Node::Image(img) = node {
                    for vuln in &mut img.vulnerabilities {
                        let Some(pkg) = vuln.pkg_name.as_deref() else {
                            // No package name to correlate — leave it Unknown.
                            continue;
                        };
                        vuln.reachability = if loads.iter().any(|lib| library_matches(lib, pkg)) {
                            Reachability::LoadedAtRuntime
                        } else {
                            Reachability::NotObserved
                        };
                    }
                }
            });
        }

        // Prune library-load noise (JEF-75): a LibraryLoaded only matters if it's a
        // *vulnerable* library — its name matches a CVE package on an image the workload
        // runs. Drop the rest (libc, libpthread, …) so they don't bloat the model prompt
        // or churn the verdict fingerprint (every process loads dozens of libraries, on a
        // 300s TTL). Reachability is already set above from the same match, so this only
        // removes loads that never contributed one.
        let mut cve_pkgs_by_image: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        let mut pkgs_by_workload: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        {
            let g = graph.inner();
            for idx in g.node_indices() {
                if let Some(node @ Node::Image(img)) = g.node_weight(idx) {
                    let pkgs: Vec<String> = img
                        .vulnerabilities
                        .iter()
                        .filter_map(|v| v.pkg_name.clone())
                        .collect();
                    if !pkgs.is_empty() {
                        cve_pkgs_by_image.insert(node.key().0, pkgs);
                    }
                }
            }
            // Each workload inherits the CVE packages of every image it runs.
            for idx in g.node_indices() {
                let Some(node @ Node::Workload(_)) = g.node_weight(idx) else {
                    continue;
                };
                let mut pkgs: Vec<String> = Vec::new();
                for edge in g.edges(idx) {
                    if matches!(edge.weight().relation, Relation::RunsImage)
                        && let Some(img_key) = g.node_weight(edge.target()).map(Node::key)
                        && let Some(p) = cve_pkgs_by_image.get(&img_key.0)
                    {
                        pkgs.extend(p.iter().cloned());
                    }
                }
                if !pkgs.is_empty() {
                    pkgs_by_workload.insert(node.key().0, pkgs);
                }
            }
        }
        let workload_keys: Vec<NodeKey> = graph
            .inner()
            .node_indices()
            .filter_map(|idx| match graph.inner().node_weight(idx) {
                Some(node @ Node::Workload(_)) => Some(node.key()),
                _ => None,
            })
            .collect();
        for key in workload_keys {
            graph.update_node(&key, |node| {
                if let Node::Workload(w) = node {
                    let pkgs = pkgs_by_workload.get(&key.0);
                    // Keep every non-library behavior; keep a LibraryLoaded only if it
                    // matches a CVE package the workload's images carry.
                    w.runtime.retain(|obs| match &obs.behavior {
                        Behavior::LibraryLoaded { name } => {
                            pkgs.is_some_and(|ps| ps.iter().any(|pkg| library_matches(name, pkg)))
                        }
                        _ => true,
                    });
                }
            });
        }
    }
}

/// Whether a loaded-library name (as the agent observed it, e.g. `libssl.so.3` or
/// `log4j-core-2.14.jar`) refers to the scanner's `pkg_name` (e.g. `openssl`,
/// `log4j-core`). Conservative on purpose: this is model evidence, and a false
/// `LoadedAtRuntime` is worse than a missed one, so the match must be *exact* after
/// normalization — no substring containment that would link `libc.so` to an
/// `openssl` CVE.
///
/// Both sides are reduced to a normalized basename ([`normalize_lib_name`]): strip the
/// directory, the `lib` prefix, the version/`.so`/`.jar` suffixes, and case. A pair
/// matches if either normalizes to the other, covering `openssl` ↔ `libssl.so.3`
/// (both → `ssl`) and `log4j-core` ↔ `log4j-core-2.14.jar` (both → `log4j-core`).
fn library_matches(loaded: &str, pkg_name: &str) -> bool {
    let loaded = normalize_lib_name(loaded);
    let pkg = normalize_lib_name(pkg_name);
    !loaded.is_empty() && loaded == pkg
}

/// Reduce a library or package name to a comparable basename: drop any directory,
/// the `lib` prefix, the first version/extension boundary, and lowercase. Deliberately
/// simple — see [`library_matches`] for why we favor precision over recall.
///
/// Examples: `/usr/lib/libssl.so.3` → `ssl`, `libssl` → `ssl`, `openssl` → `ssl` (the
/// `openssl` package's well-known `ssl` library basename is handled by stripping a
/// leading `open` only when it precedes a known core — see below), `log4j-core-2.14.jar`
/// → `log4j-core`.
fn normalize_lib_name(name: &str) -> String {
    // Basename: everything after the last path separator.
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let mut s = base.to_ascii_lowercase();

    // Drop a known archive/object extension and everything after it (covers
    // `.so`, `.so.3`, `.so.1.1`, `.jar`, `.dll`, `.dylib`, `.a`).
    for ext in [".so", ".jar", ".dll", ".dylib", ".a"] {
        if let Some(pos) = s.find(ext) {
            s.truncate(pos);
            break;
        }
    }

    // Strip a trailing `-<version>` (a dash followed by a digit) — `log4j-core-2.14`
    // → `log4j-core`. Only at a dash-then-digit boundary so we never bite into a name.
    if let Some(pos) = dash_version_start(&s) {
        s.truncate(pos);
    }

    // Strip a leading `lib` prefix so `libssl` and the `ssl` half of `openssl` align.
    let s = s.strip_prefix("lib").unwrap_or(&s).to_string();
    // The `openssl` package is the canonical fuzzy case in the issue: its libraries are
    // `libssl`/`libcrypto`. Reduce the package name `openssl` to its `ssl` library
    // basename so it matches `libssl.so.3`. Kept as a tiny, explicit alias list so we
    // never introduce broad `open*` stripping that could mis-link unrelated names.
    match s.as_str() {
        "openssl" => "ssl".to_string(),
        other => other.to_string(),
    }
}

/// The byte index of a `-<digit>` version boundary in `s`, if any — the start of the
/// trailing version segment to drop.
fn dash_version_start(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    bytes
        .windows(2)
        .enumerate()
        .find_map(|(i, w)| (w[0] == b'-' && w[1].is_ascii_digit()).then_some(i))
}

/// If `path` (a container-relative path from the agent) falls under one of `pod`'s
/// mounted **Secret** volumes, return `"<secretName>/<subpath>"` (the secret that was
/// read); else `None` (not a secret — e.g. a ConfigMap, projected SA token, or a /tmp
/// read that merely happens to be on tmpfs). The longest matching mountPath wins, so a
/// nested mount is attributed to the right volume.
///
/// Two volume shapes expose secrets:
///   * a plain `.secret` volume (`secretName`), and
///   * a `.projected` volume whose `sources[]` include a `.secret` projection.
///
/// A projected volume merges several sources into one mountPath, so a filesystem read
/// only sees the mount — we can't tell which source a sub-path came from. We attribute
/// such reads to the *first* secret source's name (deterministic, and matching the
/// existing "name the secret" idiom). Non-secret projected sources (configMap,
/// serviceAccountToken, downwardAPI, clusterTrustBundle) are ignored, consistent with
/// how plain ConfigMap volumes are already ignored.
fn secret_for_path(pod: &Pod, path: &str) -> Option<String> {
    let spec = pod.spec.as_ref()?;
    // volume name -> secret name, for plain Secret volumes and projected volumes whose
    // sources expose a secret (first secret source wins — see the attribution note above).
    let secret_vols: std::collections::HashMap<&str, &str> = spec
        .volumes
        .iter()
        .flatten()
        .filter_map(|v| {
            let secret_name = v
                .secret
                .as_ref()
                .and_then(|s| s.secret_name.as_deref())
                .or_else(|| {
                    v.projected
                        .as_ref()?
                        .sources
                        .iter()
                        .flatten()
                        .find_map(|src| src.secret.as_ref().map(|s| s.name.as_str()))
                })?;
            Some((v.name.as_str(), secret_name))
        })
        .collect();
    if secret_vols.is_empty() {
        return None;
    }
    let mut best: Option<(usize, String)> = None;
    for m in spec
        .containers
        .iter()
        .chain(spec.init_containers.iter().flatten())
        .flat_map(|c| c.volume_mounts.iter().flatten())
    {
        let Some(&secret_name) = secret_vols.get(m.name.as_str()) else {
            continue;
        };
        let Some(sub) = under(path, &m.mount_path) else {
            continue;
        };
        let len = m.mount_path.len();
        if best.as_ref().is_none_or(|&(l, _)| len > l) {
            let id = if sub.is_empty() {
                secret_name.to_string()
            } else {
                format!("{secret_name}/{sub}")
            };
            best = Some((len, id));
        }
    }
    best.map(|(_, id)| id)
}

/// If `path` is `mount_path` itself or a file beneath it, return the sub-path (possibly
/// empty); else `None`. The boundary check stops `/etc/foo` matching `/etc/foobar`.
fn under<'a>(path: &'a str, mount_path: &str) -> Option<&'a str> {
    let mp = mount_path.trim_end_matches('/');
    if path == mp {
        return Some("");
    }
    path.strip_prefix(mp)?.strip_prefix('/')
}

#[cfg(test)]
mod tests {
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

    /// The `NetworkConnection` behaviors attached to the (single) workload after the
    /// full adapter pipeline — i.e. the peer strings as `Behavior::summary()` (the
    /// prompt + dashboard) will render them.
    fn connection_peers(snap: Snapshot) -> Vec<(String, bool)> {
        let graph = super::super::build_graph(&snap, &super::super::default_adapters());
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
}
