use petgraph::visit::EdgeRef;

use super::*;
use crate::engine::graph::{Behavior, Reachability};
use crate::engine::observe::Attribution;
use crate::engine::observe::ip_index::{IpIndex, PeerResolutionMemo};

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
///
/// Holds a [`PeerResolutionMemo`] so a connection peer that IS a known cluster endpoint
/// renders the SAME token every pass even when the informer index transiently misses it
/// (JEF-375). The adapter is long-lived (built once, reused each pass), so the memo
/// persists across passes; it's behind a `Mutex` because [`Adapter::contribute`] takes
/// `&self` and the engine holds the adapter set across `await` points (`Send + Sync`).
#[derive(Default)]
pub struct RuntimeAdapter {
    peer_memo: std::sync::Mutex<PeerResolutionMemo>,
}

impl RuntimeAdapter {
    pub fn new() -> Self {
        Self::default()
    }
}

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
        // Stable peer rendering (JEF-375): resolve connection peers through the last-known
        // resolution memo so a transient informer miss reuses the prior name instead of
        // flipping a known cluster peer back to a raw IP (which would churn the prompt hash
        // into a spurious verdict-cache re-judge). `now` is captured once for the whole pass
        // so every peer this pass shares a consistent grace clock.
        let now = std::time::Instant::now();
        let mut peer_memo = self
            .peer_memo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        peer_memo.prune(now);
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
                // belongs to (JEF: resolve-connection-peers), stably across a transient
                // informer miss (JEF-375). The memo keeps an internet/unknown/unresolvable
                // peer exactly as the raw `IP:port`, so this only ever *enriches* a
                // same-cluster pod/service peer — and a peer once resolved keeps the SAME
                // name even if the index misses it this pass, so the resolved name flows
                // through `Behavior::summary()` to the prompt and dashboard without flipping.
                Behavior::NetworkConnection { peer, internet } => Behavior::NetworkConnection {
                    peer: peer_memo.resolve_peer(&ip_index, peer, *internet, now),
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
mod tests;
