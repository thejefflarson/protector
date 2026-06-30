//! An in-memory IP → cluster-object index (JEF: resolve-connection-peers).
//!
//! A `NetworkConnection` behavior carries a raw `IP:port` peer (e.g.
//! `10.42.1.159:8086`), which reads as opaque in the dashboard and the adjudicator
//! prompt. This index turns the IP half into the workload/service it belongs to —
//! `analytics/influxdb:8086 (10.42.1.159)` — so an operator (and the model) see
//! *what* a pod connects to.
//!
//! ## Why not reverse DNS
//! Cluster pod IPs (10.42.x.x) aren't in external DNS, and any outbound PTR lookup
//! would violate the zero-egress invariant (the security graph and evidence never
//! leave the cluster — see CLAUDE.md / docs/adr). So resolution is a *pure in-memory
//! lookup* against the Pod/Service objects the engine's reflector stores already
//! watch — `status.podIP` on a Pod, `spec.clusterIP` on a Service. No network call,
//! ever, on the hot path: the index is built from a [`Snapshot`] read and queried
//! with [`IpIndex::resolve`].
//!
//! The index lives in the engine (which has cluster access), never in the shared
//! `behavior` crate (which has none) — the wire type stays pure data.

use std::collections::HashMap;

use k8s_openapi::api::core::v1::{Pod, Service};

use super::Snapshot;

/// What an IP resolves to: the namespace + name of the owning cluster object. A pod
/// IP resolves to its pod's `namespace/name`; a service ClusterIP to the service's
/// `namespace/name`. (We don't keep the `kind` distinct in the rendered label — both
/// render as `namespace/name` — but it's tracked so a future caller can tell them
/// apart without rebuilding the index.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPeer {
    pub namespace: String,
    pub name: String,
    pub kind: PeerKind,
}

/// Which kind of cluster object an IP belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerKind {
    /// A Pod, resolved from `status.podIP`.
    Pod,
    /// A Service, resolved from `spec.clusterIP`.
    Service,
}

impl ResolvedPeer {
    /// The `namespace/name` label rendered into the peer string. Derived from cluster
    /// object names (namespace + pod/service name) — still untrusted-adjacent, so the
    /// prompt/render sites sanitize it exactly as they already do the raw peer.
    fn label(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }
}

/// A pure, in-memory map from a bare cluster IP to the object that owns it. Built from
/// a [`Snapshot`]'s Pods and Services (the same objects the reflector stores hold), so
/// a lookup is a hashmap probe with zero IO.
///
/// A Pod entry takes precedence over a Service entry on the rare event of a collision
/// (a ClusterIP and a podIP should never coincide, but if they did, the concrete pod
/// is the more specific answer). Pods are indexed after services so they win.
#[derive(Debug, Default, Clone)]
pub struct IpIndex {
    by_ip: HashMap<String, ResolvedPeer>,
}

impl IpIndex {
    /// Build the index from the cluster objects in `snapshot`. Pure: it reads
    /// `spec.clusterIP` off each Service and `status.podIP`/`status.podIPs` off each
    /// Pod and nothing else — no network, no blocking.
    pub fn from_snapshot(snapshot: &Snapshot) -> Self {
        let mut by_ip = HashMap::new();
        // Services first, then Pods, so a Pod IP wins any (pathological) collision.
        for svc in &snapshot.services {
            Self::index_service(&mut by_ip, svc);
        }
        for pod in &snapshot.pods {
            Self::index_pod(&mut by_ip, pod);
        }
        Self { by_ip }
    }

    fn index_service(by_ip: &mut HashMap<String, ResolvedPeer>, svc: &Service) {
        let (Some(namespace), Some(name)) =
            (svc.metadata.namespace.clone(), svc.metadata.name.clone())
        else {
            return;
        };
        let Some(spec) = &svc.spec else { return };
        // `clusterIP` is the primary; `clusterIPs` carries it plus any dual-stack
        // sibling. Index every concrete one (skip the "None" headless sentinel and
        // empty strings — a headless Service has no ClusterIP to resolve).
        let ips = spec
            .cluster_ip
            .iter()
            .chain(spec.cluster_ips.iter().flatten());
        for ip in ips {
            if is_resolvable_ip(ip) {
                by_ip.insert(
                    ip.clone(),
                    ResolvedPeer {
                        namespace: namespace.clone(),
                        name: name.clone(),
                        kind: PeerKind::Service,
                    },
                );
            }
        }
    }

    fn index_pod(by_ip: &mut HashMap<String, ResolvedPeer>, pod: &Pod) {
        let (Some(namespace), Some(name)) =
            (pod.metadata.namespace.clone(), pod.metadata.name.clone())
        else {
            return;
        };
        let Some(status) = &pod.status else { return };
        // `podIP` is the primary address; `podIPs` carries it plus any dual-stack
        // sibling. Index every concrete one so either family resolves.
        let ips = status
            .pod_ip
            .iter()
            .chain(status.pod_ips.iter().flatten().map(|p| &p.ip));
        for ip in ips {
            if is_resolvable_ip(ip) {
                by_ip.insert(
                    ip.clone(),
                    ResolvedPeer {
                        namespace: namespace.clone(),
                        name: name.clone(),
                        kind: PeerKind::Pod,
                    },
                );
            }
        }
    }

    /// Resolve a bare IP to the object that owns it, or `None` if unknown. Pure
    /// hashmap probe — no IO.
    pub fn resolve(&self, ip: &str) -> Option<&ResolvedPeer> {
        self.by_ip.get(ip)
    }

    /// Rewrite a `NetworkConnection` peer string into its resolved cluster form, or
    /// return it unchanged when it can't be resolved.
    ///
    /// Rules (JEF: resolve-connection-peers):
    /// - `internet` peers are left as the raw `IP:port` — they're external egress, not
    ///   a cluster object, so there's nothing in-cluster to resolve to (the caller's
    ///   `internet` flag still labels them as egress downstream).
    /// - A same-cluster pod or service IP becomes
    ///   `namespace/name:port (raw-ip)` — the resolved name, the original port, and the
    ///   raw IP kept in parens for forensics.
    /// - An unknown / unresolvable IP is left exactly as the raw `IP:port` — we never
    ///   fabricate a name.
    ///
    /// Deterministic and pure given the index.
    pub fn resolve_peer(&self, peer: &str, internet: bool) -> String {
        if internet {
            // External egress — nothing in-cluster to resolve to; keep it raw.
            return peer.to_string();
        }
        let Some((ip, port)) = split_ip_port(peer) else {
            // Not in `IP:port` shape — leave it untouched rather than guess.
            return peer.to_string();
        };
        match self.resolve(ip) {
            Some(resolved) => format!("{}:{port} ({ip})", resolved.label()),
            None => peer.to_string(),
        }
    }

    /// The number of indexed IPs — for observability/tests.
    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }
}

/// Whether an IP string is a concrete address we can index. Kubernetes uses the
/// literal `"None"` for a headless Service's ClusterIP and may carry an empty string;
/// neither is a real address, so we skip them.
fn is_resolvable_ip(ip: &str) -> bool {
    !ip.is_empty() && ip != "None"
}

/// Split a `peer` of the form `IP:port` into `(ip, port)`. Handles both IPv4
/// (`10.42.1.159:8086`) and bracketed IPv6 (`[fd00::1]:8086`); returns `None` when
/// there's no `:port` suffix to split on (so the caller leaves the peer untouched).
///
/// For IPv4 we split on the *last* colon (an IPv4 address has none of its own); for a
/// bracketed IPv6 literal we split after the closing bracket so the address's internal
/// colons are preserved.
fn split_ip_port(peer: &str) -> Option<(&str, &str)> {
    if let Some(rest) = peer.strip_prefix('[') {
        // Bracketed IPv6: `[addr]:port` → ip = `addr`, port after `]:`.
        let (addr, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        if addr.is_empty() || port.is_empty() {
            return None;
        }
        return Some((addr, port));
    }
    let (ip, port) = peer.rsplit_once(':')?;
    if ip.is_empty() || port.is_empty() {
        return None;
    }
    Some((ip, port))
}

#[cfg(test)]
mod tests;
