//! Peer-classification policy (JEF-307): is a `NetworkConnection`'s peer a *high-signal
//! foothold* peer — a cloud instance-metadata (IMDS) credential endpoint or the Kubernetes
//! API server?
//!
//! This is the network analogue of [`super::exec_class`]: **engine policy**, not part of
//! the shared wire type. The node-local agent has NO cluster credentials (ADR-0014), so it
//! cannot know *what* a peer is — it emits only a raw `IP:port` and an `internet` flag. The
//! engine, which does have cluster access, resolves the peer to a cluster object via the
//! JEF-131 informer-backed index (`super::ip_index`, zero-egress, pure in-memory) *before*
//! the behavior becomes graph state (in `super::adapter::enrich`). By the time these
//! classifiers see a `NetworkConnection`, its `peer` is already the enriched string:
//!   - a raw `IP:port` for internet / unresolved peers (`169.254.169.254:80`), or
//!   - `namespace/name:port (raw-ip)` for a resolved in-cluster pod/service
//!     (`default/kubernetes:443 (10.96.0.1)`).
//!
//! We classify from that enriched string — no cluster calls of our own, no new egress.
//!
//! Foothold-peer corroboration (JEF-307): a cloud-metadata-service contact and a Kubernetes
//! API-server contact are both high-signal foothold moves. The agent saw those only as a plain
//! `NetworkConnection`, so an outbound IMDS credential-grab / cluster-API abuse from a
//! compromised entry was dropped on the corroboration path. These classifiers close that gap
//! engine-side, feeding the FOOTHOLD corroboration seam in `reason::proof::corroborate`
//! (Initial Access, T1190) — shadow-gated like the rest.
//!
//! ## Conservatism (hard — ADR-0011 false-positive concern)
//! EVERY workload makes connections, so only these *specific* peers promote; ordinary
//! in-cluster traffic and ordinary internet egress must NOT corroborate a foothold. In
//! particular we match the **exact** IMDS addresses, not the whole link-local
//! `169.254.0.0/16` block, because NodeLocal DNSCache and some CNIs legitimately use other
//! link-local addresses (e.g. `169.254.20.10`) that pods hit constantly.

use crate::engine::graph::Behavior;

/// Well-known cloud instance-metadata (IMDS) endpoints. Every major cloud — AWS, GCP,
/// Azure, OpenStack, DigitalOcean, Oracle — serves instance metadata, and crucially
/// short-lived cloud credentials, at the link-local IPv4 address `169.254.169.254`; AWS
/// also exposes an IPv6 IMDS at `fd00:ec2::254`. A workload reaching one of these is the
/// classic cloud-credential-theft move (SSRF-to-IMDS / "Contact cloud metadata service").
///
/// We match these **specific** addresses, NOT the whole link-local `169.254.0.0/16` block,
/// on purpose (ADR-0011 conservatism): NodeLocal DNSCache and some CNIs legitimately use
/// other link-local addresses (e.g. `169.254.20.10`) that every pod hits constantly, and
/// corroborating those would be a false positive.
const CLOUD_METADATA_IPS: &[&str] = &["169.254.169.254", "fd00:ec2::254"];

/// The in-cluster Kubernetes API server, addressed as the `kubernetes` Service in the
/// `default` namespace — a cluster-invariant name Kubernetes guarantees exists. After
/// JEF-131 peer resolution, an in-cluster connection to its ClusterIP is enriched to
/// `default/kubernetes:port (raw-ip)`, so we match the resolved `namespace/name` label
/// (the segment before the first `:`). Matching the whole label means a look-alike such as
/// `default/kubernetes-dashboard` does NOT match.
const API_SERVER_LABEL: &str = "default/kubernetes";

/// The raw IP host of an enriched peer that is still a bare `IP:port` (an internet or
/// unresolved peer), or `None` when the peer is a resolved cluster label (`ns/name:...`)
/// or not in `IP:port` shape. Mirrors `ip_index::split_ip_port`'s host handling so we read
/// the same address token the resolver keyed on.
fn raw_peer_host(peer: &str) -> Option<&str> {
    // Bracketed IPv6 literal: `[addr]:port` -> `addr`.
    if let Some(rest) = peer.strip_prefix('[') {
        let addr = rest.split_once(']')?.0;
        return (!addr.is_empty()).then_some(addr);
    }
    // A resolved cluster peer carries a `namespace/name` label, never a raw IP.
    if peer.contains('/') {
        return None;
    }
    // IPv4 `ip:port` — the address itself has no colons, so split on the last one.
    let ip = peer.rsplit_once(':')?.0;
    (!ip.is_empty()).then_some(ip)
}

/// Whether an enriched `NetworkConnection` peer is a cloud instance-metadata (IMDS)
/// endpoint (`169.254.169.254` / `fd00:ec2::254`) — the "Contact cloud metadata service"
/// signal. Matched on the exact IMDS addresses (see [`CLOUD_METADATA_IPS`]).
pub fn is_cloud_metadata(peer: &str) -> bool {
    raw_peer_host(peer).is_some_and(|ip| CLOUD_METADATA_IPS.contains(&ip))
}

/// Whether an enriched `NetworkConnection` peer is the in-cluster Kubernetes API server —
/// the JEF-131-resolved `default/kubernetes` Service label ("Contact K8S API Server From
/// Container"). Matches the whole `namespace/name` label so look-alikes don't.
pub fn is_api_server(peer: &str) -> bool {
    peer.split(':').next() == Some(API_SERVER_LABEL)
}

/// A short, human label for a *high-signal foothold* peer — a cloud-metadata/IMDS endpoint
/// or the Kubernetes API server — or `None` for an ordinary connection. This is the network
/// analogue of [`super::exec_class::notable_exec`]: it promotes a `NetworkConnection` to
/// FOOTHOLD corroboration (Initial Access, T1190) in `reason::proof::corroborate`. Only
/// these specific peers qualify; ordinary in-cluster traffic and ordinary internet egress
/// return `None`. Always `None` for any non-connection behavior. The label is a fixed
/// internal string (never untrusted input), safe to embed in the prompt/output.
pub fn foothold_peer(behavior: &Behavior) -> Option<&'static str> {
    match behavior {
        Behavior::NetworkConnection { peer, .. } => {
            if is_cloud_metadata(peer) {
                Some("cloud instance-metadata (IMDS) endpoint")
            } else if is_api_server(peer) {
                Some("Kubernetes API server")
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::SecretReadSource;

    fn conn(peer: &str, internet: bool) -> Behavior {
        Behavior::NetworkConnection {
            peer: peer.into(),
            internet,
        }
    }

    #[test]
    fn cloud_metadata_matches_only_the_exact_imds_addresses() {
        // The universal IMDS address, IPv4 and (AWS) IPv6, at any port — a credential grab.
        assert!(is_cloud_metadata("169.254.169.254:80"));
        assert!(is_cloud_metadata("169.254.169.254:443"));
        assert!(is_cloud_metadata("[fd00:ec2::254]:80"));
        // NEGATIVE: other link-local addresses must NOT match — NodeLocal DNSCache
        // (169.254.20.10) and CNI link-local peers are hit by every pod constantly.
        assert!(!is_cloud_metadata("169.254.20.10:53"));
        assert!(!is_cloud_metadata("169.254.1.1:80"));
        // NEGATIVE: ordinary internet / in-cluster peers.
        assert!(!is_cloud_metadata("203.0.113.7:443"));
        assert!(!is_cloud_metadata("10.42.1.159:8086"));
        // NEGATIVE: a resolved cluster label that merely contains the digits is not a raw IP.
        assert!(!is_cloud_metadata("prod/metadata:80 (10.42.0.9)"));
    }

    #[test]
    fn api_server_matches_only_the_resolved_default_kubernetes_label() {
        // The JEF-131-resolved apiserver peer (ClusterIP -> default/kubernetes).
        assert!(is_api_server("default/kubernetes:443 (10.96.0.1)"));
        // NEGATIVE: a look-alike service name in default, and the same name elsewhere.
        assert!(!is_api_server(
            "default/kubernetes-dashboard:443 (10.96.0.2)"
        ));
        assert!(!is_api_server("kube-system/kubernetes:443 (10.96.0.3)"));
        // NEGATIVE: an unresolved raw IP (even the common apiserver ClusterIP) is not
        // matched by label — resolution is what makes it high-signal, not a guessed IP.
        assert!(!is_api_server("10.96.0.1:443"));
        // NEGATIVE: an ordinary in-cluster service.
        assert!(!is_api_server("analytics/influxdb:8086 (10.42.1.159)"));
    }

    #[test]
    fn foothold_peer_labels_imds_and_apiserver_and_nothing_else() {
        assert_eq!(
            foothold_peer(&conn("169.254.169.254:80", true)),
            Some("cloud instance-metadata (IMDS) endpoint")
        );
        assert_eq!(
            foothold_peer(&conn("default/kubernetes:443 (10.96.0.1)", false)),
            Some("Kubernetes API server")
        );
        // Ordinary in-cluster DB and ordinary internet egress are NOT foothold peers —
        // a benign app talking to its own database / the internet must not corroborate.
        assert_eq!(
            foothold_peer(&conn("analytics/influxdb:8086 (10.42.1.159)", false)),
            None
        );
        assert_eq!(foothold_peer(&conn("203.0.113.7:443", true)), None);
    }

    #[test]
    fn foothold_peer_is_none_for_non_connection_behaviors() {
        // The classifier is scoped to NetworkConnection — an alert / secret-read / exec
        // whose payload happens to look like a peer must never classify as a peer.
        let others = [
            Behavior::Alert {
                rule: "169.254.169.254".into(),
            },
            Behavior::SecretRead {
                secret: "default/kubernetes".into(),
                source: SecretReadSource::Mounted,
            },
            Behavior::ProcessExec {
                path: "169.254.169.254:80".into(),
            },
        ];
        for b in others {
            assert_eq!(foothold_peer(&b), None, "{b:?}");
        }
    }
}
