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

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use crate::engine::graph::Behavior;
use crate::engine::observe::asn::AsnDb;

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

/// The resolved namespace of an enriched in-cluster peer — the `namespace` segment of a
/// JEF-131-resolved `namespace/name:port (raw-ip)` label — or `None` when the peer is not a
/// resolved cluster peer (a bare `IP:port` internet / unresolved peer has no namespace).
///
/// A resolved peer always carries a `namespace/name` label before the first `:`; we take the
/// segment before the first `/` of that label. A bare `IP:port` (no `/`) resolves to `None`,
/// so internet egress and unresolved in-cluster traffic never look cross-tenant.
fn resolved_peer_namespace(peer: &str) -> Option<&str> {
    let label = peer.split(':').next()?;
    let (ns, _name) = label.split_once('/')?;
    (!ns.is_empty()).then_some(ns)
}

/// Whether an enriched `NetworkConnection` `peer` resolves to a workload in a **different**
/// namespace than `source_ns` — the cross-tenant lateral-movement shape (JEF-319). A
/// connection from the proven entry/foothold to a service/pod in another namespace/tenant is
/// the classic lateral move an attacker makes once they own the front door.
///
/// Conservative on purpose (ADR-0011 / ADR-0014): this returns `true` ONLY for a peer that
/// JEF-131 resolved to a real `namespace/name` label whose namespace differs from the source.
/// A same-namespace peer, an unresolved `IP:port`, or an internet peer all return `false`, so
/// ordinary in-cluster and internet traffic never look cross-tenant. Whether this actually
/// corroborates is gated further upstream (only from the proven internet-facing entry/foothold),
/// so a legit cross-namespace service call from an ordinary pod is NOT corroborated.
pub fn is_cross_tenant(source_ns: &str, peer: &str) -> bool {
    resolved_peer_namespace(peer).is_some_and(|peer_ns| peer_ns != source_ns)
}

/// The rendered prefix for the collapsed INTERNET-egress line (JEF-380). Kept as a single
/// constant so the prompt renderer and the tests agree on the exact byte string.
const INTERNET_EGRESS_PREFIX: &str = "INTERNET egress: ";

/// Attribute one raw internet peer (`IP:port`) to its network PROVIDER, rendered as
/// `org [ASxxxxx]` (e.g. `GitHub [AS36459]`), via the offline ASN dataset (JEF-380). Falls
/// back to the raw peer string verbatim when the address has no ASN attribution — an unknown
/// / unrouted IPv4 range, an IPv6 literal (the v4 dataset can't attribute it), or an
/// unparseable host — so a peer is NEVER dropped, only enriched when we can.
///
/// The org text is untrusted third-party feed data; it is neutralized (fenced + sanitized) by
/// the prompt renderer, so nothing hostile in a description reaches the model as instructions.
fn attribute_internet_peer(peer: &str, asn: &AsnDb) -> String {
    raw_peer_host(peer)
        .and_then(|host| host.parse::<Ipv4Addr>().ok())
        .and_then(|ip| asn.lookup(ip))
        .map(|hit| format!("{} [AS{}]", hit.org, hit.asn))
        .unwrap_or_else(|| peer.to_string())
}

/// Collapse a set of INTERNET egress peers into ONE deterministic line grouped by PROVIDER
/// (JEF-380): `INTERNET egress: Amazon [AS16509], GitHub [AS36459], OVH SAS [AS16276]`. This
/// is both the feature (the adjudicator sees WHICH provider a workload egresses to — the
/// salient signal) and the churn fix (rotating CDN IPs within one AS collapse to a single
/// stable provider entry, so the prompt fingerprint is byte-identical across IP rotation).
///
/// Providers are a sorted, deduped set, so two different IP sets that resolve to the same
/// providers render a byte-identical line. An IP with no ASN match contributes its raw
/// `IP:port` to the set (never dropped). Returns `None` when there are no internet peers, so
/// the caller adds no line at all.
pub fn internet_egress_line<'a>(
    peers: impl IntoIterator<Item = &'a str>,
    asn: &AsnDb,
) -> Option<String> {
    let providers: BTreeSet<String> = peers
        .into_iter()
        .map(|peer| attribute_internet_peer(peer, asn))
        .collect();
    if providers.is_empty() {
        return None;
    }
    let joined = providers.into_iter().collect::<Vec<_>>().join(", ");
    Some(format!("{INTERNET_EGRESS_PREFIX}{joined}"))
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

    /// A small ASN fixture: GitHub, Amazon, OVH. Two of the GitHub rows are DIFFERENT ranges
    /// in the SAME AS — the CDN-rotation case the churn fix targets.
    fn asn_db() -> AsnDb {
        AsnDb::parse(
            "140.82.112.0\t140.82.127.255\t36459\tUS\tGitHub\n\
             13.32.0.0\t13.35.255.255\t16509\tUS\tAmazon\n\
             51.75.0.0\t51.75.255.255\t16276\tFR\tOVH SAS\n",
        )
    }

    #[test]
    fn internet_peer_resolves_to_its_provider() {
        let db = asn_db();
        assert_eq!(
            attribute_internet_peer("140.82.121.3:443", &db),
            "GitHub [AS36459]"
        );
        assert_eq!(
            attribute_internet_peer("51.75.10.9:443", &db),
            "OVH SAS [AS16276]"
        );
    }

    #[test]
    fn unknown_ip_falls_back_to_the_raw_peer() {
        let db = asn_db();
        // An IP in no known range keeps its raw `IP:port` — never dropped.
        assert_eq!(
            attribute_internet_peer("203.0.113.7:443", &db),
            "203.0.113.7:443"
        );
        // An IPv6 literal can't be attributed by the v4 dataset — raw fallback.
        assert_eq!(
            attribute_internet_peer("[2606:4700::1111]:443", &db),
            "[2606:4700::1111]:443"
        );
        // With an EMPTY DB every peer falls back to raw — the graceful-degrade contract.
        assert_eq!(
            attribute_internet_peer("140.82.121.3:443", &AsnDb::empty()),
            "140.82.121.3:443"
        );
    }

    #[test]
    fn providers_render_as_one_sorted_deduped_line() {
        let db = asn_db();
        let line = internet_egress_line(
            [
                "140.82.121.3:443", // GitHub
                "13.33.9.9:443",    // Amazon
                "51.75.1.1:443",    // OVH
                "203.0.113.7:443",  // unknown → raw
            ],
            &db,
        )
        .expect("some internet peers");
        // Sorted set of providers (raw fallback sorts in too), comma-joined, one line.
        assert_eq!(
            line,
            "INTERNET egress: 203.0.113.7:443, Amazon [AS16509], GitHub [AS36459], OVH SAS [AS16276]"
        );
    }

    #[test]
    fn no_internet_peers_render_no_line() {
        assert_eq!(internet_egress_line(std::iter::empty(), &asn_db()), None);
    }

    /// The fingerprint-stability guarantee (JEF-380, the churn fix): two DIFFERENT sets of
    /// internet IPs that resolve to the SAME providers must render a BYTE-IDENTICAL line, so a
    /// CDN rotating through IPs never churns the adjudicator prompt.
    #[test]
    fn rotating_cdn_ips_in_the_same_asn_render_a_byte_identical_line() {
        let db = asn_db();
        // Window 1: one GitHub IP, one Amazon IP.
        let set_a = ["140.82.112.5:443", "13.32.0.10:443"];
        // Window 2 (CDN rotated): DIFFERENT GitHub + Amazon IPs, same two providers.
        let set_b = ["140.82.127.200:443", "13.35.255.1:443"];
        let line_a = internet_egress_line(set_a, &db).unwrap();
        let line_b = internet_egress_line(set_b, &db).unwrap();
        assert_eq!(
            line_a, line_b,
            "same providers → byte-identical line across IP rotation"
        );
        assert_eq!(
            line_a,
            "INTERNET egress: Amazon [AS16509], GitHub [AS36459]"
        );
        // And duplicate IPs within one window collapse (dedup) — three GitHub IPs, one entry.
        let deduped = internet_egress_line(
            ["140.82.112.1:443", "140.82.120.2:443", "140.82.127.3:443"],
            &db,
        )
        .unwrap();
        assert_eq!(deduped, "INTERNET egress: GitHub [AS36459]");
    }

    #[test]
    fn cross_tenant_is_true_only_for_a_resolved_peer_in_a_different_namespace() {
        // A resolved peer in ANOTHER namespace than the source is cross-tenant (JEF-319).
        assert!(is_cross_tenant("frontend", "backend/api:8080 (10.42.3.9)"));
        assert!(is_cross_tenant(
            "frontend",
            "kube-system/kube-dns:53 (10.96.0.10)"
        ));
        // NEGATIVE: a peer in the SAME namespace as the source is ordinary in-namespace
        // traffic — never cross-tenant.
        assert!(!is_cross_tenant(
            "frontend",
            "frontend/cache:6379 (10.42.1.4)"
        ));
        // NEGATIVE: an unresolved bare IP:port (internet or unresolved in-cluster) has no
        // namespace — it must never look cross-tenant.
        assert!(!is_cross_tenant("frontend", "203.0.113.7:443"));
        assert!(!is_cross_tenant("frontend", "10.42.1.159:8086"));
        assert!(!is_cross_tenant("frontend", "[2606:4700::1111]:443"));
        // NEGATIVE: an IMDS peer is a bare IP, not a resolved label — not cross-tenant.
        assert!(!is_cross_tenant("frontend", "169.254.169.254:80"));
    }

    #[test]
    fn resolved_peer_namespace_reads_only_the_label_segment() {
        assert_eq!(
            resolved_peer_namespace("backend/api:8080 (10.42.3.9)"),
            Some("backend")
        );
        assert_eq!(
            resolved_peer_namespace("default/kubernetes:443 (10.96.0.1)"),
            Some("default")
        );
        // Bare IP:port peers carry no namespace.
        assert_eq!(resolved_peer_namespace("203.0.113.7:443"), None);
        assert_eq!(resolved_peer_namespace("169.254.169.254:80"), None);
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
