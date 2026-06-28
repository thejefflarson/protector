//! Unit tests for the security graph (split out of `graph/mod.rs` to keep that file
//! under the 1,000-line cap, CLAUDE.md; behavior-preserving move, JEF-255 gate fix).

use super::*;

#[test]
fn canonical_image_converges_pod_and_scanner_forms() {
    // A pod's short ref and a scanner's fully-qualified ref for the SAME image
    // must canonicalize identically, or CVEs never attach (security fix [15]).
    let pod = canonical_image("nginx:alpine");
    eprintln!("canonical(nginx:alpine) = {pod}");
    assert_eq!(pod, canonical_image("docker.io/library/nginx:alpine"));
    assert_eq!(pod, canonical_image("index.docker.io/library/nginx:alpine"));
    // A digest pins identity regardless of how it's written.
    let d = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert_eq!(
        canonical_image(&format!("nginx@{d}")),
        canonical_image(&format!("docker.io/library/nginx@{d}"))
    );
    // A private-registry ref round-trips and stays distinct from docker.io.
    assert_eq!(
        canonical_image("ghcr.io/thejefflarson/api:1.2.3"),
        "ghcr.io/thejefflarson/api:1.2.3"
    );
    assert_ne!(
        canonical_image("nginx:alpine"),
        canonical_image("nginx:1.27")
    );
}

#[test]
fn fingerprint_key_collapses_connection_churn() {
    // The verdict cache is keyed on fingerprint_key; a high-cardinality behavior arm
    // would bust it every pass and starve the slow CPU model (ADR-0013). Connections
    // are the churny case — many distinct peers must collapse to a bounded set of
    // scope tokens, NOT one key per peer. This guards future arms from regressing it.
    use std::collections::HashSet;
    let keys: HashSet<String> = (0..1000)
        .flat_map(|i| {
            [
                Behavior::NetworkConnection {
                    peer: format!("10.0.0.{i}"),
                    internet: false,
                },
                Behavior::NetworkConnection {
                    peer: format!("93.184.{}.{}", i / 256, i % 256),
                    internet: true,
                },
            ]
        })
        .map(|b| b.fingerprint_key())
        .collect();
    // 2000 distinct peers → exactly two scope tokens.
    assert_eq!(
        keys,
        HashSet::from(["egress:cluster".into(), "egress:internet".into()])
    );
}

fn prov(source: &str) -> Provenance {
    Provenance::new(source, SystemTime::UNIX_EPOCH)
}

fn proof_edge(relation: Relation, source: &str) -> Edge {
    Edge {
        relation,
        provenance: prov(source),
        grade: Grade::Proof,
    }
}

#[test]
fn node_key_is_stable_across_fact_changes() {
    let clean = Node::Image(Image {
        digest: "sha256:abc".into(),
        reference: Some("ghcr.io/x:1".into()),
        trust: Trust::Unknown,
        vulnerabilities: vec![],
        exposed_secrets: vec![],
    });
    let scanned = Node::Image(Image {
        digest: "sha256:abc".into(),
        reference: Some("ghcr.io/x:1".into()),
        trust: Trust::Untrusted,
        vulnerabilities: vec![Vulnerability {
            id: "CVE-2026-0001".into(),
            severity: Severity::Critical,
            exploited_in_wild: true,
            epss: Some(0.9),
            sources: vec![prov("trivy"), prov("grype")],
            ..Default::default()
        }],
        exposed_secrets: vec![],
    });
    // Identity (digest) drives the key; facts (trust, vulns) do not.
    assert_eq!(clean.key(), scanned.key());
}

#[test]
fn node_key_constructors_match_node_key() {
    // The struct-free constructors the enrichment adapters use must produce exactly the
    // key `Node::key` derives from a full node — otherwise a finding silently fails to
    // attach (the security-fix [15] / JEF-244 attach bugs). Guards both arms that route
    // through a constructor.
    let image = Node::Image(Image {
        digest: "sha256:abc".into(),
        reference: Some("ghcr.io/x:1".into()),
        trust: Trust::Untrusted,
        vulnerabilities: vec![],
        exposed_secrets: vec![],
    });
    assert_eq!(NodeKey::image("sha256:abc"), image.key());

    let workload = Node::Workload(Workload {
        namespace: "app".into(),
        name: "web".into(),
        kind: "Pod".into(),
        labels: BTreeMap::new(),
        meshed: false,
        exposure: Exposure::Internal,
        runtime: vec![],
        persistent: false,
        misconfigs: vec![],
        rbac_findings: vec![],
    });
    assert_eq!(NodeKey::workload("app", "Pod", "web"), workload.key());
}

#[test]
fn upsert_replaces_in_place_and_keeps_edges() {
    let mut g = SecurityGraph::new();
    let img = g.upsert_node(Node::Image(Image {
        digest: "sha256:abc".into(),
        reference: None,
        trust: Trust::Unknown,
        vulnerabilities: vec![],
        exposed_secrets: vec![],
    }));
    let wl = g.upsert_node(Node::Workload(Workload {
        namespace: "app".into(),
        name: "api".into(),
        kind: "Pod".into(),
        labels: BTreeMap::new(),
        meshed: true,
        exposure: Exposure::Internet,
        runtime: vec![],
        persistent: false,
        misconfigs: vec![],
        rbac_findings: vec![],
    }));
    g.add_edge(wl, img, proof_edge(Relation::RunsImage, "kube"));
    assert_eq!(g.node_count(), 2);
    assert_eq!(g.edge_count(), 1);

    // Re-observe the image with a fresh vuln list: same node, edge intact.
    let img2 = g.upsert_node(Node::Image(Image {
        digest: "sha256:abc".into(),
        reference: None,
        trust: Trust::Untrusted,
        vulnerabilities: vec![Vulnerability {
            id: "CVE-2026-0001".into(),
            severity: Severity::High,
            exploited_in_wild: false,
            epss: None,
            sources: vec![prov("trivy")],
            ..Default::default()
        }],
        exposed_secrets: vec![],
    }));
    assert_eq!(img2, img, "upsert keeps the same index");
    assert_eq!(g.node_count(), 2, "no duplicate node");
    assert_eq!(g.edge_count(), 1, "edge survives the fact update");
    match g.node(img) {
        Some(Node::Image(i)) => assert_eq!(i.vulnerabilities.len(), 1),
        other => panic!("expected image node, got {other:?}"),
    }
}

#[test]
fn relations_map_to_attack_techniques() {
    // Attack-step edges carry their ATT&CK technique...
    assert_eq!(
        Relation::EscapesTo {
            via: "privileged".into()
        }
        .technique(),
        Some(super::attack::ESCAPE_TO_HOST)
    );
    assert_eq!(
        Relation::CanRead.technique(),
        Some(super::attack::CREDENTIAL_ACCESS)
    );
    assert_eq!(
        Relation::CanDo {
            verb: "get".into(),
            resource: "secrets".into()
        }
        .technique(),
        Some(super::attack::CREDENTIAL_ACCESS)
    );
    // ...structural substrate edges do not.
    assert_eq!(Relation::RunsAs.technique(), None);
    assert_eq!(
        Relation::Reaches {
            port: None,
            protocol: Protocol::Tcp
        }
        .technique(),
        None
    );
}

#[test]
fn grade_gates_what_may_move_privilege() {
    let proof = proof_edge(Relation::CanRead, "rbac");
    let hypo = Edge {
        relation: Relation::CanRead,
        provenance: prov("model"),
        grade: Grade::Hypothesis,
    };
    assert!(proof.is_proof_grade());
    assert!(!hypo.is_proof_grade());
}
