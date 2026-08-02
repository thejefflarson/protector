//! Finding skeletons shared across preview scenarios.

use protector::engine::reason::adjudicate::incident::Assessment;
use protector::engine::state::{
    CutRow, CveEvidence, EntryEvidence, Finding, IncidentSummary, PathStep,
};
use protector_behavior::Behavior;

/// A single proven-chain hop, terse to build.
pub(crate) fn hop(from: &str, relation: &str, to: &str) -> PathStep {
    PathStep {
        from: from.into(),
        relation: relation.into(),
        to: to.into(),
    }
}

/// Build the BREACH finding: an internet-facing front door with a multi-hop proven path, a
/// KEV + CVSS + EPSS CVE, a runtime alert, and a proposed cut. The verdict is set on the
/// verdict store (not the row) so it resolves exactly like the engine resolves it at snapshot.
pub(crate) fn breach_finding() -> Finding {
    let evidence = EntryEvidence {
        cves: vec![CveEvidence {
            id: "CVE-2024-3094".into(),
            severity: "critical".into(),
            score: Some("10.0".into()),
            kev: true,
            epss: Some("94%".into()),
            reachability: "loaded-at-runtime".into(),
            fix: "fix available: 5.6.0 to 5.6.1".into(),
            title: Some("xz/liblzma backdoor — pre-auth RCE via sshd".into()),
        }],
        runtime: vec![
            Behavior::Alert {
                rule: "Reverse shell spawned in container".into(),
            },
            Behavior::ProcessExec {
                path: "/bin/sh".into(),
                exe_anon_inode: false,
            },
            Behavior::NetworkConnection {
                peer: "185.220.101.4:9001".into(),
                internet: true,
            },
        ],
        exposed_secrets: vec![],
        misconfigs: vec![],
        rbac_findings: vec![],
    };
    Finding {
        entry: "deployment/edge/api-gateway".into(),
        objective: "secret/payments/stripe-live-key".into(),
        attack: protector::engine::graph::attack::CREDENTIAL_ACCESS,
        foothold: true,
        corroborated: true,
        disposition: "auto-eligible".into(),
        cut: Some(
            "deployment/edge/api-gateway -[reaches/Tcp/5432]-> statefulset/payments/ledger-db"
                .into(),
        ),
        breach_relevant: true,
        // Resolved from the verdict store at snapshot — left None on the row.
        verdict: None,
        path: vec![
            hop(
                "deployment/edge/api-gateway",
                "reaches/Tcp/5432",
                "statefulset/payments/ledger-db",
            ),
            hop(
                "statefulset/payments/ledger-db",
                "mounts",
                "secret/payments/stripe-live-key",
            ),
        ],
        paths: vec![],
        paths_truncated: false,
        evidence,
        recency: None,
        node: None,
        // A model-chosen cut-set (ADR-0034): the entry front door plus the downstream
        // workload it pivots through — demonstrates the finding detail's cut-set list.
        incident: Some(IncidentSummary {
            assessment: Assessment::Attack,
            cuts: vec![
                CutRow {
                    node: "deployment/edge/api-gateway".into(),
                    mechanism: "add a scoped deny NetworkPolicy/AuthorizationPolicy",
                    is_entry: true,
                    blast_note: "blast radius: no alive collateral".into(),
                },
                CutRow {
                    node: "statefulset/payments/ledger-db".into(),
                    mechanism: "quarantine the compromised workload with a default-deny NetworkPolicy",
                    is_entry: false,
                    blast_note: "blast radius: 1 alive workload(s) affected".into(),
                },
            ],
        }),
        // The adversary-reach annotation (ADR-0040) — demonstrates the finding detail's
        // "adversary reach" section.
        reach: Some(
            "if compromised, this workload grants the attacker: a database-credential secret; \
             1 reachable data store, 1 reachable RBAC capability, and an internet egress path"
                .into(),
        ),
    }
}

/// A plain breach-relevant finding skeleton (single hop) used for the awaiting / uncertain /
/// cleared rows. Evidence is left empty for these (the row renders an honest "no evidence").
pub(crate) fn simple_finding(entry: &str, objective: &str) -> Finding {
    Finding {
        entry: entry.into(),
        objective: objective.into(),
        attack: protector::engine::graph::attack::CREDENTIAL_ACCESS,
        foothold: entry.contains("edge") || entry.contains("ingress"),
        corroborated: false,
        disposition: "structural — propose".into(),
        cut: Some(format!("{entry} -[reaches/Tcp/443]-> {objective}")),
        breach_relevant: true,
        verdict: None,
        path: vec![hop(entry, "reaches/Tcp/443", objective)],
        paths: vec![],
        paths_truncated: false,
        evidence: EntryEvidence::default(),
        recency: None,
        node: None,
        incident: None,
        reach: None,
    }
}

/// A wide, NO-CUT finding: an internet-facing front door reaching one secret via TWO
/// redundant backends, so no single edge severs the objective. Showcases the multi-path detail —
/// both proven paths stacked, and the "reachable via N redundant paths" reason line.
pub(crate) fn redundant_finding() -> Finding {
    let entry = "deployment/edge/webhook-router";
    let objective = "secret/app/shared-creds";
    let path_via_db = vec![
        hop(entry, "reaches/Tcp/5432", "statefulset/app/ledger-db"),
        hop("statefulset/app/ledger-db", "mounts", objective),
    ];
    let path_via_cache = vec![
        hop(entry, "reaches/Tcp/6379", "deployment/app/cache"),
        hop("deployment/app/cache", "mounts", objective),
    ];
    Finding {
        entry: entry.into(),
        objective: objective.into(),
        attack: protector::engine::graph::attack::DATA_FROM_REPOSITORY,
        foothold: true,
        corroborated: false,
        disposition: "no-cut".into(),
        // No single edge severs the chain — the redundant paths ARE the reason.
        cut: None,
        breach_relevant: true,
        verdict: None,
        path: path_via_db.clone(),
        paths: vec![path_via_db, path_via_cache],
        paths_truncated: false,
        evidence: EntryEvidence::default(),
        recency: None,
        node: None,
        incident: None,
        reach: None,
    }
}
