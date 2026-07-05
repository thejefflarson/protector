//! Adjudicator unit tests, group 2: the model-call path — the null adjudicator, the
//! "every breach-relevant entry is handed to the model" invariant (JEF-134), judgement
//! journaling, and the live-model calibration gate. Split from the adjudicate tests
//! purely to keep every file under the 1,000-line cap (repo CLAUDE.md).
#![allow(unused_imports)]

use super::super::guards::{ns_marker, objective_reach};
use super::super::*;
use super::{critical_cve, entry_reaching_db, graph_with_vuln, objectives_of};
use crate::engine::graph::attack::{AttackRef, EXPLOIT_PUBLIC_FACING};
use crate::engine::graph::{
    Edge, Exposure, Grade, Image, Node, NodeKey, Provenance, Relation, SecurityGraph, Severity,
    Trust, Vulnerability, Workload,
};
use crate::engine::observe::adapter::{build_graph, default_adapters};
use crate::engine::observe::{Attribution, ImageVulnerabilities, RuntimeObservation, Snapshot};
use crate::engine::reason::proof::{ProvenChain, prove};
use serde_json::json;
use std::time::SystemTime;

#[tokio::test]
async fn null_adjudicator_confirms() {
    let graph = build_graph(&Snapshot::default(), &default_adapters());
    let chain = ProvenChain {
        entry: NodeKey("workload/app/Pod/x".into()),
        objective: NodeKey("secret/app/s".into()),
        attack: EXPLOIT_PUBLIC_FACING,
        foothold: Some(EXPLOIT_PUBLIC_FACING),
        corroborated: true,
        adjudicated: true,
        promoted: false,
        exposed_entry: true,
        verdict: None,
        links: vec![],
        paths: vec![],
        paths_truncated: false,
        single_edge_cuts: vec![],
        quarantine_targets: vec![],
    };
    assert_eq!(
        NullAdjudicator
            .judge(&chain.entry, &objectives_of(&chain), &graph)
            .await,
        Verdict::Confirmed
    );
}

/// JEF-134: the deterministic pre-decision is GONE. An entry that under the old
/// promotion-ground filter would have been refuted WITHOUT a model call — a same-ns
/// own-app DB over the network, no CVE, no alert, a Collection (not high-severity)
/// objective — must now be HANDED TO THE MODEL like every other breach-relevant entry.
/// The engine no longer pre-decides; whether this is a breach is the model's call. We
/// point the adjudicator at an unroutable endpoint: reaching the model call (and so
/// returning the skeptic `Uncertain("model unavailable")` rather than a deterministic
/// `Refuted`) proves there is no pre-call short-circuit.
#[tokio::test]
async fn every_breach_relevant_entry_is_handed_to_the_model() {
    use crate::engine::graph::attack::DATA_FROM_REPOSITORY;
    // Same-namespace DB over the network, Collection tactic: no CVE, no alert, no
    // high-severity outcome, no [cross-ns] reach — the old "zero-ground" entry the
    // pre-filter used to refute outright.
    let (g, entry, objs) = entry_reaching_db("app", "app", "postgres-0", DATA_FROM_REPOSITORY);
    // Sanity: this is genuinely the authorized/own-app shape (the model, not the
    // engine, must now decide it is not a breach).
    assert_eq!(objective_reach(&g, &objs[0].0), "NETWORK");
    assert_eq!(ns_marker(&entry, &objs[0].0), "same-ns");

    // An endpoint that can never answer: if the model were skipped (the old behavior),
    // `judge` would return a deterministic `Refuted`; reaching the failing call yields
    // `Uncertain("model unavailable")` instead, proving the model IS consulted.
    let adjudicator = ModelAdjudicator::new("http://127.0.0.1:1/v1/chat/completions", "none");
    let verdict = adjudicator.judge(&entry, &objs, &g).await;
    assert_eq!(
        verdict,
        Verdict::Uncertain("model unavailable".to_string()),
        "the engine no longer pre-decides — every breach-relevant entry reaches the model"
    );
}

/// With a journal attached, every judgement is captured in the judgement record WITH the full
/// prompt the model saw — there is no longer a prompt-less pre-filter refute (JEF-134
/// retired it). Both an own-app entry and a cross-ns entry record the prompt they built;
/// the reply is `None` here only because the endpoint is unreachable. This is the
/// diagnostic the operator reads to see why an entry was judged the way it was.
#[tokio::test]
async fn judgements_are_journaled_with_prompt_and_verdict() {
    use crate::engine::graph::attack::DATA_FROM_REPOSITORY;
    let journal = std::sync::Arc::new(crate::engine::state::JudgementLog::new());
    let adjudicator = ModelAdjudicator::new("http://127.0.0.1:1/v1/chat/completions", "none")
        .with_journal(journal.clone());

    // An own-app same-ns entry — formerly refuted without a model call; now judged.
    let (g, entry, objs) = entry_reaching_db("app", "app", "postgres-0", DATA_FROM_REPOSITORY);
    adjudicator.judge(&entry, &objs, &g).await;

    // A cross-ns entry — also judged.
    let (g2, entry2, objs2) =
        entry_reaching_db("app", "billing", "ledger-db", DATA_FROM_REPOSITORY);
    adjudicator.judge(&entry2, &objs2, &g2).await;

    let recorded = journal.snapshot(); // newest-first
    assert_eq!(recorded.len(), 2, "both judgements captured");

    // BOTH entries now record the full prompt the model saw — no prompt-less shortcut.
    for j in &recorded {
        assert!(
            j.prompt.as_deref().is_some_and(|p| p.contains(&j.entry)),
            "every judgement records the full prompt the model saw (no pre-filter shortcut)"
        );
        assert!(j.reply.is_none(), "endpoint unreachable → no reply");
        assert!(
            j.verdict.contains("Uncertain"),
            "model unreachable → skeptic Uncertain, not a deterministic Refuted"
        );
    }
    let entries: std::collections::HashSet<&str> =
        recorded.iter().map(|j| j.entry.as_str()).collect();
    assert!(entries.contains(entry.0.as_str()) && entries.contains(entry2.0.as_str()));
}

/// Exercises the *real* judgement path (build_judgment_prompt → a real model →
/// parse_verdict) against an OpenAI-compatible endpoint, on a genuinely toxic
/// chain vs an unevidenced one. Gated — `cargo test`/CI skip it; run with e.g.
///   PROTECTOR_E2E_MODEL=http://localhost:11434/v1/chat/completions \
///   PROTECTOR_E2E_MODEL_NAME=qwen2.5:1.5b \
///   cargo nextest run real_model_judges -- --ignored --nocapture
#[tokio::test]
#[ignore = "needs a real model endpoint (PROTECTOR_E2E_MODEL)"]
async fn real_model_judges_toxic_vs_unevidenced() {
    let Ok(endpoint) = std::env::var("PROTECTOR_E2E_MODEL") else {
        eprintln!("skipping: set PROTECTOR_E2E_MODEL to a chat-completions endpoint");
        return;
    };
    let model = std::env::var("PROTECTOR_E2E_MODEL_NAME").unwrap_or_else(|_| "qwen2.5:1.5b".into());
    let adjudicator = ModelAdjudicator::new(&endpoint, &model);

    // An internet-exposed `web` (LoadBalancer) that mounts a session-key secret;
    // optionally carrying a critical, exploited-in-wild CVE (log4shell).
    let exposed_chain = |with_cve: bool| {
        let web = serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
            "spec": {"containers": [{
                "name": "web", "image": "web:1",
                "envFrom": [{"secretRef": {"name": "session-key"}}]
            }]}
        }))
        .unwrap();
        let lb = serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "web-lb", "namespace": "app"},
            "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
        }))
        .unwrap();
        let image_vulns = if with_cve {
            vec![ImageVulnerabilities {
                image: "web:1".into(),
                vulnerabilities: vec![Vulnerability {
                    id: "CVE-2021-44228".into(),
                    severity: Severity::Critical,
                    exploited_in_wild: true,
                    epss: None,
                    sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                    ..Default::default()
                }],
            }]
        } else {
            vec![]
        };
        let snap = Snapshot {
            pods: vec![web],
            services: vec![lb],
            secrets: vec![crate::engine::observe::SecretMeta {
                namespace: "app".into(),
                name: "session-key".into(),
            }],
            image_vulns,
            ..Default::default()
        };
        let graph = build_graph(&snap, &default_adapters());
        let chain = prove(&graph)
            .into_iter()
            .find(|c| {
                c.entry.0 == "workload/app/Pod/web" && c.objective.0 == "secret/app/session-key"
            })
            .expect("exposed chain to the secret");
        (graph, chain)
    };

    let (g_toxic, toxic) = exposed_chain(true);
    let toxic_verdict = adjudicator
        .judge(&toxic.entry, &objectives_of(&toxic), &g_toxic)
        .await;
    eprintln!("[{model}] exposed + critical KEV CVE -> secret : {toxic_verdict:?}");

    let (g_bare, bare) = exposed_chain(false);
    let bare_verdict = adjudicator
        .judge(&bare.entry, &objectives_of(&bare), &g_bare)
        .await;
    eprintln!("[{model}] exposed, NO cve / NO runtime -> secret: {bare_verdict:?}");

    // A competence probe for "can this model be the analyst" — the speculative
    // (no-CVE) lane needs a model that PROMOTES the toxic chain yet shows
    // RESTRAINT on the unevidenced one. Empirically, small local models (≤3B)
    // do one or the other depending on framing, not both. We classify rather
    // than hard-fail (this is an eval, run manually against candidate models);
    // the architecture — deterministic foothold floor + reversible, self-
    // reverting action — is what keeps a miscalibrated analyst survivable.
    let acts_on_toxic = toxic_verdict.promotes();
    let restrains_on_bare = !bare_verdict.promotes();
    let verdict = match (acts_on_toxic, restrains_on_bare) {
        (true, true) => "CALIBRATED — usable as the speculative-lane analyst",
        (true, false) => "OVER-EAGER — promotes unevidenced paths; unsafe for the speculative lane",
        (false, true) => "TIMID — won't act even on log4shell; useless for promotion",
        (false, false) => "INCOHERENT",
    };
    eprintln!("[{model}] analyst competence: {verdict}");

    // Calibration GATE (JEF-109). When this gated test is run against a candidate
    // model as the pre-swap check (see docs/model-calibration.md), the two anchor
    // cases are hard requirements, not just a classification print: a model that
    // fails either is not allowed in prod. (a) The log4shell chain — a critical,
    // exploited-in-wild CVE loaded at runtime — MUST promote (`Exploitable`); a model
    // that won't act on the textbook KEV case is useless for the speculative lane.
    assert!(
        matches!(toxic_verdict, Verdict::Exploitable(_)),
        "calibration gate: a critical KEV CVE (log4shell) loaded at runtime must be \
             Exploitable, got {toxic_verdict:?} from {model}"
    );
    // (b) The same chain WITHOUT a CVE or runtime evidence — only an own-namespace
    // [MOUNTED] secret — MUST refute; a model that promotes here is over-eager and
    // would manufacture unevidenced cuts.
    assert!(
        matches!(bare_verdict, Verdict::Refuted(_)),
        "calibration gate: an unevidenced own-app [MOUNTED] secret must be Refuted, \
             got {bare_verdict:?} from {model}"
    );

    // (c) JEF-134 argo anchor — the live false positive this ticket fixes. An
    // internet-facing controller whose ServiceAccount is RBAC-granted secrets across
    // MANY tenant namespaces (broad, some high-impact), with NO CVE and NO runtime
    // signal. Every objective is [RBAC-GRANTED] — authorized by design — so it is NOT a
    // breach however broad or severe. A model that promotes this (the granite4:3b-h
    // confabulation that copied a [NETWORK][cross-ns] example reason onto argo) fails the
    // gate. Built directly: an Identity with CanDo grants to secrets in several
    // namespaces, the entry exposed to the internet, no image/CVE, no behavior.
    let argo_verdict = {
        use crate::engine::graph::attack::{CREDENTIAL_ACCESS, DATA_DESTRUCTION};
        use crate::engine::graph::{
            Edge, Exposure, Grade, Identity, Node, Relation, SecretRef, SecurityGraph, Workload,
        };
        let proof_edge = |relation| Edge {
            relation,
            provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
            grade: Grade::Proof,
        };
        let mut g = SecurityGraph::new();
        let entry = Node::Workload(Workload {
            namespace: "argocd".into(),
            name: "argocd-server".into(),
            kind: "Pod".into(),
            labels: Default::default(),
            meshed: false,
            exposure: Exposure::Internet,
            runtime: Vec::new(),
            persistent: false,
            misconfigs: vec![],
            rbac_findings: vec![],
        });
        let entry_key = entry.key();
        let e = g.upsert_node(entry);
        let sa = g.upsert_node(Node::Identity(Identity {
            namespace: "argocd".into(),
            name: "argocd-server".into(),
        }));
        g.add_edge(e, sa, proof_edge(Relation::RunsAs));
        // A broad ClusterRole-style grant: read secrets across several tenants, plus a
        // high-impact verb (delete pvcs) — all RBAC-GRANTED, none a breach.
        let grant = |g: &mut SecurityGraph, ns: &str, name: &str, verb: &str| {
            let secret = Node::Secret(SecretRef {
                namespace: ns.into(),
                name: name.into(),
            });
            let key = secret.key();
            let s = g.upsert_node(secret);
            g.add_edge(
                sa,
                s,
                proof_edge(Relation::CanDo {
                    verb: verb.into(),
                    resource: "secrets".into(),
                }),
            );
            key
        };
        let objectives = vec![
            (
                grant(&mut g, "argocd", "argocd-redis", "get"),
                CREDENTIAL_ACCESS,
            ),
            (
                grant(&mut g, "analytics", "postgres.credentials", "get"),
                CREDENTIAL_ACCESS,
            ),
            (grant(&mut g, "finance", "stripe", "get"), CREDENTIAL_ACCESS),
            // The high-impact objective that tripped the old deterministic high-severity
            // ground regardless of it being RBAC-authorized — now the model's call.
            (
                grant(&mut g, "data", "pvc-store", "delete"),
                DATA_DESTRUCTION,
            ),
        ];
        // Sanity: every objective really is [RBAC-GRANTED] (authorized), not [NETWORK].
        for (k, _) in &objectives {
            assert_eq!(objective_reach(&g, k), "RBAC-GRANTED");
        }
        adjudicator.judge(&entry_key, &objectives, &g).await
    };
    eprintln!("[{model}] argo: broad RBAC-granted secrets, NO cve/behavior: {argo_verdict:?}");
    assert!(
        matches!(argo_verdict, Verdict::Refuted(_)),
        "calibration gate (JEF-134 argo anchor): broad RBAC-granted access with no \
             exploit evidence is authorized-by-design and must be Refuted, got {argo_verdict:?} \
             from {model}"
    );
}
