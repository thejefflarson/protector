//! The asynchronous mitigation engine.
//!
//! Distinct from the admission webhook (see the crate root): the webhook is the
//! synchronous *floor*; the engine is the out-of-band loop that watches observed
//! cluster state, proves which changes open real attack chains, and — in hard
//! mode — cuts them. See `docs/adr/0001`–`0004` for the decisions behind it.
//!
//! [`Engine::process`] runs the five-question pipeline against one observed
//! snapshot: build the [`graph`], diff it (Q1, [`delta`]), assess health (Q3,
//! [`health`]), prove ATT&CK-tagged chains and cuts (Q2, [`proof`]) — a model may
//! [`hypothesis`]ize candidates the proof gate confirms, and [`adjudicate`] each
//! breach-relevant chain — the model judges exploitability, vetoing a live chain or
//! promoting an exposed one (ADR-0013) — reconcile proposed mitigations as
//! self-retiring debt (Q4/Q5, [`response`]), and gate + (closed-loop) actuate them
//! ([`actuator`]). [`run_watch`] drives it event-driven (the default); [`run`] is
//! the poll fallback.
//!
//! **Default posture is shadow mode**: with no action classes enabled and the
//! dry-run actuator, every decision is propose/forbid and nothing reaches the
//! cluster. What's left is integration behind ports that already exist and are
//! tested — the cluster/model I/O glue (watch streams, kube apply/delete, the
//! Falco receiver, the model call).

use std::time::Duration;

pub mod actuator;
pub mod adapter;
pub mod adjudicate;
pub mod attack;
pub mod dashboard;
pub mod delta;
pub mod exploit_intel;
pub mod graph;
pub mod health;
pub mod hypothesis;
pub mod model;
pub mod objective;
pub mod observe;
pub mod proof;
pub mod response;
pub mod runtime;
pub mod trivy;

use actuator::{
    ActionLog, Actuator, Decision, DryRunActuator, EnabledActions, decide, predict_blast_radius,
};
use adapter::Adapter;
use delta::GraphSnapshot;
use health::{Health, HealthProvider, PodStatusHealth};
use observe::Snapshot;
use response::MitigationLedger;
use std::collections::{HashMap, HashSet};

/// The engine's stateful processing core. It owns everything that persists across
/// observations — the prior graph state, the mitigation ledger, and the applied-
/// action log — and exposes one operation, [`Engine::process`], run once per
/// observed snapshot. Both the poll loop ([`run`]) and the event-driven observer
/// ([`run_watch`]) drive the same `process`, so the analysis is identical; only the
/// *trigger* differs.
pub struct Engine {
    adapters: Vec<Box<dyn Adapter>>,
    active: EnabledActions,
    actuator: Box<dyn Actuator>,
    hypothesizer: Box<dyn hypothesis::HypothesisSource>,
    adjudicator: Box<dyn adjudicate::Adjudicator>,
    findings: std::sync::Arc<dashboard::Findings>,
    previous: GraphSnapshot,
    ledger: MitigationLedger,
    actions: ActionLog,
    /// Cross-pass verdict cache, keyed by path `(entry, objective)` → (evidence
    /// fingerprint, the model's verdict). The model judges every breach-relevant path
    /// (ADR-0013), but a CPU-only local model is far too slow to re-run on every watch
    /// event; a path is re-judged only when its evidence fingerprint changes, and a
    /// brand-new path is judged because it's a new key. Pruned to currently-present
    /// paths each pass (ephemeral workloads, removed exposure).
    verdict_cache: HashMap<(String, String), (String, adjudicate::Verdict)>,
}

impl Engine {
    /// Build an engine with an explicit actuator, hypothesis source, and
    /// adjudicator. The binary passes a [`DryRunActuator`] when nothing is enabled
    /// and a live actuator otherwise, and model-backed source/adjudicator when a
    /// model is configured.
    pub fn new(
        active: EnabledActions,
        actuator: Box<dyn Actuator>,
        hypothesizer: Box<dyn hypothesis::HypothesisSource>,
        adjudicator: Box<dyn adjudicate::Adjudicator>,
    ) -> Self {
        if active.is_empty() {
            tracing::info!("engine: no action classes enabled (easy mode — proposals only)");
        } else {
            tracing::warn!("engine: action classes enabled — auto-application is on for them");
        }
        let findings = std::sync::Arc::new(dashboard::Findings::new());
        findings.set_armed(!active.is_empty());
        Self {
            adapters: adapter::default_adapters(),
            active,
            actuator,
            hypothesizer,
            adjudicator,
            findings,
            previous: GraphSnapshot::default(),
            ledger: MitigationLedger::new(),
            actions: ActionLog::new(),
            verdict_cache: HashMap::new(),
        }
    }

    /// A handle to the current findings, for the dashboard server to read.
    pub fn findings(&self) -> std::sync::Arc<dashboard::Findings> {
        self.findings.clone()
    }

    /// Run the five-question pipeline against one observed snapshot.
    ///
    /// Proof, ledger reconciliation, and the action decision run **every pass** —
    /// not only on a structural delta — because corroboration, vulnerability, and
    /// health facts can change a chain's status without changing the graph's shape
    /// (a Falco event is the motivating case: it flips a chain to fully
    /// corroborated without adding a node or edge). The structural delta only gates
    /// the *verbose reporting* (the Q1 threat-delta and per-chain logs), to keep a
    /// quiet cluster quiet.
    pub async fn process(&mut self, snapshot: &Snapshot) {
        let graph = adapter::build_graph(snapshot, &self.adapters);
        let current = GraphSnapshot::of(&graph);
        let health = PodStatusHealth.assess(snapshot);

        let delta = delta::diff(&self.previous, &current);
        let structurally_changed = !delta.is_empty();
        if structurally_changed {
            delta.emit();
            let (alive, degraded, halted) = health.counts();
            tracing::info!(alive, degraded, halted, "cluster health");
        }

        // Prove (Question 2) every pass. The deterministic enumerator finds the
        // structural chains; a model hypothesis source may *additionally* propose
        // candidates, which the confirmation gate accepts only if every link is a
        // real proof-grade edge ("a model may propose; only proof moves
        // privilege"). Confirmed model chains are merged, deduped by endpoints.
        let mut chains = proof::prove(&graph);
        let proposed = self.hypothesizer.propose(&graph).await;
        for confirmed in hypothesis::confirm_all(&graph, &proposed) {
            if !chains
                .iter()
                .any(|c| c.entry == confirmed.entry && c.objective == confirmed.objective)
            {
                chains.push(confirmed);
            }
        }

        // Publish the proven chains NOW, before the (CPU-bound, possibly slow or
        // unreachable) adjudication. The dashboard must always reflect the current
        // graph even while the model is judging or down — model latency must never
        // blank the findings view. The judging loop below enriches verdicts and
        // re-publishes; until it does, paths show as latent exposure (no verdict yet).
        self.findings
            .replace(chains.iter().map(dashboard::Finding::from_chain).collect());

        // Adjudicate (ADR-0013): the model is the JUDGE of every breach-relevant PATH,
        // always. The deterministic proof winnows to the paths an internet-facing
        // workload can actually reach (internet → entry → objective); the model then
        // makes the analyst's call on EACH one — is this reachability a real breach
        // risk, or legitimate? A path is risky two independent ways: an ACTIVE EXPLOIT
        // (a critical/KEV CVE or a live runtime signal), OR a STRUCTURAL EXPOSURE (the
        // objective is reachable from the internet when it shouldn't be — a
        // misconfiguration). So absence of a CVE is NOT safety: an internet-reachable
        // path to something sensitive is a finding on its own. Defense in depth —
        // every path is evaluated, every time the facts behind it change.
        //
        // Judged ONCE PER PATH (entry → objective) and cached across passes. The cache
        // is keyed by the path and invalidated by an evidence fingerprint (the entry's
        // CVEs/runtime/exposure), so a path is re-judged when a scan lands a new CVE —
        // and a brand-new path (e.g. a misconfig that newly exposes a secret) is judged
        // because it's a new key. A local CPU model is slow, so this caching is what
        // keeps steady state quiet; the findings were already published above, so a
        // slow or unavailable model never blocks the dashboard.
        //
        // Two consequences follow from the verdict:
        // - Corroborated chain (live runtime signal): a non-confirming verdict
        //   downgrades the eligible auto-action to a human proposal (the veto direction).
        // - Uncorroborated path: an affirmative `exploitable` verdict PROMOTES it to
        //   auto-eligible — but only when the `judgement` class is armed, since
        //   promoting on the model's say-so is the opt-in speculative lane.
        let current_paths: HashSet<(String, String)> = chains
            .iter()
            .filter(|c| c.is_breach_relevant())
            .map(|c| (c.entry.0.clone(), c.objective.0.clone()))
            .collect();
        for chain in chains.iter_mut() {
            if !chain.is_breach_relevant() {
                continue;
            }
            let path = (chain.entry.0.clone(), chain.objective.0.clone());
            let fingerprint = adjudicate::entry_fingerprint(&graph, chain);
            let verdict = match self.verdict_cache.get(&path) {
                Some((fp, v)) if *fp == fingerprint => v.clone(),
                _ => {
                    let v = self.adjudicator.judge(chain, &graph).await;
                    // An Uncertain is usually a transient model outage (e.g. a CPU-model
                    // timeout) — log it quietly and re-judge next pass rather than pin
                    // the failure into the cache. Decisive verdicts are logged + cached.
                    match &v {
                        adjudicate::Verdict::Uncertain(why) => {
                            tracing::debug!(entry = %chain.entry.0, objective = %chain.objective.0, %why, "adjudication inconclusive (will retry)");
                        }
                        decisive => {
                            tracing::info!(entry = %chain.entry.0, objective = %chain.objective.0, verdict = ?decisive, "adjudicated path");
                            self.verdict_cache.insert(path, (fingerprint, v.clone()));
                        }
                    }
                    v
                }
            };
            // Keep the model's call — positive *and* negative — on the chain so the
            // dashboard can show why it did or didn't act (not just the outcome).
            chain.verdict = Some(verdict.summary());
            if chain.corroborated {
                if !verdict.is_confirmed() {
                    chain.adjudicated = false;
                }
            } else if verdict.promotes() && self.active.judgement_enabled() {
                chain.promoted = true;
            }
        }
        // Drop verdicts for paths that no longer exist (ephemeral workloads, removed
        // exposure), so the cache tracks the live cluster rather than growing forever.
        self.verdict_cache
            .retain(|path, _| current_paths.contains(path));
        // Re-publish with the model's verdicts now attached — the enriched view
        // (promotions move into remediations; judged paths show the model's words).
        self.findings
            .replace(chains.iter().map(dashboard::Finding::from_chain).collect());

        if structurally_changed && !chains.is_empty() {
            tracing::info!(count = chains.len(), "proven chains");
            for chain in &chains {
                chain.emit();
                if chain.foothold.is_some() && health.of(&chain.entry) == Health::Alive {
                    tracing::warn!(
                        entry = %chain.entry.0,
                        objective = %chain.objective.0,
                        technique = chain.attack.technique_id,
                        "live foothold: exploitable entry is currently serving"
                    );
                }
            }
        }

        // Reconcile proposed mitigations against the current chains (Q4 and Q5).
        let ledger_delta = self.ledger.reconcile(&chains);
        if !ledger_delta.is_empty() {
            ledger_delta.emit();
        }
        let newly_proposed: HashSet<String> = ledger_delta
            .proposed
            .iter()
            .map(|m| m.cut_signature())
            .collect();

        // Decide over *all* active mitigations (Q4 hard mode), not just the
        // newly-proposed ones — so a corroboration flip on an existing proposal is
        // acted on. AutoApply is deduped by the action log; propose/forbid is logged
        // only for newly-proposed cuts to avoid per-pass spam.
        let active_mitigations: Vec<_> = self.ledger.active().cloned().collect();
        for mitigation in &active_mitigations {
            let blast = predict_blast_radius(mitigation, &graph, &health);
            match decide(mitigation, &self.active, &blast) {
                Decision::AutoApply => {
                    if !self.actions.is_active(mitigation) {
                        self.actuator.apply(mitigation).await;
                        self.actions
                            .record(mitigation.clone(), health.alive_workloads());
                    }
                }
                Decision::Propose(reason) => {
                    if newly_proposed.contains(&mitigation.cut_signature()) {
                        tracing::info!(%reason, "mitigation needs human approval");
                    }
                }
                Decision::Forbidden(reason) => {
                    if newly_proposed.contains(&mitigation.cut_signature()) {
                        tracing::info!(%reason, "mitigation not auto-enabled");
                    }
                }
            }
        }

        // Self-reverting closed loop, every pass: revert any applied action whose
        // protected workload went down (health divergence) or whose justifying
        // chain is no longer proven (posture improved).
        let justified: HashSet<String> = self.ledger.active().map(|m| m.cut_signature()).collect();
        for reversion in self.actions.reconcile(&health, &justified) {
            tracing::info!(reason = %reversion.reason, "reverting applied mitigation");
            self.actuator.revert(&reversion.mitigation).await;
        }

        self.previous = current;
    }
}

/// Poll loop: re-list the whole cluster every `interval`, assemble a snapshot, and
/// process it. The simple fallback for environments where a watch isn't available;
/// [`run_watch`] is the default. A stable cluster does no useful work here between
/// changes — it just re-lists — which is exactly why the watch path is preferred.
pub async fn run(
    client: kube::Client,
    interval: Duration,
    active: EnabledActions,
    kev: exploit_intel::KevCatalog,
) {
    let mut engine = Engine::new(
        active.clone(),
        build_actuator(&active, &client),
        build_hypothesizer(),
        build_adjudicator(),
    );
    loop {
        match Snapshot::observe(client.clone()).await {
            Ok(mut snapshot) => {
                kev.mark_exploited(&mut snapshot.image_vulns);
                engine.process(&snapshot).await;
            }
            Err(error) => tracing::warn!(%error, "observe failed; retaining previous state"),
        }
        tokio::time::sleep(interval).await;
    }
}

/// Choose the actuator. Dry-run when nothing is enabled (the engine can never touch
/// the cluster). Otherwise `PROTECTOR_ENGINE_ACTUATOR` selects the mechanism:
/// `networkpolicy` isolates the compromised workload with a default-deny
/// NetworkPolicy — works on flannel/kube-router (ADR-0010); `adminnetworkpolicy`
/// does a surgical ANP edge-cut on Cilium/Calico (ADR-0007); `dryrun` logs only.
///
/// Unknown/empty values **fail safe to dry-run** (with a warning), not to a live
/// actuator: a typo'd selector must never silently turn a shadow deployment into
/// one that mutates the cluster.
fn build_actuator(active: &EnabledActions, client: &kube::Client) -> Box<dyn Actuator> {
    if active.is_empty() {
        return Box::new(DryRunActuator);
    }
    match std::env::var("PROTECTOR_ENGINE_ACTUATOR")
        .unwrap_or_default()
        .trim()
    {
        "networkpolicy" | "net" => Box::new(actuator::IsolationActuator::new(client.clone())),
        "adminnetworkpolicy" | "anp" => Box::new(actuator::KubeActuator::new(client.clone())),
        "dryrun" => Box::new(DryRunActuator),
        other => {
            tracing::warn!(
                actuator = %other,
                "unknown PROTECTOR_ENGINE_ACTUATOR with an action class enabled; \
                 failing safe to dry-run (no cluster writes). \
                 Set 'networkpolicy', 'adminnetworkpolicy', or 'dryrun'."
            );
            Box::new(DryRunActuator)
        }
    }
}

/// The model endpoint + name, read once from `PROTECTOR_ENGINE_MODEL` /
/// `PROTECTOR_ENGINE_MODEL_NAME`. `None` when no endpoint is set (deterministic-only
/// — null hypothesizer and adjudicator). Shared by both model-backed builders so the
/// endpoint and the default model name have a single source of truth.
fn model_config() -> Option<(String, String)> {
    let endpoint = std::env::var("PROTECTOR_ENGINE_MODEL")
        .ok()
        .filter(|e| !e.is_empty())?;
    let name =
        std::env::var("PROTECTOR_ENGINE_MODEL_NAME").unwrap_or_else(|_| "qwen2.5:3b".to_string());
    Some((endpoint, name))
}

/// Choose the hypothesis source: a model-backed one when a model is configured AND
/// `PROTECTOR_ENGINE_HYPOTHESIS=model` opts it in, else the null source. Local-first:
/// point it at an in-cluster model so the graph never leaves.
fn build_hypothesizer() -> Box<dyn hypothesis::HypothesisSource> {
    // The model hypothesis source is OFF by default. The deterministic enumerator
    // already finds every structural chain at this cluster's scale (so model
    // proposals are redundant), and the hypothesis prompt sends the *whole graph* —
    // thousands of tokens, minutes of CPU inference on a Pi-class node — which would
    // block the engine loop every pass for no gain. Opt in with
    // `PROTECTOR_ENGINE_HYPOTHESIS=model` only where the model is fast enough; the
    // model's real job is adjudication (ADR-0013), wired separately below.
    let opt_in = std::env::var("PROTECTOR_ENGINE_HYPOTHESIS").as_deref() == Ok("model");
    match model_config() {
        Some((endpoint, model)) if opt_in => {
            tracing::info!(%endpoint, %model, "hypothesis source: model-backed (local tier)");
            Box::new(hypothesis::ModelHypothesizer::new(
                endpoint,
                model,
                hypothesis::Tier::Local,
            ))
        }
        _ => Box::new(hypothesis::NullHypothesizer),
    }
}

/// Choose the adjudicator (ADR-0013): a model-backed judge when a model endpoint is
/// configured, else the null adjudicator (confirm everything — the deterministic bar
/// governs). The model judges exploitability bidirectionally — vetoing a live chain
/// the deterministic bar would act on, or promoting an exposed one it wouldn't.
fn build_adjudicator() -> Box<dyn adjudicate::Adjudicator> {
    match model_config() {
        Some((endpoint, model)) => {
            tracing::info!(%model, "adjudicator: model-backed (judges exploitability — promote/veto)");
            Box::new(adjudicate::ModelAdjudicator::new(endpoint, model))
        }
        None => Box::new(adjudicate::NullAdjudicator),
    }
}

/// Event-driven observer: the default. Reflectors keep an in-memory store of each
/// watched resource current via `list`-then-`watch` (the periodic relist is the
/// resync floor ADR-0004 calls for). The engine reacts to *events* — it sits quiet
/// on a stable cluster and processes only when something actually changes, which
/// also means it catches **ephemeral** workloads (e.g. short-lived CI runners) a
/// poll between ticks would miss entirely.
///
/// The graph-building, proof, and response logic is identical to [`run`]; only the
/// trigger differs (event stream vs. timer). This path is exercised against a real
/// cluster, not unit tests — the analysis it drives is what the tests cover.
pub async fn run_watch(
    client: kube::Client,
    active: EnabledActions,
    falco_addr: Option<std::net::SocketAddr>,
    dashboard_addr: Option<std::net::SocketAddr>,
    kev: exploit_intel::KevCatalog,
) -> anyhow::Result<()> {
    use futures::stream::StreamExt;
    use k8s_openapi::api::core::v1::{Pod, Secret, Service};
    use k8s_openapi::api::networking::v1::NetworkPolicy;
    use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
    use kube::Api;
    use kube::runtime::{WatchStreamExt, reflector, watcher};

    let mut engine = Engine::new(
        active.clone(),
        build_actuator(&active, &client),
        build_hypothesizer(),
        build_adjudicator(),
    );

    // Findings dashboard (read-only): surfaces the proven chains, especially the
    // latent-foothold proposals a human acts on.
    if let Some(addr) = dashboard_addr {
        let findings = engine.findings();
        tokio::spawn(async move {
            if let Err(error) = dashboard::serve_dashboard(addr, findings).await {
                tracing::error!(%error, "dashboard stopped");
            }
        });
    }

    // Runtime evidence (Falco) is a stream, not a watched object: alerts land via
    // an HTTP endpoint falcosidekick POSTs to, are held in a TTL'd store, and wake
    // the loop so a "happening now" signal is acted on immediately (it flips a
    // chain's corroboration without changing the graph's shape). Signals expire, so
    // corroboration stays live.
    let runtime_events = std::sync::Arc::new(runtime::RuntimeEvents::new(
        std::time::Duration::from_secs(300),
    ));
    let (falco_tx, mut falco_rx) = tokio::sync::mpsc::channel::<()>(64);
    if let Some(addr) = falco_addr {
        let events = runtime_events.clone();
        tokio::spawn(async move {
            if let Err(error) = runtime::serve_falco(addr, events, falco_tx).await {
                tracing::error!(%error, "falco ingest stopped");
            }
        });
    }

    // A reflector per watched type: it owns a Store kept current as its stream is
    // polled, and yields a tick on every change. Merging the tick streams gives a
    // single "something changed" signal.
    let (pods, pods_w) = reflector::store::<Pod>();
    let (netpols, netpols_w) = reflector::store::<NetworkPolicy>();
    let (services, services_w) = reflector::store::<Service>();
    let (secrets, secrets_w) = reflector::store::<Secret>();
    let (roles, roles_w) = reflector::store::<Role>();
    let (rolebindings, rolebindings_w) = reflector::store::<RoleBinding>();
    let (clusterroles, clusterroles_w) = reflector::store::<ClusterRole>();
    let (clusterrolebindings, clusterrolebindings_w) = reflector::store::<ClusterRoleBinding>();

    let cfg = watcher::Config::default();
    // CRITICAL: each reflector runs in its OWN task so its Store stays current no
    // matter how long `process()` takes. Driving the watches inline in the loop (the
    // old design) meant a slow pass — e.g. a 30s model call — stopped reading the
    // apiserver watch streams; unread for that long they reset before the initial
    // LIST completed, so the stores never populated and the graph stayed empty. The
    // tasks ping `change_tx` on every touched object; the loop wakes on that.
    let (change_tx, mut change_rx) = tokio::sync::mpsc::channel::<()>(64);
    macro_rules! spawn_reflector {
        ($writer:expr, $typ:ty) => {{
            let tx = change_tx.clone();
            let api = Api::<$typ>::all(client.clone());
            let cfg = cfg.clone();
            tokio::spawn(
                reflector($writer, watcher(api, cfg))
                    .touched_objects()
                    .for_each(move |res| {
                        let tx = tx.clone();
                        async move {
                            if let Err(error) = res {
                                tracing::warn!(%error, kind = stringify!($typ), "watch error");
                            }
                            let _ = tx.try_send(());
                        }
                    }),
            );
        }};
    }
    spawn_reflector!(pods_w, Pod);
    spawn_reflector!(netpols_w, NetworkPolicy);
    spawn_reflector!(services_w, Service);
    spawn_reflector!(secrets_w, Secret);
    spawn_reflector!(roles_w, Role);
    spawn_reflector!(rolebindings_w, RoleBinding);
    spawn_reflector!(clusterroles_w, ClusterRole);
    spawn_reflector!(clusterrolebindings_w, ClusterRoleBinding);

    tracing::info!("engine: watching cluster (event-driven)");
    loop {
        // Wake on either a cluster change or a Falco alert.
        tokio::select! {
            next = change_rx.recv() => if next.is_none() { break },
            _ = falco_rx.recv() => {},
        }
        // Coalesce a burst (e.g. a Deployment rollout, or a flurry of alerts).
        while change_rx.try_recv().is_ok() {}
        while falco_rx.try_recv().is_ok() {}

        let snapshot = Snapshot {
            pods: pods.state().iter().map(|p| (**p).clone()).collect(),
            network_policies: netpols.state().iter().map(|n| (**n).clone()).collect(),
            services: services.state().iter().map(|s| (**s).clone()).collect(),
            secrets: secrets
                .state()
                .iter()
                .filter_map(|s| {
                    Some(observe::SecretMeta {
                        namespace: s.metadata.namespace.clone()?,
                        name: s.metadata.name.clone()?,
                    })
                })
                .collect(),
            roles: roles.state().iter().map(|r| (**r).clone()).collect(),
            role_bindings: rolebindings.state().iter().map(|r| (**r).clone()).collect(),
            cluster_roles: clusterroles.state().iter().map(|r| (**r).clone()).collect(),
            cluster_role_bindings: clusterrolebindings
                .state()
                .iter()
                .map(|r| (**r).clone())
                .collect(),
            // Vulnerabilities are listed best-effort on each pass (cheap, only when
            // something changed), then enriched with KEV exploit intel. Runtime
            // events are the live, TTL'd Falco signals.
            image_vulns: {
                let mut v = observe::list_image_vulns(&client).await;
                kev.mark_exploited(&mut v);
                v
            },
            runtime_events: runtime_events.current(),
        };
        engine.process(&snapshot).await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::adjudicate::Verdict;
    use crate::engine::graph::SecurityGraph;
    use crate::engine::observe::{SecretMeta, Snapshot};
    use crate::engine::proof::ProvenChain;
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// An adjudicator that counts how many times it's consulted (and confirms).
    struct CountingAdjudicator(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl adjudicate::Adjudicator for CountingAdjudicator {
        async fn judge(&self, _chain: &ProvenChain, _graph: &SecurityGraph) -> Verdict {
            self.0.fetch_add(1, Ordering::SeqCst);
            Verdict::Refuted("counted".into())
        }
    }

    /// An internet-exposed (LoadBalancer) web pod that mounts a secret, optionally
    /// carrying a critical CVE on its image (which makes it a proven foothold).
    fn exposed_snapshot(with_cve: bool) -> Snapshot {
        use crate::engine::graph::{Provenance, Severity, Vulnerability};
        use crate::engine::observe::ImageVulnerabilities;
        use std::time::SystemTime;

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
        Snapshot {
            pods: vec![web],
            services: vec![lb],
            secrets: vec![SecretMeta {
                namespace: "app".into(),
                name: "session-key".into(),
            }],
            image_vulns: if with_cve {
                vec![ImageVulnerabilities {
                    image: "web:1".into(),
                    vulnerabilities: vec![Vulnerability {
                        id: "CVE-2026-0001".into(),
                        severity: Severity::Critical,
                        exploited_in_wild: true,
                        epss: None,
                        sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                    }],
                }]
            } else {
                vec![]
            },
            ..Default::default()
        }
    }

    fn engine_with(counter: Arc<AtomicUsize>) -> Engine {
        Engine::new(
            EnabledActions::from_names(std::iter::empty::<&str>()),
            Box::new(DryRunActuator),
            Box::new(hypothesis::NullHypothesizer),
            Box::new(CountingAdjudicator(counter)),
        )
    }

    /// The model judges EVERY breach-relevant path, with or without a CVE — an
    /// internet-reachable path to a secret is a finding on its own (structural
    /// exposure), so absence of a CVE is not a reason to skip it (ADR-0013, defense in
    /// depth). The verdict is cached per path, so re-processing the same facts doesn't
    /// re-call the model.
    #[tokio::test]
    async fn judges_every_breach_relevant_path_even_without_a_cve() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut engine = engine_with(calls.clone());

        // Exposed, reaches a secret, NO CVE and NO runtime → still judged (structural).
        engine.process(&exposed_snapshot(false)).await;
        assert!(
            calls.load(Ordering::SeqCst) >= 1,
            "an internet-reachable path must be judged even with no CVE"
        );
        // The model's verdict is attached to the published finding.
        let findings = engine.findings().snapshot();
        assert!(
            findings
                .iter()
                .any(|f| f.breach_relevant && f.verdict.is_some()),
            "the judged breach path carries the model's verdict"
        );

        // Re-processing identical facts reuses the cached verdict — no new model call.
        let before = calls.load(Ordering::SeqCst);
        engine.process(&exposed_snapshot(false)).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before,
            "an unchanged path must not be re-judged (cache hit)"
        );
    }

    /// Findings are published even when adjudication can't run, so model latency or an
    /// outage never blanks the dashboard. With evidence present but the (counting)
    /// model refuting, the breach finding is still there.
    #[tokio::test]
    async fn publishes_findings_independent_of_the_model() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut engine = engine_with(calls.clone());
        engine.process(&exposed_snapshot(true)).await;
        let findings = engine.findings().snapshot();
        assert!(
            findings.iter().any(|f| f.breach_relevant),
            "the breach-relevant finding is published regardless of the verdict"
        );
    }
}
