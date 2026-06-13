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
//! [`hypothesis`]ize candidates the proof gate confirms, and [`adjudicate`] a
//! full-bar chain with a one-way veto — reconcile proposed mitigations as
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
pub mod graphviz;
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
use std::collections::HashSet;

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
        Self {
            adapters: adapter::default_adapters(),
            active,
            actuator,
            hypothesizer,
            adjudicator,
            findings: std::sync::Arc::new(dashboard::Findings::new()),
            previous: GraphSnapshot::default(),
            ledger: MitigationLedger::new(),
            actions: ActionLog::new(),
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

        // Adjudicate (ADR-0008 + ADR-0011). The model is consulted ONLY where there
        // is evidence to weigh — never on an evidence-empty chain (asking a model to
        // judge "(no CVE), (no runtime)" invents threats from nothing). Two lanes:
        // - Corroborated chain (runtime evidence) → veto path: a non-confirming
        //   verdict downgrades it to a proposal. The model can only subtract.
        // - Proven FOOTHOLD (internet-exposed ∧ exploited-in-wild/critical CVE ∧
        //   reachable — i.e. log4shell) → auto-promote UNLESS the model *confidently
        //   refutes* it. Uncertain / no model leaves the deterministic foothold to
        //   govern, so a weak local model can't silently block a known foothold.
        // A chain with neither runtime nor a foothold has no exploitation evidence —
        // it stays a deterministic latent/structural proposal; the model isn't asked.
        for chain in chains.iter_mut() {
            if chain.corroborated {
                let verdict = self.adjudicator.judge(chain, &graph).await;
                if !verdict.is_confirmed() {
                    chain.adjudicated = false;
                    tracing::info!(
                        entry = %chain.entry.0,
                        objective = %chain.objective.0,
                        "adjudicator vetoed auto-action; downgraded to proposal"
                    );
                }
            } else if self.active.judgement_enabled()
                && chain.foothold.is_some()
                && !chain.single_edge_cuts.is_empty()
            {
                let verdict = self.adjudicator.judge(chain, &graph).await;
                if let adjudicate::Verdict::Refuted(reason) = &verdict {
                    tracing::info!(
                        entry = %chain.entry.0,
                        objective = %chain.objective.0,
                        %reason,
                        "adjudicator refuted foothold; left as proposal"
                    );
                } else {
                    chain.promoted = true;
                    tracing::warn!(
                        entry = %chain.entry.0,
                        objective = %chain.objective.0,
                        foothold = chain.foothold.map(|f| f.technique_id),
                        "foothold promoted to auto-action (exposed + exploited/critical CVE, ADR-0011)"
                    );
                }
            }
        }
        // Publish the current findings for the dashboard (the latent-foothold rows
        // are the weaker, propose-only case a human acts on).
        self.findings
            .replace(chains.iter().map(dashboard::Finding::from_chain).collect());
        // The attack graph (internet → goal) for the /graph view — collapses the
        // per-objective fan-out the flat list explodes into.
        self.findings
            .replace_graph(graphviz::attack_graph_dot(&graph, &chains));

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

/// Choose the hypothesis source: a model-backed one when `PROTECTOR_ENGINE_MODEL`
/// names an OpenAI-compatible endpoint (a local Ollama by default), else the null
/// source. Local-first: point it at an in-cluster model so the graph never leaves.
fn build_hypothesizer() -> Box<dyn hypothesis::HypothesisSource> {
    match std::env::var("PROTECTOR_ENGINE_MODEL") {
        Ok(endpoint) if !endpoint.is_empty() => {
            let model = std::env::var("PROTECTOR_ENGINE_MODEL_NAME")
                .unwrap_or_else(|_| "qwen2.5:3b".to_string());
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

/// Choose the adjudicator (ADR-0008): a model-backed judge when a model endpoint
/// is configured (the same `PROTECTOR_ENGINE_MODEL` as the hypothesis source),
/// else the null adjudicator (confirm everything — the deterministic bar governs).
fn build_adjudicator() -> Box<dyn adjudicate::Adjudicator> {
    match std::env::var("PROTECTOR_ENGINE_MODEL") {
        Ok(endpoint) if !endpoint.is_empty() => {
            let model = std::env::var("PROTECTOR_ENGINE_MODEL_NAME")
                .unwrap_or_else(|_| "qwen2.5:3b".to_string());
            tracing::info!("adjudicator: model-backed (one-way veto)");
            Box::new(adjudicate::ModelAdjudicator::new(endpoint, model))
        }
        _ => Box::new(adjudicate::NullAdjudicator),
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
    use futures::FutureExt;
    use futures::stream::{StreamExt, select_all};
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
    let mut changes = select_all([
        reflector(
            pods_w,
            watcher(Api::<Pod>::all(client.clone()), cfg.clone()),
        )
        .touched_objects()
        .map(|_| ())
        .boxed(),
        reflector(
            netpols_w,
            watcher(Api::<NetworkPolicy>::all(client.clone()), cfg.clone()),
        )
        .touched_objects()
        .map(|_| ())
        .boxed(),
        reflector(
            services_w,
            watcher(Api::<Service>::all(client.clone()), cfg.clone()),
        )
        .touched_objects()
        .map(|_| ())
        .boxed(),
        reflector(
            secrets_w,
            watcher(Api::<Secret>::all(client.clone()), cfg.clone()),
        )
        .touched_objects()
        .map(|_| ())
        .boxed(),
        reflector(
            roles_w,
            watcher(Api::<Role>::all(client.clone()), cfg.clone()),
        )
        .touched_objects()
        .map(|_| ())
        .boxed(),
        reflector(
            rolebindings_w,
            watcher(Api::<RoleBinding>::all(client.clone()), cfg.clone()),
        )
        .touched_objects()
        .map(|_| ())
        .boxed(),
        reflector(
            clusterroles_w,
            watcher(Api::<ClusterRole>::all(client.clone()), cfg.clone()),
        )
        .touched_objects()
        .map(|_| ())
        .boxed(),
        reflector(
            clusterrolebindings_w,
            watcher(Api::<ClusterRoleBinding>::all(client.clone()), cfg.clone()),
        )
        .touched_objects()
        .map(|_| ())
        .boxed(),
    ]);

    tracing::info!("engine: watching cluster (event-driven)");
    loop {
        // Wake on either a cluster change or a Falco alert.
        tokio::select! {
            next = changes.next() => if next.is_none() { break },
            _ = falco_rx.recv() => {},
        }
        // Coalesce a burst (e.g. a Deployment rollout, or a flurry of alerts).
        while changes.next().now_or_never().flatten().is_some() {}
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
