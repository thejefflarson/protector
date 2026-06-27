//! The engine's drivers: the event-driven observer ([`run_watch`], the default) and
//! the poll-loop fallback ([`run`]), plus the small builders that wire the actuator,
//! hypothesis source, and adjudicator from the environment. Split out of the engine
//! module root (`mod.rs`) purely to keep every file under the 1,000-line cap (repo
//! CLAUDE.md); the orchestration core ([`Engine::process`]) stays there. Both drivers
//! call the same `process`, so the analysis is identical — only the trigger differs.

use std::time::Duration;

use super::respond::actuator::{ActuationScope, Actuator, DryRunActuator, EnabledActions};
use super::{
    Engine, Snapshot, dashboard, journal, model, notify, observe, policy_log, reason, respond,
};

/// Poll loop: re-list the whole cluster every `interval`, assemble a snapshot, and
/// process it. The simple fallback for environments where a watch isn't available;
/// [`run_watch`] is the default. A stable cluster does no useful work here between
/// changes — it just re-lists — which is exactly why the watch path is preferred.
pub async fn run(
    client: kube::Client,
    interval: Duration,
    active: EnabledActions,
    scope: ActuationScope,
    kev: observe::exploit_intel::KevCatalog,
    advisory: observe::advisory::AdvisoryStore,
) {
    let mut engine = Engine::new(
        active.clone(),
        scope,
        build_actuator(&active, &client),
        build_hypothesizer(),
        // The timer path serves no dashboard, so there is nowhere to read a journal.
        build_adjudicator(None),
    );
    loop {
        match Snapshot::observe(client.clone()).await {
            Ok(mut snapshot) => {
                kev.mark_exploited(&mut snapshot.image_vulns);
                advisory.apply(&mut snapshot.image_vulns);
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
        "networkpolicy" | "net" => {
            Box::new(respond::actuator::IsolationActuator::new(client.clone()))
        }
        "adminnetworkpolicy" | "anp" => {
            Box::new(respond::actuator::KubeActuator::new(client.clone()))
        }
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
    model::config()
}

/// Choose the hypothesis source: a model-backed one when a model is configured AND
/// `PROTECTOR_ENGINE_HYPOTHESIS=model` opts it in, else the null source. Local-first:
/// point it at an in-cluster model so the graph never leaves.
fn build_hypothesizer() -> Box<dyn reason::hypothesis::HypothesisSource> {
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
            Box::new(reason::hypothesis::ModelHypothesizer::new(
                endpoint,
                model,
                reason::hypothesis::Tier::Local,
            ))
        }
        _ => Box::new(reason::hypothesis::NullHypothesizer),
    }
}

/// Choose the adjudicator (ADR-0013): a model-backed judge when a model endpoint is
/// configured, else the null adjudicator (confirm everything — the deterministic bar
/// governs). The model judges exploitability bidirectionally — vetoing a live chain
/// the deterministic bar would act on, or promoting an exposed one it wouldn't.
fn build_adjudicator(
    journal: Option<std::sync::Arc<dashboard::JudgementLog>>,
) -> Box<dyn reason::adjudicate::Adjudicator> {
    match model_config() {
        Some((endpoint, model)) => {
            tracing::info!(%model, "adjudicator: model-backed (judges exploitability — promote/veto)");
            let mut adjudicator = reason::adjudicate::ModelAdjudicator::new(endpoint, model);
            if let Some(journal) = journal {
                adjudicator = adjudicator.with_journal(journal);
            }
            Box::new(adjudicator)
        }
        None => Box::new(reason::adjudicate::NullAdjudicator),
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
// This is the engine's top-level entrypoint: each argument is an independent wired-in
// capability (client, arm-state, scope, the optional feed/dashboard addrs, the intel
// snapshots, the admission-decision ring). Bundling them into a config struct belongs to
// the JEF-218 split of this orchestrator, not this additive wiring (JEF-226).
#[allow(clippy::too_many_arguments)]
pub async fn run_watch(
    client: kube::Client,
    active: EnabledActions,
    scope: ActuationScope,
    runtime_addr: Option<std::net::SocketAddr>,
    dashboard_addr: Option<std::net::SocketAddr>,
    kev: observe::exploit_intel::KevCatalog,
    advisory: observe::advisory::AdvisoryStore,
    // The webhook's admission-decision ring (JEF-226), shared so the dashboard's `/policy`
    // view can read the same decisions the webhook engine writes.
    policy_log: std::sync::Arc<policy_log::PolicyDecisionLog>,
) -> anyhow::Result<()> {
    use futures::stream::StreamExt;
    use k8s_openapi::api::core::v1::{Pod, Secret, Service};
    use k8s_openapi::api::networking::v1::NetworkPolicy;
    use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
    use kube::Api;
    use kube::runtime::{WatchStreamExt, reflector, watcher};

    // Diagnostic judgement log: the full prompt + raw reply + verdict per judgement,
    // shared from the adjudicator (writer) to the dashboard's `/judgements` (reader).
    let journal = std::sync::Arc::new(dashboard::JudgementLog::new());
    // The durable decision journal (JEF-141): reload pre-restart decisions onto the
    // in-memory views so the dashboard isn't blank while the caches + CPU model warm.
    // Unset/unwritable `PROTECTOR_ENGINE_JOURNAL_PATH` ⇒ disabled (in-memory only, no
    // crash) — the engine then behaves exactly as before.
    let mut engine = Engine::new(
        active.clone(),
        scope,
        build_actuator(&active, &client),
        build_hypothesizer(),
        build_adjudicator(Some(journal.clone())),
    )
    .with_journal(journal::DecisionJournal::from_env())
    // The one sanctioned outbound path (JEF-144, ADR-0018): operator-configured via
    // `PROTECTOR_ENGINE_NOTIFY_URL`, off (zero outbound calls) when unset, redacted by
    // default. Only the watch loop wires it — the timer path (`run`) serves no operator.
    .with_notifier(notify::BreachNotifier::from_env());

    // Findings dashboard (read-only): surfaces the proven chains, especially the
    // latent-foothold proposals a human acts on, plus `/judgements` for diagnosis and
    // `/reversions` for lifted cuts (JEF-141).
    if let Some(addr) = dashboard_addr {
        let findings = engine.findings();
        let reversions = engine.reversions();
        let judgements = journal.clone();
        // The durable decision journal (JEF-143) backs the `/report` would-have-acted view.
        let decisions = engine.journal();
        // The readiness / coverage panel's config summary (JEF-160): presence/absence of
        // each decision input, captured once here from the same env/handles the engine
        // already reads. Presence/health only — no secret names, no endpoints, no values.
        // The LIVE model health and behavioral-feed counts are read per render from the
        // shared findings handle; this is the static "is it wired" half.
        findings.set_readiness_config(dashboard::ReadinessConfig {
            model_attached: model::config().is_some(),
            kev_count: kev.len(),
            advisory_count: advisory.len(),
            journal_durable: decisions.is_enabled(),
            armed: !active.is_empty(),
        });
        let admission = policy_log.clone();
        tokio::spawn(async move {
            if let Err(error) = dashboard::serve_dashboard(
                addr, findings, judgements, reversions, decisions, admission,
            )
            .await
            {
                tracing::error!(%error, "dashboard stopped");
            }
        });
    }

    // Keep-warm (JEF-107): warm the model at startup and ping it periodically so it
    // stays resident between judging passes — the first post-restart pass isn't glacial.
    // Best-effort and shadow-safe; a no-op when no model is configured. Aborted on loop
    // exit so it can't outlive the engine.
    let keep_warm = model::spawn_keep_warm();

    // Runtime evidence (Falco alerts + the eBPF agent's behaviors) is a stream, not a
    // an HTTP endpoint falcosidekick POSTs to, are held in a TTL'd store, and wake
    // the loop so a "happening now" signal is acted on immediately (it flips a
    // chain's corroboration without changing the graph's shape). Signals expire, so
    // corroboration stays live.
    let runtime_events = std::sync::Arc::new(observe::runtime::RuntimeEvents::new(
        std::time::Duration::from_secs(300),
    ));
    let (runtime_tx, mut runtime_rx) = tokio::sync::mpsc::channel::<()>(64);
    if let Some(addr) = runtime_addr {
        let events = runtime_events.clone();
        tokio::spawn(async move {
            if let Err(error) = observe::runtime::serve_runtime(addr, events, runtime_tx).await {
                tracing::error!(%error, "runtime-evidence ingest stopped");
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
        // Wake on either a cluster change or a behavioral report. The behavioral channel
        // only fires when the ingest actually changed the evidence store (a new
        // observation, not a repeat) — see `ingest_behavior`. So a report that tells us
        // nothing new never reaches here, and we don't burn a graph rebuild + CRD lists
        // for it; mundane churn (the same connections, again) is dropped at ingest.
        tokio::select! {
            next = change_rx.recv() => if next.is_none() { break },
            _ = runtime_rx.recv() => {},
        }
        // Coalesce an already-queued burst (a Deployment rollout, or several material
        // reports) into one pass.
        while change_rx.try_recv().is_ok() {}
        while runtime_rx.try_recv().is_ok() {}

        let (linkerd_servers_now, linkerd_policies_now, linkerd_mtls_now) =
            observe::list_linkerd_authz(&client).await;
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
                advisory.apply(&mut v);
                v
            },
            runtime_events: runtime_events.current(),
            // Linkerd authz CRDs, listed best-effort each pass (the mesh-native
            // reachability source — see LinkerdReachabilityAdapter).
            linkerd_servers: linkerd_servers_now,
            linkerd_authz_policies: linkerd_policies_now,
            linkerd_mtls_auths: linkerd_mtls_now,
        };
        engine.process(&snapshot).await;
    }

    // The change stream closed (all reflectors gone) — tear down the keep-warm task so
    // it doesn't outlive the engine loop.
    if let Some(task) = keep_warm {
        task.abort();
    }
    Ok(())
}
