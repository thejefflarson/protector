//! The engine's driver: the event-driven observer ([`run_watch`]), plus the small
//! builders that wire the actuator, hypothesis source, and adjudicator from the
//! environment. Split out of the engine module root (`mod.rs`) purely to keep every file
//! under the 1,000-line cap (repo CLAUDE.md); the orchestration core
//! ([`Engine::process`]) stays there.

use super::respond::actuator::{ActuationScope, Actuator, DryRunActuator, EnabledActions};
use super::{
    Engine, Snapshot, dashboard, journal, model, notify, observe, policy_log, reason, respond,
    state,
};

/// Replay the durable journal's admission lines (JEF-237) back into the shared
/// admission-decision log on boot, preserving each row's dedup `count` + last-seen, so the
/// admission log isn't blank after a restart. Returns how many rows were restored. A
/// disabled/empty journal restores nothing.
fn restore_admission_log(
    journal: &journal::DecisionJournal,
    policy_log: &policy_log::PolicyDecisionLog,
) -> usize {
    let mut restored = 0usize;
    for entry in journal.replay() {
        if let journal::Decision::Admission { record } = entry.decision {
            policy_log.restore(record);
            restored += 1;
        }
    }
    restored
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
    match model::config() {
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
    journal: std::sync::Arc<state::JudgementLog>,
) -> Box<dyn reason::adjudicate::Adjudicator> {
    match model::config() {
        Some((endpoint, model)) => {
            tracing::info!(%model, "adjudicator: model-backed (judges exploitability — promote/veto)");
            let adjudicator =
                reason::adjudicate::ModelAdjudicator::new(endpoint, model).with_journal(journal);
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
/// This path is exercised against a real cluster, not unit tests — the analysis it
/// drives is what the tests cover.
// This is the engine's top-level entrypoint: each argument is an independent wired-in
// capability (client, arm-state, scope, the optional feed addr, the intel snapshots, the
// admission-decision ring). Bundling them into a config struct belongs to the JEF-218 split
// of this orchestrator, not this additive wiring (JEF-226).
#[allow(clippy::too_many_arguments)]
pub async fn run_watch(
    client: kube::Client,
    active: EnabledActions,
    scope: ActuationScope,
    runtime_addr: Option<std::net::SocketAddr>,
    kev: observe::exploit_intel::KevCatalog,
    epss: observe::epss::EpssStore,
    // The webhook's admission-decision ring (JEF-226), shared so the admission-decision log
    // carries the same decisions the webhook engine writes.
    policy_log: std::sync::Arc<policy_log::PolicyDecisionLog>,
) -> anyhow::Result<()> {
    use futures::stream::StreamExt;
    use k8s_openapi::api::core::v1::{Pod, Secret, Service};
    use k8s_openapi::api::networking::v1::NetworkPolicy;
    use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
    use kube::Api;
    use kube::runtime::{WatchStreamExt, reflector, watcher};

    // Diagnostic judgement log: the full prompt + raw reply + verdict per judgement,
    // written by the adjudicator for later inspection.
    let journal = std::sync::Arc::new(state::JudgementLog::new());
    // The durable decision journal (JEF-141): reload pre-restart decisions onto the
    // in-memory state so the output state isn't blank while the caches + CPU model warm.
    // Unset/unwritable `PROTECTOR_ENGINE_JOURNAL_PATH` ⇒ disabled (in-memory only, no
    // crash) — the engine then behaves exactly as before.
    let mut engine = Engine::new(
        active.clone(),
        scope,
        build_actuator(&active, &client),
        build_hypothesizer(),
        build_adjudicator(journal.clone()),
    )
    .with_journal(journal::DecisionJournal::from_env())
    // The one sanctioned outbound path (JEF-144, ADR-0018): operator-configured via
    // `PROTECTOR_ENGINE_NOTIFY_URL`, off (zero outbound calls) when unset, redacted by
    // default.
    .with_notifier(notify::BreachNotifier::from_env());

    // Repopulate the webhook's admission-decision ring from the durable journal on boot
    // (JEF-237), so the admission-decision log isn't blank after a restart — parallel to how
    // the engine's `replay_journal` restored the model verdicts above. The engine owns a
    // handle to the same journal file the webhook persists admissions to; we replay its
    // `Admission` lines (preserving each row's dedup count + last-seen) back into the shared
    // ring.
    let restored_admissions = restore_admission_log(engine.journal().as_ref(), &policy_log);
    if restored_admissions > 0 {
        tracing::info!(
            restored_admissions,
            "restored admission decisions onto the admission-decision log from the durable journal"
        );
    }

    // The readiness / coverage config summary (JEF-160): presence/absence of each decision
    // input, captured once here from the same env/handles the engine already reads.
    // Presence/health only — no secret names, no endpoints, no values. The LIVE model health
    // and behavioral-feed counts are stamped per pass into the shared findings handle; this is
    // the static "is it wired" half that the readiness aggregation reads.
    engine
        .findings()
        .set_readiness_config(state::ReadinessConfig {
            model_attached: model::config().is_some(),
            kev_count: kev.len(),
            epss_count: epss.len(),
            journal_durable: engine.journal().is_enabled(),
            armed: !active.is_empty(),
        });

    // The read-only operator dashboard (ADR-0019), served behind `PROTECTOR_DASHBOARD_ADDR`
    // (e.g. `0.0.0.0:8080`). Off when unset — zero-egress, in-cluster only. It reads the SAME
    // `state::` handles the engine writes each pass (findings, the judgement ring, the reversion
    // log), never mutating them, so it is strictly observational and a bad render can never
    // affect the engine (ADR-0016: presentation is a view, never a gate). A bind failure logs
    // and the task exits; the engine loop is unaffected.
    if let Ok(addr_str) = std::env::var("PROTECTOR_DASHBOARD_ADDR") {
        match addr_str.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                let state = dashboard::DashboardState {
                    findings: engine.findings(),
                    judgements: journal.clone(),
                    reversions: engine.reversions(),
                    // The durable decision journal backs the Trust would-have-acted report
                    // (replayed read-only). Distinct handle from `journal` (the JudgementLog).
                    decision_journal: engine.journal(),
                    // The webhook's admission-decision ring backs the Admission tab (the webhook
                    // floor). The SAME Arc the webhook engine writes — read-only here.
                    policy_log: policy_log.clone(),
                    cluster: std::env::var("PROTECTOR_CLUSTER_LABEL")
                        .unwrap_or_else(|_| "cluster".to_string()),
                };
                tokio::spawn(dashboard::serve_dashboard(addr, state));
            }
            Err(error) => tracing::error!(
                %error, addr = %addr_str,
                "PROTECTOR_DASHBOARD_ADDR is not a host:port socket address; dashboard disabled"
            ),
        }
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
        // The other trivy-operator report kinds (JEF-244): exposed secrets, config-audit,
        // and RBAC-assessment findings, listed best-effort each pass like the CVE reports.
        let (image_secrets_now, config_audits_now, rbac_assessments_now) =
            observe::list_trivy_findings(&client).await;
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
            // something changed), then enriched with KEV exploit intel and EPSS
            // exploit-prediction scores. Runtime events are the live, TTL'd Falco signals.
            image_vulns: {
                let mut v = observe::list_parsed(
                    &client,
                    observe::vulnerability_report_gvk(),
                    observe::trivy::parse_report,
                )
                .await;
                kev.mark_exploited(&mut v);
                epss.annotate(&mut v);
                v
            },
            image_secrets: image_secrets_now,
            config_audits: config_audits_now,
            rbac_assessments: rbac_assessments_now,
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
