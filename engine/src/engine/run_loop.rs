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

/// Build the signing-posture observer (ADR-0020 Stage 1, JEF-261) the per-pass running-Pod
/// sweep uses. It reuses the SAME cosign verifier the webhook gates with, but for pure
/// observation — so it needs no trusted-identity config (the Fulcio/Rekor chain is the trust
/// anchor). The identity regex is irrelevant to `observe`, so any value compiles; we pass a
/// match-nothing pattern. Bounded by the same `PROTECTOR_MAX_IMAGES` + `PROTECTOR_CACHE_TTL`
/// the webhook honors, so observing every running image stays inside the already-sanctioned
/// outbound envelope (ADR-0015 carve-out). `None` (a no-op sweep — zero outbound calls) if the
/// TUF cache dir can't be created, so a misconfigured volume degrades to today's behavior
/// rather than crashing the engine loop.
fn build_signing_observer() -> Option<crate::policies::signature::SigningObserver> {
    use crate::policies::signature::{CosignChecker, SigningObserver};

    let oidc_issuer = std::env::var("PROTECTOR_OIDC_ISSUER")
        .unwrap_or_else(|_| "https://token.actions.githubusercontent.com".to_string());
    let tuf_cache = std::path::PathBuf::from(
        std::env::var("PROTECTOR_TUF_CACHE").unwrap_or_else(|_| "/tmp/sigstore".to_string()),
    );
    let verify_timeout = std::time::Duration::from_secs(env_u64("PROTECTOR_VERIFY_TIMEOUT", 5));
    let cache_ttl = std::time::Duration::from_secs(env_u64("PROTECTOR_CACHE_TTL", 300));
    let max_images = env_u64("PROTECTOR_MAX_IMAGES", 32) as usize;
    // The engine's own registry auth mirrors the webhook's; anonymous is the safe default. An
    // unauthorized private image simply observes as `checking`/`not-signed`, never a
    // fabricated clean.
    let auth = registry_auth();

    // `observe` ignores the identity regex entirely; a match-nothing pattern keeps the gated
    // constructor happy without asserting any trusted signer.
    match CosignChecker::new("$^", oidc_issuer, auth, tuf_cache, verify_timeout) {
        Ok(checker) => Some(SigningObserver::new(
            std::sync::Arc::new(checker),
            max_images,
            cache_ttl,
        )),
        Err(error) => {
            tracing::warn!(%error, "signing-posture observer unavailable (TUF cache dir?); running-pod sweep disabled");
            None
        }
    }
}

/// Build the opt-in Rekor transparency-log lane (ADR-0020 §4, JEF-266). Returns `None` — and so
/// makes NO outbound transparency-log call ever — unless `PROTECTOR_REKOR_ENABLE` is explicitly set
/// (zero egress preserved by default). When enabled it queries the public log (or a self-hosted
/// mirror via `PROTECTOR_REKOR_URL`) to corroborate repo baselines and detect registry↔log
/// divergence, bounded by a per-query timeout + a TTL cache. A client-build failure degrades to
/// `None` (local-only) rather than crashing the loop.
fn build_rekor_lane() -> Option<crate::policies::signature::RekorLane> {
    use crate::policies::signature::{HttpRekorClient, RekorConfig, RekorLane};

    let config = RekorConfig::from_env();
    if !config.enabled {
        return None;
    }
    match HttpRekorClient::new(&config) {
        Ok(client) => {
            tracing::info!(
                base_url = %config.base_url,
                "rekor transparency-log lane ENABLED (opt-in egress carve-out, ADR-0020 §4)"
            );
            Some(RekorLane::new(
                std::sync::Arc::new(client),
                config.cache_ttl,
            ))
        }
        Err(error) => {
            tracing::warn!(%error, "rekor lane unavailable; degrading to local-only (zero egress)");
            None
        }
    }
}

/// Registry auth for fetching signatures of private images during the running-Pod posture
/// sweep — reuses the `PROTECTOR_REGISTRY_*` credentials, mirroring the webhook's
/// `registry_auth`. Anonymous unless explicit credentials are supplied.
fn registry_auth() -> sigstore::registry::Auth {
    use sigstore::registry::Auth;
    if let (Ok(user), Ok(pass)) = (
        std::env::var("PROTECTOR_REGISTRY_USERNAME"),
        std::env::var("PROTECTOR_REGISTRY_PASSWORD"),
    ) {
        return Auth::Basic(user, pass);
    }
    Auth::Anonymous
}

/// Parse a numeric env var, falling back to `default` if unset or unparseable.
fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Choose the hypothesis source: a model-backed one when a model endpoint is configured,
/// else the null source (ADR-0021: derive from "a model is configured", don't require a
/// separate opt-in). Local-first: point it at an in-cluster model so the graph never
/// leaves. The deterministic enumerator still finds every structural chain; the model
/// proposer adds contextual chains where a model is available. The hypothesis prompt sends
/// the graph, so on a Pi-class node keep the model tier fast enough that a pass isn't
/// blocked — the same node the adjudicator (ADR-0013) uses.
fn build_hypothesizer() -> Box<dyn reason::hypothesis::HypothesisSource> {
    match model::config() {
        Some((endpoint, model)) => {
            tracing::info!(%endpoint, %model, "hypothesis source: model-backed (local tier)");
            Box::new(reason::hypothesis::ModelHypothesizer::new(
                endpoint,
                model,
                reason::hypothesis::Tier::Local,
            ))
        }
        None => Box::new(reason::hypothesis::NullHypothesizer),
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
    // The k8s audit-log ingest endpoint (JEF-269): the apiserver's audit webhook POSTs
    // secret GET/LIST/WATCH events here for the RBAC-granted "corroborated-now" signal.
    // Unset = no audit feed.
    audit_addr: Option<std::net::SocketAddr>,
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
    use kube::core::PartialObjectMeta;
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

    // The signing-posture observer (ADR-0020 Stage 1, JEF-261): built ONCE so its TTL + image
    // cache persists across passes — a steady cluster re-sweeps for free. Each pass runs every
    // running-Pod image through it and records the posture (signed / invalid-signature /
    // not-signed / checking) into the shared admission-decision log, covering workloads that
    // were already running when protector started (no admission event ever replays them).
    let signing_observer = build_signing_observer();

    // The opt-in Rekor transparency-log lane (ADR-0020 §4, JEF-266): OFF unless
    // `PROTECTOR_REKOR_ENABLE` is set, so the default posture stays fully zero-egress. Built once so
    // its bounded query cache persists across passes. When enabled, the reconcile pass below
    // corroborates repo baselines against the public signing history and surfaces registry↔log
    // divergence.
    let rekor_lane = build_rekor_lane();

    // The durable per-repo TOFU signing baseline (JEF-263, ADR-0020): learned from the sweep's
    // observed postures, persisted to (and, here on boot, replayed from) the SAME decision
    // journal the engine already owns — so a repo's established signed history survives a
    // restart instead of resetting to cold-start trust. Built once and mutated each pass;
    // per-pass compaction inside the sweep keeps live baselines inside the journal's rotation
    // window. A disabled journal ⇒ in-memory only (honest re-learn on restart).
    let signing_journal = engine.journal();
    let mut signing_baselines = state::SigningBaselineStore::new();
    let restored_baselines = signing_baselines.restore(signing_journal.as_ref());
    if restored_baselines > 0 {
        tracing::info!(
            restored_baselines,
            "restored per-repo signing baselines from the durable journal"
        );
    }

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

    // API secret-reads from the apiserver audit log (JEF-269): the corroborating signal for
    // an RBAC-granted secret GET the eBPF agent can't see. Held in a TTL'd store on the same
    // freshness window as the runtime feed and woken the same way — only a *new* read wakes
    // the loop, so a workload re-reading the same secret every reconcile doesn't churn a pass.
    let audit_events = std::sync::Arc::new(observe::audit::AuditEvents::new(
        std::time::Duration::from_secs(300),
    ));
    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel::<()>(64);
    if let Some(addr) = audit_addr {
        let events = audit_events.clone();
        tokio::spawn(async move {
            if let Err(error) = observe::audit::serve_audit(addr, events, audit_tx).await {
                tracing::error!(%error, "k8s audit-log ingest stopped");
            }
        });
    }

    // A reflector per watched type: it owns a Store kept current as its stream is
    // polled, and yields a tick on every change. Merging the tick streams gives a
    // single "something changed" signal.
    let (pods, pods_w) = reflector::store::<Pod>();
    let (netpols, netpols_w) = reflector::store::<NetworkPolicy>();
    let (services, services_w) = reflector::store::<Service>();
    // Secrets are watched METADATA-ONLY (JEF-268): the graph only ever needs a
    // Secret's identity (namespace + name — see `SecretMeta`), never its `.data`, so
    // we reflect `PartialObjectMeta<Secret>`. `Api::<PartialObjectMeta<Secret>>` issues
    // metadata-only requests, so the apiserver never sends — and this in-memory store
    // never holds — any credential bytes. (`metadata_watcher` is the deprecated spelling
    // of the same behavior in kube 4.0.0; the `watcher(Api::<PartialObjectMeta<_>>, _)`
    // form below is its non-deprecated equivalent.)
    //
    // RBAC caveat: vanilla k8s RBAC can't express "metadata-only on secrets" —
    // `get/list/watch` on `secrets` is all-or-nothing — so protector's grant necessarily
    // still permits reading values. This change removes the *exposure* (what protector
    // holds in memory), a voluntary client-side restraint; it does not narrow the grant.
    // Dropping the grant entirely (deriving secret nodes from mounts + RBAC) is a
    // separate ticket, deliberately out of scope here.
    let (secrets, secrets_w) = reflector::store::<PartialObjectMeta<Secret>>();
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
    // Metadata-only Secret watch (JEF-268): reflects `PartialObjectMeta<Secret>`, so the
    // stream carries identity only — `.data` never crosses the wire or lands in the store.
    spawn_reflector!(secrets_w, PartialObjectMeta<Secret>);
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
            _ = audit_rx.recv() => {},
        }
        // Coalesce an already-queued burst (a Deployment rollout, or several material
        // reports) into one pass.
        while change_rx.try_recv().is_ok() {}
        while runtime_rx.try_recv().is_ok() {}
        while audit_rx.try_recv().is_ok() {}

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
            // API secret-reads from the audit log (JEF-269), TTL'd like the runtime feed.
            audit_secret_reads: audit_events.current(),
            // Linkerd authz CRDs, listed best-effort each pass (the mesh-native
            // reachability source — see LinkerdReachabilityAdapter).
            linkerd_servers: linkerd_servers_now,
            linkerd_authz_policies: linkerd_policies_now,
            linkerd_mtls_auths: linkerd_mtls_now,
        };
        // Observe the signing posture of every already-running image and record it into the
        // shared admission-decision log (JEF-261). Bounded by the observer's cache + MAX_IMAGES;
        // a no-op when no observer is configured. Run before `process` so the inventory reflects
        // the same snapshot the engine just reasoned over.
        let signing_map = super::signing_sweep::sweep(
            signing_observer.as_ref(),
            &snapshot,
            &policy_log,
            Some(&mut signing_baselines),
            signing_journal.as_ref(),
        )
        .await;
        // Opt-in Rekor reconciliation (JEF-266): corroborate baselines against the public log and
        // surface registry↔log divergence. A no-op (zero egress) when the lane is off.
        super::signing_rekor::reconcile(
            rekor_lane.as_ref(),
            &signing_map,
            &policy_log,
            Some(&mut signing_baselines),
            signing_journal.as_ref(),
        )
        .await;

        engine.process(&snapshot).await;
    }

    // The change stream closed (all reflectors gone) — tear down the keep-warm task so
    // it doesn't outlive the engine loop.
    if let Some(task) = keep_warm {
        task.abort();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! JEF-268: the Secret informer (reflector watch + initial list) must be
    //! metadata-only — protector reasons about a Secret's *identity* (namespace +
    //! name), never its contents, so no credential bytes must ever cross the wire or
    //! sit in the in-memory store. These tests pin that guarantee to the exact type the
    //! informer reflects, `PartialObjectMeta<Secret>`; a regression to the full `Secret`
    //! type (which carries `.data`) fails them.

    use k8s_openapi::api::core::v1::Secret;
    use kube::Resource;
    use kube::core::PartialObjectMeta;

    /// The reflected element type asks the apiserver for metadata only. `metadata_api()`
    /// is what drives both `watcher(Api::<PartialObjectMeta<Secret>>, _)` and
    /// `Api::<Secret>::list_metadata` to issue `.../secrets` requests that return
    /// `PartialObjectMeta` (no `.data`) rather than full Secret objects.
    #[test]
    fn secret_informer_requests_metadata_only() {
        assert!(
            <PartialObjectMeta<Secret> as Resource>::metadata_api(),
            "Secret informer must reflect a metadata-only type; a full Secret would \
             fetch and retain credential bytes"
        );
    }

    /// Even handed a full Secret payload (as an apiserver bug or a mistaken watch would
    /// deliver), the reflected type structurally cannot retain `.data`/`stringData`: it
    /// is dropped on deserialize, while the identity the graph needs survives. This is the
    /// "no full Secret with `.data` retained" guarantee.
    #[test]
    fn reflected_secret_drops_data_keeps_identity() {
        let full_secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "namespace": "prod", "name": "db-creds" },
            "type": "Opaque",
            "data": { "password": "c3VwZXItc2VjcmV0" },
            "stringData": { "token": "super-secret" },
        });

        let reflected: PartialObjectMeta<Secret> =
            serde_json::from_value(full_secret).expect("deserialize as metadata-only");

        // Identity — exactly what `SecretMeta` / the graph's secret-objective nodes need —
        // is preserved.
        assert_eq!(reflected.metadata.namespace.as_deref(), Some("prod"));
        assert_eq!(reflected.metadata.name.as_deref(), Some("db-creds"));

        // Round-trip back to JSON and prove no credential bytes survived anywhere. The
        // keys are matched quoted (`"data"`) so the `data` inside `"metadata"` doesn't
        // give a false positive.
        let round_trip = serde_json::to_value(&reflected).expect("serialize");
        let text = round_trip.to_string();
        assert!(
            !text.contains("\"data\""),
            "reflected Secret must not carry a `data` field"
        );
        assert!(
            !text.contains("\"stringData\""),
            "reflected Secret must not carry a `stringData` field"
        );
        assert!(
            !text.contains("c3VwZXItc2VjcmV0") && !text.contains("super-secret"),
            "no credential bytes may survive into the reflected store"
        );
    }
}
