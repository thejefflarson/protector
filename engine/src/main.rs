use std::collections::HashSet;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use protector::engine::observe::epss::EpssStore;
use protector::engine::observe::exploit_intel::KevCatalog;
use protector::engine::policy_log::PolicyDecisionLog;
use protector::engine::respond::ProposedAction;
use protector::engine::respond::actuator::{ActuationScope, EnabledActions};
use protector::engine::state::SharedSigningBaseline;
use protector::metrics::Metrics;
use protector::policies::mesh::MeshInjectionPolicy;
use protector::policies::signature::{
    ContinuityGate, CosignChecker, SignaturePolicy, SigningExceptions, SigningObserver, SigningPin,
};
use protector::policy::{EnforceScope, Engine};
use protector::server;
use sigstore::registry::Auth;

/// Fixed mount paths for the exploitation-intel feeds. JEF-273 owns the feed *mechanism*
/// (the fetcher that writes these files); the engine only reads them, from a fixed path
/// rather than an operator knob (ADR-0021 config collapse). `PROTECTOR_KEV_FILE` /
/// `PROTECTOR_EPSS_FILE` remain as escape-hatch overrides.
const FEEDS_KEV_PATH: &str = "/var/lib/protector/feeds/kev.json";
const FEEDS_EPSS_PATH: &str = "/var/lib/protector/feeds/epss.csv";

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Parse a numeric env var, falling back to `default` if unset or unparseable.
fn env_parse(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Parse a comma-separated env var into a set, falling back to `default`.
fn env_set(key: &str, default: &str) -> HashSet<String> {
    env_or(key, default)
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse a comma-separated env var of `key=value` pairs.
fn env_pairs(key: &str) -> Vec<(String, String)> {
    env_or(key, "")
        .split(',')
        .filter_map(|s| s.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// The two-setting operating posture (ADR-0021): `audit` (the default — everything
/// observes and proposes, nothing blocks or acts) or `enforce` (arm all three surfaces
/// — signature webhook deny, mesh webhook deny, engine live cut — confined to exactly
/// `enforceScope`). Parsed once at startup and derived into the internal
/// `EnforceScope`/`ActuationScope`/`EnabledActions`; there is no per-surface toggle and
/// no enforce-everywhere wildcard.
struct Posture {
    /// True for `mode: enforce`; false for `mode: audit` (the default).
    enforce: bool,
    /// The single enforced scope. Empty (namespaces + labels) is audit-everywhere.
    namespaces: HashSet<String>,
    labels: Vec<(String, String)>,
}

impl Posture {
    /// Resolve `PROTECTOR_MODE` + `PROTECTOR_ENFORCE_SCOPE_NAMESPACES` /
    /// `PROTECTOR_ENFORCE_SCOPE_LABELS`. `mode: enforce` with an empty scope is refused
    /// — enforcing everywhere is the footgun ADR-0021 guards against (no wildcard).
    fn from_env() -> Result<Self> {
        let mode = env_or("PROTECTOR_MODE", "audit")
            .trim()
            .to_ascii_lowercase();
        let enforce = match mode.as_str() {
            "enforce" => true,
            "audit" | "" => false,
            other => anyhow::bail!("PROTECTOR_MODE must be 'audit' or 'enforce', got '{other}'"),
        };
        let namespaces = env_set("PROTECTOR_ENFORCE_SCOPE_NAMESPACES", "");
        let labels = env_pairs("PROTECTOR_ENFORCE_SCOPE_LABELS");
        if enforce && namespaces.is_empty() && labels.is_empty() {
            anyhow::bail!(
                "PROTECTOR_MODE=enforce requires a non-empty enforceScope (namespaces \
                 and/or labels) — refusing to start: there is no enforce-everywhere \
                 wildcard (ADR-0021). List the namespaces/labels to enforce."
            );
        }
        Ok(Self {
            enforce,
            namespaces,
            labels,
        })
    }

    /// The webhook enforce scope: the enforced `EnforceScope` under `enforce`, else the
    /// empty (audit-everywhere) scope. Both admission gates (signature + mesh) share it,
    /// so `enforce` arms them together in exactly `enforceScope` (ADR-0021).
    fn webhook_scope(&self) -> EnforceScope {
        if self.enforce {
            EnforceScope::new(self.namespaces.clone(), self.labels.clone())
        } else {
            EnforceScope::default()
        }
    }

    /// What the engine may auto-actuate. Under `enforce`: the reversible network cuts are
    /// armed — the surgical edge-cut (`DenyNetworkPath`), the default-deny entry quarantine
    /// (`QuarantineEntry`), and the compromised-workload quarantine (`QuarantineWorkload`,
    /// JEF-284), all additive/reversible network denies (ADR-0010) — confined to
    /// `enforceScope` (namespaces or Pod labels). Under `audit`: nothing armed (dry-run) and
    /// unscoped — the shadow default.
    fn engine_arming(&self) -> (EnabledActions, ActuationScope) {
        if self.enforce {
            (
                EnabledActions::none()
                    .enable(ProposedAction::DenyNetworkPath)
                    .enable(ProposedAction::QuarantineEntry)
                    .enable(ProposedAction::QuarantineWorkload),
                ActuationScope::new(self.namespaces.clone(), self.labels.clone()),
            )
        } else {
            (EnabledActions::none(), ActuationScope::unscoped())
        }
    }
}

/// Registry auth for pulling signatures of *private* gated images. Anonymous
/// unless credentials are supplied — either explicit username/password env, or a
/// mounted dockerconfigjson (the cluster's `github` pull secret).
fn registry_auth() -> Auth {
    if let (Ok(user), Ok(pass)) = (
        env::var("PROTECTOR_REGISTRY_USERNAME"),
        env::var("PROTECTOR_REGISTRY_PASSWORD"),
    ) {
        return Auth::Basic(user, pass);
    }
    // Reuse the mounted dockerconfigjson's ghcr creds. Signatures inherit the
    // (private) package's visibility, so the verifier needs the same creds the
    // kubelet pulls with — without this, manifest fetches of private first-party
    // images 401 ("Not authorized") and verification errors out.
    if let Ok(path) = env::var("PROTECTOR_REGISTRY_AUTH_FILE")
        && let Some((user, pass)) = docker_config_basic(&path, "ghcr.io")
    {
        return Auth::Basic(user, pass);
    }
    Auth::Anonymous
}

/// Extract `(username, password)` for `registry` from a Docker `config.json`
/// (k8s `.dockerconfigjson`): prefer explicit username/password, else decode the
/// base64 `auth` field (`user:token`). `None` if absent/unparseable.
fn docker_config_basic(path: &str, registry: &str) -> Option<(String, String)> {
    use base64::Engine as _;
    let data = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&data).ok()?;
    let entry = json.get("auths")?.get(registry)?;
    if let (Some(u), Some(p)) = (
        entry.get("username").and_then(|v| v.as_str()),
        entry.get("password").and_then(|v| v.as_str()),
    ) {
        return Some((u.to_string(), p.to_string()));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(entry.get("auth")?.as_str()?)
        .ok()?;
    let pair = String::from_utf8(decoded).ok()?;
    let (user, pass) = pair.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// The scoped "exception accepted" config (JEF-265, ADR-0020 Stage 3): a mounted file
/// (`PROTECTOR_SIGNING_EXCEPTIONS_FILE`) merged with an env spec (`PROTECTOR_SIGNING_EXCEPTIONS`).
/// Each entry is `<scope> <fingerprint>` where scope is `repo:<registry/repo>` or `image:<ref>`.
/// Empty (neither set) ⇒ nothing is excepted — every repo stays enforced. Reversible: remove the
/// file/env and the exception is gone.
fn signing_exceptions() -> SigningExceptions {
    let file = env::var("PROTECTOR_SIGNING_EXCEPTIONS_FILE").ok();
    let env_spec = env_or("PROTECTOR_SIGNING_EXCEPTIONS", "");
    SigningExceptions::from_sources(file.as_deref(), &env_spec)
}

/// The back-compat identity PINs (JEF-265, ADR-0020): `PROTECTOR_SIGNING_PINS`, a `;`-separated list
/// of `prefix=identity_regexp`. Each is "every image under `prefix` must always be signed by an
/// identity matching `identity_regexp`" — the pinned special case of the pre-ADR-0020 prefix gate.
///
/// MIGRATION NOTE: the legacy `PROTECTOR_GATED_PREFIXES` + `PROTECTOR_IDENTITY_REGEXP` gate is
/// preserved unchanged (its own path) and is *equivalent* to the pin
/// `PROTECTOR_SIGNING_PINS=<prefix>=<identity_regexp>`. Operators may migrate to the pin spelling;
/// nothing is auto-mapped, so today's behavior is byte-identical.
fn signing_pins() -> Vec<SigningPin> {
    env_or("PROTECTOR_SIGNING_PINS", "")
        .split(';')
        .filter_map(|entry| {
            let (prefix, regexp) = entry.split_once('=')?;
            let prefix = prefix.trim();
            let regexp = regexp.trim();
            if prefix.is_empty() || regexp.is_empty() {
                return None;
            }
            match SigningPin::new(prefix, regexp) {
                Some(pin) => Some(pin),
                None => {
                    tracing::warn!(%prefix, "PROTECTOR_SIGNING_PINS entry has an invalid regexp; skipping");
                    None
                }
            }
        })
        .collect()
}

/// Build the webhook's signing-posture OBSERVER for the continuity gate (JEF-265) — the same
/// sanctioned cosign/Rekor observation path ADR-0020 §1 defines for admitted images. It needs no
/// trusted-identity config (the Fulcio/Rekor chain is the anchor), so a match-nothing regexp keeps
/// the constructor happy. Bounded by the same `max_images` + TTL the gate honors. `None` (continuity
/// unavailable ⇒ the policy stays byte-identical to the legacy gate) if the TUF cache can't be built.
fn build_webhook_signing_observer(
    oidc_issuer: &str,
    tuf_cache: &std::path::Path,
    verify_timeout: Duration,
    cache_ttl: Duration,
    max_images: usize,
) -> Option<Arc<SigningObserver>> {
    match CosignChecker::new(
        "$^",
        oidc_issuer.to_string(),
        registry_auth(),
        tuf_cache.to_path_buf(),
        verify_timeout,
    ) {
        Ok(checker) => Some(Arc::new(SigningObserver::new(
            Arc::new(checker),
            max_images,
            cache_ttl,
        ))),
        Err(error) => {
            tracing::warn!(%error, "signing-continuity observer unavailable (TUF cache dir?); admission continuity disabled");
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logging + (when OTEL_EXPORTER_OTLP_ENDPOINT is set) OTLP export of traces and
    // engine metrics to the node-local collector, like the cluster's other services.
    let telemetry = protector::telemetry::init(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    // Install a process-wide rustls CryptoProvider before any TLS is used. Several
    // dependencies (sigstore, axum-server, reqwest, kube) link rustls, and both
    // aws-lc-rs and ring providers are present — so rustls can't pick a default and
    // panics on first use unless we choose one here. `.ok()`: a no-op if something
    // already installed one.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let addr: SocketAddr = env_or("PROTECTOR_ADDR", "0.0.0.0:8443")
        .parse()
        .context("PROTECTOR_ADDR must be a host:port socket address")?;
    let cert = PathBuf::from(env_or("PROTECTOR_TLS_CERT", "/etc/protector/tls/tls.crt"));
    let key = PathBuf::from(env_or("PROTECTOR_TLS_KEY", "/etc/protector/tls/tls.key"));

    // Signature policy config. Unconfigured by default: with no gated prefixes the
    // signing gate is inert (no image is checked), so an out-of-the-box deploy is
    // safe and org-agnostic. Set PROTECTOR_GATED_PREFIXES to your registry/org to turn
    // it on, together with PROTECTOR_IDENTITY_REGEXP for your trusted signer (the OIDC
    // issuer defaults to GitHub Actions). It ships in audit mode (enforce=false) so it
    // can be observed before it can reject a Pod.
    let identity_regexp = env_or("PROTECTOR_IDENTITY_REGEXP", "");
    let oidc_issuer = env_or(
        "PROTECTOR_OIDC_ISSUER",
        "https://token.actions.githubusercontent.com",
    );
    let gated_prefixes: Vec<String> = env_or("PROTECTOR_GATED_PREFIXES", "")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    // Gating an image without a trusted-signer identity would accept ANY valid
    // signature (an empty identity regexp matches every SAN). Refuse to start in that
    // misconfiguration rather than silently trusting all signers.
    if !gated_prefixes.is_empty() && identity_regexp.trim().is_empty() {
        anyhow::bail!(
            "PROTECTOR_GATED_PREFIXES is set but PROTECTOR_IDENTITY_REGEXP is empty — \
             refusing to start: gating images without a trusted signer identity would accept \
             any signature. Set PROTECTOR_IDENTITY_REGEXP (e.g. ^https://github\\.com/your-org/)."
        );
    }
    if gated_prefixes.is_empty() {
        tracing::info!(
            "signature gating off (PROTECTOR_GATED_PREFIXES empty) — no images are signature-checked"
        );
    }
    let tuf_cache = PathBuf::from(env_or("PROTECTOR_TUF_CACHE", "/tmp/sigstore"));
    // 20s (was 5s): a keyless Fulcio+Rekor+TUF verify of a first-party signed image on the arm64
    // engine — especially with a cold TUF cache after a restart — routinely needs >5s, so a 5s
    // budget left those images stuck in "checking" forever (JEF-326). Still env-overridable, and
    // shared with the engine's running-pod sweep (the path that was actually stuck). NOTE: the
    // *admission* verify is additionally bounded by the ValidatingWebhookConfiguration's
    // `timeoutSeconds` (5s in the chart), so on the webhook path the effective budget is the
    // smaller of the two — this larger default mainly benefits the engine sweep, which has no such
    // k8s cap. Raising the webhook's own `timeoutSeconds` is a cluster-owned decision (it trades
    // admission latency for verify headroom) and is left as an operator follow-up.
    let verify_timeout = Duration::from_secs(env_parse("PROTECTOR_VERIFY_TIMEOUT", 20));
    let cache_ttl = Duration::from_secs(env_parse("PROTECTOR_CACHE_TTL", 300));
    let max_images = env_parse("PROTECTOR_MAX_IMAGES", 32) as usize;

    // The two-setting posture (ADR-0021): `mode` + one `enforceScope` derive BOTH
    // admission gates' enforced scope. `audit` (the default) audits everywhere — every
    // violation is logged + metered but never blocks. `enforce` arms both gates together,
    // confined to exactly `enforceScope`; no per-surface toggle, no wildcard.
    let posture = Posture::from_env()?;
    let signature_enforce = posture.webhook_scope();
    let mesh_enforce = posture.webhook_scope();
    tracing::info!(
        mode = if posture.enforce { "enforce" } else { "audit" },
        signature = %signature_enforce.describe(),
        mesh = %mesh_enforce.describe(),
        "policy enforcement scopes"
    );

    let checker = CosignChecker::new(
        &identity_regexp,
        oidc_issuer.clone(),
        registry_auth(),
        tuf_cache.clone(),
        verify_timeout,
    )
    .context("building cosign checker")?;
    let mut signature = SignaturePolicy::new(
        Arc::new(checker),
        gated_prefixes,
        signature_enforce,
        max_images,
        cache_ttl,
    );

    // The read-only, cross-task signing-baseline snapshot (JEF-265, ADR-0020 Stage 3): shared with
    // the analysis engine, which is its SOLE writer (it publishes after each sweep). The webhook only
    // ever reads it, so admission can consult signature continuity but can never poison the baseline.
    let shared_baseline = SharedSigningBaseline::new();
    // The scoped, recorded "exception accepted" config — read by BOTH the webhook block predicate and
    // the engine sweep's render, so the gate and the inventory can never disagree.
    let engine_exceptions = signing_exceptions();

    // Arm the admission-time signing-CONTINUITY gate (JEF-265) ONLY under `mode: enforce`. This
    // keeps invariant #1 exact: an unconfigured / audit-mode deploy adds NO webhook observation and
    // can NEVER deny — byte-identical shadow. Enforcement (and its ADR-0020 §1 observation) is
    // strictly opt-in via `mode: enforce` + `enforceScope`; even then a deny fires only for an
    // image IN scope with an established-baseline regression.
    if posture.enforce
        && let Some(observer) = build_webhook_signing_observer(
            &oidc_issuer,
            &tuf_cache,
            verify_timeout,
            cache_ttl,
            max_images,
        )
    {
        let pins = signing_pins();
        tracing::info!(
            pins = pins.len(),
            exceptions = !engine_exceptions.is_empty(),
            "admission signing-continuity gate armed (enforce mode): deny on established-baseline \
             regression in enforceScope; scoped exceptions + pins honored; baseline read-only"
        );
        signature = signature.with_continuity(ContinuityGate::new(
            observer,
            shared_baseline.clone(),
            engine_exceptions.clone(),
            pins,
            max_images,
        ));
    }

    let mesh = MeshInjectionPolicy::new(mesh_enforce);

    // Metrics are shared between the engine (which records violations) and the
    // server's /metrics scrape endpoint.
    let metrics = Arc::new(Metrics::new());

    // The bounded, deduped admission-decision ring (JEF-226/237): the webhook engine writes
    // each resolved decision — clean admit, audit, or deny — here. On boot the mitigation
    // engine repopulates it from the durable journal so the admission-decision log survives a
    // restart.
    let policy_log = Arc::new(PolicyDecisionLog::new());

    // The durable decision journal (JEF-141/237): the webhook engine persists each resolved
    // admission so the admission-decision log survives a restart. Unset/unwritable
    // `PROTECTOR_ENGINE_JOURNAL_PATH` ⇒ disabled (in-memory only, no crash). The mitigation
    // engine opens its own handle to the same path; both append-only writers share the file
    // safely.
    let webhook_journal = Arc::new(protector::engine::journal::DecisionJournal::from_env());

    // The policy set is fixed at startup and shared (read-only) across requests.
    let engine = Arc::new(
        Engine::new(vec![Box::new(signature), Box::new(mesh)], metrics.clone())
            .with_decision_log(policy_log.clone())
            .with_journal(webhook_journal.clone()),
    );

    // The mitigation engine is the product: it runs by default, out-of-band, with its
    // *own* kube client (the webhook keeps its zero-cluster-access property). It always
    // starts — "the engine runs in shadow by default" (ADR-0021); its arming is derived
    // from `mode`, not a separate on/off master. Without a kube client it degrades to
    // webhook-only.
    // The engine runs as a detached task; we keep its handle so it can be stopped
    // before telemetry shuts down (otherwise it emits spans after the TracerProvider
    // is gone — "Spans are being emitted even after Shutdown").
    let mut engine_task: Option<tokio::task::JoinHandle<()>> = None;
    {
        // What the engine may actuate, derived from the same two-setting posture as the
        // webhooks (ADR-0021): `enforce` arms the reversible network cut confined to
        // `enforceScope`; `audit` (the default) is dry-run + unscoped (shadow). `active`
        // says what classes are armed; `scope` says where a cut may land — the JEF-104
        // seam, now fed by one source instead of two independent env knobs.
        let (active, scope) = posture.engine_arming();
        // Runtime-evidence ingest endpoint (the first-party agent, and any sensor, POSTs
        // behaviors here) for the RuntimeEvidence "corroborated-now" signal. Unset = no runtime
        // feed. Prefer PROTECTOR_BEHAVIOR_ADDR; fall back to the deprecated PROTECTOR_FALCO_ADDR.
        // compat: cluster chart still sets PROTECTOR_FALCO_ADDR; remove after the chart migrates.
        let behavior_addr = env::var("PROTECTOR_BEHAVIOR_ADDR")
            .or_else(|_| env::var("PROTECTOR_FALCO_ADDR"))
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok());
        // The k8s audit-log ingest endpoint (JEF-269): the apiserver's audit webhook POSTs
        // secret GET/LIST/WATCH events here for the RBAC-granted "corroborated-now" signal.
        // Unset = no audit feed. The apiserver's audit-policy + webhook config is a
        // deploy-repo concern (see the JEF-269 PR); this is the in-cluster ingest.
        let audit_addr = env::var("PROTECTOR_AUDIT_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok());
        // KEV catalogue (the exploited-in-wild feed) for the ExploitIntel signal. The path
        // defaults to the fixed feeds mount (JEF-273 owns the feed mechanism); the env is a
        // code-defaulted escape hatch. A missing/empty file degrades to no exploit intel.
        let kev = KevCatalog::from_file(&env_or("PROTECTOR_KEV_FILE", FEEDS_KEV_PATH));
        // EPSS scores (the FIRST.org predictive feed, JEF-243) — same fixed mount default.
        // Missing/empty ⇒ no EPSS evidence; a CVE's `epss` stays `None` and the prompt omits
        // the `[epss: …]` token.
        let epss = EpssStore::from_file(&env_or("PROTECTOR_EPSS_FILE", FEEDS_EPSS_PATH));
        // The mitigation engine restores the webhook's admission-decision log (JEF-226) from
        // the durable journal on boot — the same `Arc` the webhook engine writes to.
        let engine_policy_log = policy_log.clone();
        // The engine is the SOLE writer of the shared signing baseline (JEF-265): move the handle
        // into the engine task, which publishes a snapshot each sweep pass for the webhook to read.
        let engine_shared_baseline = shared_baseline.clone();
        match kube::Client::try_default().await {
            Ok(client) => {
                tracing::info!("starting mitigation engine (event-driven observer)");
                engine_task = Some(tokio::spawn(async move {
                    if let Err(error) = protector::engine::run_watch(
                        client,
                        active,
                        scope,
                        behavior_addr,
                        audit_addr,
                        kev,
                        epss,
                        engine_policy_log,
                        engine_shared_baseline,
                        engine_exceptions,
                    )
                    .await
                    {
                        tracing::error!(%error, "mitigation engine stopped");
                    }
                }));
            }
            Err(error) => {
                tracing::warn!(%error, "no kube client; mitigation engine disabled, webhook only");
            }
        }
    }

    let result = server::serve(addr, cert, key, engine, metrics).await;

    // Server returned (shutdown signal). Stop the engine task BEFORE telemetry so it
    // can't emit spans after the TracerProvider is shut down, then flush + stop the
    // OTLP exporters so the final trace/metric window isn't lost.
    if let Some(task) = engine_task {
        task.abort();
        let _ = task.await;
    }
    telemetry.shutdown();
    result
}

#[cfg(test)]
mod tests {
    use super::{Posture, docker_config_basic};
    use protector::engine::respond::ProposedAction;
    use protector::policy::EnforceScope;
    use std::collections::HashSet;

    /// Build a Posture directly, bypassing env, so the derivation is tested without
    /// touching process-global env.
    fn posture(enforce: bool, namespaces: &[&str], labels: &[(&str, &str)]) -> Posture {
        Posture {
            enforce,
            namespaces: namespaces.iter().map(|s| s.to_string()).collect(),
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn audit_posture_is_the_safe_default_everywhere() {
        // ADR-0021: `mode: audit` derives the empty (audit-everywhere) webhook scope and a
        // dry-run, unscoped engine — byte-identical to the historical all-defaults posture.
        let p = posture(false, &["payments"], &[("tier", "prod")]);
        assert!(
            p.webhook_scope().is_audit_only(),
            "audit mode never enforces, even if a scope is present"
        );
        let (active, _scope) = p.engine_arming();
        assert!(
            active.is_empty(),
            "audit mode arms no engine actuation (dry-run)"
        );
    }

    #[test]
    fn enforce_posture_arms_all_surfaces_in_exactly_the_scope() {
        // `mode: enforce` + a namespace scope arms both webhook gates (same EnforceScope)
        // AND the engine's network cut, confined to that scope.
        let p = posture(true, &["payments"], &[]);
        let scope = p.webhook_scope();
        assert!(!scope.is_audit_only(), "enforce mode enforces");
        assert!(
            scope.describe().contains("payments"),
            "the webhook scope is exactly enforceScope, got: {}",
            scope.describe()
        );
        let (active, _actuation) = p.engine_arming();
        assert!(
            active.is_enabled(ProposedAction::DenyNetworkPath),
            "enforce arms the reversible network cut"
        );
        assert!(
            !active.judgement_enabled(),
            "enforce does NOT enable model promotion — only the corroborated cut"
        );
    }

    #[test]
    fn labels_behave_like_namespaces() {
        // A label-only enforceScope still arms enforcement (the in-process gate matches
        // namespace OR pod label) and the engine cut.
        let p = posture(true, &[], &[("tier", "prod")]);
        assert!(!p.webhook_scope().is_audit_only());
        let (active, _scope) = p.engine_arming();
        assert!(active.is_enabled(ProposedAction::DenyNetworkPath));
    }

    #[test]
    fn webhook_and_engine_share_one_scope() {
        // The signature gate, the mesh gate, and the engine cut all derive from the same
        // enforceScope — they cannot drift.
        let ns: HashSet<String> = ["payments".to_string()].into_iter().collect();
        let p = posture(true, &["payments"], &[]);
        let sig = p.webhook_scope();
        let mesh = p.webhook_scope();
        let expected = EnforceScope::new(ns.clone(), vec![]);
        assert_eq!(sig.describe(), expected.describe());
        assert_eq!(mesh.describe(), expected.describe());
    }

    #[test]
    fn enforce_with_empty_scope_is_refused() {
        // ADR-0021: no enforce-everywhere wildcard. `mode: enforce` with an empty scope
        // must fail at startup. Serial env mutation guarded like the other env tests.
        // SAFETY: single-threaded within this test; vars are set + cleared here only.
        unsafe {
            std::env::set_var("PROTECTOR_MODE", "enforce");
            std::env::remove_var("PROTECTOR_ENFORCE_SCOPE_NAMESPACES");
            std::env::remove_var("PROTECTOR_ENFORCE_SCOPE_LABELS");
        }
        assert!(
            Posture::from_env().is_err(),
            "enforce with an empty scope is the wildcard footgun — must refuse to start"
        );
        // A scoped enforce is accepted.
        unsafe {
            std::env::set_var("PROTECTOR_ENFORCE_SCOPE_NAMESPACES", "payments");
        }
        let p = Posture::from_env().expect("scoped enforce is accepted");
        assert!(p.enforce);
        assert!(p.namespaces.contains("payments"));
        unsafe {
            std::env::remove_var("PROTECTOR_MODE");
            std::env::remove_var("PROTECTOR_ENFORCE_SCOPE_NAMESPACES");
        }
    }

    #[test]
    fn docker_config_decodes_ghcr_auth() {
        // base64("thejefflarson:ghp_token") = dGhlamVmZmxhcnNvbjpnaHBfdG9rZW4=
        let dir = std::env::temp_dir().join(format!("protector-dockercfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(
            &path,
            r#"{"auths":{"ghcr.io":{"auth":"dGhlamVmZmxhcnNvbjpnaHBfdG9rZW4="}}}"#,
        )
        .unwrap();
        let p = path.to_str().unwrap();
        assert_eq!(
            docker_config_basic(p, "ghcr.io"),
            Some(("thejefflarson".into(), "ghp_token".into()))
        );
        assert_eq!(docker_config_basic(p, "docker.io"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
