//! The behavioral-evidence wire contract (ADR-0014).
//!
//! These types are the normalized shape any sensor maps its events into and POSTs to
//! the engine's behavioral ingest: [`Behavior`] (what a workload did) and
//! [`RuntimeObservation`] (one behavior, attributed to a workload). They are shared by
//! the engine and protector's first-party eBPF agent so the two can't drift.
//!
//! Per ADR-0003 the *contract* is the JSON (`{"kind": "...", ...}`), not this Rust type
//! — a third-party sensor (via its own adapter) speaks the same JSON without depending
//! on this crate. The crate is a convenience for the first-party components, nothing the
//! port requires. The serde shape is pinned by the tests below.

use serde::{Deserialize, Serialize};

pub mod elf;
pub use elf::elf_static_linkage;

/// An observed runtime **behavior** — what a workload actually did, from any sensor
/// (the first-party eBPF agent, or any sensor with an adapter) through the tool-agnostic
/// behavioral port (ADR-0003/0014). Typed so the engine reasons about the *signal*, not the source.
/// Serde-tagged for the normalized ingest contract (`{"kind": "...", ...}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Behavior {
    /// A sensor rule fired (an alert from any sensor) — "something alarming, now."
    Alert { rule: String },
    /// An outbound connection the workload made; `internet` if it left the cluster.
    NetworkConnection { peer: String, internet: bool },
    /// A read of a secret. `source` distinguishes *how* it was read: a mounted-file read
    /// (the eBPF agent's on-disk path) or a Kubernetes API GET/LIST/WATCH via the
    /// workload's ServiceAccount RBAC (observed engine-side from the apiserver audit log,
    /// JEF-269) — two genuinely different runtime facts that both reach the same secret.
    /// Older sensors omit `source`, which defaults to [`SecretReadSource::Mounted`] (the
    /// only kind eBPF can see), preserving the pre-existing wire shape.
    SecretRead {
        secret: String,
        #[serde(default, skip_serializing_if = "SecretReadSource::is_mounted")]
        source: SecretReadSource,
    },
    /// A load of a shared library / dependency artifact.
    LibraryLoaded { name: String },
    /// A **transport-stage** signal: a file open the sensor couldn't classify on its own.
    /// The eBPF agent emits this for reads on a tmpfs (where Secret/ConfigMap/projected
    /// volumes live) carrying the *container-relative* path — it has no cluster access to
    /// know if that path is a Secret. The engine refines it (in the RuntimeAdapter) into a
    /// [`Behavior::SecretRead`] using the pod's secret `volumeMounts`, or drops it. It
    /// never persists as graph state, so [`Self::summary`]/[`Self::fingerprint_key`] only
    /// see it defensively.
    FileRead { path: String },
    /// A process gained root — its real UID changed to 0 from a non-root UID (the eBPF
    /// agent's privilege-change probe, fentry on `security_task_fix_setuid`). Model
    /// evidence, not blanket corroboration:
    /// legitimate workloads sometimes escalate (init/entrypoint), so wiring this to
    /// corroborate a specific attack is JEF-49's job.
    PrivilegeChange { from_uid: u32, to_uid: u32 },
    /// A process was exec'd in the workload — the runtime signal for "unexpected process
    /// spawned" (ADR-0014). `path` is the exec'd binary's path as the
    /// kernel saw it (`linux_binprm->filename`). Evidence for the model only today;
    /// wiring exec → corroboration is JEF-49.
    ProcessExec { path: String },
    /// A **write** to a file — the runtime signal for container drift: drop-and-execute
    /// (a new file created then run) and config tampering (an existing file overwritten).
    /// The eBPF agent's file-write probe (fentry on `security_file_open` filtered to
    /// write-intent open flags, ADR-0014). `path` is the
    /// written file's path as the kernel saw it (`bpf_d_path`). PURE DATA (JEF-306): whether
    /// the path is *sensitive* — the container-drift / tamper judgement — is engine
    /// corroboration policy (JEF-306 F3), not a property of this shared wire type. The agent
    /// emits the path; the engine classifies. Model evidence only today.
    FileWrite { path: String },
    /// The workload's entrypoint binary's **static/dynamic linkage** (JEF-407) — read by
    /// the node-local agent from the executable's ELF header (`/proc/<pid>/exe`, no
    /// `PT_INTERP` ⇒ statically linked). This is the byte source that ACTIVATES JEF-404's
    /// static-linkage reachability in prod: the engine has no in-cluster access to the
    /// entrypoint bytes, so without this signal `Image::static_binary` stays `None` and a
    /// Go / musl-static CVE renders `not-observed` forever. `static_linkage == true` ⇒ a
    /// static binary; the engine maps it onto `Image::static_binary` so a would-be
    /// `not-observed` CVE tags `present-static-binary` (indeterminate, not observed-absent).
    ///
    /// It is a *structural* fact about the image, NOT an attack signal — it never
    /// corroborates ([`Self::is_alert`] is false) and is CONTEXT only. Reported over the
    /// SAME behavioral channel (ADR-0014), so no new egress (the zero-egress invariant
    /// holds — the agent already sees `/proc/<pid>/exe`). PURE DATA: the agent classifies
    /// the bytes; the *reachability* consequence is engine policy (JEF-404).
    ImageLinkage { static_linkage: bool },
}

/// How a [`Behavior::SecretRead`] was observed — a type distinction, not a string
/// convention. The wire type stays cluster-agnostic (ADR-0003): a sensor names only the
/// *kind* of read it saw; the engine, not the agent, resolves the ServiceAccount→edge
/// attribution for an API read (JEF-269).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReadSource {
    /// The secret's on-disk contents were read from a mounted volume — the eBPF agent's
    /// file-read path (the only secret read a node-local sensor can see). The default so
    /// older agents' `{"kind":"secret_read","secret":"..."}` keeps its meaning.
    #[default]
    Mounted,
    /// The secret was fetched through the Kubernetes API (a `get`/`list`/`watch` on
    /// `secrets`) via the workload's ServiceAccount RBAC — a TLS call to the apiserver
    /// eBPF cannot attribute as a secret read. Observed engine-side from the audit log.
    Api,
}

impl SecretReadSource {
    /// Whether this is the default (mounted) source. Used to omit `source` from the wire
    /// for the common mounted read, keeping the eBPF agent's contract byte-for-byte stable.
    fn is_mounted(&self) -> bool {
        matches!(self, SecretReadSource::Mounted)
    }
}

/// The basename of a binary path as the kernel saw it (`/usr/bin/apt` -> `apt`) — the
/// last `/`-separated segment. Used by [`Behavior::fingerprint_key`] to coarsen an exec
/// path to a stable, low-cardinality cache token.
///
/// Note: exec *classification* (is this a shell / package manager?) is engine policy, not
/// part of this wire type — it lives in `engine::observe::exec_class` (JEF-113), keyed on
/// this same basename token, so a list change rebuilds only the engine, never the agent.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The directory portion of a path (`/etc/cron.d/x` -> `/etc/cron.d`) — the last `/` and
/// everything after it removed. Used by [`Behavior::fingerprint_key`] to coarsen a file
/// *write* path to a stable, low-cardinality cache token: per-file churn within a
/// directory (drop-and-execute dropping many temp files, a config dir rewritten
/// file-by-file) collapses to one key so a burst of writes never busts the verdict cache.
/// A top-level path (`/foo`) or a bare filename (no `/`) coarsens to `/`.
fn dirname(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None => "/",
    }
}

impl Behavior {
    /// Whether this behavior **corroborates** the action bar (ADR-0009): only an
    /// alerting signal means "an attack is happening now." Mundane behaviors
    /// (connections, reads, loads) are *evidence for the model*, never blanket
    /// corroboration — otherwise every workload, which all make connections, would
    /// corroborate everything.
    pub fn is_alert(&self) -> bool {
        matches!(self, Behavior::Alert { .. })
    }

    /// A stable, **low-cardinality** label naming this behavior's variant — one of a
    /// fixed, small set (`alert`/`connection`/`secret-read`/`library-load`/`file-read`/
    /// `priv-change`/`exec`). Used as a metric label for behavioral-signal counters
    /// (JEF-100): it must never carry per-instance payload (a peer, a path, a secret
    /// name), which would explode metric cardinality — only the variant name. Distinct
    /// from [`Self::summary`] (human prose) and [`Self::fingerprint_key`] (cache key).
    pub fn variant_label(&self) -> &'static str {
        match self {
            Behavior::Alert { .. } => "alert",
            Behavior::NetworkConnection { .. } => "connection",
            Behavior::SecretRead { .. } => "secret-read",
            Behavior::LibraryLoaded { .. } => "library-load",
            Behavior::FileRead { .. } => "file-read",
            Behavior::PrivilegeChange { .. } => "priv-change",
            Behavior::ProcessExec { .. } => "exec",
            Behavior::FileWrite { .. } => "file-write",
            Behavior::ImageLinkage { .. } => "image-linkage",
        }
    }

    /// A one-line, human summary for the adjudication prompt. For a
    /// [`Behavior::ProcessExec`] this is the bare `executed {path}` — *classification* of a
    /// notable exec (shell / package manager in container) is engine policy
    /// (`engine::observe::exec_class`, JEF-113), not a property of this shared wire type, so
    /// the engine annotates the path when it builds the prompt/output line rather than
    /// this crate baking a rule list into the contract.
    pub fn summary(&self) -> String {
        match self {
            Behavior::Alert { rule } => format!("alert: {rule}"),
            Behavior::NetworkConnection { peer, internet } => format!(
                "connects to {peer}{}",
                if *internet { " (INTERNET egress)" } else { "" }
            ),
            Behavior::SecretRead { secret, source } => match source {
                SecretReadSource::Mounted => format!("reads secret {secret}"),
                SecretReadSource::Api => format!("reads secret {secret} (via Kubernetes API)"),
            },
            Behavior::LibraryLoaded { name } => format!("loaded library {name}"),
            Behavior::FileRead { path } => format!("opened file {path}"),
            Behavior::PrivilegeChange { from_uid, to_uid } => {
                format!("privilege change uid {from_uid} -> {to_uid}")
            }
            // Just the exec'd path. Whether it's a *notable* exec (a shell or package
            // manager run in the container — JEF-55) is engine classification policy
            // (`engine::observe::exec_class`), applied by the engine when it builds the
            // prompt/output line — this shared wire type stays pure data (JEF-113).
            Behavior::ProcessExec { path } => format!("executed {path}"),
            // Just the written path. Whether the write is *sensitive* (container drift /
            // config tampering) is engine corroboration policy (JEF-306 F3), not a property
            // of this shared wire type — the agent emits the path, the engine classifies.
            Behavior::FileWrite { path } => format!("wrote file {path}"),
            // A structural linkage fact, not an action. Named so the prompt/dashboard read
            // it as CONTEXT (why a Go/musl-static CVE can't be library-load-correlated),
            // never as an event that happened.
            Behavior::ImageLinkage { static_linkage } => {
                if *static_linkage {
                    "entrypoint is a statically linked binary".to_string()
                } else {
                    "entrypoint is a dynamically linked binary".to_string()
                }
            }
        }
    }

    /// A COARSE, stable key for the verdict-cache fingerprint. Mundane per-peer
    /// connection churn must NOT bust the cache (that would re-judge every pass on a
    /// slow model), so connections collapse to a scope token; stable facts (alerts,
    /// libs, which secret) are kept verbatim.
    pub fn fingerprint_key(&self) -> String {
        match self {
            Behavior::Alert { rule } => format!("alert:{rule}"),
            Behavior::NetworkConnection { internet: true, .. } => "egress:internet".to_string(),
            Behavior::NetworkConnection {
                internet: false, ..
            } => "egress:cluster".to_string(),
            // Keep the source in the key so a mounted read and an API read of the same
            // secret are distinct facts (they corroborate the same tactic, but they are
            // genuinely different observations). Mounted keeps its historical `read:` key.
            Behavior::SecretRead {
                secret,
                source: SecretReadSource::Mounted,
            } => format!("read:{secret}"),
            Behavior::SecretRead {
                secret,
                source: SecretReadSource::Api,
            } => format!("read-api:{secret}"),
            Behavior::LibraryLoaded { name } => format!("lib:{name}"),
            Behavior::FileRead { path } => format!("file:{path}"),
            // Keyed on the gained UID only (always 0 today, but stable if the escalation
            // predicate widens): repeated escalations to the same UID collapse to one
            // fingerprint and don't bust the verdict cache.
            Behavior::PrivilegeChange { to_uid, .. } => format!("priv:{to_uid}"),
            // Coarsen to the basename so repeated execs of the same binary from different
            // absolute paths collapse to one stable key (mirrors how LibraryLoaded keys on
            // the lib name, not the full path) — keeps exec churn from busting the cache.
            Behavior::ProcessExec { path } => format!("exec:{}", basename(path)),
            // Coarsen to the DIRNAME so per-file write churn within a directory
            // (drop-and-execute writing many files, a config dir rewritten file-by-file)
            // collapses to one stable key — writes are high-frequency, so keying on the
            // full path would thrash the verdict cache (mirrors the exec/library basename
            // coarsening, one level up the tree for the higher write volume).
            Behavior::FileWrite { path } => format!("write:{}", dirname(path)),
            // The linkage is a stable per-image fact (static vs dynamic), so key on the
            // bool verbatim — the two states are genuinely distinct facts, and it's
            // low-cardinality by construction (exactly two values).
            Behavior::ImageLinkage { static_linkage } => format!("linkage:{static_linkage}"),
        }
    }
}

/// How a sensor **attributed** an observation to a workload — a type distinction, not an
/// empty-string convention (JEF-59). A sensor either knows the pod's cgroup UID (the
/// first-party eBPF agent, which stays node-local and can't resolve names itself) or it
/// already has the namespace/name (a sensor that reads k8s metadata). The engine resolves
/// [`Self::ByPodUid`] → namespace/pod via its own pod watch (ADR-0014); the agent needs no
/// cluster credentials.
///
/// Serialized **untagged + flattened** onto [`RuntimeObservation`], so the JSON stays the
/// same flat shape as before — `{"pod_uid": "..."}` or `{"namespace": "...", "pod": "..."}`
/// — and serde picks the variant by which fields are present. The contract is the JSON
/// (ADR-0003); this keeps that contract identical while making the Rust type honest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Attribution {
    /// The eBPF agent: a pod UID read from the cgroup; the engine resolves UID → pod.
    ByPodUid { pod_uid: String },
    /// Any sensor with cluster metadata: the namespace/name directly.
    ByNamespacedName { namespace: String, pod: String },
}

impl Attribution {
    /// Attribute by pod UID (the eBPF agent's path).
    pub fn by_pod_uid(uid: impl Into<String>) -> Self {
        Attribution::ByPodUid {
            pod_uid: uid.into(),
        }
    }

    /// Attribute by namespace + pod name (a metadata-aware sensor's path).
    pub fn by_namespaced_name(namespace: impl Into<String>, pod: impl Into<String>) -> Self {
        Attribution::ByNamespacedName {
            namespace: namespace.into(),
            pod: pod.into(),
        }
    }

    /// Whether this attribution resolves to a live workload, given a way to ask whether a
    /// pod UID is currently observed. A [`ByNamespacedName`](Self::ByNamespacedName)
    /// attribution (a sensor that already carries cluster metadata) always resolves; a
    /// [`ByPodUid`](Self::ByPodUid) one (the eBPF agent) resolves only when a pod with that
    /// UID is present — an unknown UID (pod gone / not yet observed) does not resolve and is
    /// dropped rather than guessed (ADR-0014).
    ///
    /// This is the single owner of the resolution rule: the engine's `RuntimeAdapter`
    /// applies it to attach signals and the attribution-outcome metric applies it to count
    /// resolved vs unresolved, so the two can't drift. `pod_uid_known` is a caller-supplied
    /// lookup (e.g. membership in the snapshot's live pod-UID set), keeping this crate free
    /// of any Kubernetes/engine types.
    pub fn resolves_in(&self, pod_uid_known: impl FnOnce(&str) -> bool) -> bool {
        match self {
            Attribution::ByNamespacedName { .. } => true,
            Attribution::ByPodUid { pod_uid } => pod_uid_known(pod_uid),
        }
    }
}

/// A normalized live runtime observation about a workload — the behavioral port's input
/// shape (ADR-0014). Any sensor (the first-party eBPF agent, Tetragon, …) maps
/// its events into this; the graph sees only the normalized signal, not a vendor type.
/// `Deserialize` so a sensor can POST it directly to the normalized ingest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeObservation {
    /// How this observation is attributed to a workload — by cgroup UID (eBPF agent) or by
    /// namespace/name (a metadata-aware sensor). Flattened so its fields sit at the JSON top
    /// level, preserving the original flat wire shape.
    #[serde(flatten)]
    pub attribution: Attribution,
    /// Which sensor observed this — `"protector-agent"`, `"alert"`, … Carried into the
    /// signal's provenance so two sensors observing the same activity are corroboration,
    /// not one indistinguishable source (ADR-0003). Defaulted (older agents omit it) →
    /// the adapter falls back to its own name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// When the sensor observed it, as Unix epoch milliseconds. Freshness is a
    /// first-class correctness concern (ADR-0002), so we carry the *sensor's* observation
    /// time rather than re-stamping at adapter-run time (which can lag the real event by a
    /// batch interval + a judging pass). Defaulted → adapter uses now().
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at_ms: Option<u64>,
    /// The Kubernetes NODE the sensor observed this on (JEF-308) — the eBPF agent reports its
    /// own node (from the downward API, `spec.nodeName`), so the engine can reason about
    /// runtime-corroboration coverage PER NODE ("blind on node X"), not just fleet-aggregate.
    /// Defaulted (older agents, or a node-agnostic sensor, omit it) — an absent node is
    /// honestly node-unattributed, never guessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// What the workload actually did.
    pub behavior: Behavior,
}

/// A per-node **agent-liveness beacon** (JEF-308): the eBPF agent's own self-report, one per
/// report window, distinct from a workload [`RuntimeObservation`]. It is what makes
/// runtime-corroboration coverage honestly derivable per node: liveness is **signal-flow**, not
/// pod-Ready — a Ready agent whose eBPF probes failed to attach is still BLIND (a Ready-but-blind
/// sensor), so it reports `probes_loaded = 0`, and the engine reads it as blind despite the
/// pod being up.
///
/// Critically, the agent emits this **every window even when it saw nothing**, so a quiet node
/// (`signals_emitted = 0`, probes loaded) reads HEALTHY-quiet — NOT blind. Only a node that never
/// reports, or reports `probes_loaded = 0`, reads blind. Sent over the same in-cluster ingest the
/// observations already use (zero egress) — never the agent's OTLP/metrics endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentReport {
    /// The node this agent runs on (downward API `spec.nodeName`). Untrusted-adjacent at
    /// render — the engine escapes it like any cluster name (never `PreEscaped`).
    pub node: String,
    /// How many eBPF probes ACTUALLY attached this window. `0` ⇒ the agent is Ready but blind
    /// (nothing is being observed); `< probes_total` ⇒ partial coverage (degraded).
    pub probes_loaded: u32,
    /// How many probes the agent tried to load — the denominator for "partial". `0` only for a
    /// build with no collection (the default no-eBPF image), which is also honestly blind.
    pub probes_total: u32,
    /// Signals the agent emitted this window. `0` is HEALTHY-quiet when probes are loaded — a
    /// quiet node is not a down sensor (the JEF-308 quiet≠blind invariant).
    pub signals_emitted: u64,
    /// When the window closed, as Unix epoch millis. Defaulted → the engine stamps ingest time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at_ms: Option<u64>,
}

impl AgentReport {
    /// Whether this report means the node is **blind** despite the agent being up: no probe
    /// attached, so nothing is being observed. This is the Ready-but-blind failure mode
    /// liveness-as-signal-flow catches (a pod-Ready check never would).
    pub fn is_blind(&self) -> bool {
        self.probes_loaded == 0
    }

    /// Whether the agent loaded only SOME of its probes — partial coverage (degraded, not blind).
    /// False when fully loaded, or when blind (`probes_loaded == 0`, which reads as blind, not
    /// partial), or when the build declares no probes at all (`probes_total == 0`).
    pub fn is_partial(&self) -> bool {
        self.probes_loaded > 0 && self.probes_total > 0 && self.probes_loaded < self.probes_total
    }
}

/// A per-window **runtime report** (JEF-336): the single envelope every sensor POSTs to the
/// engine's unified runtime ingest (`/behavior`). It carries the window's normalized
/// [`RuntimeObservation`]s AND — for a sensor that has one — its per-node liveness
/// [`AgentReport`], so liveness ALWAYS travels with the report. That is what keeps the JEF-308
/// "quiet ≠ blind" guarantee honest: a node that saw nothing still POSTs an envelope with empty
/// `observations` and its `liveness` present, so the engine records it HEALTHY-quiet instead of
/// reading it blind for want of a beacon.
///
/// `liveness` is [`Option`] so the ADR-0003 tool-agnostic port still accepts a third-party sensor
/// that sends only observations (it has no agent-specific `probes_loaded` to report). Both fields
/// are defaulted and skip-if-empty on the wire, so an observations-only envelope is just
/// `{"observations":[...]}` and a quiet liveness-only one is `{"liveness":{...}}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuntimeReport {
    /// The normalized observations seen this window — possibly empty (a quiet node still reports).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<RuntimeObservation>,
    /// This sensor's per-node liveness beacon (JEF-308), when it has one. Absent for a
    /// node-agnostic third-party sensor with no agent-specific liveness to report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness: Option<AgentReport>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behavior_serializes_to_the_kind_tagged_contract() {
        let v = serde_json::to_value(Behavior::NetworkConnection {
            peer: "1.2.3.4:443".into(),
            internet: true,
        })
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({"kind": "network_connection", "peer": "1.2.3.4:443", "internet": true})
        );
    }

    #[test]
    fn resolves_in_applies_the_attribution_resolution_rule() {
        // A namespace/name attribution always resolves — even when the lookup
        // would reject everything.
        assert!(Attribution::by_namespaced_name("app", "web").resolves_in(|_| false));
        // A cgroup-UID attribution (the eBPF agent) resolves iff the UID is known.
        assert!(Attribution::by_pod_uid("uid-1").resolves_in(|uid| uid == "uid-1"));
        assert!(!Attribution::by_pod_uid("uid-unknown").resolves_in(|uid| uid == "uid-1"));
    }

    #[test]
    fn observation_roundtrips_and_omits_absent_optionals() {
        // An eBPF-agent observation: attributed by uid, source + time set.
        let obs = RuntimeObservation {
            attribution: Attribution::by_pod_uid("uid"),
            source: Some("protector-agent".into()),
            observed_at_ms: Some(1_710_000_000_000),
            node: None,
            behavior: Behavior::SecretRead {
                secret: "app/session-key".into(),
                source: SecretReadSource::Mounted,
            },
        };
        let v = serde_json::to_value(&obs).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "pod_uid": "uid",
                "source": "protector-agent",
                "observed_at_ms": 1_710_000_000_000u64,
                "behavior": {"kind": "secret_read", "secret": "app/session-key"}
            })
        );
        assert_eq!(
            serde_json::from_value::<RuntimeObservation>(v).unwrap(),
            obs
        );
    }

    #[test]
    fn secret_read_source_distinguishes_mounted_from_api() {
        // Mounted is the default and is OMITTED on the wire, so the eBPF agent's existing
        // `{"kind":"secret_read","secret":"..."}` contract is byte-for-byte unchanged.
        let mounted = Behavior::SecretRead {
            secret: "app/db".into(),
            source: SecretReadSource::Mounted,
        };
        assert_eq!(
            serde_json::to_value(&mounted).unwrap(),
            serde_json::json!({"kind": "secret_read", "secret": "app/db"})
        );
        // An absent `source` deserializes back to Mounted (older sensors).
        let from_legacy: Behavior =
            serde_json::from_value(serde_json::json!({"kind": "secret_read", "secret": "app/db"}))
                .unwrap();
        assert_eq!(from_legacy, mounted);

        // An API read serializes its source explicitly and round-trips.
        let api = Behavior::SecretRead {
            secret: "app/db".into(),
            source: SecretReadSource::Api,
        };
        let v = serde_json::to_value(&api).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"kind": "secret_read", "secret": "app/db", "source": "api"})
        );
        assert_eq!(serde_json::from_value::<Behavior>(v).unwrap(), api);

        // The two are distinguishable everywhere it matters: summary prose and the
        // verdict-cache fingerprint. The metric label stays the coarse shared token.
        assert_eq!(mounted.summary(), "reads secret app/db");
        assert_eq!(api.summary(), "reads secret app/db (via Kubernetes API)");
        assert_eq!(mounted.fingerprint_key(), "read:app/db");
        assert_eq!(api.fingerprint_key(), "read-api:app/db");
        assert_ne!(mounted.fingerprint_key(), api.fingerprint_key());
        assert_eq!(mounted.variant_label(), api.variant_label());
    }

    #[test]
    fn namespaced_observation_deserializes_from_namespace_pod() {
        // A metadata-attributed observation: ns/pod set, no uid/source/time.
        let obs: RuntimeObservation = serde_json::from_value(serde_json::json!({
            "namespace": "app", "pod": "web",
            "behavior": {"kind": "alert", "rule": "Terminal shell in container"}
        }))
        .unwrap();
        assert_eq!(
            obs.attribution,
            Attribution::by_namespaced_name("app", "web")
        );
        assert!(obs.behavior.is_alert());
    }

    #[test]
    fn process_exec_fingerprint_coarsens_to_basename() {
        // Different absolute paths to the same binary must collapse to one stable key so
        // exec churn doesn't bust the verdict cache (mirrors LibraryLoaded's basename key).
        let a = Behavior::ProcessExec {
            path: "/usr/bin/bash".into(),
        };
        let b = Behavior::ProcessExec {
            path: "/bin/bash".into(),
        };
        assert_eq!(a.fingerprint_key(), "exec:bash");
        assert_eq!(a.fingerprint_key(), b.fingerprint_key());
        // The wire type's summary is the bare path; *classification* of a notable exec
        // (shell / package manager) is engine policy (engine::observe::exec_class, JEF-113),
        // so it's not annotated here.
        assert_eq!(a.summary(), "executed /usr/bin/bash");
    }

    #[test]
    fn process_exec_summary_is_the_bare_path() {
        // The shared wire type emits only the path — engine policy decides if it's notable
        // (a shell / package manager) and annotates the prompt/output line (JEF-113).
        let shell = Behavior::ProcessExec {
            path: "/bin/bash".into(),
        };
        let normal = Behavior::ProcessExec {
            path: "/app/server".into(),
        };
        assert_eq!(shell.summary(), "executed /bin/bash");
        assert_eq!(normal.summary(), "executed /app/server");
        // Classification is engine evidence, NOT action-bar corroboration — only Alerts
        // corroborate from the wire type's perspective.
        assert!(!shell.is_alert());
    }

    #[test]
    fn variant_label_is_a_stable_low_cardinality_token() {
        // Each variant maps to a fixed token carrying NO per-instance payload (no peer,
        // path, or secret name) — so it's safe as a metric label without cardinality blow-up.
        let cases: [(Behavior, &str); 9] = [
            (Behavior::Alert { rule: "x".into() }, "alert"),
            (
                Behavior::NetworkConnection {
                    peer: "1.2.3.4:443".into(),
                    internet: true,
                },
                "connection",
            ),
            (
                Behavior::SecretRead {
                    secret: "s".into(),
                    source: SecretReadSource::Mounted,
                },
                "secret-read",
            ),
            (Behavior::LibraryLoaded { name: "l".into() }, "library-load"),
            (Behavior::FileRead { path: "/p".into() }, "file-read"),
            (
                Behavior::PrivilegeChange {
                    from_uid: 1000,
                    to_uid: 0,
                },
                "priv-change",
            ),
            (
                Behavior::ProcessExec {
                    path: "/bin/bash".into(),
                },
                "exec",
            ),
            (
                Behavior::FileWrite {
                    path: "/etc/cron.d/x".into(),
                },
                "file-write",
            ),
            (
                Behavior::ImageLinkage {
                    static_linkage: true,
                },
                "image-linkage",
            ),
        ];
        for (behavior, want) in cases {
            assert_eq!(behavior.variant_label(), want, "{behavior:?}");
        }
    }

    #[test]
    fn file_write_fingerprint_coarsens_to_the_dirname() {
        // Per-file write churn within a directory must collapse to one stable key so a
        // burst of writes (drop-and-execute, a config dir rewritten file-by-file) doesn't
        // bust the verdict cache — the write signal is high-frequency (JEF-306).
        let a = Behavior::FileWrite {
            path: "/etc/cron.d/dropper".into(),
        };
        let b = Behavior::FileWrite {
            path: "/etc/cron.d/other".into(),
        };
        assert_eq!(a.fingerprint_key(), "write:/etc/cron.d");
        assert_eq!(a.fingerprint_key(), b.fingerprint_key());
        // A top-level path and a bare filename coarsen to `/` (low cardinality, never panics).
        assert_eq!(
            Behavior::FileWrite {
                path: "/passwd".into()
            }
            .fingerprint_key(),
            "write:/"
        );
        assert_eq!(
            Behavior::FileWrite {
                path: "relative".into()
            }
            .fingerprint_key(),
            "write:/"
        );
    }

    #[test]
    fn file_write_summary_is_the_bare_path_and_never_corroborates() {
        // The shared wire type emits only the path — whether the write is *sensitive*
        // (container drift / config tampering) is engine corroboration policy (JEF-306 F3),
        // so it's pure data here and, like other mundane behaviors, never an alert.
        let w = Behavior::FileWrite {
            path: "/etc/ssh/sshd_config".into(),
        };
        assert_eq!(w.summary(), "wrote file /etc/ssh/sshd_config");
        assert!(!w.is_alert());
    }

    #[test]
    fn file_write_serializes_to_the_kind_tagged_contract() {
        // Pure-data wire shape: `{"kind":"file_write","path":"..."}`, round-trips (JEF-306).
        let w = Behavior::FileWrite {
            path: "/etc/cron.d/x".into(),
        };
        let v = serde_json::to_value(&w).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"kind": "file_write", "path": "/etc/cron.d/x"})
        );
        assert_eq!(serde_json::from_value::<Behavior>(v).unwrap(), w);
    }

    #[test]
    fn observation_carries_the_node_and_omits_it_when_absent() {
        // JEF-308: the agent stamps its node so coverage is derivable PER NODE. When present it
        // rides the wire; when absent (a node-agnostic sensor, older agents) it is omitted — never guessed.
        let with_node = RuntimeObservation {
            attribution: Attribution::by_pod_uid("uid"),
            source: Some("protector-agent".into()),
            observed_at_ms: None,
            node: Some("node-a".into()),
            behavior: Behavior::ProcessExec {
                path: "/bin/sh".into(),
            },
        };
        let v = serde_json::to_value(&with_node).unwrap();
        assert_eq!(v["node"], serde_json::json!("node-a"));
        assert_eq!(
            serde_json::from_value::<RuntimeObservation>(v).unwrap(),
            with_node
        );

        // Absent node ⇒ the key is omitted (byte-stable for node-agnostic sensors), and a legacy
        // observation with no `node` deserializes back to `None`.
        let no_node: RuntimeObservation = serde_json::from_value(serde_json::json!({
            "namespace": "app", "pod": "web",
            "behavior": {"kind": "alert", "rule": "shell"}
        }))
        .unwrap();
        assert_eq!(no_node.node, None);
        let reser = serde_json::to_value(&no_node).unwrap();
        assert!(
            reser.get("node").is_none(),
            "absent node is omitted on the wire"
        );
    }

    #[test]
    fn agent_report_round_trips_and_classifies_blind_vs_partial() {
        // A healthy report: all probes loaded, some signals — round-trips.
        let healthy = AgentReport {
            node: "node-a".into(),
            probes_loaded: 6,
            probes_total: 6,
            signals_emitted: 12,
            observed_at_ms: Some(1_710_000_000_000),
        };
        let v = serde_json::to_value(&healthy).unwrap();
        assert_eq!(serde_json::from_value::<AgentReport>(v).unwrap(), healthy);
        assert!(!healthy.is_blind());
        assert!(!healthy.is_partial());

        // Quiet but healthy: probes loaded, zero signals — NOT blind, NOT partial (quiet≠blind).
        let quiet = AgentReport {
            signals_emitted: 0,
            ..healthy.clone()
        };
        assert!(
            !quiet.is_blind(),
            "a quiet node with probes loaded is not blind"
        );
        assert!(!quiet.is_partial());

        // Ready but blind: the agent is up but no probe attached — blind despite pod-Ready.
        let blind = AgentReport {
            probes_loaded: 0,
            ..healthy.clone()
        };
        assert!(blind.is_blind());
        assert!(
            !blind.is_partial(),
            "zero probes reads as blind, not partial"
        );

        // Partial: some but not all probes attached — degraded coverage.
        let partial = AgentReport {
            probes_loaded: 4,
            ..healthy
        };
        assert!(!partial.is_blind());
        assert!(partial.is_partial());
    }

    #[test]
    fn agent_report_observed_at_ms_is_omitted_when_absent() {
        let report = AgentReport {
            node: "n".into(),
            probes_loaded: 1,
            probes_total: 1,
            signals_emitted: 0,
            observed_at_ms: None,
        };
        let v = serde_json::to_value(&report).unwrap();
        assert!(v.get("observed_at_ms").is_none());
        assert_eq!(serde_json::from_value::<AgentReport>(v).unwrap(), report);
    }

    #[test]
    fn runtime_report_round_trips_with_observations_and_liveness() {
        // JEF-336: the unified envelope carries the window's observations AND the per-node
        // liveness beacon in one shape, and round-trips byte-for-byte.
        let report = RuntimeReport {
            observations: vec![RuntimeObservation {
                attribution: Attribution::by_pod_uid("uid"),
                source: Some("protector-agent".into()),
                observed_at_ms: None,
                node: Some("node-a".into()),
                behavior: Behavior::Alert {
                    rule: "Terminal shell in container".into(),
                },
            }],
            liveness: Some(AgentReport {
                node: "node-a".into(),
                probes_loaded: 6,
                probes_total: 6,
                signals_emitted: 1,
                observed_at_ms: None,
            }),
        };
        let v = serde_json::to_value(&report).unwrap();
        assert!(v.get("observations").is_some());
        assert_eq!(v["liveness"]["node"], serde_json::json!("node-a"));
        assert_eq!(serde_json::from_value::<RuntimeReport>(v).unwrap(), report);
    }

    #[test]
    fn runtime_report_omits_empty_observations_and_absent_liveness() {
        // A quiet node's envelope: no observations, liveness present — `observations` is omitted
        // (skip_serializing_if empty) so the wire is just `{"liveness":{...}}`.
        let quiet = RuntimeReport {
            observations: Vec::new(),
            liveness: Some(AgentReport {
                node: "node-a".into(),
                probes_loaded: 6,
                probes_total: 6,
                signals_emitted: 0,
                observed_at_ms: None,
            }),
        };
        let v = serde_json::to_value(&quiet).unwrap();
        assert!(
            v.get("observations").is_none(),
            "empty observations omitted from the wire"
        );
        assert!(v.get("liveness").is_some());
        assert_eq!(serde_json::from_value::<RuntimeReport>(v).unwrap(), quiet);

        // A third-party observations-only envelope: liveness absent → `liveness` omitted, and it
        // deserializes back with `liveness: None` (the ADR-0003 tool-agnostic path).
        let obs_only = RuntimeReport {
            observations: vec![RuntimeObservation {
                attribution: Attribution::by_namespaced_name("app", "web"),
                source: None,
                observed_at_ms: None,
                node: None,
                behavior: Behavior::LibraryLoaded {
                    name: "openssl".into(),
                },
            }],
            liveness: None,
        };
        let v = serde_json::to_value(&obs_only).unwrap();
        assert!(
            v.get("liveness").is_none(),
            "absent liveness omitted from the wire"
        );
        assert_eq!(
            serde_json::from_value::<RuntimeReport>(v).unwrap(),
            obs_only
        );
    }

    #[test]
    fn image_linkage_serializes_to_the_kind_tagged_contract_and_round_trips() {
        // JEF-407: the linkage signal rides the same `{"kind": "...", ...}` behavioral wire.
        // A static-linkage report and a dynamic one both round-trip byte-for-byte.
        let stat = Behavior::ImageLinkage {
            static_linkage: true,
        };
        let v = serde_json::to_value(&stat).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"kind": "image_linkage", "static_linkage": true})
        );
        assert_eq!(serde_json::from_value::<Behavior>(v).unwrap(), stat);

        let dynm = Behavior::ImageLinkage {
            static_linkage: false,
        };
        let v = serde_json::to_value(&dynm).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"kind": "image_linkage", "static_linkage": false})
        );
        assert_eq!(serde_json::from_value::<Behavior>(v).unwrap(), dynm);
    }

    #[test]
    fn image_linkage_is_context_not_corroboration() {
        // A structural fact about the image, never an "attack is happening now" signal —
        // only Alerts corroborate the action bar (else linkage would fire it, which is wrong).
        assert!(
            !Behavior::ImageLinkage {
                static_linkage: true
            }
            .is_alert()
        );
        // Distinct summaries and fingerprints for the two linkage states.
        assert_eq!(
            Behavior::ImageLinkage {
                static_linkage: true
            }
            .summary(),
            "entrypoint is a statically linked binary"
        );
        assert_eq!(
            Behavior::ImageLinkage {
                static_linkage: false
            }
            .summary(),
            "entrypoint is a dynamically linked binary"
        );
        assert_ne!(
            Behavior::ImageLinkage {
                static_linkage: true
            }
            .fingerprint_key(),
            Behavior::ImageLinkage {
                static_linkage: false
            }
            .fingerprint_key()
        );
    }

    #[test]
    fn image_linkage_observation_round_trips_over_the_wire() {
        // The full RuntimeObservation the agent POSTs for a static entrypoint — attributed by
        // pod UID (the eBPF agent's path), source + node stamped — round-trips.
        let obs = RuntimeObservation {
            attribution: Attribution::by_pod_uid("uid"),
            source: Some("protector-agent".into()),
            observed_at_ms: None,
            node: Some("node-a".into()),
            behavior: Behavior::ImageLinkage {
                static_linkage: true,
            },
        };
        let v = serde_json::to_value(&obs).unwrap();
        assert_eq!(
            v["behavior"],
            serde_json::json!({"kind": "image_linkage", "static_linkage": true})
        );
        assert_eq!(
            serde_json::from_value::<RuntimeObservation>(v).unwrap(),
            obs
        );
    }

    #[test]
    fn only_alert_corroborates() {
        assert!(Behavior::Alert { rule: "x".into() }.is_alert());
        assert!(
            !Behavior::NetworkConnection {
                peer: "p".into(),
                internet: true
            }
            .is_alert()
        );
    }
}
