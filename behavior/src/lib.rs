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
    /// (the eBPF agent's on-disk path), a Kubernetes API GET/LIST/WATCH via the
    /// workload's ServiceAccount RBAC (observed engine-side from the apiserver audit log,
    /// JEF-269), or a well-known ON-HOST credential path — the host shadow file, an SSH
    /// private-key dir, a cloud-credential file (observed engine-side from the path alone,
    /// JEF-320) — three genuinely different runtime facts that all reach credential
    /// material. Older sensors omit `source`, which defaults to
    /// [`SecretReadSource::Mounted`] (the only kind eBPF originally saw), preserving the
    /// pre-existing wire shape.
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
    /// spawned" (ADR-0014). `path` is the exec'd binary's path as the kernel saw it
    /// (`linux_binprm->filename`). PURE DATA: whether a `path` is a shell / package manager
    /// is engine classification (`observe::exec_class`, JEF-113), not a property of this
    /// shared wire type.
    ///
    /// `exe_anon_inode` (JEF-317, Route A) is a SEPARATE kernel-observed fact, not derived
    /// from `path`: whether the exec'd binary's backing inode is anonymous — memfd/shmem-
    /// backed, or unlinked (`i_nlink == 0`) — rather than a normal, linked, on-disk file.
    /// This is the Falco-parity signal ("memfd_create + execve of an anonymous fd") a path
    /// string alone cannot carry: the kernel synthesizes the SAME `/dev/fd/<n>`-shaped
    /// `bprm->filename` for a benign `fexecve()` of an on-disk file as it does for a real
    /// memfd payload, so an earlier version of this signal that classified the *path shape*
    /// was withdrawn (a security review caught it forging corroboration on routine
    /// behavior — see JEF-317). The exec probe now reads `bprm->file->f_inode` directly
    /// instead. Defaulted `false` (an older sensor, or a sensor without inode access, omits
    /// it) — never inferred, so an unset flag reads as "not anonymous", never guessed
    /// `true`. A raw kernel fact, not a verdict: whether it's alarming is engine policy
    /// (`observe::exec_class`, `reason::proof::corroborate`), scoped conservatively — see
    /// those modules for why (the runc-memfd-reexec false-positive risk).
    ProcessExec {
        path: String,
        #[serde(default, skip_serializing_if = "is_false")]
        exe_anon_inode: bool,
    },
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
    /// A ptrace ATTACH access check (JEF-318, Retire-Falco G2): the eBPF agent's
    /// `security_ptrace_access_check` probe, filtered in-kernel to `mode &
    /// PTRACE_MODE_ATTACH` so the read-only `PTRACE_MODE_READ` checks `/proc/<pid>/…` makes
    /// constantly never reach the wire. The classic process-injection primitive Falco fires
    /// critical on (debugger-attach, code injection, credential/memory scraping via
    /// `process_vm_readv`). No fields: unlike a struct-offset read, this is a PURE
    /// occurrence fact — the attacking workload is already carried by
    /// [`RuntimeObservation::attribution`], and the target process's pid is deliberately not
    /// read by the agent (a `struct task_struct` offset read judged too fragile for this
    /// signal — see the agent's probe doc). PURE DATA (JEF-113): whether an attach on this
    /// entry is alarming is engine policy (`engine::reason::proof::corroborate`),
    /// conservatively foothold-scoped, not decided here.
    PtraceAttach,
    /// A kernel module load (JEF-318, Retire-Falco G2): the eBPF agent's
    /// `security_kernel_load_data` probe, filtered in-kernel to `id == LOADING_MODULE` so
    /// firmware/kexec/policy/x509 loads on the SAME hook never reach the wire. Covers BOTH
    /// `init_module` and `finit_module` — `load_module()` reaches this hook on either path.
    /// The module-load parity signal Falco fires critical on: a container loading arbitrary
    /// code into the HOST kernel. No fields — the occurrence, attributed by
    /// [`RuntimeObservation::attribution`], is the whole fact. PURE DATA (JEF-113): engine
    /// policy decides whether it's alarming, conservatively foothold-scoped, not this crate.
    ModuleLoad,
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
    /// The path read is a well-known ON-HOST sensitive credential path — the host
    /// password/shadow file, a per-user SSH private-key directory, or a cloud-provider
    /// credential file — outside any k8s Secret mount (JEF-320, Retire-Falco G3). The
    /// eBPF agent still only emits a path (pure data, JEF-113); the engine classifies it
    /// (`engine::observe::host_credential_class`), same division of labor as `Mounted`.
    HostPath,
}

impl SecretReadSource {
    /// Whether this is the default (mounted) source. Used to omit `source` from the wire
    /// for the common mounted read, keeping the eBPF agent's contract byte-for-byte stable.
    fn is_mounted(&self) -> bool {
        matches!(self, SecretReadSource::Mounted)
    }
}

/// Whether `b` is `false` — a named predicate for `#[serde(skip_serializing_if)]` (no
/// built-in one exists for `bool`). Used to omit a `false` anon-inode-exec flag from the
/// wire (JEF-317), keeping the common (non-anonymous) exec's JSON byte-identical to before
/// this field existed.
fn is_false(b: &bool) -> bool {
    !b
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
            Behavior::PtraceAttach => "ptrace-attach",
            Behavior::ModuleLoad => "module-load",
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
                SecretReadSource::HostPath => {
                    format!("reads secret {secret} (on-host filesystem)")
                }
            },
            Behavior::LibraryLoaded { name } => format!("loaded library {name}"),
            Behavior::FileRead { path } => format!("opened file {path}"),
            Behavior::PrivilegeChange { from_uid, to_uid } => {
                format!("privilege change uid {from_uid} -> {to_uid}")
            }
            // The exec'd path, plus the raw `exe_anon_inode` kernel fact when set (JEF-317)
            // — unlike the shell/package-manager CLASSIFICATION (a curated list, engine
            // policy in `engine::observe::exec_class`), this is a single kernel-computed
            // boolean the agent already resolved, so it rides the bare summary like
            // `PrivilegeChange`'s uids do, not as an engine annotation.
            Behavior::ProcessExec {
                path,
                exe_anon_inode,
            } => {
                if *exe_anon_inode {
                    format!(
                        "executed {path} (anonymous-inode: memfd/unlinked backing, no on-disk file)"
                    )
                } else {
                    format!("executed {path}")
                }
            }
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
            // No fields to render — the occurrence, attributed by the observation's
            // workload, is the whole fact (JEF-318).
            Behavior::PtraceAttach => "ptrace attach (process injection primitive)".to_string(),
            Behavior::ModuleLoad => "loaded a kernel module".to_string(),
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
            Behavior::SecretRead {
                secret,
                source: SecretReadSource::HostPath,
            } => format!("read-host:{secret}"),
            Behavior::LibraryLoaded { name } => format!("lib:{name}"),
            Behavior::FileRead { path } => format!("file:{path}"),
            // Keyed on the gained UID only (always 0 today, but stable if the escalation
            // predicate widens): repeated escalations to the same UID collapse to one
            // fingerprint and don't bust the verdict cache.
            Behavior::PrivilegeChange { to_uid, .. } => format!("priv:{to_uid}"),
            // Coarsen to the basename so repeated execs of the same binary from different
            // absolute paths collapse to one stable key (mirrors how LibraryLoaded keys on
            // the lib name, not the full path) — keeps exec churn from busting the cache.
            // `exe_anon_inode` is kept in the key (JEF-317): it is a genuinely different
            // security-relevant fact about the SAME binary name (an on-disk `bash` vs. an
            // anonymous-inode exec that happens to report itself as "bash"), so folding it
            // in must not silently collapse the two into one cache entry.
            Behavior::ProcessExec {
                path,
                exe_anon_inode,
            } => format!(
                "exec:{}{}",
                basename(path),
                if *exe_anon_inode { ":anon-inode" } else { "" }
            ),
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
            // No varying fields, so a fixed token is already maximally coarse (JEF-318) —
            // mirrors how a fieldless fact would key regardless of source.
            Behavior::PtraceAttach => "ptrace-attach".to_string(),
            Behavior::ModuleLoad => "module-load".to_string(),
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
mod tests;
