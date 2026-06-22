//! The behavioral-evidence wire contract (ADR-0014).
//!
//! These types are the normalized shape any sensor maps its events into and POSTs to
//! the engine's behavioral ingest: [`Behavior`] (what a workload did) and
//! [`RuntimeObservation`] (one behavior, attributed to a workload). They are shared by
//! the engine and protector's first-party eBPF agent so the two can't drift.
//!
//! Per ADR-0003 the *contract* is the JSON (`{"kind": "...", ...}`), not this Rust type
//! — a third-party sensor (Falco via its adapter) speaks the same JSON without depending
//! on this crate. The crate is a convenience for the first-party components, nothing the
//! port requires. The serde shape is pinned by the tests below.

use serde::{Deserialize, Serialize};

/// An observed runtime **behavior** — what a workload actually did, from any sensor
/// (the first-party eBPF agent, Falco, …) through the tool-agnostic behavioral port
/// (ADR-0003/0014). Typed so the engine reasons about the *signal*, not the source.
/// Serde-tagged for the normalized ingest contract (`{"kind": "...", ...}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Behavior {
    /// A sensor rule fired (e.g. a Falco alert) — "something alarming, now."
    Alert { rule: String },
    /// An outbound connection the workload made; `internet` if it left the cluster.
    NetworkConnection { peer: String, internet: bool },
    /// A read of a mounted secret's contents.
    SecretRead { secret: String },
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
    /// agent's privilege-change probe, fentry on `security_task_fix_setuid`; Falco
    /// privilege-escalation-rule parity). Model evidence, not blanket corroboration:
    /// legitimate workloads sometimes escalate (init/entrypoint), so wiring this to
    /// corroborate a specific attack is JEF-49's job.
    PrivilegeChange { from_uid: u32, to_uid: u32 },
    /// A process was exec'd in the workload — the runtime signal for "unexpected process
    /// spawned" (Falco-rule parity, ADR-0014). `path` is the exec'd binary's path as the
    /// kernel saw it (`linux_binprm->filename`). Evidence for the model only today;
    /// wiring exec → corroboration is JEF-49.
    ProcessExec { path: String },
}

/// Interactive shells a process-exec might be (matched on the binary's basename).
/// An exec of one of these inside a container is the classic Falco "Terminal shell in
/// container" runtime signal (JEF-55). Kept deliberately small and conservative —
/// well-known shell *interpreters*, not every program that can run a script — because a
/// false "shell" annotation is misleading model evidence.
const INTERACTIVE_SHELLS: &[&str] = &[
    "sh",   // POSIX shell (often a symlink to dash/bash/busybox)
    "bash", // GNU Bourne-Again shell
    "zsh",  // Z shell
    "ash",  // Almquist shell (BusyBox's default `sh`)
    "dash", // Debian Almquist shell (Debian/Ubuntu `/bin/sh`)
];

/// Package managers a process-exec might be (matched on the binary's basename). An exec
/// of one inside a running container is the classic Falco "package management launched"
/// runtime signal (JEF-55): images are meant to be immutable, so installing software at
/// runtime is a strong tamper indicator. Small and explicit on purpose.
const PACKAGE_MANAGERS: &[&str] = &[
    "apt",     // Debian/Ubuntu
    "apt-get", // Debian/Ubuntu (non-interactive front end)
    "apk",     // Alpine
    "yum",     // RHEL/CentOS (legacy)
    "dnf",     // Fedora/RHEL (yum's successor)
    "pip",     // Python
    "pip3",    // Python 3
    "gem",     // Ruby
    "npm",     // Node.js
];

/// The basename of a binary path as the kernel saw it (`/usr/bin/apt` -> `apt`) — the
/// last `/`-separated segment. Mirrors how [`Behavior::fingerprint_key`] coarsens an
/// exec path, so the classifiers below see the same token the cache keys on.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
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

    /// Whether this is a [`Behavior::ProcessExec`] of an interactive **shell**
    /// (sh/bash/zsh/ash/dash) — the Falco "Terminal shell in container" rule, classified
    /// ENGINE-SIDE from the path the agent already emits (JEF-55), so no wire change. The
    /// match is on the binary's basename, so `/bin/bash` and `bash` both count. Always
    /// `false` for any other behavior.
    pub fn is_interactive_shell(&self) -> bool {
        match self {
            Behavior::ProcessExec { path } => INTERACTIVE_SHELLS.contains(&basename(path)),
            _ => false,
        }
    }

    /// Whether this is a [`Behavior::ProcessExec`] of a **package manager**
    /// (apt/apt-get/apk/yum/dnf/pip/pip3/gem/npm) — the Falco "package management
    /// launched" rule, classified ENGINE-SIDE from the emitted path (JEF-55), no wire
    /// change. Matched on the binary's basename. Always `false` for any other behavior.
    pub fn is_package_manager(&self) -> bool {
        match self {
            Behavior::ProcessExec { path } => PACKAGE_MANAGERS.contains(&basename(path)),
            _ => false,
        }
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
        }
    }

    /// A short, human label for a *notable* runtime exec — a shell or package manager run
    /// inside the container (JEF-55) — or `None` for an unremarkable behavior. Surfaced in
    /// [`Self::summary`] so the adjudication prompt sees "executed /bin/bash (interactive
    /// shell in container)" rather than a bare path; the model already treats a shell in a
    /// container as a strong signal. This is a classification, not an [`Self::is_alert`]:
    /// it does NOT by itself corroborate the action bar (some entrypoints legitimately
    /// shell out), matching how `PrivilegeChange`/`ProcessExec` are model evidence today.
    pub fn notable_exec(&self) -> Option<&'static str> {
        if self.is_interactive_shell() {
            Some("interactive shell in container")
        } else if self.is_package_manager() {
            Some("package manager in container")
        } else {
            None
        }
    }

    /// A one-line, human summary for the adjudication prompt.
    pub fn summary(&self) -> String {
        match self {
            Behavior::Alert { rule } => format!("alert: {rule}"),
            Behavior::NetworkConnection { peer, internet } => format!(
                "connects to {peer}{}",
                if *internet { " (INTERNET egress)" } else { "" }
            ),
            Behavior::SecretRead { secret } => format!("reads secret {secret}"),
            Behavior::LibraryLoaded { name } => format!("loaded library {name}"),
            Behavior::FileRead { path } => format!("opened file {path}"),
            Behavior::PrivilegeChange { from_uid, to_uid } => {
                format!("privilege change uid {from_uid} -> {to_uid}")
            }
            // Annotate a notable exec (a shell or package manager run in the container —
            // JEF-55) so the model sees the classification, not just a path. The label is
            // a fixed internal string (never untrusted input), so it can't inject prompt
            // structure even though the path itself is fenced at prompt-build time.
            Behavior::ProcessExec { path } => match self.notable_exec() {
                Some(label) => format!("executed {path} ({label})"),
                None => format!("executed {path}"),
            },
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
            Behavior::SecretRead { secret } => format!("read:{secret}"),
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
        }
    }
}

/// How a sensor **attributed** an observation to a workload — a type distinction, not an
/// empty-string convention (JEF-59). A sensor either knows the pod's cgroup UID (the
/// first-party eBPF agent, which stays node-local and can't resolve names itself) or it
/// already has the namespace/name (Falco, which reads k8s metadata). The engine resolves
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
    /// Falco (and any sensor with cluster metadata): the namespace/name directly.
    ByNamespacedName { namespace: String, pod: String },
}

impl Attribution {
    /// Attribute by pod UID (the eBPF agent's path).
    pub fn by_pod_uid(uid: impl Into<String>) -> Self {
        Attribution::ByPodUid {
            pod_uid: uid.into(),
        }
    }

    /// Attribute by namespace + pod name (Falco's path).
    pub fn by_namespaced_name(namespace: impl Into<String>, pod: impl Into<String>) -> Self {
        Attribution::ByNamespacedName {
            namespace: namespace.into(),
            pod: pod.into(),
        }
    }
}

/// A normalized live runtime observation about a workload — the behavioral port's input
/// shape (ADR-0014). Any sensor (the first-party eBPF agent, Falco, Tetragon, …) maps
/// its events into this; the graph sees only the normalized signal, not a vendor type.
/// `Deserialize` so a sensor can POST it directly to the normalized ingest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeObservation {
    /// How this observation is attributed to a workload — by cgroup UID (eBPF agent) or by
    /// namespace/name (Falco). Flattened so its fields sit at the JSON top level, preserving
    /// the original flat wire shape.
    #[serde(flatten)]
    pub attribution: Attribution,
    /// Which sensor observed this — `"protector-agent"`, `"falco"`, … Carried into the
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
    /// What the workload actually did.
    pub behavior: Behavior,
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
    fn observation_roundtrips_and_omits_absent_optionals() {
        // An eBPF-agent observation: attributed by uid, source + time set.
        let obs = RuntimeObservation {
            attribution: Attribution::by_pod_uid("uid"),
            source: Some("protector-agent".into()),
            observed_at_ms: Some(1_710_000_000_000),
            behavior: Behavior::SecretRead {
                secret: "app/session-key".into(),
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
    fn falco_style_observation_deserializes_from_namespace_pod() {
        // A Falco-shaped observation: ns/pod set, no uid/source/time.
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
        // bash is a notable exec (JEF-55), so its summary is annotated — the bare-path
        // case is covered by `notable_exec_annotates_the_summary_but_does_not_corroborate`.
        assert_eq!(
            a.summary(),
            "executed /usr/bin/bash (interactive shell in container)"
        );
    }

    #[test]
    fn classifies_shells_and_package_managers_from_the_exec_path() {
        // (exec path, is_shell, is_pkg_mgr) — positives across both lists, with absolute
        // and bare paths to exercise basename extraction.
        let exec = |p: &str| Behavior::ProcessExec { path: p.into() };
        let cases = [
            // Interactive shells — Falco "Terminal shell in container".
            ("/bin/sh", true, false),
            ("/bin/bash", true, false),
            ("bash", true, false), // bare basename, no directory
            ("/usr/bin/zsh", true, false),
            ("/bin/ash", true, false),
            ("/usr/bin/dash", true, false),
            // Package managers — Falco "package management launched".
            ("/usr/bin/apt", false, true),
            ("/usr/bin/apt-get", false, true),
            ("apk", false, true),
            ("/usr/bin/yum", false, true),
            ("/usr/bin/dnf", false, true),
            ("/usr/local/bin/pip", false, true),
            ("/usr/local/bin/pip3", false, true),
            ("gem", false, true),
            ("/usr/bin/npm", false, true),
            // Negatives — a normal app binary, and look-alikes that must NOT match
            // (substring containment / prefix must not fire).
            ("/app/server", false, false),
            ("/usr/bin/python3", false, false), // an interpreter, but not in our lists
            ("/usr/bin/bashful", false, false), // basename != bash
            ("/opt/aptitude", false, false),    // not apt/apt-get
            ("/bin/npm-check", false, false),   // basename != npm
        ];
        for (path, want_shell, want_pkg) in cases {
            let b = exec(path);
            assert_eq!(
                b.is_interactive_shell(),
                want_shell,
                "is_interactive_shell({path:?})"
            );
            assert_eq!(
                b.is_package_manager(),
                want_pkg,
                "is_package_manager({path:?})"
            );
        }
    }

    #[test]
    fn non_exec_behaviors_are_never_shell_or_package_manager() {
        // The classifiers are scoped to ProcessExec — a library named like a shell or a
        // secret/alert must never be classified as a runtime exec signal.
        let others = [
            Behavior::Alert {
                rule: "bash".into(),
            },
            Behavior::LibraryLoaded {
                name: "bash".into(),
            },
            Behavior::SecretRead {
                secret: "apt".into(),
            },
            Behavior::FileRead {
                path: "/bin/bash".into(),
            },
            Behavior::PrivilegeChange {
                from_uid: 1000,
                to_uid: 0,
            },
        ];
        for b in others {
            assert!(!b.is_interactive_shell(), "{b:?} is_interactive_shell");
            assert!(!b.is_package_manager(), "{b:?} is_package_manager");
            assert_eq!(b.notable_exec(), None, "{b:?} notable_exec");
        }
    }

    #[test]
    fn notable_exec_annotates_the_summary_but_does_not_corroborate() {
        let shell = Behavior::ProcessExec {
            path: "/bin/bash".into(),
        };
        let pkg = Behavior::ProcessExec {
            path: "/usr/bin/apt".into(),
        };
        let normal = Behavior::ProcessExec {
            path: "/app/server".into(),
        };
        assert_eq!(
            shell.summary(),
            "executed /bin/bash (interactive shell in container)"
        );
        assert_eq!(
            pkg.summary(),
            "executed /usr/bin/apt (package manager in container)"
        );
        // An unremarkable exec keeps the bare-path summary (no annotation).
        assert_eq!(normal.summary(), "executed /app/server");
        // Classification is model evidence, NOT action-bar corroboration — only Alerts
        // corroborate (else every entrypoint that shells out would fire the action bar).
        assert!(!shell.is_alert());
        assert!(!pkg.is_alert());
        // The notable label is a fixed internal token, safe to embed in the prompt.
        assert_eq!(shell.notable_exec(), Some("interactive shell in container"));
        assert_eq!(pkg.notable_exec(), Some("package manager in container"));
        assert_eq!(normal.notable_exec(), None);
    }

    #[test]
    fn variant_label_is_a_stable_low_cardinality_token() {
        // Each variant maps to a fixed token carrying NO per-instance payload (no peer,
        // path, or secret name) — so it's safe as a metric label without cardinality blow-up.
        let cases: [(Behavior, &str); 7] = [
            (Behavior::Alert { rule: "x".into() }, "alert"),
            (
                Behavior::NetworkConnection {
                    peer: "1.2.3.4:443".into(),
                    internet: true,
                },
                "connection",
            ),
            (Behavior::SecretRead { secret: "s".into() }, "secret-read"),
            (
                Behavior::LibraryLoaded { name: "l".into() },
                "library-load",
            ),
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
        ];
        for (behavior, want) in cases {
            assert_eq!(behavior.variant_label(), want, "{behavior:?}");
        }
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
