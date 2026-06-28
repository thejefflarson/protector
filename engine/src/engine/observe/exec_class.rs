//! Exec-classification policy (JEF-55 / JEF-113): is a process-exec a *notable* runtime
//! signal — an interactive shell or a package manager run inside a container?
//!
//! This is **engine policy**, not part of the wire type. The shared [`Behavior`] crate is
//! pure data (agent + engine both depend on it), so the lists of "what counts as a shell /
//! package manager" live here — alongside the other engine classification thresholds
//! (CVE severity, corroboration) — rather than on the wire type. Keeping it here means a
//! list change rebuilds only the engine, never the agent. These are free functions that
//! classify a [`Behavior`] from the OUTSIDE, mirroring how the rest of the engine treats
//! `Behavior` as inert evidence.
//!
//! Falco-rule parity: an interactive-shell exec is "Terminal shell in container"; a
//! package-manager exec is "package management launched" — both classic container-tamper
//! signals, classified ENGINE-SIDE from the path the agent already emits (no wire change).

use crate::engine::graph::Behavior;

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
/// last `/`-separated segment. Mirrors how `Behavior::fingerprint_key` coarsens an exec
/// path, so the classifiers here see the same token the cache keys on.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Whether `behavior` is a [`Behavior::ProcessExec`] of an interactive **shell**
/// (sh/bash/zsh/ash/dash) — the Falco "Terminal shell in container" rule, classified
/// ENGINE-SIDE from the path the agent already emits (JEF-55), so no wire change. The
/// match is on the binary's basename, so `/bin/bash` and `bash` both count. Always
/// `false` for any other behavior.
pub fn is_interactive_shell(behavior: &Behavior) -> bool {
    match behavior {
        Behavior::ProcessExec { path } => INTERACTIVE_SHELLS.contains(&basename(path)),
        _ => false,
    }
}

/// Whether `behavior` is a [`Behavior::ProcessExec`] of a **package manager**
/// (apt/apt-get/apk/yum/dnf/pip/pip3/gem/npm) — the Falco "package management launched"
/// rule, classified ENGINE-SIDE from the emitted path (JEF-55), no wire change. Matched
/// on the binary's basename. Always `false` for any other behavior.
pub fn is_package_manager(behavior: &Behavior) -> bool {
    match behavior {
        Behavior::ProcessExec { path } => PACKAGE_MANAGERS.contains(&basename(path)),
        _ => false,
    }
}

/// A short, human label for a *notable* runtime exec — a shell or package manager run
/// inside the container (JEF-55) — or `None` for an unremarkable behavior. Used to
/// annotate the adjudication prompt ("executed /bin/bash (interactive shell in
/// container)") and as the corroboration predicate (a notable exec corroborates like an
/// alert, JEF-117). This is a classification, NOT an `is_alert`: it does not by itself
/// corroborate the action bar from the wire type's view — the engine decides what it
/// means. The label is a fixed internal string (never untrusted input), safe to embed in
/// the prompt.
pub fn notable_exec(behavior: &Behavior) -> Option<&'static str> {
    if is_interactive_shell(behavior) {
        Some("interactive shell in container")
    } else if is_package_manager(behavior) {
        Some("package manager in container")
    } else {
        None
    }
}

/// The human one-line summary for a behavior **with** the engine's notable-exec
/// annotation applied (JEF-55) — `executed /bin/bash (interactive shell in container)` for
/// a notable exec, the plain [`Behavior::summary`] otherwise. This is the engine-side
/// replacement for the annotation that used to live on `Behavior::summary` before the
/// classifier moved out of the shared wire type (JEF-113). Prompt- and dashboard-building
/// code that wants the annotated line calls this instead of `Behavior::summary` directly.
///
/// The label is a fixed internal string (never untrusted input), so it can't inject prompt
/// structure even though the path itself is still fenced at prompt-build time.
pub fn annotated_summary(behavior: &Behavior) -> String {
    let base = behavior.summary();
    match notable_exec(behavior) {
        Some(label) => format!("{base} ({label})"),
        None => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                is_interactive_shell(&b),
                want_shell,
                "is_interactive_shell({path:?})"
            );
            assert_eq!(
                is_package_manager(&b),
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
            assert!(!is_interactive_shell(&b), "{b:?} is_interactive_shell");
            assert!(!is_package_manager(&b), "{b:?} is_package_manager");
            assert_eq!(notable_exec(&b), None, "{b:?} notable_exec");
        }
    }

    #[test]
    fn annotated_summary_appends_the_notable_label() {
        // A notable exec gets the engine annotation appended to the bare wire summary; an
        // unremarkable behavior is unchanged. This reproduces the exact line the prompt /
        // dashboard saw before the classifier moved out of the wire type (JEF-113).
        let shell = Behavior::ProcessExec {
            path: "/bin/bash".into(),
        };
        let pkg = Behavior::ProcessExec {
            path: "/usr/bin/apt".into(),
        };
        let normal = Behavior::ProcessExec {
            path: "/app/server".into(),
        };
        let secret = Behavior::SecretRead {
            secret: "app/session-key".into(),
        };
        assert_eq!(
            annotated_summary(&shell),
            "executed /bin/bash (interactive shell in container)"
        );
        assert_eq!(
            annotated_summary(&pkg),
            "executed /usr/bin/apt (package manager in container)"
        );
        assert_eq!(annotated_summary(&normal), "executed /app/server");
        // Non-exec behaviors pass through their plain summary untouched.
        assert_eq!(annotated_summary(&secret), "reads secret app/session-key");
    }

    #[test]
    fn notable_exec_labels_shells_and_package_managers() {
        let shell = Behavior::ProcessExec {
            path: "/bin/bash".into(),
        };
        let pkg = Behavior::ProcessExec {
            path: "/usr/bin/apt".into(),
        };
        let normal = Behavior::ProcessExec {
            path: "/app/server".into(),
        };
        // The notable label is a fixed internal token, safe to embed in the prompt.
        assert_eq!(notable_exec(&shell), Some("interactive shell in container"));
        assert_eq!(notable_exec(&pkg), Some("package manager in container"));
        // An unremarkable exec is not notable.
        assert_eq!(notable_exec(&normal), None);
    }
}
