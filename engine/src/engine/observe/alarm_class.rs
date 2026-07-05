//! The engine-side **"alarming-now"** classifier (JEF-309): which agent-observed
//! behaviors are a *tamper-now* signal that evidences active intrusion.
//!
//! This generalizes [`super::exec_class::notable_exec`] (an interactive shell / package
//! manager run in a container, JEF-55/JEF-117) into the single predicate the corroboration
//! and quarantine paths key on. Its new arm is [`alarming_write`]: a
//! [`Behavior::FileWrite`] to a **sensitive path** — the container-drift / drop-and-execute
//! / config-tamper subset of the F2 write signal (JEF-306), classified engine-side.
//!
//! ## Why here (JEF-113 pattern)
//! The shared [`Behavior`] wire type stays **pure data**: the agent emits the written path,
//! the engine decides whether it is *sensitive*. Keeping the path lists here — alongside the
//! other engine classification thresholds (`exec_class`, `peer_class`) — means a policy change
//! rebuilds only the engine, never the node-local agent, and never touches the wire contract.
//!
//! ## Conservatism (hard — ADR-0011 false-positive concern)
//! Every workload writes files — its own `/data`, `/tmp`, and logs are the common case and
//! must NEVER corroborate. Only the specific sensitive subset below alarms. Corroboration is
//! also always shadow-gated (ADR-0014): it only sets `corroborated`; actuation stays behind the
//! empty-by-default `engine.enable` set, and a proven, breach-relevant chain is still required.
//!
//! ## Consistency (hard)
//! A "tamper-now" signal that some code paths see and others don't is a bug. [`is_alarming_now`]
//! is the ONE predicate the blanket-corroboration consumers share — `reason::proof::corroborate`
//! (the FileWrite arm), `reason::proof::chain::actively_exploited` (JEF-284 condition-2
//! quarantine), and `reason::adjudicate::guards` (the zero-anchor backstop) — so alert / notable
//! exec / alarming write can never drift apart between them.

use crate::engine::graph::Behavior;

/// Directories whose contents are **sensitive** — a write at or below one of these is
/// container drift worth corroborating (a "write below etc / binary dir" tamper). Matched
/// with a segment-aligned prefix ([`under`]), so `/etc` matches `/etc/passwd` but never
/// `/etcd` or `/etc-backup`. Kept explicit and conservative (ADR-0011): only paths an
/// immutable container image should never be rewriting at runtime.
const SENSITIVE_DIRS: &[&str] = &[
    // System configuration — "write below etc". Also covers /etc/ssh, /etc/passwd, and
    // /etc/cron* (the latter classified with a more specific label by `is_cron_path`).
    "/etc",
    // Executable directories — writing a binary here is drop-into-PATH / on-disk binary tamper
    // (the drop half of drop-and-execute landing in the image's own bin dirs).
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    // Shared-library directories (/lib*) — writing here is library implantation.
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/usr/lib",
    "/usr/lib32",
    "/usr/lib64",
    "/usr/libx32",
    "/usr/local/lib",
    "/usr/local/lib64",
];

/// Whether `path` is at or below directory `dir` — a **segment-aligned** prefix match, so a
/// sensitive-dir prefix can't falsely match a longer sibling name (`/etc` vs `/etcd`). Mirrors
/// how the rest of the engine coarsens paths on `/` boundaries.
fn under(path: &str, dir: &str) -> bool {
    path == dir
        || path
            .strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The basename of a path (`/root/.ssh/authorized_keys` -> `authorized_keys`) — the last
/// `/`-separated segment. Mirrors the `basename` helper the other classifiers use.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// A write to a **cron** location — persistence via scheduled execution. `/etc/cron*`
/// (`/etc/crontab`, `/etc/cron.d/…`, `/etc/cron.daily/…`) or the system crontab spool
/// (`/var/spool/cron/…`). The `/etc/cron` string-prefix mirrors the ticket's `/etc/cron*` glob.
fn is_cron_path(path: &str) -> bool {
    path.starts_with("/etc/cron") || under(path, "/var/spool/cron")
}

/// A write to a **service-account / mounted-secret token** projection — tampering with the
/// workload's identity material. The projected SA token lives under
/// `/var/run/secrets/kubernetes.io/…` (with `/run/secrets/kubernetes.io/…` for the common
/// `/var/run -> /run` symlink).
fn is_service_account_path(path: &str) -> bool {
    under(path, "/var/run/secrets/kubernetes.io") || under(path, "/run/secrets/kubernetes.io")
}

/// A write to an **SSH key** location — classic persistence. Any file under a `.ssh` directory
/// (`/root/.ssh/…`, `/home/<user>/.ssh/…`) or any `authorized_keys` file. Conservative: a `.ssh`
/// directory is not something an immutable container image should be writing at runtime.
fn is_ssh_key_path(path: &str) -> bool {
    basename(path) == "authorized_keys" || path.split('/').any(|seg| seg == ".ssh")
}

/// A short, human label for an *alarming* file write — a sensitive-path / drop-and-execute /
/// config-tamper write (JEF-309) — or `None` for a benign write (an app writing its own
/// `/data`, `/tmp`, or logs). Mirrors [`super::exec_class::notable_exec`]: it promotes a
/// [`Behavior::FileWrite`] to **blanket** corroboration (any objective) in
/// `reason::proof::corroborate`, exactly as an `Alert` or a notable exec does. Always
/// `None` for any non-write behavior. The label is a fixed internal string (never untrusted
/// input), safe to embed in the prompt/output.
pub fn alarming_write(behavior: &Behavior) -> Option<&'static str> {
    let Behavior::FileWrite { path } = behavior else {
        return None;
    };
    // Specific labels first (cron / SA-token / ssh can live under a broader sensitive dir),
    // then the general system-path catch-all.
    if is_cron_path(path) {
        Some("drift write to a cron path (persistence)")
    } else if is_service_account_path(path) {
        Some("drift write to a service-account token path (credential tamper)")
    } else if is_ssh_key_path(path) {
        Some("drift write to an SSH key path (persistence)")
    } else if SENSITIVE_DIRS.iter().any(|d| under(path, d)) {
        Some("drift write to a sensitive system path (drop-and-execute / config tamper)")
    } else {
        None
    }
}

/// The single **"alarming-now"** predicate (JEF-309) shared by every blanket-corroboration
/// consumer: whether `behavior` is a tamper-now signal that evidences active intrusion —
///   * an [`Alert`](Behavior::Alert) (a sensor rule fired),
///   * a *notable* exec — an interactive shell / package manager in a container
///     ([`super::exec_class::notable_exec`], JEF-55/JEF-117), or
///   * an *alarming* file write — a sensitive-path / drop-and-execute drift ([`alarming_write`]).
///
/// This is the ONE definition `reason::proof::chain::actively_exploited` (JEF-284 condition-2
/// quarantine) and `reason::adjudicate::guards` (the zero-anchor backstop) both call, so a new
/// alarm source can't be seen by one path and missed by another. It is deliberately NOT the
/// per-objective corroboration seam (a benign connection / secret-read still corroborates only
/// its own tactic in `corroborate`); it is the *blanket* "an attack is happening now" gate.
pub fn is_alarming_now(behavior: &Behavior) -> bool {
    behavior.is_alert()
        || super::exec_class::notable_exec(behavior).is_some()
        || alarming_write(behavior).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::SecretReadSource;

    fn write(path: &str) -> Behavior {
        Behavior::FileWrite { path: path.into() }
    }

    #[test]
    fn alarming_write_flags_each_sensitive_class() {
        // Each sensitive class the F3 policy promotes, with an absolute path the agent emits.
        let sensitive = [
            // System config — "write below etc".
            "/etc/passwd",
            "/etc/ssh/sshd_config",
            "/etc/ld.so.preload",
            // Cron persistence (both /etc/cron* forms and the spool).
            "/etc/crontab",
            "/etc/cron.d/dropper",
            "/etc/cron.daily/backup",
            "/var/spool/cron/crontabs/root",
            // Executable / library directories — drop-and-execute / binary + library tamper.
            "/bin/nc",
            "/sbin/ip",
            "/usr/bin/dropper",
            "/usr/sbin/sshd",
            "/usr/local/bin/miner",
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/evil.so",
            "/usr/lib/libssl.so.1.1",
            "/usr/local/lib/hook.so",
            // Service-account token / mounted-secret tamper (both /var/run and /run).
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/run/secrets/kubernetes.io/serviceaccount/token",
            // SSH persistence.
            "/root/.ssh/authorized_keys",
            "/home/app/.ssh/authorized_keys",
            "/data/authorized_keys",
        ];
        for path in sensitive {
            assert!(
                alarming_write(&write(path)).is_some(),
                "expected {path:?} to be an alarming write"
            );
        }
    }

    #[test]
    fn benign_writes_are_never_alarming() {
        // The common case: an app writing its OWN data / tmp / logs must NOT corroborate
        // (ADR-0011). Includes look-alikes that a substring/prefix match would wrongly catch.
        let benign = [
            "/data/app.db",
            "/data/uploads/photo.jpg",
            "/tmp/scratch",
            "/var/log/app.log",
            "/var/lib/postgresql/data/base", // /var/lib is NOT /lib
            "/app/cache/index",
            "/home/app/data/report.csv", // a home dir, but not under `.ssh`
            "/etcd/data/wal",            // /etcd is NOT /etc
            "/etc-backup/snapshot",      // /etc-backup is NOT /etc
            "/binfmt/config",            // /binfmt is NOT /bin
            "/usr/share/app/asset",      // /usr/share is not a bin/lib dir
            "/var/run/app/state.sock",   // /var/run/app is not the SA-token path
            "relative/path",             // no leading slash
        ];
        for path in benign {
            assert!(
                alarming_write(&write(path)).is_none(),
                "expected {path:?} to be a benign (non-alarming) write"
            );
        }
    }

    #[test]
    fn alarming_write_is_none_for_non_write_behaviors() {
        // Scoped to FileWrite — an alert / exec / secret-read whose payload happens to look
        // like a sensitive path must never classify as an alarming write.
        let others = [
            Behavior::Alert {
                rule: "/etc/passwd".into(),
            },
            Behavior::ProcessExec {
                path: "/usr/bin/dropper".into(),
            },
            Behavior::SecretRead {
                secret: "/var/run/secrets/kubernetes.io/serviceaccount/token".into(),
                source: SecretReadSource::Mounted,
            },
            Behavior::FileRead {
                path: "/etc/shadow".into(),
            },
        ];
        for b in others {
            assert_eq!(alarming_write(&b), None, "{b:?}");
        }
    }

    #[test]
    fn is_alarming_now_unifies_alert_notable_exec_and_alarming_write() {
        // Positive: the three tamper-now sources.
        assert!(is_alarming_now(&Behavior::Alert {
            rule: "Terminal shell in container".into(),
        }));
        assert!(is_alarming_now(&Behavior::ProcessExec {
            path: "/bin/bash".into(), // notable exec (interactive shell)
        }));
        assert!(is_alarming_now(&write("/etc/cron.d/dropper"))); // alarming write

        // Negative: benign behaviors are never "alarming now".
        assert!(!is_alarming_now(&write("/data/app.log")));
        assert!(!is_alarming_now(&Behavior::ProcessExec {
            path: "/app/server".into(), // bare exec, not a shell/pkg-mgr
        }));
        assert!(!is_alarming_now(&Behavior::NetworkConnection {
            peer: "10.42.0.1:8086".into(),
            internet: false,
        }));
        assert!(!is_alarming_now(&Behavior::PrivilegeChange {
            from_uid: 1000,
            to_uid: 0,
        }));
    }
}
