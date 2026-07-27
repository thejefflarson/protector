//! On-host credential-path classification policy (JEF-320, Retire-Falco G3).
//!
//! The agent's `SecretRead` (via `security_file_open`) started out scoped to the tmpfs
//! superblock — the k8s Secret/ConfigMap/projected-volume mount point — so a read of a
//! **host-filesystem** credential file (the host password/shadow file, a user's SSH
//! private-key directory, a cloud-provider credential file) produced no CredentialAccess
//! corroboration, even though it lives on the container's ordinary rootfs and Falco's
//! "Read sensitive file untrusted" / "Read ssh information" rules fire on exactly this.
//! This module is the engine-side classifier that closes that gap.
//!
//! Authoritative source for the path list: the F0 Falco-parity audit
//! (`docs/falco-parity-audit.md` §3 Class E / §7-8 G3; removed from the tree in the F8
//! retirement commit but preserved in history — `git show a2c7620:docs/falco-parity-audit.md`,
//! landed in PR #169) plus the well-known on-disk conventions for the AWS/GCP/Azure CLIs.
//!
//! ENGINE-SIDE policy, not wire data (JEF-113, mirroring `exec_class`): the shared
//! [`crate::engine::graph::Behavior`] type stays pure — the agent emits a
//! `FileRead { path }` for a file it can't classify itself, unchanged wire shape. The
//! probe was minimally widened (JEF-320) to also emit a `FileRead` for a small, fixed
//! allowlist of on-host credential-file BASENAMES outside tmpfs (a cheap in-kernel volume
//! gate — see `is_sensitive_credential_basename` in
//! `agent/protector-agent-ebpf/src/main.rs` — NOT the security decision). This module makes
//! the actual "is this path a known on-host credential path" call, from the full path
//! alone, exactly like `adapter::enrich::secret_for_path` does for k8s Secret mounts.
//!
//! **FP-scoping (container/entry context only):** every `RuntimeSignal` that reaches a
//! Workload node in `RuntimeAdapter::contribute` is already attributed to a *Pod* — a
//! genuine host-system daemon (e.g. the node's real `sshd`, running outside any container
//! cgroup) has neither a resolvable `ByPodUid` nor a `ByNamespacedName` attribution, so its
//! events are dropped upstream (`unresolved`) before this classifier ever runs. That gives
//! "scope to container/entry context" for free from the existing attribution mechanism — no
//! extra check needed here. What this does NOT filter out: a *legitimate* in-container auth
//! process (e.g. a bastion/jump pod's own `sshd` reading its own `/etc/shadow` for PAM, or
//! its own `authorized_keys`) still matches. That residual false-positive is accepted
//! deliberately: this signal is CORROBORATION ONLY (`corroborates()` only ever sets
//! `corroborated`, never actuates — shadow-only, ADR-0014), it is combined with the model's
//! own reasoning and every other piece of evidence on the chain, and it targets an
//! explicitly off-critical-path residual gap (F0 §7) rather than a live corroboration path.

/// Absolute on-host paths matched **exactly** — the host password/shadow/sudoers files
/// (F0 §3 Class E1, "Read sensitive file untrusted": `/etc/shadow` et al.). Deliberately a
/// short, exact list (not a directory-prefix match on all of `/etc`) so an unrelated
/// `/etc/*` config read never false-positives.
const EXACT_HOST_PATHS: &[&str] = &["/etc/shadow", "/etc/passwd", "/etc/sudoers"];

/// The path SEGMENT (not substring) that marks a per-user SSH private-key directory (F0
/// §3 Class E1, "Read ssh information": any read under `~/.ssh`, regardless of whose home
/// directory it is). Any file read one level under a `.ssh` segment counts — private keys,
/// `authorized_keys`, `known_hosts` are all credential-adjacent, matching the breadth of
/// Falco's own rule.
const SSH_DIR_SEGMENT: &str = ".ssh";

/// Cloud-provider credential files for the major providers (AWS/GCP/Azure), each paired
/// with the provider's conventional config-directory SEGMENT so a same-named file in an
/// unrelated directory (e.g. some app's own `credentials` file) does not match. `file`
/// must be the exact basename; `dir_segment` must appear as a whole path segment.
const CLOUD_CREDENTIAL_FILES: &[(&str, &str)] = &[
    // AWS CLI / SDKs: ~/.aws/credentials.
    (".aws", "credentials"),
    // gcloud CLI application-default credentials and the legacy credentials DB.
    ("gcloud", "application_default_credentials.json"),
    ("gcloud", "credentials.db"),
    // Azure CLI: ~/.azure/{azureProfile.json,accessTokens.json,msal_token_cache.json}.
    (".azure", "azureProfile.json"),
    (".azure", "accessTokens.json"),
    (".azure", "msal_token_cache.json"),
];

/// The last `/`-separated, non-empty segment of `path` — its basename. Bare (no `/`)
/// paths return themselves, mirroring [`crate::engine::graph::Behavior`]'s own
/// `basename` helper.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Whether `path` contains `segment` as a whole `/`-delimited component (never a
/// substring match — `.ssh` must not match `.sshrc` or `.ssh-backup`).
fn has_segment(path: &str, segment: &str) -> bool {
    path.split('/').any(|s| s == segment)
}

/// Classify `path` (a container-relative path the agent observed, from a `FileRead`) as a
/// well-known **on-host** sensitive credential path (JEF-320). Returns the path itself —
/// used verbatim as the [`crate::engine::graph::Behavior::SecretRead`] `secret` identifier
/// (mirrors how a k8s-mounted secret is named by `adapter::enrich::secret_for_path`) — or
/// `None` for anything else, including deliberate near-misses: a look-alike basename
/// outside its expected directory, a backup/rotated file (`shadow.bak`), or a directory
/// read of `.ssh` itself rather than a file inside it.
pub fn host_credential_path(path: &str) -> Option<String> {
    if EXACT_HOST_PATHS.contains(&path) {
        return Some(path.to_string());
    }
    if has_segment(path, SSH_DIR_SEGMENT) {
        return Some(path.to_string());
    }
    let name = basename(path);
    if CLOUD_CREDENTIAL_FILES
        .iter()
        .any(|&(dir, file)| file == name && has_segment(path, dir))
    {
        return Some(path.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_shadow_passwd_sudoers_match_exactly() {
        for path in EXACT_HOST_PATHS {
            assert_eq!(
                host_credential_path(path),
                Some((*path).to_string()),
                "{path}"
            );
        }
    }

    #[test]
    fn host_shadow_near_misses_do_not_match() {
        // A backup/rotated copy, a different directory, and a substring look-alike must
        // all stay unclassified — this is an exact-path list, not a prefix match.
        let near_misses = [
            "/etc/shadow.bak",
            "/etc/shadow-",
            "/mnt/host/etc/shadow", // a bind-mounted copy at a different absolute path
            "/etc/shadowdir/x",
            "/app/etc/passwd",
            "/etc/passwd.orig",
        ];
        for path in near_misses {
            assert_eq!(host_credential_path(path), None, "{path}");
        }
    }

    #[test]
    fn ssh_key_material_matches_any_file_under_a_dot_ssh_segment() {
        // Any home directory, any filename directly under `.ssh` — private keys,
        // authorized_keys, known_hosts — matches Falco's "read ssh information" breadth.
        let matches = [
            "/root/.ssh/id_rsa",
            "/root/.ssh/id_ed25519",
            "/home/app/.ssh/authorized_keys",
            "/home/app/.ssh/known_hosts",
            "/var/lib/jenkins/.ssh/id_rsa.pub",
            "/.ssh/id_rsa", // no home dir prefix at all
        ];
        for path in matches {
            assert_eq!(host_credential_path(path), Some(path.to_string()), "{path}");
        }
    }

    #[test]
    fn ssh_look_alikes_do_not_match() {
        // A `.ssh`-PREFIXED name is a different, unrelated file/dir — substring
        // containment must never fire.
        let near_misses = [
            "/home/app/.sshrc",
            "/home/app/.ssh-backup/id_rsa",
            "/home/app/sshconfig",
            "/home/app/ssh/id_rsa", // "ssh", not ".ssh"
        ];
        for path in near_misses {
            assert_eq!(host_credential_path(path), None, "{path}");
        }
    }

    #[test]
    fn cloud_credential_files_match_under_their_provider_directory() {
        let matches = [
            "/root/.aws/credentials",
            "/home/app/.aws/credentials",
            "/root/.config/gcloud/application_default_credentials.json",
            "/root/.config/gcloud/credentials.db",
            "/home/app/.azure/azureProfile.json",
            "/home/app/.azure/accessTokens.json",
            "/home/app/.azure/msal_token_cache.json",
        ];
        for path in matches {
            assert_eq!(host_credential_path(path), Some(path.to_string()), "{path}");
        }
    }

    #[test]
    fn cloud_credential_look_alikes_do_not_match() {
        // The right basename in the WRONG directory, and the right directory with a
        // benign file, must both stay unclassified — the pairing is required, not either
        // half alone.
        let near_misses = [
            "/app/credentials",  // "credentials" but no .aws segment
            "/root/.aws/config", // .aws segment but not the credentials file
            "/root/.aws/credentials.bak",
            "/root/.config/gcloud/logs/credentials.db.old",
            "/home/app/.azure/clouds.config", // .azure segment, unrelated file
        ];
        for path in near_misses {
            assert_eq!(host_credential_path(path), None, "{path}");
        }
    }

    #[test]
    fn ordinary_application_paths_never_match() {
        // The general "don't false-positive on normal app I/O" sanity sweep.
        let benign = [
            "/app/config.yaml",
            "/app/data/users.db",
            "/var/log/app.log",
            "/tmp/scratch",
            "/usr/lib/libssl.so.3",
            "/etc/resolv.conf",
            "/etc/hosts",
        ];
        for path in benign {
            assert_eq!(host_credential_path(path), None, "{path}");
        }
    }
}
