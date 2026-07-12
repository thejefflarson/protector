//! Tests for the shared per-image registry-auth resolver (JEF-339, JEF-352).
//!
//! [`RegistryAuth::from_env`] reads three **process-global** env vars
//! (`PROTECTOR_REGISTRY_USERNAME` / `PROTECTOR_REGISTRY_PASSWORD` /
//! `PROTECTOR_REGISTRY_AUTH_FILE`). Rust's default test harness runs tests as parallel
//! threads within one process, so a `set_var`/`remove_var` in one test is visible to any
//! sibling that reads the same var mid-flight — a data race that made these cases flaky
//! (JEF-412). Every case that touches those vars therefore goes through [`EnvGuard`], which
//! serializes them on a shared lock and restores the prior values on drop (even on panic),
//! so no test can observe another's env mutation.

use std::sync::{Mutex, MutexGuard};

use super::RegistryAuth;
use sigstore::registry::Auth;

/// The three process-global env vars [`RegistryAuth::from_env`] reads. [`EnvGuard`] snapshots
/// and restores exactly these, and holds the lock for the whole set → read → assert window.
const CRED_ENV_VARS: [&str; 3] = [
    "PROTECTOR_REGISTRY_USERNAME",
    "PROTECTOR_REGISTRY_PASSWORD",
    "PROTECTOR_REGISTRY_AUTH_FILE",
];

/// Serializes every test that mutates the credential env vars. Without this, `cargo test` runs
/// these cases as concurrent threads in one process and their `set_var`/`remove_var` calls race.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard that gives a test exclusive, restore-on-drop access to the credential env vars.
///
/// On construction it takes [`ENV_LOCK`] (so only one env-mutating test runs at a time),
/// snapshots the current value of each [`CRED_ENV_VARS`] entry, then clears them all so the test
/// starts from a known-clean env. On drop it restores the snapshot — even if the test panics —
/// so a failing assertion can never leak creds into a sibling.
struct EnvGuard {
    _lock: MutexGuard<'static, ()>,
    saved: [(&'static str, Option<String>); 3],
}

impl EnvGuard {
    /// Acquire the lock, snapshot the credential env vars, and clear them to a known-clean state.
    fn acquire() -> Self {
        // A prior test that panicked mid-window would poison the lock; recover the guard so one
        // legitimate assertion failure doesn't cascade into spurious failures for later tests.
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let saved = CRED_ENV_VARS.map(|k| (k, std::env::var(k).ok()));
        // SAFETY: the lock guarantees no sibling test reads/writes these vars concurrently.
        unsafe {
            for (k, _) in &saved {
                std::env::remove_var(k);
            }
        }
        Self { _lock: lock, saved }
    }

    /// Set one credential env var within the guarded window.
    fn set<V: AsRef<std::ffi::OsStr>>(&self, key: &str, value: V) {
        // SAFETY: the guard holds the lock, so no sibling test races this mutation.
        unsafe { std::env::set_var(key, value) };
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: still holding the lock; restore each var to its pre-test value.
        unsafe {
            for (key, prior) in &self.saved {
                match prior {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

/// Assert `auth` is `Basic(user, pass)`; panics with the actual variant otherwise.
#[track_caller]
fn assert_basic(auth: Auth, user: &str, pass: &str) {
    match auth {
        Auth::Basic(u, p) => {
            assert_eq!(u, user, "username");
            assert_eq!(p, pass, "password");
        }
        other => panic!("expected Auth::Basic({user:?}, {pass:?}), got {other:?}"),
    }
}

/// Write a `.dockerconfigjson` with `contents` to a unique per-test dir and return its path.
fn write_config(tag: &str, contents: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "protector-auth-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(&path, contents).unwrap();
    path
}

/// A multi-registry k8s `.dockerconfigjson`: ghcr.io (base64 `auth`), Docker Hub keyed by the
/// legacy `https://index.docker.io/v1/` URL, and a private `host:port` registry.
/// base64("thejefflarson:ghp_token")   = dGhlamVmZmxhcnNvbjpnaHBfdG9rZW4=
/// base64("dockerbot:dckr_pat")        = ZG9ja2VyYm90OmRja3JfcGF0
/// base64("reguser:regpass")           = cmVndXNlcjpyZWdwYXNz
const MULTI_REGISTRY: &str = r#"{"auths":{
    "ghcr.io":{"auth":"dGhlamVmZmxhcnNvbjpnaHBfdG9rZW4="},
    "https://index.docker.io/v1/":{"auth":"ZG9ja2VyYm90OmRja3JfcGF0"},
    "myreg.example:5000":{"auth":"cmVndXNlcjpyZWdwYXNz"}
}}"#;

/// A dockerconfig with several registries resolves EACH image to that registry's own creds — the
/// core JEF-352 fix (before this, only ghcr.io authenticated and every other private image 401ed).
#[test]
fn resolves_per_image_across_multiple_registries() {
    let path = write_config("multi", MULTI_REGISTRY);
    let env = EnvGuard::acquire();
    env.set("PROTECTOR_REGISTRY_AUTH_FILE", &path);

    let auth = RegistryAuth::from_env();
    assert_basic(
        auth.for_image("ghcr.io/thejefflarson/app:1"),
        "thejefflarson",
        "ghp_token",
    );
    assert_basic(
        auth.for_image("myreg.example:5000/team/service:v2"),
        "reguser",
        "regpass",
    );
    // An unlisted registry gets Anonymous — never another registry's creds, never a fabrication.
    assert!(matches!(
        auth.for_image("quay.io/some/image:latest"),
        Auth::Anonymous
    ));

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// Docker Hub host normalization: `docker.io/...`, `index.docker.io/...`, the bare shorthand, and
/// `registry-1.docker.io/...` all match the `https://index.docker.io/v1/` config key.
#[test]
fn docker_io_variants_match_the_index_v1_config_key() {
    let path = write_config("dockerio", MULTI_REGISTRY);
    let env = EnvGuard::acquire();
    env.set("PROTECTOR_REGISTRY_AUTH_FILE", &path);

    let auth = RegistryAuth::from_env();
    for image in [
        "docker.io/library/redis:7",
        "index.docker.io/library/redis:7",
        "registry-1.docker.io/library/redis:7",
        // A bare Docker Hub shorthand has no host segment but a runtime resolves it to docker.io.
        "redis:7",
        "library/redis",
    ] {
        assert_basic(auth.for_image(image), "dockerbot", "dckr_pat");
    }

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// JEF-339 must still hold: a private `ghcr.io/thejefflarson/*` image resolves to `Basic` from the
/// mounted fixture dockerconfig (the exact production shape — only the auth file is set).
#[test]
fn ghcr_private_image_still_resolves_basic_from_the_auth_file() {
    let path = write_config(
        "ghcr",
        r#"{"auths":{"ghcr.io":{"auth":"dGhlamVmZmxhcnNvbjpnaHBfdG9rZW4="}}}"#,
    );
    let env = EnvGuard::acquire();
    env.set("PROTECTOR_REGISTRY_AUTH_FILE", &path);

    let auth = RegistryAuth::from_env();
    assert_basic(
        auth.for_image("ghcr.io/thejefflarson/protector:sha-abc"),
        "thejefflarson",
        "ghp_token",
    );

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// An entry with explicit `username`/`password` wins over its base64 `auth` field.
#[test]
fn explicit_username_password_wins_over_auth_field() {
    let path = write_config(
        "explicit",
        r#"{"auths":{"ghcr.io":{"username":"bot","password":"pw","auth":"aWdub3JlZDppZ25vcmVk"}}}"#,
    );
    let env = EnvGuard::acquire();
    env.set("PROTECTOR_REGISTRY_AUTH_FILE", &path);

    let auth = RegistryAuth::from_env();
    assert_basic(auth.for_image("ghcr.io/org/app"), "bot", "pw");

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// The explicit env override is a GLOBAL fallback: with it set, EVERY registry (listed, unlisted,
/// Docker Hub) resolves to the env creds, taking precedence over any matching file entry.
#[test]
fn env_override_applies_across_all_registries() {
    let path = write_config("envoverride", MULTI_REGISTRY);
    let env = EnvGuard::acquire();
    env.set("PROTECTOR_REGISTRY_USERNAME", "envuser");
    env.set("PROTECTOR_REGISTRY_PASSWORD", "envpass");
    env.set("PROTECTOR_REGISTRY_AUTH_FILE", &path);

    let auth = RegistryAuth::from_env();
    // ghcr.io has a file entry, yet the env override still wins…
    assert_basic(auth.for_image("ghcr.io/org/app"), "envuser", "envpass");
    // …and it also applies to a registry with NO file entry.
    assert_basic(auth.for_image("quay.io/org/app"), "envuser", "envpass");

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// With no credentials of any kind, every image resolves to Anonymous — the safe default.
#[test]
fn anonymous_without_any_credentials() {
    let _env = EnvGuard::acquire();
    let auth = RegistryAuth::from_env();
    assert!(matches!(auth.for_image("ghcr.io/org/app"), Auth::Anonymous));
    assert!(matches!(
        auth.for_image("docker.io/library/redis"),
        Auth::Anonymous
    ));
}

/// A missing/unparseable auth file never errors — it degrades to Anonymous per image.
#[test]
fn missing_auth_file_degrades_to_anonymous() {
    let env = EnvGuard::acquire();
    env.set(
        "PROTECTOR_REGISTRY_AUTH_FILE",
        "/nonexistent/protector/registry/config.json",
    );
    let auth = RegistryAuth::from_env();
    assert!(matches!(auth.for_image("ghcr.io/org/app"), Auth::Anonymous));
}
