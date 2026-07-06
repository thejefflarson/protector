//! Tests for the shared per-image registry-auth resolver (JEF-339, JEF-352).
//!
//! The env-mutating cases rely on nextest's per-test process isolation, so each test owns a
//! clean process env; the `unsafe { set_var }` blocks mirror the pattern the rest of the
//! crate's env tests use.

use super::RegistryAuth;
use sigstore::registry::Auth;

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

/// Clear every credential env var so a test starts from a known-clean process env.
/// SAFETY: nextest runs each test in its own process, so this mutation is isolated.
fn clear_cred_env() {
    unsafe {
        std::env::remove_var("PROTECTOR_REGISTRY_USERNAME");
        std::env::remove_var("PROTECTOR_REGISTRY_PASSWORD");
        std::env::remove_var("PROTECTOR_REGISTRY_AUTH_FILE");
    }
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
    clear_cred_env();
    unsafe { std::env::set_var("PROTECTOR_REGISTRY_AUTH_FILE", &path) };

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
    clear_cred_env();
    unsafe { std::env::set_var("PROTECTOR_REGISTRY_AUTH_FILE", &path) };

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
    clear_cred_env();
    unsafe { std::env::set_var("PROTECTOR_REGISTRY_AUTH_FILE", &path) };

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
    clear_cred_env();
    unsafe { std::env::set_var("PROTECTOR_REGISTRY_AUTH_FILE", &path) };

    let auth = RegistryAuth::from_env();
    assert_basic(auth.for_image("ghcr.io/org/app"), "bot", "pw");

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// The explicit env override is a GLOBAL fallback: with it set, EVERY registry (listed, unlisted,
/// Docker Hub) resolves to the env creds, taking precedence over any matching file entry.
#[test]
fn env_override_applies_across_all_registries() {
    let path = write_config("envoverride", MULTI_REGISTRY);
    clear_cred_env();
    unsafe {
        std::env::set_var("PROTECTOR_REGISTRY_USERNAME", "envuser");
        std::env::set_var("PROTECTOR_REGISTRY_PASSWORD", "envpass");
        std::env::set_var("PROTECTOR_REGISTRY_AUTH_FILE", &path);
    }

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
    clear_cred_env();
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
    clear_cred_env();
    unsafe {
        std::env::set_var(
            "PROTECTOR_REGISTRY_AUTH_FILE",
            "/nonexistent/protector/registry/config.json",
        )
    };
    let auth = RegistryAuth::from_env();
    assert!(matches!(auth.for_image("ghcr.io/org/app"), Auth::Anonymous));
}
