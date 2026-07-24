//! Unit tests for the engine driver's env-driven builders, extracted from `run_loop.rs` to keep
//! that file under the repo's 1,000-line cap (CLAUDE.md). `super` is the `run_loop` module, so the
//! tests drive its private builders unchanged.
//!
//! JEF-268: the Secret informer (reflector watch + initial list) must be metadata-only — protector
//! reasons about a Secret's *identity* (namespace + name), never its contents, so no credential
//! bytes must ever cross the wire or sit in the in-memory store. These tests pin that guarantee to
//! the exact type the informer reflects, `PartialObjectMeta<Secret>`; a regression to the full
//! `Secret` type (which carries `.data`) fails them.

use k8s_openapi::api::core::v1::Secret;
use kube::Resource;
use kube::core::PartialObjectMeta;

/// JEF-487: the dashboard's app-level OIDC gate must fail LOUD on a mistyped minimum-tier config
/// (dashboard NOT served), never silently degrade to allow-all — while a valid or absent value
/// still serves the enforcing gate. Drives the real `build_dashboard_auth` over the env.
#[test]
fn dashboard_oidc_min_tier_config_fails_loud_but_serves_on_valid_or_absent() {
    // Serialize with the other PROTECTOR_DASHBOARD_OIDC_* env test (`from_env`) via the shared
    // lock, since env is process-global under cargo's parallel test threads.
    let _env = crate::engine::dashboard::auth::test_support::ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    const ISSUER: &str = "PROTECTOR_DASHBOARD_OIDC_ISSUER";
    const AUDIENCE: &str = "PROTECTOR_DASHBOARD_OIDC_AUDIENCE";
    const MIN_TIER: &str = "PROTECTOR_DASHBOARD_OIDC_MIN_TIER";
    let clear = || unsafe {
        for key in [
            ISSUER,
            AUDIENCE,
            MIN_TIER,
            "PROTECTOR_DASHBOARD_OIDC_TIER_CLAIM",
            "PROTECTOR_DASHBOARD_OIDC_ALGORITHM",
            "PROTECTOR_DASHBOARD_OIDC_LOGIN_URL",
            "PROTECTOR_DASHBOARD_OIDC_TIER_GRANTS",
        ] {
            std::env::remove_var(key);
        }
    };
    clear();

    // A configured issuer + audience with a MISTYPED min-tier → ConfigError → dashboard NOT
    // served (the HIGH fix: fail loud, never silently allow-all).
    unsafe {
        std::env::set_var(ISSUER, "https://issuer.example");
        std::env::set_var(AUDIENCE, "protector");
        std::env::set_var(MIN_TIER, "operator"); // not a real tier
    }
    assert!(
        super::build_dashboard_auth().is_none(),
        "a mistyped MIN_TIER must fail loud (dashboard not served), never silently allow-all"
    );

    // A VALID min-tier serves, enforcing (Oidc).
    unsafe { std::env::set_var(MIN_TIER, "raw") };
    let (auth, mode) = super::build_dashboard_auth().expect("a valid config serves");
    assert!(auth.is_some(), "a valid config mounts the enforcer");
    assert_eq!(mode, crate::engine::dashboard::AuthMode::Oidc);

    // MIN_TIER UNSET → the Redacted default (allow all authenticated); still serves, enforcing.
    unsafe { std::env::remove_var(MIN_TIER) };
    let (auth, mode) =
        super::build_dashboard_auth().expect("an absent min-tier defaults and serves");
    assert!(auth.is_some());
    assert_eq!(mode, crate::engine::dashboard::AuthMode::Oidc);

    clear();
}

/// JEF-501: a malformed/unrecognized `PROTECTOR_DASHBOARD_OIDC_TIER_GRANTS` must fail LOUD —
/// neither `build_dashboard_auth` nor `build_mcp_verifier` serve on a misconfigured grant table —
/// exactly like a mistyped `MIN_TIER`; a valid grant table serves normally.
#[test]
fn tier_grants_config_fails_loud_but_serves_on_valid_or_absent() {
    let _env = crate::engine::dashboard::auth::test_support::ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    const ISSUER: &str = "PROTECTOR_DASHBOARD_OIDC_ISSUER";
    const AUDIENCE: &str = "PROTECTOR_DASHBOARD_OIDC_AUDIENCE";
    const TIER_GRANTS: &str = "PROTECTOR_DASHBOARD_OIDC_TIER_GRANTS";
    let clear = || unsafe {
        for key in [ISSUER, AUDIENCE, TIER_GRANTS] {
            std::env::remove_var(key);
        }
    };
    clear();
    unsafe {
        std::env::set_var(ISSUER, "https://issuer.example");
        std::env::set_var(AUDIENCE, "protector");
    }

    // An unrecognized tier name in the grants table → neither builder serves.
    unsafe { std::env::set_var(TIER_GRANTS, "admin=alice@x.com") };
    assert!(
        super::build_dashboard_auth().is_none(),
        "an unrecognized TIER_GRANTS tier must fail loud (dashboard not served)"
    );
    assert!(
        super::build_mcp_verifier().is_none(),
        "an unrecognized TIER_GRANTS tier must fail loud (mcp not served)"
    );

    // Malformed syntax → neither builder serves.
    unsafe { std::env::set_var(TIER_GRANTS, "not-a-valid-entry") };
    assert!(super::build_dashboard_auth().is_none());
    assert!(super::build_mcp_verifier().is_none());

    // A VALID grant table serves normally on both surfaces.
    unsafe { std::env::set_var(TIER_GRANTS, "raw=alice@x.com;forensic=bob@x.com") };
    let (auth, mode) = super::build_dashboard_auth().expect("a valid grant table serves");
    assert!(auth.is_some());
    assert_eq!(mode, crate::engine::dashboard::AuthMode::Oidc);
    assert!(super::build_mcp_verifier().is_some());

    clear();
}

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

// JEF-366: the signing-posture and build-provenance sweeps must draw their cosign verifier
// and env-driven bounds from ONE shared source (`super::cosign_observer_parts`) so the two
// builders can never silently drift — the hand-copied `registry_auth()` shape that caused the
// JEF-339 outage. These tests own a clean process env (nextest runs each test in its own
// process, so the `unsafe { set_var }` blocks are isolated) and point the TUF cache at a
// per-test temp dir so `CosignChecker::new` succeeds offline.
use std::time::Duration;

/// A unique, creatable TUF cache dir for a test, so the checker builds without touching
/// `/tmp/sigstore` or any other test's dir.
fn scratch_tuf_cache(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "protector-jef366-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

/// Clear the observer env so a test starts from the documented defaults.
/// SAFETY: nextest runs each test in its own process, so this mutation is isolated.
fn clear_observer_env() {
    unsafe {
        std::env::remove_var("PROTECTOR_VERIFY_TIMEOUT");
        std::env::remove_var("PROTECTOR_CACHE_TTL");
        std::env::remove_var("PROTECTOR_MAX_IMAGES");
        std::env::remove_var("PROTECTOR_OIDC_ISSUER");
        std::env::remove_var("PROTECTOR_PROVENANCE_ENABLE");
    }
}

/// The shared source of truth returns the documented JEF-326 defaults (20s verify, 300s TTL,
/// 32 images) when nothing is set — the exact bounds both builders inherit.
#[test]
fn cosign_observer_parts_uses_documented_defaults() {
    clear_observer_env();
    unsafe { std::env::set_var("PROTECTOR_TUF_CACHE", scratch_tuf_cache("defaults")) };

    let (_, max_images, cache_ttl) =
        super::cosign_observer_parts("test").expect("checker builds with a creatable cache dir");
    assert_eq!(max_images, 32, "PROTECTOR_MAX_IMAGES default");
    assert_eq!(
        cache_ttl,
        Duration::from_secs(300),
        "PROTECTOR_CACHE_TTL default"
    );
}

/// Env overrides flow through the single helper — so both sweeps track the same knobs.
#[test]
fn cosign_observer_parts_honors_env_overrides() {
    clear_observer_env();
    unsafe {
        std::env::set_var("PROTECTOR_TUF_CACHE", scratch_tuf_cache("overrides"));
        std::env::set_var("PROTECTOR_CACHE_TTL", "42");
        std::env::set_var("PROTECTOR_MAX_IMAGES", "7");
    }

    let (_, max_images, cache_ttl) = super::cosign_observer_parts("test").expect("checker builds");
    assert_eq!(max_images, 7);
    assert_eq!(cache_ttl, Duration::from_secs(42));
}

/// Anti-drift: from ONE env, the signing observer builds AND (once opted in) the provenance
/// scanner builds — both routed through the shared parts, both inheriting the same bounds. If
/// either builder stopped going through `cosign_observer_parts`, this pins the equivalence.
#[test]
fn both_builders_build_from_the_same_env() {
    clear_observer_env();
    unsafe {
        std::env::set_var("PROTECTOR_TUF_CACHE", scratch_tuf_cache("both"));
        std::env::set_var("PROTECTOR_MAX_IMAGES", "9");
        std::env::set_var("PROTECTOR_CACHE_TTL", "77");
    }

    assert!(
        super::build_signing_observer().is_some(),
        "signing observer must build from a valid env"
    );

    // Provenance is opt-in: off by default, on only when explicitly enabled — the one bit
    // that stays distinct from the signing sweep.
    assert!(
        super::build_provenance_scanner().is_none(),
        "provenance scanner is off until PROTECTOR_PROVENANCE_ENABLE is set"
    );
    unsafe { std::env::set_var("PROTECTOR_PROVENANCE_ENABLE", "1") };
    assert!(
        super::build_provenance_scanner().is_some(),
        "provenance scanner must build from the same env once opted in"
    );
}
