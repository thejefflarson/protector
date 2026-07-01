//! Unit tests for the k8s audit-log ingest (JEF-269): the pure parser and the TTL'd store.
//! The HTTP glue is the cluster-facing half exercised against a real apiserver; these cover
//! the parsing and windowing the corroboration depends on.

use super::*;
use serde_json::json;

/// A minimal audit event for `verb` on a secret `ns/name`, attributed to SA
/// `system:serviceaccount:app:reader-sa`, with the given authz `decision`.
fn event(verb: &str, ns: &str, name: Option<&str>, decision: &str) -> Value {
    let mut object_ref = json!({"resource": "secrets", "namespace": ns});
    if let Some(name) = name {
        object_ref["name"] = json!(name);
    }
    json!({
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "verb": verb,
        "user": {"username": "system:serviceaccount:app:reader-sa"},
        "objectRef": object_ref,
        "annotations": {"authorization.k8s.io/decision": decision},
    })
}

#[test]
fn allowed_get_secret_by_sa_parses() {
    let parsed =
        parse_audit_event(&event("get", "app", Some("db-creds"), "allow")).expect("parses");
    assert_eq!(
        parsed,
        AuditSecretRead {
            sa_namespace: "app".into(),
            sa_name: "reader-sa".into(),
            secret_namespace: Some("app".into()),
            secret_name: Some("db-creds".into()),
            verb: "get".into(),
        }
    );
    assert_eq!(parsed.secret_display(), "app/db-creds");
}

#[test]
fn list_and_watch_are_covered() {
    // A namespaced list/watch of the whole collection carries no objectRef.name.
    for verb in ["list", "watch"] {
        let parsed = parse_audit_event(&event(verb, "app", None, "allow")).expect("parses");
        assert_eq!(parsed.verb, verb);
        assert_eq!(parsed.secret_namespace, Some("app".into()));
        assert_eq!(parsed.secret_name, None);
        assert_eq!(parsed.secret_display(), "app/*");
    }
}

#[test]
fn cluster_wide_list_has_no_namespace() {
    // A cluster-scoped `list secrets` (all namespaces) has neither name nor namespace.
    let mut ev = event("list", "app", None, "allow");
    ev["objectRef"].as_object_mut().unwrap().remove("namespace");
    let parsed = parse_audit_event(&ev).expect("parses");
    assert_eq!(parsed.secret_namespace, None);
    assert_eq!(parsed.secret_name, None);
    assert_eq!(parsed.secret_display(), "*");
}

#[test]
fn denied_request_is_not_a_read() {
    // A forbidden GET is a real audit event but must NEVER be recorded as a read.
    assert!(parse_audit_event(&event("get", "app", Some("db-creds"), "forbid")).is_none());
    // A missing decision annotation is also not an allow.
    let mut ev = event("get", "app", Some("db-creds"), "allow");
    ev["annotations"] = json!({});
    assert!(parse_audit_event(&ev).is_none());
}

#[test]
fn non_read_verbs_are_ignored() {
    for verb in ["create", "update", "patch", "delete", "deletecollection"] {
        assert!(
            parse_audit_event(&event(verb, "app", Some("db-creds"), "allow")).is_none(),
            "{verb} must not be a read"
        );
    }
}

#[test]
fn non_secret_resources_are_ignored() {
    let mut ev = event("get", "app", Some("cm"), "allow");
    ev["objectRef"]["resource"] = json!("configmaps");
    assert!(parse_audit_event(&ev).is_none());
    // A non-core `secrets` CRD (some apiGroup) is not a Kubernetes Secret.
    let mut crd = event("get", "app", Some("thing"), "allow");
    crd["objectRef"]["apiGroup"] = json!("example.com");
    assert!(parse_audit_event(&crd).is_none());
}

#[test]
fn non_service_account_users_are_ignored() {
    // A human `kubectl get secret` is audited but is not a workload's runtime behavior.
    let mut ev = event("get", "app", Some("db-creds"), "allow");
    ev["user"]["username"] = json!("alice@example.com");
    assert!(parse_audit_event(&ev).is_none());
    // A malformed SA username (missing the name segment) is dropped, not guessed.
    let mut bad = event("get", "app", Some("db-creds"), "allow");
    bad["user"]["username"] = json!("system:serviceaccount:app");
    assert!(parse_audit_event(&bad).is_none());
}

#[test]
fn malformed_payloads_are_rejected_without_panic() {
    // Every one of these is missing or wrong-typed somewhere; none must panic.
    let cases = [
        json!({}),
        json!({"verb": "get"}),
        json!({"verb": 5, "objectRef": {"resource": "secrets"}}),
        json!({"verb": "get", "objectRef": "not-an-object"}),
        json!({"verb": "get", "objectRef": {"resource": "secrets"}}), // no user/decision
        json!({"verb": "get", "objectRef": {"resource": "secrets"},
               "user": {}, "annotations": {"authorization.k8s.io/decision": "allow"}}),
        json!(null),
        json!("a string"),
        json!([1, 2, 3]),
    ];
    for case in cases {
        assert!(parse_audit_event(&case).is_none(), "should drop: {case}");
    }
}

#[test]
fn untrusted_fields_are_size_bounded() {
    // A hostile apiserver payload with a giant secret name can't balloon the store.
    let huge = "x".repeat(10_000);
    let ev = event("get", "app", Some(&huge), "allow");
    let parsed = parse_audit_event(&ev).expect("parses");
    assert_eq!(parsed.secret_name.unwrap().chars().count(), MAX_FIELD_LEN);
}

#[test]
fn event_list_batch_parses_only_the_secret_reads() {
    // The shape the apiserver's audit webhook actually POSTs: an EventList mixing secret
    // reads with unrelated audited requests. Only the allowed secret reads are lifted.
    let body = json!({
        "kind": "EventList",
        "apiVersion": "audit.k8s.io/v1",
        "items": [
            event("get", "app", Some("db-creds"), "allow"),
            event("get", "app", Some("nope"), "forbid"),   // denied → dropped
            {"verb": "list", "objectRef": {"resource": "pods"},
             "user": {"username": "system:serviceaccount:app:reader-sa"},
             "annotations": {"authorization.k8s.io/decision": "allow"}}, // non-secret → dropped
            event("watch", "billing", None, "allow"),
        ]
    });
    let reads = parse_audit_body(&body);
    assert_eq!(reads.len(), 2);
    assert_eq!(reads[0].secret_display(), "app/db-creds");
    assert_eq!(reads[1].secret_display(), "billing/*");
}

#[test]
fn a_bare_single_event_is_also_accepted() {
    let reads = parse_audit_body(&event("get", "app", Some("db-creds"), "allow"));
    assert_eq!(reads.len(), 1);
}

#[test]
fn reads_expire_after_the_ttl() {
    let store = AuditEvents::new(Duration::from_secs(300));
    let t0 = Instant::now();
    let read = parse_audit_event(&event("get", "app", Some("db-creds"), "allow")).unwrap();
    store.record_at(t0, read);
    assert_eq!(store.current_at(t0 + Duration::from_secs(60)).len(), 1);
    assert!(store.current_at(t0 + Duration::from_secs(301)).is_empty());
}

#[test]
fn repeat_read_is_not_a_change_but_refreshes_ttl() {
    let store = AuditEvents::new(Duration::from_secs(300));
    let t0 = Instant::now();
    let read = || parse_audit_event(&event("get", "app", Some("db-creds"), "allow")).unwrap();
    // First sighting wakes the engine; the same (SA, secret, verb) again does not.
    assert!(store.record_at(t0, read()));
    assert!(!store.record_at(t0 + Duration::from_secs(290), read()));
    // The refresh kept it alive past the original expiry, and did not duplicate it.
    assert_eq!(store.current_at(t0 + Duration::from_secs(400)).len(), 1);
    // A different verb on the same secret IS a new fact.
    let watch = parse_audit_event(&event("watch", "app", None, "allow")).unwrap();
    assert!(store.record_at(t0 + Duration::from_secs(400), watch));
    assert_eq!(store.current_at(t0 + Duration::from_secs(400)).len(), 2);
}
