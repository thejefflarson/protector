//! Tests for the hard-parse-failure retry (`chat_with_retry_on_hard_parse_failure`):
//! the seam that distinguishes a genuine hard-parse-failure (no recoverable JSON at
//! all — retry-worthy) from a legitimately-parsed decision that happens to land on
//! `Uncertain` (a real skeptic answer — must NOT retry). Exercised end-to-end through
//! `ModelAdjudicator::judge` against a localhost stub chat endpoint that scripts its
//! replies per connection, mirroring `engine::model`'s own test-server pattern.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::engine::reason::adjudicate::tests::{critical_cve, graph_with_vuln};

/// A localhost stub chat endpoint: the i-th connection it accepts is answered with
/// `responses[i]` as the assistant `content` (the last scripted response repeats for any
/// call beyond the list, so a test that only cares about the first N calls doesn't need to
/// script every possible extra one). Returns the endpoint URL and a shared call counter so
/// a test can assert exactly how many model calls were made.
async fn spawn_stub_chat_server(responses: Vec<String>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let srv_count = count.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let n = srv_count.fetch_add(1, Ordering::SeqCst);
            let content = responses
                .get(n)
                .or_else(|| responses.last())
                .cloned()
                .unwrap_or_default();
            let mut buf = [0u8; 8192];
            let _ = sock.read(&mut buf).await;
            let payload = json!({ "choices": [{ "message": { "content": content } }] }).to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        }
    });
    (format!("http://{addr}/v1/chat/completions"), count)
}

/// `is_hard_parse_failure` is `true` only when no JSON object can be extracted at all —
/// the exact retry-worthy condition.
#[test]
fn is_hard_parse_failure_true_only_when_no_json_object_extracts() {
    assert!(is_hard_parse_failure("not json at all"));
    assert!(is_hard_parse_failure(""));
    assert!(is_hard_parse_failure("{unterminated"));
}

/// A real JSON object — even one `parse_incident_decision` will go on to degrade to
/// `Uncertain` (an out-of-range `assessment`) — is NOT a hard parse failure: the seam only
/// inspects JSON-extractability, never the parsed content, so a legitimate skeptic answer
/// can never be mistaken for a transport/formatting fluke.
#[test]
fn is_hard_parse_failure_false_for_any_extractable_object_even_a_degraded_one() {
    assert!(!is_hard_parse_failure(
        r#"{"assessment": "maybe", "reason": "not sure"}"#
    ));
    assert!(!is_hard_parse_failure(
        r#"{"assessment": "uncertain", "reason": "x", "contain": []}"#
    ));
}

/// Acceptance: unparseable → valid `attack` recovers to `Attack` via exactly one retry
/// (two model calls total).
#[tokio::test]
async fn recovers_to_attack_after_one_hard_parse_failure_retry() {
    let (graph, entry) = graph_with_vuln(critical_cve("CVE-2024-24786"));
    let attack_reply = json!({
        "assessment": "attack",
        "reason": "critical vulnerability exposed on the internet-facing entry",
        "contain": []
    })
    .to_string();
    let (endpoint, count) =
        spawn_stub_chat_server(vec!["not json at all, sorry".to_string(), attack_reply]).await;

    let adjudicator = ModelAdjudicator::new(endpoint, "stub-model");
    let decision = adjudicator
        .judge(&entry, &[], &graph, "prompt", &[], &Menu::default())
        .await;

    assert_eq!(
        decision.assessment,
        Assessment::Attack,
        "the retry must recover the second, valid reply"
    );
    assert!(decision.cuts.is_empty());
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "exactly one retry — two model calls total"
    );
}

/// Acceptance: unparseable → unparseable falls to the skeptic default (`Uncertain`, no
/// cuts) after exactly one retry — never a third call.
#[tokio::test]
async fn double_hard_failure_falls_to_the_skeptic_default() {
    let (graph, entry) = graph_with_vuln(critical_cve("CVE-2024-24786"));
    let (endpoint, count) = spawn_stub_chat_server(vec![
        "still garbled".to_string(),
        "still garbled on the retry too".to_string(),
    ])
    .await;

    let adjudicator = ModelAdjudicator::new(endpoint, "stub-model");
    let decision = adjudicator
        .judge(&entry, &[], &graph, "prompt", &[], &Menu::default())
        .await;

    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert!(decision.cuts.is_empty());
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "one retry attempted, then the existing skeptic default stands — no further retries"
    );
}

/// Acceptance: a legitimately-parsed `Uncertain` (a real skeptic answer, not a parse
/// failure) must NOT trigger a retry — only one model call.
#[tokio::test]
async fn legitimate_uncertain_does_not_retry() {
    let (graph, entry) = graph_with_vuln(critical_cve("CVE-2024-24786"));
    let uncertain_reply = json!({
        "assessment": "uncertain",
        "reason": "can't tell from the evidence",
        "contain": []
    })
    .to_string();
    let (endpoint, count) = spawn_stub_chat_server(vec![uncertain_reply]).await;

    let adjudicator = ModelAdjudicator::new(endpoint, "stub-model");
    let decision = adjudicator
        .judge(&entry, &[], &graph, "prompt", &[], &Menu::default())
        .await;

    assert_eq!(decision.assessment, Assessment::Uncertain);
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "a legitimately-parsed Uncertain must not trigger a retry — only one model call"
    );
}
