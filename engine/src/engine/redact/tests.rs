//! Unit tests for the shared redaction primitives, exercised on the GENERALIZED inputs the
//! MCP server (ADR-0031) will pass — a finding/verdict text blob, a CVE-token line, a bare
//! decision name — including the edge cases the ADR-0018 notifier tests already pin.

use super::scrub::REDACTED;
use super::{redacted_attack_outcome, sanitize, scrub_cve_tokens, scrub_decision_names};
use crate::engine::graph::attack::{CREDENTIAL_ACCESS, EXPLOIT_PUBLIC_FACING};

// --- sanitize: STRUCTURE stripping -------------------------------------------------

#[test]
fn sanitize_strips_fence_and_structure_chars() {
    let out = sanitize("see <<<inject>>> `code`\nrun {x}");
    for bad in ['<', '>', '`', '\n', '\r', '{', '}'] {
        assert!(
            !out.contains(bad),
            "sanitized text must not contain {bad:?}"
        );
    }
    // Stripped chars become spaces (length preserved), not deletions.
    assert_eq!(sanitize("a<b").len(), 3);
}

#[test]
fn sanitize_leaves_ordinary_text_untouched() {
    // A workload key and prose with no structure chars pass through verbatim.
    assert_eq!(sanitize("workload/app/Pod/web"), "workload/app/Pod/web");
    assert_eq!(sanitize("reaches the secret"), "reaches the secret");
}

// --- scrub_decision_names: SEMANTIC name stripping ---------------------------------

#[test]
fn scrub_decision_names_replaces_each_supplied_name() {
    // The generalized shape: a verdict blob + the list of names the decision was keyed on.
    let text = "web reaches secret/app/Secret/db-password (db-password)";
    let names = ["web", "secret/app/Secret/db-password", "db-password"];
    let out = scrub_decision_names(text, &names);
    assert!(!out.contains("db-password"), "bare secret name scrubbed");
    assert!(!out.contains("secret/app/Secret"), "full node-key scrubbed");
    assert!(
        out.contains(REDACTED),
        "scrubbed names become the placeholder"
    );
}

#[test]
fn scrub_decision_names_replaces_longest_first_no_fragment() {
    // The full key and its bare suffix both appear; longest-first must leave no fragment of
    // the longer behind after the shorter is scrubbed.
    let text = "reaches secret/app/Secret/db-password then db-password";
    let names = ["db-password", "secret/app/Secret/db-password"];
    let out = scrub_decision_names(text, &names);
    assert!(
        !out.contains("secret/app/Secret"),
        "no node-key fragment survives"
    );
    assert!(
        !out.contains("db-password"),
        "no bare-name fragment survives"
    );
}

#[test]
fn scrub_decision_names_ignores_empty_and_whitespace_names() {
    // Empty / whitespace-only names are dropped (they would otherwise match everywhere).
    let text = "nothing to scrub here";
    let out = scrub_decision_names(text, &["", "   ", "\t"]);
    assert_eq!(out, text, "blank names must be no-ops");
}

#[test]
fn scrub_decision_names_leaves_cve_tokens_alone() {
    // Independence: the name scrubber must NOT touch CVE tokens (the MCP `raw` tier relaxes
    // names but keeps CVE scrubbing; the notifier composes the two).
    let out = scrub_decision_names("CVE-2021-44228 in web", &["web"]);
    assert!(
        out.contains("CVE-2021-44228"),
        "CVE left for scrub_cve_tokens"
    );
    assert!(!out.contains("web") || out.contains(REDACTED));
}

// --- scrub_cve_tokens: CVE token stripping -----------------------------------------

#[test]
fn scrub_cve_tokens_scrubs_a_cve_line() {
    let out = scrub_cve_tokens("finding: CVE-2021-44228 reaches the secret");
    assert!(!out.contains("CVE-2021-44228"), "CVE id scrubbed");
    assert!(out.contains(REDACTED));
}

#[test]
fn scrub_cve_tokens_is_case_insensitive() {
    let out = scrub_cve_tokens("cve-2021-44228 is exploitable");
    assert!(
        !out.to_ascii_uppercase().contains("CVE-2021-44228"),
        "a lowercase CVE token is still scrubbed"
    );
}

#[test]
fn scrub_cve_tokens_scrubs_five_digit_sequence_and_multiple() {
    // The sequence is 4+ digits, and every token on the line is scrubbed.
    let out = scrub_cve_tokens("CVE-2024-12345 and CVE-2019-0708 both apply");
    assert!(!out.contains("CVE-2024-12345"));
    assert!(!out.contains("CVE-2019-0708"));
    assert_eq!(out.matches(REDACTED).count(), 2);
}

#[test]
fn scrub_cve_tokens_leaves_non_cve_text() {
    let text = "no cve here, just prose about 2021 and codes";
    assert_eq!(scrub_cve_tokens(text), text);
}

// --- redacted_attack_outcome: counts-only outcome ----------------------------------

#[test]
fn attack_outcome_is_distinct_ordered_and_capped() {
    // Duplicate refs collapse; the outcome is the distinct technique triples, sanitized.
    let refs = [
        CREDENTIAL_ACCESS,
        EXPLOIT_PUBLIC_FACING,
        CREDENTIAL_ACCESS, // duplicate
    ];
    let out = redacted_attack_outcome(refs.iter(), 16);
    assert_eq!(out.len(), 2, "duplicates collapse to distinct techniques");
    // Deterministic BTreeSet order: TA0001 (Exploit Public-Facing) sorts before TA0006.
    assert_eq!(out[0]["tactic"], "TA0001");
    assert_eq!(out[0]["technique_id"], "T1190");
    assert_eq!(out[1]["tactic"], "TA0006");
    assert_eq!(out[1]["technique_id"], "T1552");
}

#[test]
fn attack_outcome_respects_the_cap() {
    let refs = [CREDENTIAL_ACCESS, EXPLOIT_PUBLIC_FACING];
    assert_eq!(
        redacted_attack_outcome(refs.iter(), 1).len(),
        1,
        "cap bounds the outcome"
    );
    assert!(redacted_attack_outcome([].iter(), 16).is_empty());
}

// --- the composed egress path the notifier and MCP `redacted` tier both run --------

#[test]
fn composed_redacted_tier_strips_structure_names_and_cves() {
    // The full `redacted` composition (ADR-0031 §2): sanitize (structure) → scrub names →
    // scrub CVEs. The MCP server runs exactly this over a finding's verdict prose.
    let verdict = "CVE-2021-44228 in web reaches secret/app/Secret/db-password `x`\n<<<inject>>>";
    let names = ["secret/app/Secret/db-password", "db-password", "web"];
    let out = scrub_cve_tokens(&scrub_decision_names(&sanitize(verdict), &names));
    assert!(!out.contains("CVE-2021-44228"), "CVE scrubbed");
    assert!(!out.contains("secret/app/Secret"), "node-key scrubbed");
    assert!(!out.contains("db-password"), "secret name scrubbed");
    for bad in ['<', '>', '`', '\n', '\r'] {
        assert!(!out.contains(bad), "structure char {bad:?} stripped");
    }
    assert!(
        out.contains(REDACTED),
        "placeholders mark what was scrubbed"
    );
}
