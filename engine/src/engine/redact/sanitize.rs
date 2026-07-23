//! `sanitize` — strip the STRUCTURE an attacker could use to close a prompt fence or
//! inject prompt/wire structure. Kept in its own file (repo CLAUDE.md file-size cap).

/// Strip the characters an attacker could use to close a fence or inject prompt
/// structure (`<>{}`, backtick, CR/LF), replacing each with a space. The values come
/// from cluster objects and third-party feeds, so they are data, never instructions.
///
/// This is the ONE shared implementation (ADR-0031): the adjudication prompt (ADR-0011,
/// via `reason::adjudicate::guards`) and the two sanctioned egress paths — the breach
/// notifier (ADR-0018) and the read-only MCP server — all neutralize untrusted text
/// through this exact function, so they cannot drift in what they consider structure-safe.
///
/// It strips STRUCTURE, not SEMANTICS: a name or CVE id a model echoes into prose is
/// still present after `sanitize` — compose with [`super::scrub_decision_names`] /
/// [`super::scrub_cve_tokens`] to strip those.
pub(crate) fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if "<>{}`\n\r".contains(c) { ' ' } else { c })
        .collect()
}
