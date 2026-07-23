//! The SEMANTIC scrubbers: strip the specific names and CVE tokens a model can echo into
//! free-text prose, which [`super::sanitize`] (structure only) leaves intact. Split from
//! `sanitize` so the MCP tiers (ADR-0031 §2) can relax each independently — `forensic`
//! relaxes the CVE scrubber, `raw` relaxes the name scrubber — while `redacted` runs all.

/// The placeholder substituted for any name or CVE token scrubbed from free-text prose.
pub(crate) const REDACTED: &str = "[redacted]";

/// Scrub `text` of each supplied `name`, replacing every occurrence with [`REDACTED`].
///
/// A model can echo a secret/peer name it was shown in evidence into its free-text reason;
/// [`super::sanitize`] strips structure but not that semantic, so the name would egress
/// around the ADR-0018/0031 redaction unless scrubbed here. The caller supplies the names
/// its decision was keyed on (the notifier: the entry + each objective node-key + its bare
/// last segment; the MCP server: the same, per finding) — this function knows only "replace
/// these strings," so it stays generic and shared across both egress paths.
///
/// Names are trimmed and empties dropped; then the LONGEST are replaced first, so a full
/// key (`secret/app/Secret/db-password`) is removed before its bare-name suffix
/// (`db-password`) and a substring match never leaves a fragment behind. This does NOT
/// touch CVE tokens — compose with [`scrub_cve_tokens`] (the notifier runs both).
pub(crate) fn scrub_decision_names(text: &str, names: &[&str]) -> String {
    // Trim + drop empties, then order longest-first so a full key is removed before its
    // bare-name suffix (and no shorter name leaves a longer one half-scrubbed).
    let mut ordered: Vec<String> = names
        .iter()
        .map(|n| n.trim())
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .collect();
    ordered.sort_by_key(|b| std::cmp::Reverse(b.len()));
    ordered.dedup();

    let mut out = text.to_string();
    for name in ordered {
        if out.contains(&name) {
            out = out.replace(&name, REDACTED);
        }
    }
    out
}

/// Replace every `CVE-<4-digit year>-<4+ digit sequence>` token (case-insensitive) with
/// [`REDACTED`]. A model can name a CVE it was shown in evidence; the CVE inventory is
/// crown-jewel data the zero-egress posture keeps in-cluster (ADR-0018), so it must not
/// ride out in the prose either. Independent of [`scrub_decision_names`] so the MCP
/// `forensic` tier (ADR-0031 §2) can relax CVE scrubbing without relaxing name scrubbing.
pub(crate) fn scrub_cve_tokens(text: &str) -> String {
    static CVE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = CVE.get_or_init(|| {
        regex::Regex::new(r"(?i)CVE-\d{4}-\d{4,}").expect("static CVE regex compiles")
    });
    re.replace_all(text, REDACTED).into_owned()
}
