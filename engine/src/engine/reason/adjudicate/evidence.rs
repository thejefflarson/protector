//! Evidence assembly for the adjudication prompt and the verdict cache: rendering an
//! entry's CVEs + runtime behavior into the prompt-string form, and the structured
//! enrichment-coverage ([`EntryCoverage`]) the journal records. Split out of the
//! adjudicate module root purely to keep every file under the 1,000-line cap (repo
//! CLAUDE.md). The raw evidence is read from [`SecurityGraph::entry_evidence`] (the
//! single source of truth shared with the dashboard), then rendered here.

use super::guards::sanitize;
use crate::engine::graph::{Behavior, NodeKey, SecurityGraph, Vulnerability};

/// Cap untrusted free-text to keep the prompt small for the CPU-only model. The
/// `entry_fingerprint` discipline means the (capped) string is what the cache keys
/// on — fine, since the cap is deterministic, so the same advisory always yields the
/// same string.
const TITLE_CAP: usize = 120;

/// Hard cap on the advisory summary surfaced in the prompt (JEF-103/JEF-106). The store
/// already caps at parse time; this is a second, independent cap at the prompt boundary
/// so the untrusted free-text can never bloat the prompt or the verdict fingerprint
/// regardless of how the advisory arrived. Deterministic, so the same advisory always
/// renders the same line.
pub(crate) const ADVISORY_SUMMARY_CAP: usize = 200;

/// Hard cap on how many CWE ids are surfaced per CVE — the structured, injection-safe
/// signal JEF-106 PREFERS over free prose. Bounds the prompt/fingerprint cardinality.
const ADVISORY_CWE_CAP: usize = 4;

/// Hard cap on the `fix_ref` surfaced in the prompt (JEF-106). The advisory store already
/// caps `fix_ref` at parse time; this is the SECOND, independent cap at the prompt
/// boundary — the defense-in-depth `title`/`summary` already get — so the field is bounded
/// regardless of how the advisory reached the graph (a future live-OSV path, JEF-110,
/// would bypass the parse-time cap). A fix reference is a version or a short URL, so this
/// cap is generous for legitimate values.
pub(crate) const ADVISORY_FIX_REF_CAP: usize = 64;

/// Per-entry AGGREGATE budget (chars) for ALL untrusted free-text surfaced across an
/// entry's CVE lines (JEF-106). Per-field caps bound any ONE field, but a CVE-heavy image
/// (hundreds of CVEs, each at its per-field cap) could still aggregate an unbounded prompt
/// — the security review's "TOTAL untrusted-evidence budget per entry" gap. Once the
/// running total of untrusted free-text (titles + advisory summaries) crosses this budget,
/// later CVE lines drop their free prose and fall back to the STRUCTURED, low-cardinality
/// fields only (id/severity/reachability/fix + CWE + fix-ref) — the JEF-106 structural-first
/// stance: the model never loses a CVE, only its unbounded prose. Deterministic (CVEs are
/// sorted before rendering, see `build_judgment_prompt_with`), so the same evidence always
/// renders the same budgeted prompt and the verdict fingerprint stays stable across passes.
pub(crate) const ENTRY_FREETEXT_BUDGET: usize = 1200;

/// Char-safe truncate-then-sanitize for one untrusted free-text field (JEF-106). The
/// ORDER is load-bearing: cap FIRST (bound the length), then [`sanitize`] (strip the
/// fence-closing / prompt-structure chars). Doing it in this order means a capped value
/// can never reconstruct a `<<<`/`>>>` fence delimiter or smuggle structure — `sanitize`
/// is the LAST thing applied to the field, so whatever survives the cap is still
/// neutralized. (`fence`/`fence_list` sanitize the joined list again at prompt-build, but
/// per-field sanitizing here makes the guarantee hold field-by-field, not just in
/// aggregate.) Char-based truncation keeps multi-byte text valid.
fn cap_untrusted(value: &str, cap: usize) -> String {
    sanitize(&value.chars().take(cap).collect::<String>())
}

/// Build one CVE's evidence line for the prompt and the verdict fingerprint (JEF-66):
/// id, severity, runtime reachability, fix-availability, the short advisory title when
/// present, and — when a mounted advisory snapshot enriched this CVE (JEF-103) — its
/// structured CWE id(s), fix reference, and a hard length-capped summary. NOTHING
/// volatile (no timestamps) — the whole list is fenced+sanitized by `fence_list` before
/// it reaches the model, so the free-text fields are data only. JEF-106: structured
/// fields (CWE/fix) lead; the free-prose summary is hard-capped here at the prompt
/// boundary as the second layer. When `v.advisory` is `None` the rendered line is
/// BYTE-IDENTICAL to before advisory enrichment existed.
///
/// Each line is rendered through [`cve_evidence_budgeted`] with a fresh, generous budget
/// so a single CVE keeps its full free prose; the per-entry aggregate budget is applied
/// by [`entry_evidence`] across the whole list. Kept as a thin wrapper so the unit tests
/// can render exactly one CVE the same way the prompt does (the production path always
/// goes through `entry_evidence`, which threads the shared budget).
#[cfg(test)]
pub(crate) fn cve_evidence(v: &Vulnerability) -> String {
    // A single CVE's free-text (title + summary, each per-field capped) is well under the
    // per-entry budget, so render it with the full budget — byte-identical (after the
    // per-field cap+sanitize) to the pre-budget single-line shape the tests pin.
    let mut budget = ENTRY_FREETEXT_BUDGET;
    cve_evidence_budgeted(v, &mut budget)
}

/// As [`cve_evidence`], but draws each untrusted free-text field (title, advisory summary)
/// from a shared per-entry `budget` (JEF-106). The STRUCTURED, low-cardinality fields —
/// id, severity, reachability, fix-availability, CWE id(s), and the capped fix-ref — are
/// ALWAYS rendered (they are bounded by construction and are the signal the model should
/// weigh first). The free prose (title, summary) is rendered ONLY while `budget` remains,
/// decrementing it by what each field contributes; once it is exhausted, later CVE lines
/// surface structure only. Every free-text field is capped THEN sanitized (`cap_untrusted`)
/// before it reaches the line, so a capped value can never reconstruct the fence.
fn cve_evidence_budgeted(v: &Vulnerability, budget: &mut usize) -> String {
    // Fix availability is the exploitability signal JEF-66 is after: a fix existing
    // while the workload is still on the vulnerable version is a different posture from
    // "no fix exists at all". `installed_version`/`fixed_version` are scanner-reported
    // (untrusted) version strings, so cap+sanitize them too — they are bounded structural
    // fields, charged to no budget, but still must not carry fence/structure chars.
    // Use "to" rather than an arrow: the prompt fences this text and `sanitize` strips
    // `>` (a fence-closing char), which would mangle "->" into "-".
    let fixed = v
        .fixed_version
        .as_deref()
        .map(|s| cap_untrusted(s, TITLE_CAP));
    let installed = v
        .installed_version
        .as_deref()
        .map(|s| cap_untrusted(s, TITLE_CAP));
    let fix = match (fixed.as_deref(), installed.as_deref()) {
        (Some(fixed), Some(installed)) => format!("fix available: {installed} to {fixed}"),
        (Some(fixed), None) => format!("fix available: {fixed}"),
        (None, _) => "no fix available".to_string(),
    };
    let mut line = format!(
        "{} [severity: {}] [reachability: {}] [{}]",
        sanitize(&v.id),
        v.severity.label(),
        v.reachability.label(),
        fix,
    );
    // Untrusted free prose (the advisory/scanner title) — charged to the per-entry budget.
    if let Some(title) = v.title.as_deref() {
        let title = cap_untrusted(title, TITLE_CAP);
        if let Some(title) = take_from_budget(title, budget) {
            line.push_str(" — ");
            line.push_str(&title);
        }
    }
    // Advisory enrichment (JEF-103), only when the mounted snapshot matched this CVE.
    // Absent ⇒ the line above is byte-identical to today. Structured fields (CWE, fix)
    // lead per JEF-106 and are ALWAYS shown (bounded, structural); the free-prose summary
    // trails, is hard-capped, and is the only advisory field charged to the budget.
    if let Some(advisory) = v.advisory.as_ref() {
        if !advisory.cwe.is_empty() {
            let cwe = advisory
                .cwe
                .iter()
                .take(ADVISORY_CWE_CAP)
                .map(|c| cap_untrusted(c, TITLE_CAP))
                .collect::<Vec<_>>()
                .join(", ");
            line.push_str(&format!(" [cwe: {cwe}]"));
        }
        if let Some(fix_ref) = advisory.fix_ref.as_deref() {
            // Second, independent cap at the prompt boundary (the parse-time cap is the
            // first); cap THEN sanitize so it can't reconstruct the fence.
            let fix_ref = cap_untrusted(fix_ref, ADVISORY_FIX_REF_CAP);
            line.push_str(&format!(" [fix: {fix_ref}]"));
        }
        if !advisory.summary.is_empty() {
            let summary = cap_untrusted(&advisory.summary, ADVISORY_SUMMARY_CAP);
            if let Some(summary) = take_from_budget(summary, budget) {
                line.push_str(" — advisory: ");
                line.push_str(&summary);
            }
        }
    }
    line
}

/// Charge a free-text field against the shared per-entry budget (JEF-106): if the whole
/// field fits, decrement the budget and return it; otherwise spend what remains and return
/// `None` so the caller omits the field rather than splicing in a half-string. Returning
/// all-or-nothing keeps every rendered field a complete, sensible value (a truncated
/// sentence is no more useful to the model than its absence) and is deterministic.
fn take_from_budget(field: String, budget: &mut usize) -> Option<String> {
    let cost = field.chars().count();
    if cost <= *budget {
        *budget -= cost;
        Some(field)
    } else {
        *budget = 0;
        None
    }
}

/// The evidence behind an entry: the CVEs its image carries and the runtime signals
/// observed on it — what the model needs to judge contextual realness. The raw evidence
/// (structured `Vulnerability` + `Behavior`) comes from [`SecurityGraph::entry_evidence`],
/// the single source of truth shared with the dashboard's per-finding evidence blocks
/// (JEF-133), so the model and the operator can never see a different set of facts. Here
/// the CVEs are rendered into the prompt-string form:
///
/// each line widens the CVE's evidence (JEF-51 + JEF-66): id, severity, reachability, and
/// a fix-availability indication so the model can reason about exploitability — "a fix
/// exists but the workload is still on the vulnerable version" vs "no fix available". The
/// short advisory title (untrusted free-text) is appended when present; the WHOLE string
/// is fenced+sanitized by `fence_list` at prompt-build time, so the title can't inject
/// prompt structure. The string flows verbatim into both the prompt and the verdict
/// fingerprint, so any of these fields changing busts the cache and re-judges that entry.
pub(crate) fn entry_evidence(
    graph: &SecurityGraph,
    entry_key: &NodeKey,
) -> (Vec<String>, Vec<Behavior>) {
    let (mut vulns, behaviors) = graph.entry_evidence(entry_key);
    // Render in a STABLE order so the per-entry free-text budget (below) is deterministic:
    // the same evidence must always produce the same budgeted lines, both for the prompt
    // and for the verdict fingerprint that keys on them. Sort by CVE id (the budget only
    // affects WHICH lines keep their free prose once it is exhausted, so the order it spends
    // in must not depend on graph-traversal order). The prompt re-sorts the rendered lines
    // anyway; sorting here just fixes the order the budget is consumed in.
    vulns.sort_by(|a, b| a.id.cmp(&b.id));
    // Apply the per-entry AGGREGATE untrusted-free-text budget (JEF-106): a shared budget
    // is threaded across the lines so a CVE-heavy image can't aggregate an unbounded prompt
    // even when every per-field cap holds. Early CVE lines keep their prose; once the budget
    // is spent, later lines fall back to the structured fields only.
    let mut budget = ENTRY_FREETEXT_BUDGET;
    let cves = vulns
        .iter()
        .map(|v| cve_evidence_budgeted(v, &mut budget))
        .collect();
    (cves, behaviors)
}

/// The set of CVE ids in an entry's actual evidence — the ground truth the model's
/// citations are checked against by [`guard_fabricated_cve`]. The first token of each
/// `cve_evidence` line is the id (e.g. `CVE-2021-44228 [severity: ...]`). Takes the
/// already-fetched evidence lines (from a single `entry_evidence` call in `judge`)
/// rather than re-fetching them.
pub(crate) fn cve_ids_of(cves: &[String]) -> std::collections::HashSet<String> {
    cves.iter()
        .filter_map(|line| line.split_whitespace().next().map(str::to_string))
        .collect()
}

/// The structured enrichment-coverage behind an entry's breach decision (JEF-145): the
/// CVE ids and the behavioral-signal presence that went into the model's prompt, read
/// from the SAME evidence (`entry_evidence`) the model was handed. The journal-append
/// site records this so `/report` classifies a coverage gap from fact, not by grepping
/// the verdict prose for a `CVE-` token.
///
/// Pure and deterministic: a no-op-cheap re-derivation of the prompt evidence for an
/// entry. The CVE id set is sorted+deduped for a stable journal line.
pub fn entry_coverage(graph: &SecurityGraph, entry_key: &NodeKey) -> EntryCoverage {
    let (cves, behaviors) = entry_evidence(graph, entry_key);
    let mut ids: Vec<String> = cve_ids_of(&cves).into_iter().collect();
    ids.sort();
    EntryCoverage {
        cves: ids,
        behavioral: !behaviors.is_empty(),
    }
}

/// The enrichment a breach decision was made over (JEF-145): the matched CVE ids and
/// whether any behavioral signal was present. Mirrors the journal's `EnrichmentCoverage`
/// without coupling this module to the journal type — the engine maps one to the other
/// at the journal-append site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryCoverage {
    /// The CVE ids in the entry's actual evidence that reached the model (sorted, deduped).
    pub cves: Vec<String>,
    /// Whether any behavioral signal was present on the entry when it was judged.
    pub behavioral: bool,
}
