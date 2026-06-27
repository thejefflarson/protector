//! Evidence assembly for the adjudication prompt and the verdict cache: rendering an
//! entry's CVEs + runtime behavior into the prompt-string form, and the structured
//! enrichment-coverage ([`EntryCoverage`]) the journal records. Split out of the
//! adjudicate module root purely to keep every file under the 1,000-line cap (repo
//! CLAUDE.md). The raw evidence is read from [`SecurityGraph::entry_evidence`] (the
//! single source of truth shared with the dashboard), then rendered here.

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

/// Build one CVE's evidence line for the prompt and the verdict fingerprint (JEF-66):
/// id, severity, runtime reachability, fix-availability, the short advisory title when
/// present, and — when a mounted advisory snapshot enriched this CVE (JEF-103) — its
/// structured CWE id(s), fix reference, and a hard length-capped summary. NOTHING
/// volatile (no timestamps) — the whole list is fenced+sanitized by `fence_list` before
/// it reaches the model, so the free-text fields are data only. JEF-106: structured
/// fields (CWE/fix) lead; the free-prose summary is hard-capped here at the prompt
/// boundary as the second layer. When `v.advisory` is `None` the rendered line is
/// BYTE-IDENTICAL to before advisory enrichment existed.
pub(crate) fn cve_evidence(v: &Vulnerability) -> String {
    // Fix availability is the exploitability signal JEF-66 is after: a fix existing
    // while the workload is still on the vulnerable version is a different posture from
    // "no fix exists at all".
    // Use "to" rather than an arrow: the prompt fences this text and `sanitize` strips
    // `>` (a fence-closing char), which would mangle "->" into "-".
    let fix = match (v.fixed_version.as_deref(), v.installed_version.as_deref()) {
        (Some(fixed), Some(installed)) => format!("fix available: {installed} to {fixed}"),
        (Some(fixed), None) => format!("fix available: {fixed}"),
        (None, _) => "no fix available".to_string(),
    };
    let mut line = format!(
        "{} [severity: {}] [reachability: {}] [{}]",
        v.id,
        v.severity.label(),
        v.reachability.label(),
        fix,
    );
    if let Some(title) = v.title.as_deref() {
        let title: String = title.chars().take(TITLE_CAP).collect();
        line.push_str(" — ");
        line.push_str(&title);
    }
    // Advisory enrichment (JEF-103), only when the mounted snapshot matched this CVE.
    // Absent ⇒ the line above is byte-identical to today. Structured fields (CWE, fix)
    // lead per JEF-106; the free-prose summary trails and is hard-capped.
    if let Some(advisory) = v.advisory.as_ref() {
        if !advisory.cwe.is_empty() {
            let cwe = advisory
                .cwe
                .iter()
                .take(ADVISORY_CWE_CAP)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            line.push_str(&format!(" [cwe: {cwe}]"));
        }
        if let Some(fix_ref) = advisory.fix_ref.as_deref() {
            line.push_str(&format!(" [fix: {fix_ref}]"));
        }
        if !advisory.summary.is_empty() {
            let summary: String = advisory
                .summary
                .chars()
                .take(ADVISORY_SUMMARY_CAP)
                .collect();
            line.push_str(" — advisory: ");
            line.push_str(&summary);
        }
    }
    line
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
    let (vulns, behaviors) = graph.entry_evidence(entry_key);
    let cves = vulns.iter().map(cve_evidence).collect();
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
