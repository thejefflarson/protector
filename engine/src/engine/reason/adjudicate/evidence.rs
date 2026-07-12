//! Evidence assembly for the adjudication prompt and the verdict cache: rendering an
//! entry's CVEs + runtime behavior into the prompt-string form, and the structured
//! enrichment-coverage ([`EntryCoverage`]) the journal records. Split out of the
//! adjudicate module root purely to keep every file under the 1,000-line cap (repo
//! CLAUDE.md). The raw evidence is read from [`SecurityGraph::entry_evidence`] (the
//! single source of truth shared with the findings snapshot), then rendered here.

use super::guards::sanitize;
use crate::engine::graph::attack::{AttackRef, Tactic};
use crate::engine::graph::{Behavior, NodeKey, ScanFinding, SecurityGraph, Vulnerability};

/// Cap untrusted free-text to keep the prompt small for the CPU-only model. Since the
/// prompt is the verdict-cache key (hashed, JEF-350), this cap must be DETERMINISTIC —
/// which it is: the same title always yields the same capped string, so the cache key is
/// stable across passes. Trivy's `title` is the only untrusted free-text that still reaches
/// the prompt (the NVD advisory feed is retired, JEF-242); this cap stays to keep it fenced.
const TITLE_CAP: usize = 120;

/// Per-entry AGGREGATE budget (chars) for ALL untrusted free-text surfaced across an
/// entry's CVE lines (JEF-106). Per-field caps bound any ONE field, but a CVE-heavy image
/// (hundreds of CVEs, each at its per-field cap) could still aggregate an unbounded prompt
/// — the security review's "TOTAL untrusted-evidence budget per entry" gap. Once the
/// running total of untrusted free-text (the trivy `title`s) crosses this budget, later
/// CVE lines drop their free prose and fall back to the STRUCTURED, low-cardinality fields
/// only (id/severity/score/reachability/fix) — the JEF-106 structural-first stance: the
/// model never loses a CVE, only its unbounded prose. Deterministic (CVEs are sorted before
/// rendering, see `build_judgment_prompt_with`), so the same evidence always renders the
/// same budgeted prompt and the verdict fingerprint stays stable across passes.
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
/// id, severity, the CVSS score when trivy reported it (JEF-242), runtime reachability,
/// fix-availability, and the short trivy title when present. NOTHING volatile (no
/// timestamps) — the whole list is fenced+sanitized by `fence_list` before it reaches the
/// model, so the title (the only untrusted free-text) is data only. JEF-106: the
/// structured fields (severity/score/fix) lead; the free-prose title is hard-capped here
/// at the prompt boundary. When `v.title` and `v.score` are both absent the rendered line
/// is BYTE-IDENTICAL to the pre-advisory baseline (the NVD advisory feed is retired,
/// JEF-242 — confirmed: with no advisory the line shape is unchanged from before it
/// existed, and that is now the baseline).
///
/// Each line is rendered through [`cve_evidence_budgeted`] with a fresh, generous budget
/// so a single CVE keeps its full free prose; the per-entry aggregate budget is applied
/// by [`entry_evidence`] across the whole list. Kept as a thin wrapper so the unit tests
/// can render exactly one CVE the same way the prompt does (the production path always
/// goes through `entry_evidence`, which threads the shared budget).
#[cfg(test)]
pub(crate) fn cve_evidence(v: &Vulnerability) -> String {
    // A single CVE's free-text (the title, per-field capped) is well under the per-entry
    // budget, so render it with the full budget — byte-identical (after the per-field
    // cap+sanitize) to the pre-budget single-line shape the tests pin.
    let mut budget = ENTRY_FREETEXT_BUDGET;
    cve_evidence_budgeted(v, &mut budget)
}

/// As [`cve_evidence`], but draws the untrusted free-text title from a shared per-entry
/// `budget` (JEF-106). The STRUCTURED, low-cardinality fields — id, severity, CVSS score,
/// EPSS probability, reachability, and fix-availability — are ALWAYS rendered (they are bounded by
/// construction and are the signal the model should weigh first). The free prose (title)
/// is rendered ONLY while `budget` remains, decrementing it by what it contributes; once
/// it is exhausted, later CVE lines surface structure only. The title is capped THEN
/// sanitized (`cap_untrusted`) before it reaches the line, so a capped value can never
/// reconstruct the fence.
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
    // CVSS score (JEF-242): a STRUCTURED numeric severity signal from trivy — never
    // untrusted free-text, so it is rendered deterministically and charged to NO budget.
    // Formatted to one decimal (`9.8`) so the same score always renders the same token and
    // the verdict fingerprint stays stable across passes. Absent ⇒ omitted entirely, so a
    // scoreless CVE's line stays byte-identical to the pre-advisory baseline.
    if let Some(score) = v.score {
        line.push_str(&format!(" [cvss: {score:.1}]"));
    }
    // EPSS exploit-prediction probability (JEF-243): the PREDICTIVE exploitation axis — a
    // `[0, 1]` chance the CVE is exploited in the next 30 days, from the FIRST.org feed.
    // Like the CVSS score it is a STRUCTURED numeric (never untrusted free-text), charged
    // to NO budget, and formatted to two decimals (`0.94`) so the same probability always
    // renders the same token and the verdict fingerprint stays stable across passes. Absent
    // ⇒ omitted entirely, so an unscored CVE's line is unchanged. This is the slot the
    // prompt reserved for `epss` (JEF-66); it only renders now that the feed populates it.
    if let Some(epss) = v.epss {
        line.push_str(&format!(" [epss: {epss:.2}]"));
    }
    // Untrusted free prose (trivy's title) — the ONLY untrusted free-text that still
    // reaches the prompt (the NVD advisory feed is retired, JEF-242). Charged to the
    // per-entry budget and capped+sanitized so it stays fenced data, never instructions.
    if let Some(title) = v.title.as_deref() {
        let title = cap_untrusted(title, TITLE_CAP);
        if let Some(title) = take_from_budget(title, budget) {
            line.push_str(" — ");
            line.push_str(&title);
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

/// Is vulnerability `a` the WORSE instance of a shared CVE id, the one to keep when
/// trivy reported the same CVE against several affected packages (JEF-133 dedup)?
/// Worst = highest severity, tie-broken by highest CVSS score; if those are equal,
/// prefer the instance that carries the most exploitability signal — a fix-availability
/// indication (the workload is on a vulnerable version a fix exists for) and/or an EPSS
/// probability — so deduping never drops a fix range or EPSS the other instance had.
/// Total + deterministic on equal-id instances (the only thing it is asked to compare):
/// equal severity, CVSS, and signal-count means neither is "worse" and the first
/// encountered (id order) wins.
fn worse_vuln(a: &Vulnerability, b: &Vulnerability) -> bool {
    use std::cmp::Ordering;
    // `score` is `Option<f64>`; an absent score sorts below any present one. NaN should
    // never reach here (trivy emits finite CVSS), but treat it as the smallest so the
    // comparison stays total rather than panicking.
    let score = |v: &Vulnerability| v.score.unwrap_or(f64::NEG_INFINITY);
    // Count the exploitability signals an instance carries, used only to break a
    // severity+CVSS tie so the survivor keeps the richer fix/EPSS metadata.
    let signal =
        |v: &Vulnerability| usize::from(v.fixed_version.is_some()) + usize::from(v.epss.is_some());
    // Highest severity, then highest CVSS, then most exploitability signal. `total_cmp`
    // keeps the CVSS comparison total even for the NEG_INFINITY sentinel.
    a.severity
        .cmp(&b.severity)
        .then_with(|| score(a).total_cmp(&score(b)))
        .then_with(|| signal(a).cmp(&signal(b)))
        == Ordering::Greater
}

/// The evidence behind an entry: the CVEs its image carries and the runtime signals
/// observed on it — what the model needs to judge contextual realness. The raw evidence
/// (structured `Vulnerability` + `Behavior`) comes from [`SecurityGraph::entry_evidence`],
/// the single source of truth shared with the findings snapshot's per-finding evidence blocks
/// (JEF-133), so the model and the operator can never see a different set of facts. Here
/// the CVEs are rendered into the prompt-string form:
///
/// each line widens the CVE's evidence (JEF-51 + JEF-66 + JEF-242 + JEF-243): id, severity, the CVSS
/// score (when trivy reported it), the EPSS exploit-prediction probability (when the FIRST.org
/// feed scored it), reachability, and a fix-availability indication so the
/// model can reason about exploitability — "a fix exists but the workload is still on the
/// vulnerable version" vs "no fix available". The short trivy title (untrusted free-text)
/// is appended when present; the WHOLE string is fenced+sanitized by `fence_list` at
/// prompt-build time, so the title can't inject prompt structure. The string flows verbatim
/// into both the prompt and the verdict fingerprint, so any of these fields changing busts
/// the cache and re-judges that entry.
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
    // Collapse duplicate CVE ids to one representative BEFORE rendering (JEF-133 source of
    // truth, so both the prompt and the dashboard's per-finding evidence agree). Trivy
    // reports the same CVE once PER affected package, so the same id can arrive several
    // times with different CVSS / fix ranges; the prior string-level `cves.dedup()` in
    // `build_judgment_prompt_with` can't collapse them (the trailing metadata differs), so
    // the judge saw a noisy triplicate list. Keep the WORST instance per id so no signal is
    // lost — see `worse_vuln`. `vulns` is already sorted by id, so equal ids are adjacent;
    // deduping keeps id order and is therefore deterministic (the prompt re-sorts the
    // rendered lines anyway, but the budget below must spend in a stable order).
    vulns.dedup_by(|a, b| {
        if a.id != b.id {
            return false;
        }
        // `dedup_by` keeps the FIRST of each adjacent equal run (`b`) and drops `a`; fold
        // `a`'s superiority into `b` so the survivor is the worst instance, not just the
        // first-encountered one.
        if worse_vuln(a, b) {
            *b = a.clone();
        }
        true
    });
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

/// Render one non-CVE scanner finding (JEF-244 — exposed secret / misconfig / RBAC) into a
/// prompt line: the structured, low-cardinality fields lead (id + severity), then the short
/// untrusted title, capped+sanitized exactly as a CVE title is. Charged to the same shared
/// per-entry free-text budget so a finding-heavy entry can't bloat the prompt. The whole list
/// is fenced by `fence_list` at prompt-build time, so the title is data, never instructions.
fn finding_evidence_budgeted(f: &ScanFinding, budget: &mut usize) -> String {
    let mut line = format!("{} [severity: {}]", sanitize(&f.id), f.severity.label());
    if let Some(title) = f.title.as_deref() {
        let title = cap_untrusted(title, TITLE_CAP);
        if let Some(title) = take_from_budget(title, budget) {
            line.push_str(" — ");
            line.push_str(&title);
        }
    }
    line
}

/// The non-CVE scanner findings behind an entry (JEF-244), rendered into prompt lines and
/// drawn from the SAME [`SecurityGraph::entry_findings`] the findings snapshot reads. Returns
/// `(exposed_secrets, static_posture)`: exposed secrets are kept separate because they ARE
/// exploitation evidence (a usable credential baked into the image), while the config-audit
/// and RBAC-assessment findings are folded together as STATIC POSTURE / severity context — on
/// the same calibrated footing the prompt gives reachability breadth, never a breach driver on
/// their own. Each list is sorted (stable prompt + fingerprint) and shares the per-entry
/// free-text budget with the CVE lines.
pub(crate) fn entry_findings(
    graph: &SecurityGraph,
    entry_key: &NodeKey,
) -> (Vec<String>, Vec<String>) {
    let (mut secrets, mut misconfigs, mut rbac) = graph.entry_findings(entry_key);
    secrets.sort_by(|a, b| a.id.cmp(&b.id));
    misconfigs.sort_by(|a, b| a.id.cmp(&b.id));
    rbac.sort_by(|a, b| a.id.cmp(&b.id));
    let mut budget = ENTRY_FREETEXT_BUDGET;
    let secret_lines = secrets
        .iter()
        .map(|f| finding_evidence_budgeted(f, &mut budget))
        .collect();
    // Misconfig + RBAC share one "static posture" list: same role in the prompt (severity
    // context), so the model sees one fenced block rather than two it might over-weight.
    let posture_lines = misconfigs
        .iter()
        .chain(rbac.iter())
        .map(|f| finding_evidence_budgeted(f, &mut budget))
        .collect();
    (secret_lines, posture_lines)
}

/// Render one reachable objective's ATT&CK OUTCOME suffix — what an attacker would OBTAIN
/// *if this workload were exploited*, NOT a property asserting the target is already
/// compromised (JEF-402). `reach` is the JEF-79 authorization tag (`MOUNTED`, `RBAC-GRANTED`,
/// combinations, or `NETWORK`); it decides only the CredentialAccess wording below.
///
/// The false-breach this fixes: a reachable secret objective used to render as
/// `(Credential Access: Unsecured Credentials)` (T1552's ATT&CK name). "Unsecured
/// Credentials" reads as "an exposed/unprotected credential" — the SAME category as the
/// "Exposed secrets baked into this image" exploitation-evidence field — and on an
/// `[RBAC-GRANTED]`/`[MOUNTED]` (authorized-by-design) objective it is self-contradictory
/// ("unsecured" vs "granted"). A small judge resolved the contradiction toward the scarier
/// reading and HALLUCINATED an exposed baked-in secret from a merely-reachable one
/// (argocd-server, v0.3.100). So for an AUTHORIZED Credential-Access objective we render the
/// OUTCOME — "could read a credential store (Credential Access)" — never the bare "Unsecured
/// Credentials" phrase. The technique id is still carried so nothing downstream loses the
/// ATT&CK anchor. Every other tactic keeps its `(tactic: technique)` rendering unchanged.
pub(crate) fn objective_outcome(reach: &str, attack: &AttackRef) -> String {
    // An authorized (mounted or RBAC-granted) reach into a credential store is the trap: the
    // ATT&CK technique name ("Unsecured Credentials") contradicts the authorization tag and
    // reads as exposed-secret evidence. Render the attacker OUTCOME instead — a target reached,
    // not a credential already exposed — and keep the technique id as the ATT&CK anchor.
    let authorized = reach.contains("MOUNTED") || reach.contains("RBAC-GRANTED");
    if attack.tactic == Tactic::CredentialAccess && authorized {
        return format!(
            "could read a credential store if exploited (Credential Access, {})",
            attack.technique_id
        );
    }
    format!("{}: {}", attack.tactic.name(), attack.technique)
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
/// site records this so the would-have-acted report aggregation classifies a coverage gap from
/// fact, not by grepping the verdict prose for a `CVE-` token.
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
