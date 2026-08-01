//! Evidence assembly for the adjudication prompt and the verdict cache: rendering an
//! entry's CVEs + runtime behavior into the prompt-string form, and the structured
//! enrichment-coverage ([`EntryCoverage`]) the journal records. Split out of the
//! adjudicate module root purely to keep every file under the 1,000-line cap (repo
//! CLAUDE.md). The raw evidence is read from [`SecurityGraph::entry_evidence`] (the
//! single source of truth shared with the findings snapshot), then rendered here.

use super::guards::sanitize;
use crate::engine::graph::attack::{AttackRef, Tactic};
use crate::engine::graph::{Behavior, NodeKey, ScanFinding, SecurityGraph, Vulnerability};
use crate::engine::observe::asn::AsnDb;
// The engine's single "alarming-now" definition (an alert, a notable shell/package-manager
// exec, or an alarming sensitive-path write) — see the tag below.
use crate::engine::observe::alarm_class::is_alarming_now;
// JEF-113: exec *classification* (shell / package-manager in container) moved out of the
// shared `Behavior` wire type into engine policy; annotate here so the model still sees
// "executed /bin/bash (interactive shell in container)" rather than the bare path
// `Behavior::summary` now returns.
use crate::engine::observe::exec_class::annotated_summary;
// JEF-380: for INTERNET egress render the deduped, sorted PROVIDER set via the offline ASN
// dataset — cluster peers are untouched.
use crate::engine::observe::peer_class::internet_egress_line;

/// The fixed, non-untrusted tag appended to a behavior line the deterministic layer has
/// already classified as ordinary telemetry, never a live signal — see
/// [`render_behavior_lines_budgeted`]'s doc for why this is done at the SOURCE rather than
/// left for the judge to sort out from prose. A fixed internal string (never untrusted
/// input), safe to embed in the prompt/output.
///
/// `[square]`-bracketed, matching this codebase's other structured tags (`[MOUNTED]`,
/// `[severity: ...]`) — NOT `{curly}`/`<angle>`-bracketed: [`fence_list`](super::guards::fence_list)
/// re-applies [`sanitize`] to the WHOLE joined behavior-line string at prompt-assembly time,
/// and `sanitize` strips `<>{}` + backtick (never `[]`, which is why every existing bracketed
/// tag in this prompt uses square brackets) — a `{`/`<`-delimited tag would be stripped right
/// back out at that second pass. Because a bracket delimiter therefore can NOT be made
/// unforgeable by character-class stripping, [`render_behavior_lines_budgeted`] additionally
/// defangs any attacker-supplied lookalike of this EXACT tag text before conditionally
/// appending the real one — see [`defang_tag_lookalike`].
pub(crate) const BENIGN_OWN_ACTIVITY_TAG: &str = "[benign observed — not a signal]";

/// Defang an exact, attacker-supplied lookalike of [`BENIGN_OWN_ACTIVITY_TAG`] found in a
/// behavior line's own free text (a chosen file path, peer string, or secret name), so the tag
/// text can appear in a rendered line ONLY when [`render_behavior_lines_budgeted`] itself
/// appended it. The tag DECREASES suspicion — unlike the existing notable-exec annotation,
/// which only ever makes an attacker's OWN activity look MORE alarming — so a forged copy on a
/// genuinely alarming write (e.g. a drop into `/etc/cron.d/` whose path is crafted to contain
/// this tag's text) would suppress real evidence from the judge; that is the one direction
/// worth defending.
///
/// MUST run on the FINAL rendered text — after [`cap_untrusted`] (cap THEN [`sanitize`]) and
/// the free-text-budget fallback, immediately before the caller decides whether to append the
/// real tag. Order is load-bearing: `sanitize` REPLACES `<>{}` and the backtick with a SPACE
/// rather than deleting them, so an attacker who spells the tag's spaces as one of those chars
/// (e.g. a path containing `benign<observed<—<not<a<signal`) produces no literal-space match if
/// defanged on the RAW, pre-sanitize text — sanitize reconstructs the exact tag right
/// afterward. Defanging AFTER `cap_untrusted` closes that: nothing transforms the text again
/// past this point, so whatever survives here is exactly what the judge sees.
///
/// Also collapses runs of whitespace before matching (defense-in-depth): an attacker could
/// otherwise widen the gaps between the tag's words to dodge the exact match while still
/// reading, to a small model, as the same tag. A behavior line's free text has no legitimate
/// reason to carry a run of internal whitespace, so collapsing is harmless to any real path/
/// peer/secret name.
fn defang_tag_lookalike(text: &str) -> String {
    collapse_whitespace_runs(text)
        .replace(BENIGN_OWN_ACTIVITY_TAG, "[attempted tag forgery, ignored]")
}

/// Collapse any run of whitespace in `text` to a single ASCII space — see
/// [`defang_tag_lookalike`]'s doc for why.
fn collapse_whitespace_runs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev_was_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !prev_was_space {
                out.push(' ');
            }
            prev_was_space = true;
        } else {
            out.push(ch);
            prev_was_space = false;
        }
    }
    out
}

/// Cap untrusted free-text to keep the prompt small for the CPU-only model. Since the
/// prompt is the verdict-cache key (hashed, JEF-350), this cap must be DETERMINISTIC —
/// which it is: the same title always yields the same capped string, so the cache key is
/// stable across passes. Trivy's `title` is the only untrusted free-text that still reaches
/// the prompt (the NVD advisory feed is retired, JEF-242); this cap stays to keep it fenced.
const TITLE_CAP: usize = 120;

/// Per-entry AGGREGATE budget (chars) for ALL untrusted free-text surfaced across ONE
/// category of an entry's evidence lines (JEF-106) — CVEs, findings (secrets+posture), and
/// observed behavior each thread their OWN fresh instance of this budget (see
/// [`entry_evidence_budgeted`], [`entry_findings_budgeted`], [`render_behavior_lines`]). Per-field
/// caps bound any ONE field, but a CVE-heavy image (hundreds of CVEs, each at its per-field cap)
/// — or, per the same reasoning, a workload with many observed behaviors — could still aggregate
/// an unbounded prompt — the security review's "TOTAL untrusted-evidence budget per entry" gap.
/// Once the running total of untrusted free-text in a category crosses this budget, later lines
/// in that category drop their free prose and fall back to the STRUCTURED, low-cardinality
/// fields only (id/severity/score/reachability/fix for a CVE; the behavior KIND alone for a
/// behavior line) — the JEF-106 structural-first stance: the model never loses a CVE or a
/// behavior, only its unbounded prose. Deterministic (each category is sorted before rendering),
/// so the same evidence always renders the same budgeted prompt and the verdict fingerprint
/// stays stable across passes.
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
    let mut budget = ENTRY_FREETEXT_BUDGET;
    entry_evidence_budgeted(graph, entry_key, &mut budget)
}

/// As [`entry_evidence`], but draws the CVE free-text budget from a shared external `budget`
/// rather than a fresh [`ENTRY_FREETEXT_BUDGET`] (JEF-565): the entry's own call still passes a
/// fresh budget (unchanged behavior), while each downstream workload on the entry's proven
/// paths (`downstream::render_downstream`) threads ONE shared incident-wide budget across every
/// node, so a wide entry (argo, ~110 objectives) cannot multiply the per-node budget into an
/// unbounded prompt. Structural fields are never dropped — only prose beyond the budget.
pub(crate) fn entry_evidence_budgeted(
    graph: &SecurityGraph,
    entry_key: &NodeKey,
    budget: &mut usize,
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
    // Apply the AGGREGATE untrusted-free-text budget (JEF-106): a shared budget is threaded
    // across the lines so a CVE-heavy image can't aggregate an unbounded prompt even when
    // every per-field cap holds. Early CVE lines keep their prose; once the budget is spent,
    // later lines fall back to the structured fields only.
    let cves = vulns
        .iter()
        .map(|v| cve_evidence_budgeted(v, budget))
        .collect();
    (cves, behaviors)
}

/// JEF-453 (skip non-reachable CVEs): the judge decides breach from EXPLOITATION EVIDENCE, and
/// the ONLY CVE category that is exploitation evidence is `[reachability: loaded-at-runtime]`
/// (vulnerable code observed running on the reachable path). CVEs that are present-but-not-running
/// (`not-observed`), static-binary-unknowable, or unknown-reachability are CONTEXT — "how bad IF
/// exploited" — never a breach on their own, and they stay on the dashboard for operators. Sending
/// them to the JUDGE only hands a small model a non-evidence CVE to fabricate a `loaded-at-runtime`
/// tag onto (JEF-451, the recurring false `exploitable`). So the judge's CVE field carries only the
/// reachable (running) CVEs; `(none)` otherwise. This is enrichment/filtering of NON-evidence, not
/// the objective-breadth capping ADR-0029 forbids (a not-observed CVE can never change a correct
/// verdict). Measured on the deployed qwen3:1.7b: it collapses the temp-0.8 flip mass 15%→0% with
/// no false negatives. The anti-fabrication guards read the FULL list separately (`model_call`), so
/// their behaviour is unchanged. NOTE: `objective_reach` is not this — this is the CVE image-reach.
///
/// Shared by the entry's own CVE field (`prompt::render_evidence`) and each downstream node's
/// block (JEF-565, `downstream::render_downstream`) so both filter with the EXACT same rule —
/// one source of truth for what counts as CVE exploitation evidence in the judge prompt.
const LOADED_AT_RUNTIME: &str = "[reachability: loaded-at-runtime]";

/// Retain only the CVE lines that are exploitation evidence (see [`LOADED_AT_RUNTIME`]).
pub(crate) fn retain_reachable_cves(cves: &mut Vec<String>) {
    cves.retain(|line| line.contains(LOADED_AT_RUNTIME));
}

/// Render the observed behaviors into the sorted, deduped lines the prompt's "Observed
/// runtime behavior" field carries. Shared by the entry's own field and each downstream
/// node's block (JEF-565) so both apply the SAME two engine policies:
///
/// - When the ASN dataset is EMPTY (no feed wired / unreadable file), every behavior —
///   including each internet connection — renders one line via [`annotated_summary`], exactly
///   as it did before the feed existed (the graceful-degrade contract).
/// - When the dataset is present, INTERNET egress connections are pulled out and collapsed
///   into ONE deduped, sorted provider line ([`internet_egress_line`]); every other behavior
///   (including CLUSTER connections, whose JEF-131/375 resolution is untouched) renders via
///   `annotated_summary` as before.
///
/// A THIRD policy, applied to every line either way: a behavior the deterministic layer does
/// NOT classify as [`is_alarming_now`] (own connections, own reads/writes/loads — the
/// workload's ordinary telemetry) is tagged with [`BENIGN_OWN_ACTIVITY_TAG`]. This is done HERE,
/// at the single source both the entry's own field and every downstream block render from — and
/// (via [`super::surface::JudgedSurface`], which projects its "behaviors" category from these
/// exact strings) the "Changes since the last decisive verdict" section too, so a benign write
/// that just became newly-observed carries the SAME tag there rather than being spotlighted as
/// a bare "newly-observed runtime behavior" the judge has to independently discount. Tagging
/// (never omitting) matches this module's existing structural-first stance: the judge never
/// loses a behavior, only gets it correctly labeled — the same discipline the free-text budget
/// applies to prose. The fixed tag string carries no untrusted content and is charged to no
/// budget, mirroring the CVSS/EPSS structured suffixes above. Only [`Behavior::Alert`], a
/// notable shell/package-manager exec, and an alarming sensitive-path write are exempt — the
/// SAME "alarming-now" boundary the corroboration/quarantine paths already key on
/// ([`crate::engine::observe::alarm_class`]), so this tag can never disagree with what actually
/// corroborates.
///
/// Either way the result is sorted + deduped so behavior order (HashMap/traversal) never
/// changes the prompt or its verdict-cache hash.
pub(crate) fn render_behavior_lines(behaviors: &[Behavior], asn: &AsnDb) -> Vec<String> {
    let mut budget = ENTRY_FREETEXT_BUDGET;
    render_behavior_lines_budgeted(behaviors, asn, &mut budget)
}

/// As [`render_behavior_lines`], but draws the free-text budget from a shared external
/// `budget` — the behavior-line counterpart of [`entry_evidence_budgeted`] (JEF-565's
/// security-review follow-up): `Behavior::summary` embeds attacker-influenced free-text (an
/// exec'd path, a file path, a raw peer string) that is fenced+sanitized but was previously
/// neither length-capped nor charged to any budget — harmless for a single entry, but this
/// ticket multiplies it across every downstream node on a proven path, exactly the "total
/// untrusted prose on a wide entry" the per-incident budget exists to bound. Each line is
/// capped to [`TITLE_CAP`] and charged to `budget`; once exhausted, later lines fall back to
/// the STRUCTURED, low-cardinality behavior KIND alone ([`Behavior::variant_label`]) — the
/// model never loses that a behavior was observed, only its free-text detail (the same
/// JEF-106 structural-first stance as a CVE/finding title). The entry's own call
/// ([`render_behavior_lines`]) threads a fresh [`ENTRY_FREETEXT_BUDGET`], unchanged from
/// before this budget existed for any evidence short of it; the downstream path
/// (`downstream::render_downstream`) threads ONE shared incident-wide pool across every node.
pub(crate) fn render_behavior_lines_budgeted(
    behaviors: &[Behavior],
    asn: &AsnDb,
    budget: &mut usize,
) -> Vec<String> {
    // Kept alongside each rendered line so a budget-exhausted line still falls back to its
    // KIND rather than being dropped outright; the grouped INTERNET-egress line has no single
    // behavior behind it, so it falls back to the generic "connection" kind. The third element
    // is whether the SOURCE behavior is benign (not `is_alarming_now`) — carried alongside the
    // line so the tag survives the budget fallback too.
    let mut lines: Vec<(String, &str, bool)> = Vec::with_capacity(behaviors.len());
    if asn.is_empty() {
        // Degrade to pre-feed behavior: one line per behavior, internet peers as raw IPs.
        lines.extend(
            behaviors
                .iter()
                .map(|b| (annotated_summary(b), b.variant_label(), !is_alarming_now(b))),
        );
    } else {
        // Collapse INTERNET egress to a provider set; everything else renders as before.
        let mut internet_peers: Vec<&str> = Vec::new();
        for behavior in behaviors {
            match behavior {
                Behavior::NetworkConnection {
                    peer,
                    internet: true,
                } => internet_peers.push(peer),
                other => lines.push((
                    annotated_summary(other),
                    other.variant_label(),
                    !is_alarming_now(other),
                )),
            }
        }
        if let Some(line) = internet_egress_line(internet_peers.iter().copied(), asn) {
            // No single `Behavior` behind the grouped provider line (it summarizes N internet
            // connections) — `"connection"` matches `Behavior::NetworkConnection`'s own
            // `variant_label()`, the kind every one of those N behaviors shares. A
            // `NetworkConnection` is never `is_alarming_now`, so this is always benign.
            lines.push((line, "connection", true));
        }
    }
    let mut out: Vec<String> = lines
        .into_iter()
        .map(|(line, kind, benign)| {
            let capped = cap_untrusted(&line, TITLE_CAP);
            let text = take_from_budget(capped, budget)
                .unwrap_or_else(|| format!("{kind} (free-text budget exhausted)"));
            // Defang AFTER cap+sanitize+budget resolve — nothing transforms `text` again past
            // this point, so a lookalike reconstructed BY `sanitize` (see the function's doc)
            // is still caught here, immediately before the real tag might be appended below.
            let text = defang_tag_lookalike(&text);
            if benign {
                format!("{text} {BENIGN_OWN_ACTIVITY_TAG}")
            } else {
                text
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
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
    let mut budget = ENTRY_FREETEXT_BUDGET;
    entry_findings_budgeted(graph, entry_key, &mut budget)
}

/// As [`entry_findings`], but draws the finding free-text budget from a shared external
/// `budget` (JEF-565) — the downstream counterpart of [`entry_evidence_budgeted`]; see its
/// doc for why (the per-incident aggregate budget across every downstream node on the entry's
/// proven paths).
pub(crate) fn entry_findings_budgeted(
    graph: &SecurityGraph,
    entry_key: &NodeKey,
    budget: &mut usize,
) -> (Vec<String>, Vec<String>) {
    let (mut secrets, mut misconfigs, mut rbac) = graph.entry_findings(entry_key);
    secrets.sort_by(|a, b| a.id.cmp(&b.id));
    misconfigs.sort_by(|a, b| a.id.cmp(&b.id));
    rbac.sort_by(|a, b| a.id.cmp(&b.id));
    let secret_lines = secrets
        .iter()
        .map(|f| finding_evidence_budgeted(f, budget))
        .collect();
    // Misconfig + RBAC share one "static posture" list: same role in the prompt (severity
    // context), so the model sees one fenced block rather than two it might over-weight.
    let posture_lines = misconfigs
        .iter()
        .chain(rbac.iter())
        .map(|f| finding_evidence_budgeted(f, budget))
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
