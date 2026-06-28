//! The findings DATA layer (JEF-205, ADR-0019): pure functions that map the engine's
//! resolved [`Finding`]s + per-entry [`EntryEvidence`] into the plain `Props` the
//! `components::findings` renderers consume. No maud, no markup — just the shaping: the
//! verdict gist, the evidence-glyph derivation, the attention tier / sort key, the
//! `humanize_relation`-style edge labels, and the per-endpoint card data (rail facts,
//! evidence, graph edges, fan-out expanders, what-to-do).
//!
//! This is the only findings layer that sees an `engine::` domain type; the components it
//! feeds see only the `Props` defined here.

use crate::engine::dashboard::model::{AUTO_ELIGIBLE, CveEvidence, EntryEvidence, Finding};
use crate::engine::dashboard::recency::{Delta, RecencyInfo};
use std::collections::{BTreeMap, BTreeSet};

// The graph node-key helpers live in the presentation graph module (pure over strings);
// the data layer reuses them to shape labels without re-implementing the parsing.
use crate::engine::dashboard::components::graph::{kind, short};

/// A model verdict counts as a flag only when the model affirmed exploitability — its own
/// words begin with "exploitable" (a "not exploitable — …" verdict does not). Shared with
/// the report / attack-vector panels via the `legacy` re-export.
pub fn flagged(verdict: Option<&str>) -> bool {
    verdict.is_some_and(|v| {
        v.trim_start()
            .to_ascii_lowercase()
            .starts_with("exploitable")
    })
}

/// The three posture states a verdict can be in, for the verdict-first card and the
/// `/judgements` view (JEF-161). The breach call is the model's (ADR-0013/0016), so this
/// maps only the model's *own* affirmation to `[BREACH]` — a "not exploitable" verdict is
/// `[SAFE]`, and no verdict yet is the muted `[awaiting judgement]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// The model affirmed a real breach (its words begin with "exploitable").
    Breach,
    /// The model judged this NOT a breach (a "not exploitable — …" call).
    Safe,
    /// The model hasn't reached this entry yet (slow CPU model) — not "clear".
    Awaiting,
}

impl Posture {
    /// The posture for a verdict summary string (the model's own words), or `Awaiting` if
    /// the model hasn't judged the entry yet. Mirrors [`flagged`] for the breach test.
    pub fn of(verdict: Option<&str>) -> Self {
        match verdict {
            None => Posture::Awaiting,
            Some(v) if flagged(Some(v)) => Posture::Breach,
            Some(_) => Posture::Safe,
        }
    }

    /// The chip TEXT — meaning carried in words, never color/glyph alone (accessibility,
    /// JEF-161 AC #4). The brackets read as a posture chip in a screen reader too.
    pub fn label(self) -> &'static str {
        match self {
            Posture::Breach => "[BREACH]",
            Posture::Safe => "[SAFE]",
            Posture::Awaiting => "[awaiting judgement]",
        }
    }

    /// The CSS tone class for the chip — red breach / green-calm safe / muted awaiting.
    pub fn tone(self) -> &'static str {
        match self {
            Posture::Breach => "chip-breach",
            Posture::Safe => "chip-safe",
            Posture::Awaiting => "chip-awaiting",
        }
    }
}

/// The operator-attention TIER a finding falls in (JEF-163) — the **view** label that says
/// *why a card is where it is*, NOT a decision (ADR-0016: ordering is a view, never a gate).
/// Computed read-only from existing [`Finding`] fields at render time; it only reorders +
/// labels the already-decided cards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// The model judged this a real breach (its verdict affirms `exploitable`). Always at
    /// the top — a flagged endpoint sorts above a larger-but-unflagged one (AC #2).
    Flagged,
    /// Warrants a look but the model hasn't flagged a breach: either a coverage-gap / latent
    /// foothold carrying a cited CVE, or a runtime-corroborated chain.
    Watch,
    /// Everything else — proven-reachable but neither flagged, CVE-bearing-latent, nor
    /// runtime-corroborated. De-emphasized / collapsible in the view.
    Context,
}

impl Tier {
    /// The short label shown on the row so the operator sees its tier at a glance.
    pub fn label(self) -> &'static str {
        match self {
            Tier::Flagged => "flagged",
            Tier::Watch => "watch",
            Tier::Context => "context",
        }
    }

    /// The chip tone class (reusing the existing card chip idiom): red for flagged, amber
    /// for watch, grey for the de-emphasized context tier.
    pub fn chip_class(self) -> &'static str {
        match self {
            Tier::Flagged => "tier-flagged",
            Tier::Watch => "tier-watch",
            Tier::Context => "tier-context",
        }
    }
}

/// A human edge label for a graph relation, so an operator can tell *how* a hop works — most
/// importantly the two ways to reach a secret: a **mounted** secret it already holds
/// (`can-read`, direct, just that one secret) vs an **RBAC** grant its identity can exercise
/// against the API (`can-do/get/secrets`, often any secret in scope).
pub fn humanize_relation(rel: &str) -> String {
    if rel == "can-read" {
        return "mounts (direct read)".to_string();
    }
    if let Some(rest) = rel.strip_prefix("can-do/") {
        // can-do/get/secrets → "RBAC get secrets (API)"
        return format!("RBAC {} (API)", rest.replace('/', " "));
    }
    if let Some(via) = rel.strip_prefix("escapes-to/") {
        return format!("escapes via {via}");
    }
    if rel.starts_with("can-egress") {
        return "internet egress (exfil)".to_string();
    }
    if rel.starts_with("reaches") {
        return "network reach".to_string();
    }
    if rel == "runs-as" {
        return "runs as".to_string();
    }
    rel.to_string()
}

/// Pluralize an objective kind for an aggregate label ("47 secrets").
pub fn plural(kind: &str, n: usize) -> String {
    if n == 1 {
        return kind.to_string();
    }
    match kind {
        "capability" => "capabilities".to_string(),
        "identity" => "identities".to_string(),
        k => format!("{k}s"),
    }
}

/// Whether an entry's reach is "broad" — the threshold the wide-reach-≠-break-in treatment
/// keys on (ADR-0016, the argocd case). The long-standing `objectives >= 20` bar.
pub fn is_broad(objectives: usize) -> bool {
    objectives >= 20
}

/// How many CVEs to list inline before the rest go behind a "show all" `<details>` expander
/// (JEF-133). The top-N are shown by [`severity_rank`] so the worst surface first.
pub const CVE_INLINE_CAP: usize = 3;

/// The CSS tone class for a CVE severity label — reuses the chip idiom so critical/high read
/// as alarming and low/medium calm, WITHOUT relying on color alone (the label text carries
/// the meaning too, JEF-161 AC #4 accessibility).
pub fn severity_tone(severity: &str) -> &'static str {
    match severity {
        "critical" => "sev-critical",
        "high" => "sev-high",
        "medium" => "sev-medium",
        _ => "sev-low",
    }
}

/// A sort key putting the worst CVEs first: critical, then high, then KEV-flagged, then the
/// rest. Used for both the inline top-N and the severity summary.
pub fn severity_rank(c: &CveEvidence) -> u8 {
    match c.severity.as_str() {
        "critical" => 0,
        "high" => 1,
        _ if c.kev => 2,
        "medium" => 3,
        _ => 4,
    }
}

/// The first `CVE-NNNN-NNNN` id in a string (case-insensitive prefix), if any — the only CVE
/// signal available from existing fields (the model cites it in its verdict). Used by the
/// certainty rail and the verdict gist's CVE fallback.
pub fn cve_id(s: &str) -> Option<&str> {
    let upper = s.to_ascii_uppercase();
    let start = upper.find("CVE-")?;
    let bytes = s.as_bytes();
    let mut end = start + 4;
    while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'-') {
        end += 1;
    }
    // Trim a trailing '-' (e.g. cited at the end of a sentence "… CVE-2021-44228.").
    while end > start + 4 && bytes[end - 1] == b'-' {
        end -= 1;
    }
    (end > start + 4).then(|| &s[start..end])
}

/// The certainty-rail CVE fact, derived from the entry's real [`EntryEvidence::cves`] — a
/// SHORT counts-only summary (critical + KEV tallies), never the full list (that is the
/// evidence block's job). This is the breach-relevant subset only (KEV-or-critical), so the
/// honest-empty state says exactly that, and never claims the image is vulnerability-free.
/// Returns plain text (no markup wrapper); the component spans/escapes at render.
pub fn cve_fact(ev: &EntryEvidence) -> CveFact {
    let n = ev.cves.len();
    if n == 0 {
        return CveFact::None;
    }
    let critical = ev.cves.iter().filter(|c| c.severity == "critical").count();
    let kev = ev.cves.iter().filter(|c| c.kev).count();
    CveFact::Present { n, critical, kev }
}

/// The certainty-rail CVE fact (the data form). `None` is the honest-empty state ("no KEV or
/// critical CVE"); `Present` carries the counts the rail summarizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CveFact {
    None,
    Present {
        n: usize,
        critical: usize,
        kev: usize,
    },
}

/// The "what's proven" certainty rail (JEF-161): the deterministic facts drawn from existing
/// `Finding` fields — the proof side of the proof-vs-judgement line (ADR-0016). No model
/// call. The facts, as plain data the rail component renders:
///   1. internet-reachable (the entry is an internet-facing service).
///   2. how it reaches each objective kind — the humanized terminal relation(s).
///   3. the CVE fact, derived from the SAME [`EntryEvidence`] the evidence block reads.
pub fn rail_facts(entry: &str, fs: &[&Finding], ev: &EntryEvidence) -> RailProps {
    let mut relations: BTreeSet<String> = BTreeSet::new();
    for f in fs {
        if let Some(step) = f.path.iter().find(|s| s.to == f.objective) {
            relations.insert(humanize_relation(&step.relation));
        }
    }
    RailProps {
        entry_short: short(entry),
        relations: relations.into_iter().collect(),
        cve: cve_fact(ev),
    }
}

/// The certainty-rail data (JEF-161): the entry's short name, the humanized terminal
/// relations (deduped, stable-ordered), and the CVE fact. The `components::findings::rail`
/// renderer turns this into the `<div class="rail">` list. Plain data, no markup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RailProps {
    /// The entry's short name — the internet-reachable fact's `<code>` value.
    pub entry_short: String,
    /// The humanized terminal relations the entry reaches an objective by.
    pub relations: Vec<String>,
    /// The CVE summary fact (counts-only; the full list is the evidence block's job).
    pub cve: CveFact,
}

/// One CVE row's plain data for the evidence block (JEF-133): the id, its severity (+ tone),
/// KEV flag, reachability, fix phrasing, CWE list, and title. All free-text is rendered
/// through auto-escaping maud braces in the component (it is untrusted third-party data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveRow {
    pub id: String,
    pub severity: String,
    pub severity_tone: &'static str,
    pub kev: bool,
    pub reachability: String,
    pub fix: String,
    pub cwe: Vec<String>,
    pub title: Option<String>,
}

impl CveRow {
    fn of(c: &CveEvidence) -> Self {
        CveRow {
            id: c.id.clone(),
            severity: c.severity.clone(),
            severity_tone: severity_tone(&c.severity),
            kev: c.kev,
            reachability: c.reachability.clone(),
            fix: c.fix.clone(),
            cwe: c.cwe.clone(),
            title: c.title.clone(),
        }
    }
}

/// The CVE evidence block's plain data (JEF-133) — the SEVERITY/reachability input half of
/// ADR-0016. `None` if the entry has no KEV/critical CVE (the honest-empty state); otherwise
/// the count, the per-severity tally (worst-first), the inline top-N, and the rest behind a
/// "show all" expander.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveBlockProps {
    pub n: usize,
    /// `(label, count)` worst-first, e.g. `[("critical", 2), ("high", 1)]`.
    pub tally: Vec<(&'static str, usize)>,
    pub inline: Vec<CveRow>,
    pub rest: Vec<CveRow>,
}

/// Shape the CVE evidence block from the entry evidence (JEF-133). `None` ⇒ the honest-empty
/// "none on this service's image" state. Sorted worst-first; the inline cap is
/// [`CVE_INLINE_CAP`].
pub fn cve_block_props(ev: &EntryEvidence) -> Option<CveBlockProps> {
    if ev.cves.is_empty() {
        return None;
    }
    let mut sorted: Vec<&CveEvidence> = ev.cves.iter().collect();
    sorted.sort_by(|a, b| {
        severity_rank(a)
            .cmp(&severity_rank(b))
            .then(a.id.cmp(&b.id))
    });
    let mut by_sev: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &sorted {
        *by_sev.entry(c.severity.as_str()).or_default() += 1;
    }
    let order: [&'static str; 4] = ["critical", "high", "medium", "low"];
    let tally: Vec<(&'static str, usize)> = order
        .iter()
        .filter_map(|s| by_sev.get(*s).map(|n| (*s, *n)))
        .collect();
    let inline: Vec<CveRow> = sorted
        .iter()
        .take(CVE_INLINE_CAP)
        .map(|c| CveRow::of(c))
        .collect();
    let rest: Vec<CveRow> = sorted
        .iter()
        .skip(CVE_INLINE_CAP)
        .map(|c| CveRow::of(c))
        .collect();
    Some(CveBlockProps {
        n: sorted.len(),
        tally,
        inline,
        rest,
    })
}

/// The runtime-alert block's plain data (JEF-133) — the LIVE-corroboration half of ADR-0016.
/// `corroborating` are the Falco-style alert summaries (what flips `corroborated`);
/// `context` are the non-corroborating agent behaviors `(variant_label, summary)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBlockProps {
    pub corroborating: Vec<String>,
    pub context: Vec<(String, String)>,
}

/// Shape the runtime-alert block from the entry evidence (JEF-133). Corroborating alerts
/// first, then the agent behaviors as context.
pub fn runtime_block_props(ev: &EntryEvidence) -> RuntimeBlockProps {
    RuntimeBlockProps {
        corroborating: ev.corroborating().map(|b| b.summary()).collect(),
        context: ev
            .context_behaviors()
            .map(|b| (b.variant_label().to_string(), b.summary()))
            .collect(),
    }
}

/// The two ADR-0016 evidence blocks for a finding's entry (JEF-133): CVEs (severity input)
/// then runtime alerts (live corroboration), each with its own honest empty state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceProps {
    /// `None` ⇒ the CVE block's honest-empty state.
    pub cve: Option<CveBlockProps>,
    pub runtime: RuntimeBlockProps,
}

/// Shape both evidence blocks for an entry (JEF-133).
pub fn evidence_props(ev: &EntryEvidence) -> EvidenceProps {
    EvidenceProps {
        cve: cve_block_props(ev),
        runtime: runtime_block_props(ev),
    }
}

/// The compact evidence-glyph cell data for the dense table (JEF-202): the CVE count, the
/// KEV/critical tallies, and whether a runtime signal corroborates. The component renders
/// the badges; this layer derives the counts. `awaiting` distinguishes the honest "unjudged"
/// empty state from the "no evidence" em-dash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlyphProps {
    pub cves: usize,
    pub kev: usize,
    pub crit: usize,
    pub live: bool,
    pub awaiting: bool,
}

/// Derive the evidence-glyph counts (JEF-202) from the entry evidence + corroboration flag.
pub fn glyph_props(ev: &EntryEvidence, corroborated: bool, awaiting: bool) -> GlyphProps {
    GlyphProps {
        cves: ev.cves.len(),
        kev: ev.cves.iter().filter(|c| c.kev).count(),
        crit: ev.cves.iter().filter(|c| c.severity == "critical").count(),
        live: corroborated || ev.corroborating().next().is_some(),
        awaiting,
    }
}

/// The crisp verdict GIST for the dense findings table (JEF-199): the posture TAG plus ONE
/// decisive clause — never the model's paragraph (that stays VERBATIM in the expanded row).
/// Derived DETERMINISTICALLY from facts, not by blindly truncating prose. The clause is
/// chosen in decisiveness order: a cited KEV/critical CVE, then runtime-corroboration, then
/// the terminal relation, then (last resort) the verdict's truncated first clause.
///
/// Returns `(tag, clause)`; `tag` is the `Posture::label`. The clause may be empty.
pub fn verdict_gist(
    verdict: Option<&str>,
    ev: &EntryEvidence,
    fs: &[&Finding],
) -> (&'static str, String) {
    let tag = Posture::of(verdict).label();

    // 1. A cited KEV/critical CVE — the most decisive enrichment.
    if let Some(c) = ev
        .cves
        .iter()
        .filter(|c| c.kev || c.severity == "critical")
        .min_by_key(|c| severity_rank(c))
    {
        let kind = if c.kev { "KEV" } else { "critical CVE" };
        return (tag, format!("{} ({kind})", c.id));
    }
    if let Some(id) = verdict.and_then(cve_id) {
        return (tag, format!("cites {id}"));
    }

    // 2. Runtime-corroborated — a live signal demonstrated the chain now.
    if fs.iter().any(|f| f.corroborated) || ev.corroborating().next().is_some() {
        return (tag, "runtime-corroborated".to_string());
    }

    // 3. The terminal relation the proof establishes.
    if let Some(summary) = terminal_reach_clause(fs) {
        return (tag, summary);
    }

    // 4. Last resort: the verdict's first clause, truncated.
    match verdict {
        Some(v) => (tag, truncate_clause(first_clause(v))),
        None => (tag, String::new()),
    }
}

/// The deterministic "reaches" clause from the proven paths: the dominant terminal objective
/// kind + count, and the relation that reaches it ("reaches 120 secrets via authorized
/// RBAC"). `None` when there are no terminal hops to summarize.
pub fn terminal_reach_clause(fs: &[&Finding]) -> Option<String> {
    let mut by_kind: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut rel_for_kind: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for f in fs {
        if let Some(step) = f.path.iter().find(|s| s.to == f.objective) {
            let k = kind(&step.to).to_string();
            by_kind
                .entry(k.clone())
                .or_default()
                .insert(step.to.clone());
            *rel_for_kind
                .entry(k)
                .or_default()
                .entry(step.relation.clone())
                .or_default() += 1;
        }
    }
    let (kind, objs) = by_kind
        .iter()
        .max_by(|a, b| a.1.len().cmp(&b.1.len()).then(b.0.cmp(a.0)))?;
    let n = objs.len();
    let rel = rel_for_kind
        .get(kind)
        .and_then(|m| m.iter().max_by_key(|(_, c)| **c).map(|(r, _)| r.clone()))
        .map(|r| reach_relation_phrase(&r))
        .unwrap_or_default();
    let via = if rel.is_empty() {
        String::new()
    } else {
        format!(" via {rel}")
    };
    Some(format!("reaches {n} {}{via}", plural(kind, n)))
}

/// A terse phrase for the terminal relation used in the verdict gist's "reaches … via …"
/// clause — calmer than the full graph edge label, naming the authorization mechanism.
pub fn reach_relation_phrase(rel: &str) -> String {
    if rel == "can-read" {
        return "a mounted secret".to_string();
    }
    if rel.starts_with("can-do/") {
        return "authorized RBAC".to_string();
    }
    if let Some(via) = rel.strip_prefix("escapes-to/") {
        return format!("a {via} escape");
    }
    if rel.starts_with("reaches") {
        return "network reach".to_string();
    }
    humanize_relation(rel)
}

/// The first clause of a verdict string — up to the first sentence/dash break — the
/// LAST-resort gist fallback (JEF-199) when no structured clause applies.
pub fn first_clause(v: &str) -> &str {
    let v = v.trim();
    let end = v
        .char_indices()
        .find(|(_, c)| matches!(c, '.' | ';' | '—'))
        .map(|(i, _)| i)
        .unwrap_or(v.len());
    v[..end].trim_end()
}

/// Truncate a clause to ~90 chars at a char boundary, appending an ellipsis when cut.
pub fn truncate_clause(s: &str) -> String {
    const CAP: usize = 90;
    if s.chars().count() <= CAP {
        return s.to_string();
    }
    let mut out: String = s.chars().take(CAP).collect();
    out.push('…');
    out
}

/// The terse "next lever" tag for the dense table (JEF-202, JEF-225). Operator-facing advice
/// is gated on the model's POSTURE, not the mechanical `disposition` (ADR-0016: reachability
/// is not a breach). For a NON-breach finding (SAFE / awaiting / a "working as intended" broad
/// row) there is no lever to pull — the cell shows an em-dash, never a remediation verb. Only
/// a FLAGGED breach surfaces the next step, in plain words (no raw `no-cut`/`durable-fix PR`/
/// `forbidden`/`unclassified` token). The full instruction stays in the expanded
/// [`what_to_do`].
pub fn next_lever_tag(f: &Finding, posture: Posture) -> &'static str {
    if posture != Posture::Breach {
        // Non-breach: nothing to remediate. The em-dash is the dense-table empty cell idiom.
        return "—";
    }
    match f.disposition.as_str() {
        AUTO_ELIGIBLE
        | "latent foothold — propose"
        | "structural — propose"
        | "vetoed — propose" => "arm network",
        "durable-fix PR" => "permanent fix",
        "forbidden" => "fix by hand (escape)",
        _ => "fix by hand",
    }
}

/// The "what to do" line for a FLAGGED breach (JEF-161 AC #1, JEF-179, JEF-225). Gated on the
/// model's POSTURE: a non-breach finding (SAFE / awaiting / "working as intended") gets NO
/// remediation — `None`, so the card/row renders no "what to do" block (ADR-0016: a reachable
/// path the model cleared is not a misconfig to fix). For a breach it is plain-language advice
/// derived from the finding's mechanical `disposition` + the concrete object/edge on its
/// proven `path`; no new model call, no new action, no enforcement, and no raw disposition
/// token reaches the screen. Returns plain text; the component escapes it (path-derived names
/// are untrusted node keys).
pub fn what_to_do(f: &Finding, posture: Posture) -> Option<String> {
    if posture != Posture::Breach {
        return None;
    }
    Some(match f.disposition.as_str() {
        AUTO_ELIGIBLE
        | "latent foothold — propose"
        | "structural — propose"
        | "vetoed — propose" => "would cut in shadow; arm `network` to act".to_string(),
        "durable-fix PR" => durable_fix_todo(f).unwrap_or_else(|| {
            "Permanent fix: revoke the grant / remove the mount, then protector re-checks."
                .to_string()
        }),
        "forbidden" => blocking_edge_todo(f, true).unwrap_or_else(|| {
            "Fix by hand — the only cut is an irreversible escape primitive; \
             protector clears this finding on its own once the escape primitive is removed."
                .to_string()
        }),
        // `no-cut` and `unclassified` (and any other) collapse to the same plain "change the
        // workload by hand" guidance — no raw token reaches the operator.
        _ => blocking_edge_todo(f, false).unwrap_or_else(|| {
            "No automatic fix — change the workload by hand; protector clears this finding on \
             its own once the misconfig is gone."
                .to_string()
        }),
    })
}

/// The concrete durable-fix instruction for a `durable-fix PR` finding: name the secret, the
/// workload that holds it, and how it's reached (mounted secret vs RBAC grant), from the
/// terminal hop. `None` when the path has no terminal step (degrade to the generic line).
/// The names are NOT escaped here — the component does the escaping.
fn durable_fix_todo(f: &Finding) -> Option<String> {
    let step = f
        .path
        .iter()
        .rev()
        .find(|s| s.to == f.objective)
        .or_else(|| f.path.last())?;
    let secret = short(&step.to);
    let workload = short(&step.from);
    if let Some(rest) = step.relation.strip_prefix("can-do/") {
        Some(format!(
            "Permanent fix: revoke the `{rest}` RBAC grant from `{workload}` (it reaches \
             `{secret}`) — then protector re-checks next pass."
        ))
    } else {
        Some(format!(
            "Permanent fix: remove the secret mount `{secret}` from `{workload}` — then \
             protector re-checks next pass."
        ))
    }
}

/// The concrete by-hand instruction for a `no-cut`/`forbidden` finding: name the specific
/// blocking edge and state that protector clears the finding by itself once the misconfig is
/// gone, in plain language (no raw `no-cut`/`forbidden` token). `escape_primitive` picks the
/// `forbidden` phrasing vs the `no-cut` phrasing. `None` when no informative hop exists. Names
/// are NOT escaped here (the component escapes).
fn blocking_edge_todo(f: &Finding, escape_primitive: bool) -> Option<String> {
    let step = if escape_primitive {
        f.path
            .iter()
            .find(|s| s.relation.starts_with("escapes-to/"))
            .or_else(|| f.path.last())?
    } else {
        f.path
            .iter()
            .rev()
            .find(|s| s.to == f.objective)
            .or_else(|| f.path.last())?
    };
    let from = short(&step.from);
    let to = short(&step.to);
    let edge = humanize_relation(&step.relation);
    if escape_primitive {
        Some(format!(
            "Fix by hand — the only cut is the irreversible escape primitive on `{from}` → \
             `{to}` ({edge}); protector clears this finding on its own once that escape \
             primitive is removed."
        ))
    } else {
        Some(format!(
            "No automatic fix — change the `{from}` → `{to}` hop ({edge}) by hand; \
             protector clears this finding on its own once that misconfig is gone."
        ))
    }
}

/// The Mermaid graph's `aria-label` (JEF-161 AC #4): the proven path summarized IN WORDS so
/// a screen reader conveys the picture the SVG draws. Plain text (the component escapes it).
pub fn path_aria_label(entry: &str, fs: &[&Finding]) -> String {
    let objectives = fs
        .iter()
        .flat_map(|f| f.path.iter())
        .filter(|s| fs.iter().any(|f| s.to == f.objective))
        .map(|s| s.to.clone())
        .collect::<BTreeSet<_>>()
        .len();
    format!(
        "Attack-path graph: the internet reaches {entry}, which reaches {objectives} \
         target{} it can get to.",
        if objectives == 1 { "" } else { "s" },
        entry = short(entry),
    )
}

// ---- attention ranking (JEF-163) -------------------------------------------------------

/// The OPERATOR-PRIORITY rank of a single finding (JEF-163) — a tested pure function over
/// existing [`Finding`] fields. Lower number = more attention. View-only (ADR-0016).
pub fn attention_priority(f: &Finding) -> u8 {
    if flagged(f.verdict.as_deref()) {
        0
    } else if f.disposition.contains("latent foothold")
        && f.verdict.as_deref().and_then(cve_id).is_some()
    {
        1
    } else if f.corroborated {
        2
    } else {
        3
    }
}

/// The [`Tier`] a priority level maps to for display: level 0 is `Flagged`, levels 1–2 are
/// `Watch`, level 3 is the de-emphasized `Context` tier.
pub fn tier_of_priority(priority: u8) -> Tier {
    match priority {
        0 => Tier::Flagged,
        1 | 2 => Tier::Watch,
        _ => Tier::Context,
    }
}

/// The attention rank of one finding: its priority level and the display tier.
pub fn attention_rank(f: &Finding) -> (u8, Tier) {
    let priority = attention_priority(f);
    (priority, tier_of_priority(priority))
}

/// The attention rank of an ENDPOINT card — a card coalesces every finding from one
/// internet-facing entry, so it takes its group's WORST-CASE (lowest-number) priority.
pub fn endpoint_attention_rank(fs: &[&Finding]) -> (u8, Tier) {
    let priority = fs.iter().map(|f| attention_rank(f).0).min().unwrap_or(3);
    (priority, tier_of_priority(priority))
}

// ---- the per-endpoint card / row data --------------------------------------------------

/// A stable, HTML-id-safe token for an endpoint ROW (JEF-202), derived from the entry key,
/// so the row-expand `<button aria-controls>` → detail `<tr id>` pair and its persisted
/// open-state survive the `/fragment` swap. Non-`[A-Za-z0-9_-]` chars become `-`.
pub fn row_id(entry: &str) -> String {
    let slug: String = entry
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("row-{slug}")
}

// ---- the recency / Δ column (JEF-201) --------------------------------------------------

/// The dense table's Δ cell as PLAIN presentation data (JEF-201): the terse glyph/age, the
/// screen-reader label (so meaning is carried in TEXT, never the glyph/color alone — AC #4),
/// and the CSS tone class. The `components::findings::row` renderer emits this verbatim and
/// imports none of the recency enums — exactly the ADR-0019 Props boundary the rail/evidence
/// cells already follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecencyCell {
    /// What the cell shows: `NEW` / `↑` / `↓`, or the quiet age (`2m`) for an unchanged row,
    /// or `·` when there is no age yet. Glyph chars come from the closed [`Delta`] set.
    pub glyph: String,
    /// The meaning IN WORDS for `aria-label` (AC #4): "new this pass" / "escalated" / etc.
    pub aria_label: String,
    /// The CSS tone class — `rc-new` / `rc-up` / `rc-down` / `rc-steady` — so the glyph can be
    /// styled WITHOUT being the sole carrier of meaning (the aria-label carries that).
    pub tone: &'static str,
}

/// Humanize a whole-seconds age into a terse `Ns`/`Nm`/`Nh`/`Nd` (JEF-201) — the quiet age the
/// steady-state Δ cell shows in place of a glyph. Mirrors `model::relative_time`'s buckets but
/// over a raw seconds count (the recency age is an `Instant` delta, not a `SystemTime`).
pub fn humanize_age_secs(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

/// Shape the Δ cell from a resolved [`RecencyInfo`] (JEF-201). `None` (a row published before
/// any recency update) reads as a quiet steady cell with no glyph — never a spurious NEW. An
/// `Unchanged`/`Restored` cell shows the age (when known); the active deltas show their glyph.
pub fn recency_cell(recency: Option<&RecencyInfo>) -> RecencyCell {
    let Some(r) = recency else {
        return RecencyCell {
            glyph: "·".to_string(),
            aria_label: "no recency yet".to_string(),
            tone: "rc-steady",
        };
    };
    let age = r.age_secs.map(humanize_age_secs);
    let tone = match r.delta {
        Delta::New => "rc-new",
        Delta::Escalated => "rc-up",
        Delta::DeEscalated => "rc-down",
        Delta::Unchanged | Delta::Restored => "rc-steady",
    };
    // A steady/restored cell shows the age in place of the glyph; the active deltas show the
    // glyph itself (the age still rides in the aria-label for the unchanged case).
    let glyph = match r.delta {
        Delta::Unchanged | Delta::Restored => age.clone().unwrap_or_else(|| "·".to_string()),
        other => other.glyph().to_string(),
    };
    RecencyCell {
        glyph,
        aria_label: r.delta.aria_label(age.as_deref()),
        tone,
    }
}

/// The worst-case Δ across an endpoint's coalesced findings (JEF-201): one dense-table row
/// represents every finding from an entry, so its Δ takes the most NOTEWORTHY of them —
/// escalation first, then new, then de-escalation, then restored, then unchanged. Each
/// endpoint's findings share one entry key, so they share one stored `RecencyInfo`; this
/// simply picks the first present (and is robust if that ever changes).
pub fn endpoint_recency(fs: &[&Finding]) -> Option<RecencyInfo> {
    fn weight(d: Delta) -> u8 {
        match d {
            Delta::Escalated => 0,
            Delta::New => 1,
            Delta::DeEscalated => 2,
            Delta::Restored => 3,
            Delta::Unchanged => 4,
        }
    }
    fs.iter()
        .filter_map(|f| f.recency)
        .min_by_key(|r| weight(r.delta))
}

/// The findings-region recency TALLY for the latest pass (JEF-201): how many endpoints are
/// NEW this pass and how many newly FLAGGED (escalated). Rendered as the region header line
/// "N new · M newly flagged since last pass". Counts only — pure presentation (ADR-0016).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecencyTally {
    pub new: usize,
    pub newly_flagged: usize,
}

impl RecencyTally {
    /// Whether the tally has anything to announce (so the header line is omitted when nothing
    /// changed, rather than reading a hollow "0 new").
    pub fn is_empty(self) -> bool {
        self.new == 0 && self.newly_flagged == 0
    }
}

/// Tally the per-endpoint recency over a set of endpoint finding-groups (JEF-201): one count
/// per ENDPOINT (not per finding), using each endpoint's worst-case Δ. `groups` is the same
/// per-entry grouping the region renders.
pub fn recency_tally<'a>(groups: impl IntoIterator<Item = &'a [&'a Finding]>) -> RecencyTally {
    let mut tally = RecencyTally::default();
    for fs in groups {
        if let Some(r) = endpoint_recency(fs) {
            if r.delta.is_new() {
                tally.new += 1;
            }
            if r.delta.is_escalation() {
                tally.newly_flagged += 1;
            }
        }
    }
    tally
}

// The per-endpoint card/row + remediation assembly (the heavier Props builders) live in a
// sibling module so each file stays under the 1,000-line cap (repo CLAUDE.md); re-exported
// so the `view_model::findings::` paths callers use are unchanged.
pub mod endpoint;
pub use endpoint::*;

#[cfg(test)]
#[path = "findings_tests.rs"]
mod tests;
