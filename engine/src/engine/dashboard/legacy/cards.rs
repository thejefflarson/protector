//! Transitional legacy module (pre-ADR-0019 string-concat rendering).
//!
//! Migrated piecemeal in tickets 3–6; extracted here only so each file
//! stays under the 1,000-line cap (repo CLAUDE.md). New work goes in the
//! `components`/`view_model` maud layers, not here.
#![allow(dead_code)]

use super::*;

/// One remediation card: the kill chain caption and a graph of the path with the
/// severing edge dashed.
pub(crate) fn remediation_card(f: &Finding, armed: bool) -> String {
    let mut m = Mermaid::default();
    m.add_internet(&f.entry);
    for step in &f.path {
        let sig = format!("{} -[{}]-> {}", step.from, step.relation, step.to);
        let is_cut = f.cut.as_deref() == Some(sig.as_str());
        let label = if is_cut {
            "✂ NetworkPolicy cut".to_string()
        } else {
            humanize_relation(&step.relation)
        };
        m.edge(&step.from, &step.to, &label, is_cut);
    }
    let status = if armed {
        "<span class=\"applied\">applied</span>"
    } else {
        "<span class=\"proposed\">would apply (shadow)</span>"
    };
    // JEF-161 verdict-first card: posture chip + the model's words VERBATIM above
    // everything, then the "what's proven" certainty rail, then the (cut-marked) graph,
    // then the disposition-derived "what to do". The remediation card is one chain, so
    // the rail/aria are built over that single finding.
    let one = std::slice::from_ref(&f);
    let verdict_line = verdict_line(f.verdict.as_deref());
    let facts: String = proven_facts(&f.entry, one, &f.evidence)
        .iter()
        .map(|b| format!("<li>{b}</li>"))
        .collect();
    let rail = format!(
        "<div class=\"rail\"><div class=\"rail-cap\">proven facts</div>\
         <ul>{facts}</ul></div>"
    );
    // The per-path evidence (JEF-133): the entry's CVEs (severity input) and runtime
    // alerts (live corroboration), the two ADR-0016 blocks — placed right after the
    // certainty rail so "what's proven" → "what's the evidence" reads top to bottom.
    let evidence = evidence_blocks(&f.evidence);
    let todo_line = format!(
        "<div class=\"todo\"><b>what to do:</b> {}</div>",
        what_to_do(f)
    );
    let aria = escape(&path_aria_label(&f.entry, one));
    format!(
        "<div class=\"card\">{verdict_line}{rail}{evidence}\
         <div class=\"kc2\">the picture of those facts — attack steps: {}  {status}</div>\
         <pre class=\"mermaid\" data-aria=\"{aria}\">{}</pre>{todo_line}</div>",
        killchain_html(f),
        m.finish(),
    )
}

/// Pluralize an objective kind for an aggregate label ("47 secrets").
pub(crate) fn plural(kind: &str, n: usize) -> String {
    if n == 1 {
        return kind.to_string();
    }
    match kind {
        "capability" => "capabilities".to_string(),
        "identity" => "identities".to_string(),
        k => format!("{k}s"),
    }
}

/// One endpoint card: every breach path from this internet-facing entry in a single
/// graph, captioned with the **model's judgement** of the entry — the LLM is the
/// judge (ADR-0013), so the disposition is its own words ("not exploitable — …"),
/// never a rule-based category. The verdict is per-entry, so one judgement covers the
/// whole card. A broadly-privileged entry (argocd, protector) fans out to hundreds of
/// objectives, so terminal objectives sharing a (hop, kind) are **collapsed into one
/// aggregate node** ("47 secrets") — the graph stays readable. Intermediate hops are
/// deduped.
/// A human edge label for a graph relation, so an operator can tell *how* a hop works
/// — most importantly the two ways to reach a secret: a **mounted** secret it already
/// holds (`can-read`, direct, just that one secret) vs an **RBAC** grant its identity
/// can exercise against the API (`can-do/get/secrets`, often any secret in scope).
pub(crate) fn humanize_relation(rel: &str) -> String {
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

/// The three posture states a verdict can be in, for the verdict-first card and the
/// `/judgements` view (JEF-161). The breach call is the model's (ADR-0013/0016), so
/// this maps only the model's *own* affirmation to `[BREACH]` — a "not exploitable"
/// verdict is `[SAFE]`, and no verdict yet is the muted `[awaiting judgement]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Posture {
    /// The model affirmed a real breach (its words begin with "exploitable").
    Breach,
    /// The model judged this NOT a breach (a "not exploitable — …" call).
    Safe,
    /// The model hasn't reached this entry yet (slow CPU model) — not "clear".
    Awaiting,
}

impl Posture {
    /// The posture for a verdict summary string (the model's own words), or `None` if
    /// the model hasn't judged the entry yet. Mirrors [`flagged`] for the breach test.
    pub(crate) fn of(verdict: Option<&str>) -> Self {
        match verdict {
            None => Posture::Awaiting,
            Some(v) if flagged(Some(v)) => Posture::Breach,
            Some(_) => Posture::Safe,
        }
    }

    /// The chip TEXT — meaning carried in words, never color/glyph alone (accessibility,
    /// JEF-161 AC #4). The brackets read as a posture chip in a screen reader too.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Posture::Breach => "[BREACH]",
            Posture::Safe => "[SAFE]",
            Posture::Awaiting => "[awaiting judgement]",
        }
    }

    /// The CSS tone class for the chip — red breach / green-calm safe / muted awaiting.
    pub(crate) fn tone(self) -> &'static str {
        match self {
            Posture::Breach => "chip-breach",
            Posture::Safe => "chip-safe",
            Posture::Awaiting => "chip-awaiting",
        }
    }
}

/// The posture chip + the model's verdict VERBATIM (never paraphrased — the LLM is the
/// judge, ADR-0013), foregrounded above everything on a finding card (JEF-161). When the
/// model hasn't judged the entry, the chip stands alone with a muted "the model hasn't
/// reached this entry yet" — an honest awaiting state, not an implied "clear".
pub(crate) fn verdict_line(verdict: Option<&str>) -> String {
    let posture = Posture::of(verdict);
    let chip = format!(
        "<span class=\"chip {}\">{}</span>",
        posture.tone(),
        posture.label()
    );
    match verdict {
        Some(v) => format!(
            "<div class=\"vline\">{chip} <span class=\"vwords\">{}</span></div>",
            escape(v)
        ),
        None => format!(
            "<div class=\"vline\">{chip} <span class=\"muted\">the model hasn't reached \
             this entry yet — paths below are proven, the breach call is pending</span></div>"
        ),
    }
}

/// The "what's proven" certainty rail (JEF-161 AC #1/#2): 2–4 bullets of DETERMINISTIC
/// facts drawn only from existing `Finding` fields — the proof side of the proof-vs-
/// judgement line (ADR-0016). Missing evidence reads "unknown / not cited", never
/// implied-absent (coverage-gap honesty, AC #2). No model call. Facts:
///   1. internet-reachable (every shown finding is `breach_relevant` from an entry).
///   2. how it reaches each objective kind — by RBAC vs mount, via [`humanize_relation`].
///   3. CVE presence — surfaced ONLY from a `CVE-` id the model cited in its verdict
///      (JEF-133 builds the real per-path evidence feed; here we read existing fields).
pub(crate) fn proven_facts(entry: &str, fs: &[&Finding], ev: &EntryEvidence) -> Vec<String> {
    let mut facts = Vec::new();

    // 1. Internet-reachability is the entry-level fact (only breach-relevant chains from
    // an internet-facing entry reach this card — ProvenChain::is_breach_relevant).
    facts.push(format!(
        "internet-reachable: <code>{}</code> is an internet-facing service (a front door)",
        escape(&short(entry))
    ));

    // 2. The distinct terminal relations — HOW it reaches an objective (RBAC vs mount vs
    // network), the deterministic mechanism. Deduped, stable-ordered.
    let mut relations: BTreeSet<String> = BTreeSet::new();
    for f in fs {
        if let Some(step) = f.path.iter().find(|s| s.to == f.objective) {
            relations.insert(humanize_relation(&step.relation));
        }
    }
    for rel in &relations {
        facts.push(format!("reaches a target by <b>{}</b>", escape(rel)));
    }

    // 3. CVE presence — read from the SAME per-entry evidence the card lists below (the
    // entry's KEV-or-critical CVEs, what the adjudicator reads), NOT scraped from the
    // model's prose verdict. A short counts-only summary; the full per-CVE list lives in
    // the evidence block one section down, so the rail names the shape, not the detail.
    facts.push(cve_fact(ev));

    facts
}

/// The certainty-rail CVE fact, derived from the entry's real `EntryEvidence.cves` — a
/// SHORT counts-only summary (critical + KEV tallies), never the full list (that is the
/// evidence block's job, right below the rail). This is the breach-relevant subset only
/// (KEV-or-critical, the same selection the adjudicator reads), so the honest-empty state
/// says exactly that — "no KEV/critical CVE on this image" — and never claims the image is
/// vulnerability-free, nor "none cited / coverage unknown" when CVEs ARE present.
pub(crate) fn cve_fact(ev: &EntryEvidence) -> String {
    let n = ev.cves.len();
    if n == 0 {
        // Honest-empty: distinguishes "no breach-relevant CVE present" from "CVE data
        // absent". This block only ever carries KEV-or-critical CVEs, so an empty list is
        // the genuine no-high-severity-CVE state, not a missing-scan blank — but lower-
        // severity CVEs are out of this subset, so we don't claim the image is clean.
        return "CVE: <span class=\"muted\">no KEV or critical CVE on this service's image \
                (lower-severity CVEs not shown here)</span>"
            .to_string();
    }

    let critical = ev.cves.iter().filter(|c| c.severity == "critical").count();
    let kev = ev.cves.iter().filter(|c| c.kev).count();

    let mut parts: Vec<String> = Vec::new();
    if critical > 0 {
        parts.push(format!("{critical} critical"));
    }
    if kev > 0 {
        parts.push(format!("{kev} KEV-listed"));
    }
    let detail = if parts.is_empty() {
        String::new()
    } else {
        format!(" — {}", parts.join(", "))
    };

    format!(
        "CVE present: <b>{n}</b> known vuln{}{} on this image (full list below)",
        if n == 1 { "" } else { "s" },
        detail,
    )
}

/// How many CVEs to list inline before the rest go behind a "show all" `<details>`
/// expander (JEF-133 AC: CVE lists can be long — summarize, detail on demand). The
/// top-N are shown by `severity_rank` so the worst surface first.
pub(crate) const CVE_INLINE_CAP: usize = 3;

/// The CSS tone class for a CVE severity label — reuses the chip idiom so critical/high
/// read as alarming and low/medium calm, WITHOUT relying on color alone (the label text
/// carries the meaning too, JEF-161 AC #4 accessibility).
pub(crate) fn severity_tone(severity: &str) -> &'static str {
    match severity {
        "critical" => "sev-critical",
        "high" => "sev-high",
        "medium" => "sev-medium",
        _ => "sev-low",
    }
}

/// A sort key putting the worst CVEs first: critical, then high, then KEV-flagged, then
/// the rest. Used for both the inline top-N and the severity summary.
pub(crate) fn severity_rank(c: &CveEvidence) -> u8 {
    match c.severity.as_str() {
        "critical" => 0,
        "high" => 1,
        _ if c.kev => 2,
        "medium" => 3,
        _ => 4,
    }
}

/// One CVE as a list item: id, a severity chip, KEV/reachability/fix, and CWE/title when
/// present. All free-text (title) is HTML-escaped — it is untrusted third-party data.
pub(crate) fn cve_li(c: &CveEvidence) -> String {
    let kev = if c.kev {
        " <span class=\"kev\" title=\"CISA Known-Exploited\">KEV</span>"
    } else {
        ""
    };
    let cwe = if c.cwe.is_empty() {
        String::new()
    } else {
        format!(
            " <span class=\"muted\">[{}]</span>",
            escape(&c.cwe.join(", "))
        )
    };
    let title = match c.title.as_deref() {
        Some(t) if !t.is_empty() => format!(" — {}", escape(t)),
        _ => String::new(),
    };
    format!(
        "<li><code>{}</code> <span class=\"chip {}\">{}</span>{kev} \
         <span class=\"muted\">reachability: {} · {}</span>{cwe}{title}</li>",
        escape(&c.id),
        severity_tone(&c.severity),
        escape(&c.severity),
        escape(&c.reachability),
        escape(&c.fix),
    )
}

/// The CVE evidence block (JEF-133) — the SEVERITY/reachability input half of ADR-0016.
/// A one-line summary (count + the worst severities) with the full list behind a
/// `<details>` expander when it runs long. Empty CVEs render an honest muted "none on the
/// entry's image" — never an implied-absent blank box (JEF-161 coverage-gap idiom).
pub(crate) fn cve_block(ev: &EntryEvidence) -> String {
    if ev.cves.is_empty() {
        return "<div class=\"ev ev-cve\"><div class=\"ev-cap\">CVEs \
                <span class=\"muted\">— how bad it would be if exploited</span>\
                </div><div class=\"muted\">none on this service's image \
                <span class=\"muted\">(KEV or critical; lower-severity CVEs not shown)</span>\
                </div></div>"
            .to_string();
    }

    let mut sorted: Vec<&CveEvidence> = ev.cves.iter().collect();
    sorted.sort_by(|a, b| {
        severity_rank(a)
            .cmp(&severity_rank(b))
            .then(a.id.cmp(&b.id))
    });

    // Summary: count + a per-severity tally (critical/high/medium/low), worst first.
    let mut by_sev: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &sorted {
        *by_sev.entry(c.severity.as_str()).or_default() += 1;
    }
    let order = ["critical", "high", "medium", "low"];
    let tally: Vec<String> = order
        .iter()
        .filter_map(|s| by_sev.get(*s).map(|n| format!("{n} {s}")))
        .collect();
    let n = sorted.len();
    let summary = format!(
        "<b>{n}</b> CVE{} <span class=\"muted\">({})</span>",
        if n == 1 { "" } else { "s" },
        tally.join(", ")
    );

    let inline: String = sorted
        .iter()
        .take(CVE_INLINE_CAP)
        .map(|c| cve_li(c))
        .collect();
    let rest: String = sorted
        .iter()
        .skip(CVE_INLINE_CAP)
        .map(|c| cve_li(c))
        .collect();
    let more = if rest.is_empty() {
        String::new()
    } else {
        format!("<details><summary>show all {n} CVEs</summary><ul>{rest}</ul></details>",)
    };

    format!(
        "<div class=\"ev ev-cve\"><div class=\"ev-cap\">CVEs \
         <span class=\"muted\">— how bad it would be if exploited</span></div>\
         <div class=\"ev-sum\">{summary}</div><ul>{inline}</ul>{more}</div>"
    )
}

/// The runtime-alert block (JEF-133) — the LIVE-corroboration half of ADR-0016. Lists the
/// corroborating signals first (Falco-style `Alert`s, what flips `corroborated`), then the
/// non-corroborating agent behaviors as context. Empty renders an honest muted "no runtime
/// signal observed" — never implied-absent.
pub(crate) fn runtime_block(ev: &EntryEvidence) -> String {
    let corroborating: Vec<&Behavior> = ev.corroborating().collect();
    let context: Vec<&Behavior> = ev.context_behaviors().collect();

    let body = if corroborating.is_empty() && context.is_empty() {
        "<div class=\"muted\">no live activity seen on this service \
         <span class=\"muted\">(no Falco alert, no agent behavior attributed)</span></div>"
            .to_string()
    } else {
        let mut out = String::new();
        if corroborating.is_empty() {
            out.push_str(
                "<div class=\"muted\">nothing seen happening live \
                 (no live activity backs this up as being exploited now)</div>",
            );
        } else {
            let items: String = corroborating
                .iter()
                .map(|b| {
                    format!(
                        "<li><span class=\"chip chip-breach\">SEEN LIVE</span> {}</li>",
                        escape(&b.summary())
                    )
                })
                .collect();
            out.push_str(&format!("<ul>{items}</ul>"));
        }
        if !context.is_empty() {
            let items: String = context
                .iter()
                .map(|b| {
                    format!(
                        "<li><span class=\"muted\">[{}]</span> {}</li>",
                        escape(b.variant_label()),
                        escape(&b.summary())
                    )
                })
                .collect();
            out.push_str(&format!(
                "<details><summary>{} agent behavior{} (background, not seen exploited)</summary>\
                 <ul>{items}</ul></details>",
                context.len(),
                if context.len() == 1 { "" } else { "s" },
            ));
        }
        out
    };

    format!(
        "<div class=\"ev ev-runtime\"><div class=\"ev-cap\">live activity \
         <span class=\"muted\">— is it being exploited right now</span></div>{body}</div>"
    )
}

/// The two ADR-0016 evidence blocks for a finding's entry (JEF-133), wrapped so they read
/// as one "evidence for this path" section beneath the certainty rail. CVEs (severity
/// input) then runtime alerts (live corroboration) — always both blocks, each with its own
/// honest empty state, so the operator can tell "no CVE" from "CVE block missing".
pub(crate) fn evidence_blocks(ev: &EntryEvidence) -> String {
    format!(
        "<div class=\"evidence\"><div class=\"ev-head\">evidence for this path</div>{}{}</div>",
        cve_block(ev),
        runtime_block(ev),
    )
}

/// The first `CVE-NNNN-NNNN` id in a string (case-insensitive prefix), if any — the
/// only CVE signal available from existing fields (the model cites it in its verdict).
/// Used by the certainty rail; the full per-path CVE evidence is JEF-133's job.
pub(crate) fn cve_id(s: &str) -> Option<&str> {
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

/// The "what to do" line, derived from the finding's mechanical `disposition` AND the
/// concrete object/edge on its proven `path` (JEF-161 AC #1, JEF-179) — no new model
/// call, no new action, no enforcement. The disposition encodes the cut type (see
/// [`classify`]); for the manual classes the proven path above names the exact offending
/// object/edge, so a solo operator (who has no security team to hand "manual" to) gets a
/// concrete next step. All path-derived names are untrusted node keys, so every injected
/// substring is HTML-[`escape`]d. When the path lacks the specific names this degrades to
/// the prior generic text rather than printing empty `<>` placeholders.
pub(crate) fn what_to_do(f: &Finding) -> String {
    match f.disposition.as_str() {
        AUTO_ELIGIBLE
        | "latent foothold — propose"
        | "structural — propose"
        | "vetoed — propose" => "would cut in shadow; arm `network` to act".to_string(),
        // The durable fix is at the terminal hop: the secret-bearing edge into the
        // objective. `can-read` is a mounted secret (remove the mount); `can-do/<verb>/…`
        // is an RBAC grant (revoke it). Name the secret, the workload that holds it, and
        // the grant — then say protector re-checks on its own next pass.
        "durable-fix PR" => durable_fix_todo(f)
            .unwrap_or_else(|| "revoke the grant / remove the mount (durable fix)".to_string()),
        // The blocking edge is the single hop that can't be safely severed in-place — for
        // `forbidden` an irreversible escape primitive, for `no-cut` the un-cuttable hop.
        // Name it and state that protector clears the finding by itself once it's gone
        // (the self-revert behaviour — said in plain words).
        "forbidden" => blocking_edge_todo(f, true).unwrap_or_else(|| {
            "manual — the only cut is an irreversible escape primitive; \
             protector clears this finding on its own once the escape primitive is removed"
                .to_string()
        }),
        "no-cut" => blocking_edge_todo(f, false).unwrap_or_else(|| {
            "manual — no single-edge cut severs this path; \
             protector clears this finding on its own once the misconfig is gone"
                .to_string()
        }),
        // "unclassified" and any future disposition: the safe, conservative default.
        _ => "manual — no automatic cut classified for this path".to_string(),
    }
}

/// The concrete durable-fix instruction for a `durable-fix PR` finding: name the secret,
/// the workload that holds it, and how it's reached (mounted secret vs RBAC grant), from
/// the terminal hop of the proven path. Returns `None` when the path has no terminal step
/// (degrade to the generic line). Injected node names are HTML-escaped.
pub(crate) fn durable_fix_todo(f: &Finding) -> Option<String> {
    // The objective-bearing hop: the last step whose `to` is the objective, else the last
    // step of the path.
    let step = f
        .path
        .iter()
        .rev()
        .find(|s| s.to == f.objective)
        .or_else(|| f.path.last())?;
    let secret = escape(&short(&step.to));
    let workload = escape(&short(&step.from));
    if let Some(rest) = step.relation.strip_prefix("can-do/") {
        // An RBAC grant: `can-do/get/secrets` → "get/secrets". Revoke the grant.
        let grant = escape(rest);
        Some(format!(
            "Revoke the `{grant}` RBAC grant from `{workload}` (it reaches `{secret}`) \
             — then protector re-checks next pass."
        ))
    } else {
        // A mounted secret (`can-read`) or other direct hold: remove the mount.
        Some(format!(
            "Remove the secret mount `{secret}` from `{workload}` — then protector \
             re-checks next pass."
        ))
    }
}

/// The concrete manual instruction for a `no-cut`/`forbidden` finding: name the specific
/// blocking edge (the un-cuttable hop) and state that protector clears the finding by
/// itself once the misconfig is gone. `escape_primitive` picks the `forbidden` phrasing
/// (an irreversible escape) vs the `no-cut` phrasing (no single-edge cut). Returns `None`
/// when no informative hop exists (degrade to the generic line). Names are HTML-escaped.
pub(crate) fn blocking_edge_todo(f: &Finding, escape_primitive: bool) -> Option<String> {
    // The blocking edge: for `forbidden` the escape hop if the path has one, else the
    // terminal hop; for `no-cut` the terminal hop into the objective.
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
    let from = escape(&short(&step.from));
    let to = escape(&short(&step.to));
    let edge = escape(&humanize_relation(&step.relation));
    if escape_primitive {
        Some(format!(
            "manual — the only cut is the irreversible escape primitive on `{from}` → \
             `{to}` ({edge}); protector clears this finding on its own once that escape \
             primitive is removed."
        ))
    } else {
        Some(format!(
            "manual — no single-edge cut severs the `{from}` → `{to}` hop ({edge}); \
             protector clears this finding on its own once that misconfig is gone."
        ))
    }
}

/// The Mermaid graph's `aria-label` (JEF-161 AC #4): the proven path summarized IN WORDS
/// so a screen reader conveys the picture the SVG draws. Applied to the rendered graph by
/// the inline script (the SVG is client-rendered) via a `data-aria` attribute on the
/// `<pre>`. Plain text only (it is an attribute value); escaped at the call site.
pub(crate) fn path_aria_label(entry: &str, fs: &[&Finding]) -> String {
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

/// Whether an entry's reach is "broad" — the threshold the wide-reach-≠-break-in
/// treatment keys on (ADR-0016, the argocd case). Reuses the long-standing inline
/// `objectives >= 20` bar so the calm-card lead and any future caller agree; factored
/// into one place so the threshold is never duplicated.
pub(crate) fn is_broad(objectives: usize) -> bool {
    objectives >= 20
}

/// The crisp verdict GIST for the dense findings table (JEF-199): the posture TAG plus ONE
/// decisive clause — never the model's paragraph (that stays VERBATIM in the expanded row
/// and at `/judgements`; ADR-0013 forbids paraphrasing the judgement itself). A pure
/// function over the verdict string and the entry's structured [`EntryEvidence`], so the
/// clause is derived DETERMINISTICALLY from facts, not by blindly truncating prose. The
/// clause is chosen in decisiveness order:
///   1. a cited KEV/critical CVE (from the evidence, else a `CVE-…` the verdict cited),
///   2. runtime-corroboration (a live signal on the entry),
///   3. the terminal relation the verdict's facts prove ("reaches N targets via …"),
///   4. LAST resort only: the verdict's first clause, truncated (≤ ~90 chars, trailing `…`).
///
/// Returns `(tag, clause)`; `tag` is the `Posture::label`. The clause may be empty (awaiting
/// with no facts), and is plain text — escape at the call site.
pub(crate) fn verdict_gist(
    verdict: Option<&str>,
    ev: &EntryEvidence,
    fs: &[&Finding],
) -> (&'static str, String) {
    let tag = Posture::of(verdict).label();

    // 1. A cited KEV/critical CVE — the most decisive enrichment. Prefer the evidence's
    // own worst CVE (it carries the KEV/severity fields); fall back to a `CVE-…` id the
    // model cited in its verdict when the structured evidence is empty.
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

    // 3. The terminal relation the proof establishes — the dominant objective kind, count,
    // and how it's reached (RBAC vs mount vs network). Deterministic, from the path.
    if let Some(summary) = terminal_reach_clause(fs) {
        return (tag, summary);
    }

    // 4. Last resort: the verdict's first clause, truncated. Only when nothing structured
    // applied (e.g. an awaiting/odd verdict with no path facts).
    match verdict {
        Some(v) => (tag, truncate_clause(first_clause(v))),
        None => (tag, String::new()),
    }
}

/// The deterministic "reaches" clause from the proven paths: the dominant terminal
/// objective kind + count, and the relation that reaches it ("reaches 120 secrets via
/// authorized RBAC"). `None` when there are no terminal hops to summarize.
pub(crate) fn terminal_reach_clause(fs: &[&Finding]) -> Option<String> {
    // Count distinct terminal objectives by kind, and tally the relations used to reach
    // them, so the dominant kind and its dominant relation surface.
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
    // Dominant kind = the one with the most distinct objectives (ties broken by kind name
    // for determinism).
    let (kind, objs) = by_kind
        .iter()
        .max_by(|a, b| a.1.len().cmp(&b.1.len()).then(b.0.cmp(a.0)))?;
    let n = objs.len();
    // Dominant relation for that kind.
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
pub(crate) fn reach_relation_phrase(rel: &str) -> String {
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

/// The first clause of a verdict string — up to the first sentence/dash break — the LAST-
/// resort gist fallback (JEF-199) when no structured clause applies.
pub(crate) fn first_clause(v: &str) -> &str {
    let v = v.trim();
    let end = v
        .char_indices()
        .find(|(_, c)| matches!(c, '.' | ';' | '—'))
        .map(|(i, _)| i)
        .unwrap_or(v.len());
    v[..end].trim_end()
}

/// Truncate a clause to ~90 chars at a char boundary, appending an ellipsis when cut.
pub(crate) fn truncate_clause(s: &str) -> String {
    pub(crate) const CAP: usize = 90;
    if s.chars().count() <= CAP {
        return s.to_string();
    }
    let mut out: String = s.chars().take(CAP).collect();
    out.push('…');
    out
}

/// The terse "next lever" disposition tag for the dense table (JEF-202) — what the operator
/// would do next, in two-or-three words, derived from the finding's mechanical
/// `disposition` (see [`classify`]). The full concrete instruction stays in the expanded
/// row's [`what_to_do`]; this is the at-a-glance lever. A broadly-privileged, model-cleared
/// entry reads "working as intended" (the calm case), handled by the caller.
pub(crate) fn next_lever_tag(f: &Finding) -> &'static str {
    match f.disposition.as_str() {
        AUTO_ELIGIBLE
        | "latent foothold — propose"
        | "structural — propose"
        | "vetoed — propose" => "arm network",
        "durable-fix PR" => "durable fix",
        "forbidden" => "manual (escape)",
        "no-cut" => "manual (no cut)",
        _ => "manual",
    }
}

/// The compact evidence-glyph cell for the dense table (JEF-202): `N CVE`, a `K·KEV` badge
/// (reusing the `.kev` idiom), a `crit` count, and `◆live` when runtime-corroborated. `—`
/// when there is no evidence at all; `unjudged` when the model hasn't reached the entry yet
/// (an honest awaiting state, JEF-161 — never an implied "no evidence"). Plain glyphs;
/// the verbose per-CVE / per-signal blocks stay in the expanded row. CVE ids are a closed
/// catalogue shape, but the cell carries only counts, so nothing untrusted is emitted here.
pub(crate) fn evidence_glyphs(ev: &EntryEvidence, corroborated: bool, awaiting: bool) -> String {
    let n = ev.cves.len();
    let kev = ev.cves.iter().filter(|c| c.kev).count();
    let crit = ev.cves.iter().filter(|c| c.severity == "critical").count();
    let live = corroborated || ev.corroborating().next().is_some();

    let mut parts: Vec<String> = Vec::new();
    if n > 0 {
        parts.push(format!("{n} CVE"));
    }
    if kev > 0 {
        parts.push(format!("<span class=\"kev\">{kev}·KEV</span>"));
    }
    if crit > 0 {
        parts.push(format!("<span class=\"ev-crit\">{crit} crit</span>"));
    }
    if live {
        parts.push("<span class=\"ev-live\">◆live</span>".to_string());
    }

    if !parts.is_empty() {
        parts.join(" ")
    } else if awaiting {
        "<span class=\"muted\">unjudged</span>".to_string()
    } else {
        "<span class=\"muted\">—</span>".to_string()
    }
}

/// A stable, HTML-id-safe token for an endpoint ROW (JEF-202), derived from the entry key,
/// so the row-expand `<button aria-controls>` → detail `<tr id>` pair and its persisted
/// open-state survive the `/fragment` swap (the same content maps to the same id pass to
/// pass). Non-`[A-Za-z0-9_-]` chars become `-`; prefixed so it is never empty / digit-led.
pub(crate) fn row_id(entry: &str) -> String {
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

/// The computed metadata for one endpoint's dense table ROW (JEF-202), produced alongside
/// the expandable card body so the summary row's cells and the detail body never drift.
pub(crate) struct RowMeta {
    /// The model's posture for the entry (one judgement per entry, ADR-0013).
    pub(crate) posture: Posture,
    /// How many distinct targets the entry reaches — the blast radius.
    pub(crate) objectives: usize,
    /// Whether the model cleared a broad entry → the calm "working as intended" row.
    pub(crate) calm: bool,
}
