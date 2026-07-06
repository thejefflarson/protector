//! The fence/sanitize prompt-injection defenses and the anti-fabrication backstop. Split
//! out of the adjudicate module root purely to keep every file under the 1,000-line cap
//! (repo CLAUDE.md). These are pure helpers: `sanitize`/`fence` neutralize untrusted text,
//! and `guard_fabricated_cve` is the sole remaining deterministic backstop (it never
//! decides breach). The cross-pass verdict cache no longer keys on a predicted-input
//! fingerprint; it keys on a hash of the deterministic prompt (JEF-350, see
//! `prompt::prompt_cache_key`).

use crate::engine::graph::{Behavior, NodeKey, Relation, SecurityGraph};

use super::Verdict;

/// Normalize free text before CVE extraction so a model can't dodge the
/// anti-fabrication guard with a cosmetic spelling of a CVE id. Uppercases ASCII,
/// folds the unicode dash family (U+2010..U+2015, U+2212) to the ASCII hyphen,
/// and collapses any run of whitespace to a single hyphen — so `cve-2023-9999`,
/// `CVE 2023 9999`, and `CVE‑2023‑9999` (unicode hyphen) all canonicalize to the
/// ASCII `CVE-2023-9999` that [`extract_cve_ids`] looks for. The SAME
/// normalization is applied to the real evidence ids, so a legitimate citation
/// still matches. The result is used only for id matching, never for display.
fn normalize_cve_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev_ws = false;
    for ch in text.chars() {
        let mapped = match ch {
            // Unicode dash family folded to the ASCII hyphen.
            '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2015}'
            | '\u{2212}' => Some('-'),
            c if c.is_whitespace() => None, // handled via run-collapsing below
            c => Some(c.to_ascii_uppercase()),
        };
        match mapped {
            Some(c) => {
                out.push(c);
                prev_ws = false;
            }
            None => {
                // Collapse a whitespace run to a single hyphen so `CVE 2023 9999`
                // reads as the hyphenated form.
                if !prev_ws {
                    out.push('-');
                    prev_ws = true;
                }
            }
        }
    }
    out
}

/// Extract CVE ids (`CVE-<4-digit year>-<4+ digit sequence>`) mentioned in free text,
/// used to check the model's `reason` against the real evidence. Endpoints are ASCII so
/// byte slicing is safe.
pub(crate) fn extract_cve_ids(text: &str) -> Vec<String> {
    let digits = |s: &str| s.bytes().take_while(|b| b.is_ascii_digit()).count();
    let mut ids = Vec::new();
    for (i, _) in text.match_indices("CVE-") {
        let rest = &text[i + 4..];
        if digits(rest) == 4 && rest[4..].starts_with('-') {
            let n = digits(&rest[5..]);
            if n >= 4 {
                ids.push(format!("CVE-{}", &rest[..5 + n]));
            }
        }
    }
    ids
}

/// Shared gate for an `Exploitable`-only backstop: acts ONLY on an `Exploitable`
/// verdict, leaving every other verdict untouched. `check` is handed the model's
/// `Exploitable` reason and returns `Some(downgrade)` to override the verdict, or
/// `None` to let it stand. Used by the one remaining backstop, [`guard_fabricated_cve`]
/// (anti-fabrication), which downgrades a fabricated-CVE citation to `Uncertain`.
fn guard_exploitable(verdict: Verdict, check: impl FnOnce(&str) -> Option<Verdict>) -> Verdict {
    match &verdict {
        Verdict::Exploitable(reason) => check(reason).unwrap_or(verdict),
        _ => verdict,
    }
}

/// Hallucination guard (JEF-79): a small CPU model can copy a CVE id from the prompt's
/// worked examples onto a workload that has none. If it PROMOTES (`Exploitable`) while
/// citing a CVE absent from the entry's real evidence, the citation is fabricated — so
/// downgrade to the skeptic verdict. A hallucinated CVE can then never promote an action;
/// the entry is re-judged next pass. A legitimate `Exploitable` via a non-CVE step (host
/// escape, cross-tenant network) cites no CVE and passes through untouched.
pub(crate) fn guard_fabricated_cve(
    verdict: Verdict,
    real_ids: &std::collections::HashSet<String>,
) -> Verdict {
    // Canonicalize both sides identically (case / unicode dash / spacing) so a
    // cosmetic spelling can neither evade detection nor cause a false positive
    // against a legitimately-cited id.
    let real_ids: std::collections::HashSet<String> =
        real_ids.iter().map(|c| normalize_cve_text(c)).collect();
    guard_exploitable(verdict, |reason| {
        let fabricated: Vec<String> = extract_cve_ids(&normalize_cve_text(reason))
            .into_iter()
            .filter(|c| !real_ids.contains(c))
            .collect();
        (!fabricated.is_empty()).then(|| {
            Verdict::Uncertain(format!(
                "model cited CVE(s) not in the evidence (possible hallucination): {}",
                fabricated.join(", ")
            ))
        })
    })
}

/// Whether a runtime behavior CORROBORATES an exploit — the engine's single shared
/// "alarming-now" definition ([`crate::engine::observe::alarm_class::is_alarming_now`]), NOT a
/// new one: an `Alert` ([`Behavior::is_alert`]), a notable shell/package-manager
/// exec (JEF-117), OR an alarming file write (sensitive-path drop-and-execute / config tamper,
/// JEF-309). Sharing that one predicate with the corroboration and quarantine paths keeps the
/// alarm sources from drifting apart. Benign
/// `NetworkConnection`/`FileRead`/`LibraryLoaded`/`SecretRead` and benign writes (an app's own
/// `/data`/`/tmp`/logs) — a workload's own observed activity — are NOT corroborating and so
/// must never anchor an `exploitable` (the watcher-server false breach: three benign
/// connections to its own DB/metrics were read as a live signal).
fn corroborating_behavior(behavior: &Behavior) -> bool {
    crate::engine::observe::alarm_class::is_alarming_now(behavior)
}

/// Zero-anchor safety net (the symmetric backstop to [`guard_fabricated_cve`]): a 1B judge
/// fabricated an `Exploitable` verdict for the internet-facing `watcher-server` with NO
/// exploitation evidence at all — no CVE was shown, no exposed secret was baked in, and the
/// only runtime behavior was three benign `NetworkConnection`s to its own DB/metrics. It got
/// there by (a) treating benign network connections as a live signal and (b) conflating
/// reaching a `secret/…` objective with an exposed secret in the image. The correct verdict
/// is `refuted`: reachability is not a breach.
///
/// This guard DOWNGRADES an `Exploitable` verdict to `Refuted` ONLY when ALL THREE
/// exploitation anchors are absent:
/// - the CVE evidence list is empty (no CVE was shown to the model), AND
/// - there is no exposed-secret finding for the entry (`has_exposed_secret == false`), AND
/// - no observed behavior is [`corroborating_behavior`] (no alert, no notable exec).
///
/// Be conservative: if ANY anchor is present — a CVE in the list (even
/// reachability:not-observed), an exposed secret, or a corroborating behavior — the model's
/// (debatable) call stands untouched. Those are the model's calls to make, not this guard's
/// to override; this is purely the zero-anchor net. Like the fabrication guard it only ever
/// acts on `Exploitable`, leaving every other verdict alone, and the entry is re-judged next
/// pass.
pub(crate) fn guard_unsupported_exploitable(
    verdict: Verdict,
    cves: &[String],
    behaviors: &[Behavior],
    has_exposed_secret: bool,
) -> Verdict {
    guard_exploitable(verdict, |_reason| {
        let has_cve = !cves.is_empty();
        let has_corroborating = behaviors.iter().any(corroborating_behavior);
        let any_anchor = has_cve || has_exposed_secret || has_corroborating;
        (!any_anchor).then(|| {
            Verdict::Refuted(
                "no exploitation evidence present (no CVE, no exposed secret, no runtime alert) \
                 — reachability is not a breach"
                    .to_string(),
            )
        })
    })
}

/// Wrap an untrusted value in a fence and strip the characters that could close it
/// or inject prompt structure (ADR-0011 — closes the prompt-injection finding). The
/// values come from cluster objects and third-party feeds, so they are data, never
/// instructions.
pub(crate) fn fence(value: &str) -> String {
    format!("<<<{}>>>", sanitize(value).trim())
}

/// Strip the characters an attacker could use to close a fence or inject prompt
/// structure (`<>{}`, backtick, CR/LF). Used to neutralize cluster-controlled
/// names before they enter the adjudication prompt.
pub(crate) fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if "<>{}`\n\r".contains(c) { ' ' } else { c })
        .collect()
}

pub(crate) fn fence_list(values: &[String]) -> String {
    if values.is_empty() {
        "<<<(none)>>>".into()
    } else {
        fence(&values.join(", "))
    }
}

/// JEF-79 — how the entry reaches an objective, derived from the objective node's
/// incoming proof edges. This is the AUTHORIZATION signal that lets the model judge
/// authorization rather than mere identity/breadth (fixing the ArgoCD false positive):
/// `[RBAC-GRANTED]` and `[MOUNTED]` access is authorized-by-design and refuted however
/// broad; only `[NETWORK]` reach into a *different* tenant is unauthorized lateral
/// movement. A secret is reached only via a pod-spec mount (`CanRead`, same-namespace by
/// Kubernetes rule, so the workload's own) or an RBAC grant (`CanDo`); a workload or host
/// objective is reached over the network. Unknown/structural ⇒ NETWORK (conservative: it
/// is not an authorization grant).
pub(crate) fn objective_reach(graph: &SecurityGraph, objective: &NodeKey) -> &'static str {
    let Some(idx) = graph.index_of(objective) else {
        return "NETWORK";
    };
    let g = graph.inner();
    let mut rbac = false;
    for edge in g.edges_directed(idx, petgraph::Direction::Incoming) {
        match &edge.weight().relation {
            // A pod-spec mount is the strongest "own" signal (same namespace by k8s rule).
            Relation::CanRead => return "MOUNTED",
            Relation::CanDo { .. } => rbac = true,
            _ => {}
        }
    }
    if rbac { "RBAC-GRANTED" } else { "NETWORK" }
}

/// JEF-79 — whether an objective sits in the SAME namespace as the entry. The model
/// cannot reliably infer namespace-equality from raw keys (granite4:1b-h misread a
/// same-namespace DB as cross-tenant and falsely promoted it), so we state it explicitly:
/// `same-ns` (the entry's own tenant — a [NETWORK] reach here is normal app topology) vs
/// `cross-ns` (a different tenant — a [NETWORK] reach here is unauthorized lateral
/// movement). Cluster-scoped objectives (host) have no namespace ⇒ `cross-ns`.
/// The namespace seam itself is owned by [`NodeKey::namespace`] (one parser, all consumers).
pub(crate) fn ns_marker(entry: &NodeKey, objective: &NodeKey) -> &'static str {
    match (entry.namespace(), objective.namespace()) {
        (Some(a), Some(b)) if a == b => "same-ns",
        _ => "cross-ns",
    }
}
