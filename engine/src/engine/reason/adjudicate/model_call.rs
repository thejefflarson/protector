//! The model-backed adjudicator: the OpenAI-compatible model call plus the
//! diagnostic judgement log. Split out of the adjudicate module root purely to keep
//! every file under the 1,000-line cap (repo CLAUDE.md). It calls the shared model client
//! with the caller-built prompt (JEF-350 — the same bytes the verdict cache keyed on),
//! assembles the entry's evidence for the deterministic backstops, and runs the remaining
//! backstop (anti-fabrication) over the parsed verdict.

use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{Behavior, NodeKey, SecurityGraph};

use super::evidence::{entry_evidence, entry_findings, reachable_cve_lines};
use super::guards::guard_unsupported_exploitable;
use super::incident::{
    Assessment, IncidentDecision, Menu, guard_assessment_cuts_consistency,
    guard_containment_grounding, guard_fabrication, parse_incident_decision,
};
use super::{Adjudicator, Verdict};

/// The downstream counterpart of the entry's own evidence fetch below (JEF-565): every
/// downstream node on the entry's proven paths is real, structural evidence — same standing as
/// the entry's own — so the anti-fabrication and zero-anchor backstops must ground against it
/// too, exactly as the prompt shows it (same per-node fetch + [`reachable_cve_lines`] filter
/// the downstream prompt blocks use).
fn downstream_backstop_evidence(
    graph: &SecurityGraph,
    downstream: &[NodeKey],
) -> (Vec<String>, bool, Vec<Behavior>) {
    let mut cves = Vec::new();
    let mut has_secret = false;
    let mut behaviors = Vec::new();
    for node in downstream {
        let (node_cves, node_behaviors) = reachable_cve_lines(graph, node);
        cves.extend(node_cves);
        behaviors.extend(node_behaviors);
        let (secret_lines, _posture) = entry_findings(graph, node);
        has_secret |= !secret_lines.is_empty();
    }
    (cves, has_secret, behaviors)
}

/// A model-backed adjudicator (OpenAI-compatible endpoint via [`crate::engine::model`]).
pub struct ModelAdjudicator {
    endpoint: String,
    model: String,
    client: reqwest::Client,
    /// Optional diagnostic sink: every judgement's full prompt, raw reply, and
    /// verdict, recorded into the judgement log for inspection. `None` outside the
    /// long-running engine (tests, the timer path) so journaling never affects the verdict.
    journal: Option<std::sync::Arc<crate::engine::state::JudgementLog>>,
}

impl ModelAdjudicator {
    pub fn new(endpoint: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            model: model.into(),
            client: crate::engine::model::client(),
            journal: None,
        }
    }

    /// Attach a diagnostic judgement log; the adjudicator records each judgement's
    /// prompt/reply/verdict into it for inspection.
    pub fn with_journal(
        mut self,
        journal: std::sync::Arc<crate::engine::state::JudgementLog>,
    ) -> Self {
        self.journal = Some(journal);
        self
    }

    /// Record a judgement into the diagnostic log, if one is attached. Logs the legacy
    /// [`Verdict`] shape (via [`IncidentDecision::to_verdict`]) so the diagnostic record's
    /// format is unchanged (JEF-570) — the cuts themselves are the caller's `judge` return.
    fn record_judgement(
        &self,
        entry: &NodeKey,
        objectives: usize,
        prompt: Option<String>,
        reply: Option<String>,
        decision: &IncidentDecision,
    ) {
        if let Some(journal) = &self.journal {
            journal.record(crate::engine::state::Judgement {
                entry: entry.0.clone(),
                objectives,
                verdict: format!("{:?}", decision.to_verdict()),
                prompt,
                reply,
            });
        }
    }
}

/// ADR-0034 D5 (grandfathered): the zero-anchor backstop
/// ([`guard_unsupported_exploitable`]), reused UNCHANGED by round-tripping an `Attack`
/// decision through the legacy [`Verdict`] shape it operates on — no reimplementation. A
/// zero-anchor `Attack` (no CVE, no exposed secret, no corroborating behavior anywhere in the
/// entry+downstream evidence this call already fetched) downgrades all the way to `NoAttack`
/// (the old `Refuted`), never merely `Uncertain`: reachability alone was never a breach, so
/// there is nothing here to re-judge later, exactly the pre-ADR-0034 behavior. Every other
/// assessment passes through untouched — this only ever narrows an `Attack`.
fn guard_zero_anchor(
    decision: IncidentDecision,
    cves: &[String],
    behaviors: &[Behavior],
    has_exposed_secret: bool,
) -> IncidentDecision {
    if decision.assessment != Assessment::Attack {
        return decision;
    }
    let verdict = guard_unsupported_exploitable(
        Verdict::Exploitable(decision.reason.clone()),
        cves,
        behaviors,
        has_exposed_secret,
    );
    match verdict {
        Verdict::Refuted(reason) => IncidentDecision {
            assessment: Assessment::NoAttack,
            reason,
            cuts: Vec::new(),
        },
        // `guard_unsupported_exploitable` only ever returns the verdict unchanged or
        // downgrades it to `Refuted` — no other arm is reachable.
        _ => decision,
    }
}

#[async_trait::async_trait]
impl Adjudicator for ModelAdjudicator {
    #[tracing::instrument(
        name = "engine.adjudicate",
        skip_all,
        fields(model = %self.model, entry = %entry.0, objectives = objectives.len())
    )]
    async fn judge(
        &self,
        entry: &NodeKey,
        objectives: &[(NodeKey, AttackRef)],
        graph: &SecurityGraph,
        prompt: &str,
        downstream: &[NodeKey],
        menu: &Menu,
    ) -> IncidentDecision {
        // Fetch the entry's evidence ONCE for the two anti-fabrication backstops. JEF-134:
        // the deterministic layer PROVES + ENRICHES only — there is no pre-call decision
        // filter and no deterministic promotion-ground gate. EVERY breach-relevant entry's
        // proven chain + enrichment is handed to the model, which decides breach holistically.
        // Authorized access (RBAC/mounted), however broad or high-severity, is not a breach
        // without exploitation evidence; that call is the model's, not the engine's. The ONE
        // remaining backstop is anti-fabrication (guard_fabricated_cve), not a decision gate.
        let (mut cves, mut behaviors) = entry_evidence(graph, entry);
        // Exposed-secret presence for the zero-anchor backstop, read from the SAME source the
        // prompt uses (`entry_findings` → `(secret_lines, posture_lines)`): a non-empty
        // `secret_lines` means a usable credential is baked into the image. Posture (misconfig
        // / RBAC) is NOT an exploitation anchor, so it is ignored here.
        let (secret_lines, _posture_lines) = entry_findings(graph, entry);
        let mut has_exposed_secret = !secret_lines.is_empty();
        // JEF-565: the prompt now shows a fenced evidence block for every DOWNSTREAM workload on
        // the entry's proven paths too, not just the entry — so a genuine downstream CVE/secret/
        // behavior citation is real, grounded evidence and must not trip the anti-fabrication or
        // zero-anchor backstops below. Fold it into the SAME real-evidence sets those backstops
        // already check, exactly as the downstream prompt blocks render it.
        let (downstream_cves, downstream_has_secret, downstream_behaviors) =
            downstream_backstop_evidence(graph, downstream);
        cves.extend(downstream_cves);
        has_exposed_secret |= downstream_has_secret;
        behaviors.extend(downstream_behaviors);

        // JEF-350: the caller already built this exact prompt to derive the verdict-cache key
        // (its hash); reuse those bytes for the model call rather than rebuilding, so the input
        // the cache keyed on and the input the model sees can never drift.
        let (reply, decision) =
            match crate::engine::model::chat(&self.client, &self.endpoint, &self.model, prompt)
                .await
            {
                Some(reply) => {
                    // The tolerant, skeptic-default parser (ADR-0034 D3): unparseable/out-of-
                    // range/non-member `contain` all degrade to Uncertain, no cuts — the
                    // membership check against `menu` is the structural grounding guard.
                    let decision = parse_incident_decision(&reply, menu);
                    // The ADR-0034 D5 grounding guards, chained (all downgrade to `Uncertain`,
                    // never `Refuted`/carry a hidden line of evidence): a contained downstream
                    // node with no exploitation evidence of its own, then the reused
                    // anti-fabrication backstops (a fabricated CVE id, or a fabricated
                    // `[reachability: loaded-at-runtime]` tag — JEF-451 G1) over the
                    // entry+downstream evidence union, then the assessment↔cuts consistency
                    // check (idempotent — the parser already enforces it).
                    let decision = guard_containment_grounding(decision, graph, entry);
                    let decision = guard_fabrication(decision, graph, entry, downstream);
                    let decision = guard_assessment_cuts_consistency(decision);
                    // Grandfathered zero-anchor backstop (ADR-0029 scope note): an `Attack`
                    // resting on NO anchor at all (no CVE, no exposed secret, no corroborating
                    // behavior anywhere in the entry+downstream evidence) downgrades all the way
                    // to `NoAttack`, not merely `Uncertain` — reachability alone was never a
                    // breach, so there is nothing to re-judge later (the watcher-server false
                    // breach this backstop was built for).
                    let decision =
                        guard_zero_anchor(decision, &cves, &behaviors, has_exposed_secret);
                    (Some(reply), decision)
                }
                // Model unavailable → skeptic: do not let an auto-action proceed.
                None => (None, IncidentDecision::uncertain("model unavailable")),
            };
        // Capture the prompt the model saw, its raw reply, and the guarded decision so an
        // `attack` call can be diagnosed from the judgement record (JEF diagnostic).
        self.record_judgement(
            entry,
            objectives.len(),
            Some(prompt.to_string()),
            reply,
            &decision,
        );
        decision
    }
}
