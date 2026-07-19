//! The model-backed adjudicator: the OpenAI-compatible model call plus the
//! diagnostic judgement log. Split out of the adjudicate module root purely to keep
//! every file under the 1,000-line cap (repo CLAUDE.md). It calls the shared model client
//! with the caller-built prompt (JEF-350 — the same bytes the verdict cache keyed on),
//! assembles the entry's evidence for the deterministic backstops, and runs the remaining
//! backstop (anti-fabrication) over the parsed verdict.

use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{NodeKey, SecurityGraph};

use super::evidence::{cve_ids_of, entry_evidence, entry_findings};
use super::guards::{
    guard_fabricated_cve, guard_fabricated_reachability_tag, guard_unsupported_exploitable,
};
use super::prompt::parse_verdict;
use super::{Adjudicator, Verdict};

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

    /// Record a judgement into the diagnostic log, if one is attached.
    fn record_judgement(
        &self,
        entry: &NodeKey,
        objectives: usize,
        prompt: Option<String>,
        reply: Option<String>,
        verdict: &Verdict,
    ) {
        if let Some(journal) = &self.journal {
            journal.record(crate::engine::state::Judgement {
                entry: entry.0.clone(),
                objectives,
                verdict: format!("{verdict:?}"),
                prompt,
                reply,
            });
        }
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
    ) -> Verdict {
        // Fetch the entry's evidence ONCE for the two anti-fabrication backstops. JEF-134:
        // the deterministic layer PROVES + ENRICHES only — there is no pre-call decision
        // filter and no deterministic promotion-ground gate. EVERY breach-relevant entry's
        // proven chain + enrichment is handed to the model, which decides breach holistically.
        // Authorized access (RBAC/mounted), however broad or high-severity, is not a breach
        // without exploitation evidence; that call is the model's, not the engine's. The ONE
        // remaining backstop is anti-fabrication (guard_fabricated_cve), not a decision gate.
        let (cves, behaviors) = entry_evidence(graph, entry);
        // Exposed-secret presence for the zero-anchor backstop, read from the SAME source the
        // prompt uses (`entry_findings` → `(secret_lines, posture_lines)`): a non-empty
        // `secret_lines` means a usable credential is baked into the image. Posture (misconfig
        // / RBAC) is NOT an exploitation anchor, so it is ignored here.
        let (secret_lines, _posture_lines) = entry_findings(graph, entry);
        let has_exposed_secret = !secret_lines.is_empty();

        // JEF-350: the caller already built this exact prompt to derive the verdict-cache key
        // (its hash); reuse those bytes for the model call rather than rebuilding, so the input
        // the cache keyed on and the input the model sees can never drift.
        let (reply, verdict) =
            match crate::engine::model::chat(&self.client, &self.endpoint, &self.model, prompt)
                .await
            {
                // The sole deterministic backstop on a promotion is anti-fabrication (JEF-79):
                // a fabricated CVE citation can never auto-promote (→ skeptic). This is NOT a
                // breach-decision gate — it only ensures the model cannot cite a CVE absent
                // from the real evidence. A genuine `Exploitable` (a real CVE, or a non-CVE
                // step that cites no CVE) passes through untouched.
                Some(reply) => {
                    // Two deterministic backstops, chained, both only ever acting on an
                    // `Exploitable` verdict: anti-fabrication first (a cited CVE absent from the
                    // evidence → skeptic), then the symmetric zero-anchor net (an `Exploitable`
                    // with NO CVE, NO exposed secret, and NO corroborating runtime behavior →
                    // `Refuted`, since reachability is not a breach — the watcher-server false
                    // breach). Order is harmless: the fabrication guard only fires when a CVE is
                    // cited, the unsupported guard only when no anchor exists.
                    let verdict = guard_fabricated_cve(parse_verdict(&reply), &cve_ids_of(&cves));
                    // JEF-451 (G1): a cited-real-id Exploitable that fabricates the
                    // `[reachability: loaded-at-runtime]` TAG the evidence doesn't carry → skeptic.
                    // Grounding/integrity, not a breach gate (ADR-0029 scope-note); reads the same
                    // rendered `cves` strings the prompt shows.
                    let verdict = guard_fabricated_reachability_tag(verdict, &cves);
                    let verdict = guard_unsupported_exploitable(
                        verdict,
                        &cves,
                        &behaviors,
                        has_exposed_secret,
                    );
                    (Some(reply), verdict)
                }
                // Model unavailable → skeptic: do not let an auto-action proceed.
                None => (None, Verdict::Uncertain("model unavailable".to_string())),
            };
        // Capture the prompt the model saw, its raw reply, and the guarded verdict so an
        // `exploitable` call can be diagnosed from the judgement record (JEF diagnostic).
        self.record_judgement(
            entry,
            objectives.len(),
            Some(prompt.to_string()),
            reply,
            &verdict,
        );
        verdict
    }
}
