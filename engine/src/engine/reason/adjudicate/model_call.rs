//! The model-backed adjudicator: the OpenAI-compatible model call plus the
//! diagnostic judgement log. Split out of the adjudicate module root purely to keep
//! every file under the 1,000-line cap (repo CLAUDE.md). It assembles the entry's
//! evidence ONCE, builds the prompt, calls the shared model client, and runs the one
//! remaining deterministic backstop (anti-fabrication) over the parsed verdict.

use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{NodeKey, SecurityGraph};

use super::evidence::{cve_ids_of, entry_evidence};
use super::guards::guard_fabricated_cve;
use super::prompt::{build_judgment_prompt_with, parse_verdict};
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
    ) -> Verdict {
        // Fetch the entry's evidence ONCE; the prompt and the anti-fabrication backstop
        // share it. JEF-134: the deterministic layer PROVES + ENRICHES only — there is no
        // pre-call decision filter and no deterministic promotion-ground gate. EVERY
        // breach-relevant entry's proven chain + enrichment is handed to the model, which
        // decides breach holistically. Authorized access (RBAC/mounted), however broad or
        // high-severity, is not a breach without exploitation evidence; that call is the
        // model's, not the engine's. The ONE remaining backstop is anti-fabrication
        // (guard_fabricated_cve), not a decision gate.
        let (cves, behaviors) = entry_evidence(graph, entry);

        let prompt = build_judgment_prompt_with(entry, objectives, graph, &cves, &behaviors);
        let (reply, verdict) =
            match crate::engine::model::chat(&self.client, &self.endpoint, &self.model, &prompt)
                .await
            {
                // The sole deterministic backstop on a promotion is anti-fabrication (JEF-79):
                // a fabricated CVE citation can never auto-promote (→ skeptic). This is NOT a
                // breach-decision gate — it only ensures the model cannot cite a CVE absent
                // from the real evidence. A genuine `Exploitable` (a real CVE, or a non-CVE
                // step that cites no CVE) passes through untouched.
                Some(reply) => {
                    let verdict = guard_fabricated_cve(parse_verdict(&reply), &cve_ids_of(&cves));
                    (Some(reply), verdict)
                }
                // Model unavailable → skeptic: do not let an auto-action proceed.
                None => (None, Verdict::Uncertain("model unavailable".to_string())),
            };
        // Capture the prompt the model saw, its raw reply, and the guarded verdict so an
        // `exploitable` call can be diagnosed from the judgement record (JEF diagnostic).
        self.record_judgement(entry, objectives.len(), Some(prompt), reply, &verdict);
        verdict
    }
}
