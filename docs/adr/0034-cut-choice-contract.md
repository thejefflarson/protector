# 0034. The cut-choice contract: the model names the compromised nodes; determinism resolves the narrowest cut

- Status: Proposed
- Date: 2026-07-28

## Context

[ADR-0032](0032-model-is-incident-responder.md) makes the model the incident responder but
left its **decision output** sketched as a *menu of mechanisms* (§3: the model emits
`cuts:[menu-id…]` selecting `QuarantineEntry` / `QuarantineWorkload` / `DenyNetworkPath`
edge-cut lines). Two things force that open question closed and, on examination, redirect it:

1. **The judge is a 1.7B CPU model, first (re-scope).** The parent plan assumed a 4B
   judge ("do not assume 1.7b"). Re-scoped: qwen3:1.7b is the deployed judge and passes the
   current 4-value verdict (14/15 this session, the miss a mislabeled fixture; ADR-0026 12/12).
   The contract must be one **1.7b can emit reliably** — strict JSON, correct ids, correct
   minimality, no over-cut at temp>0 — or the refactor lands unarmed. Escalate to 4B/8B only
   on measured failure.
2. **Mechanism choice is not a judgment (current vocabulary).** For any one target, minimality
   is monotone and deterministically computable — entry: surgical `DenyNetworkPath` ⊂
   `QuarantineEntry` (the `containment_for` ladder); downstream compromised workload:
   `QuarantineWorkload` is the *only* additive-live lever. No two incomparable mechanisms for
   one target ⇒ nothing to delegate. ADR-0032's own rail says the model chooses **what**, the
   rails bound **how** — mechanism is *how*.

Option A (model picks mechanism ids) therefore front-loads the hardest cognitive task (pick
from 2^N opaque-id subsets, comparing mechanisms) onto the weakest link, **for zero authority
gained** — and its membership guard has no teeth against the worst small-model failure:
every menu entry is legal by construction, so "select the whole list" passes every check.

## Decision

**The model names the compromised nodes; determinism resolves each to its narrowest legal
cut.** (Option B. Supersedes ADR-0032 §3's mechanism-menu; ADR-0032's vocabulary, shapes,
ladder, and entry-exclusion all survive as the resolver + fallback.)

1. **Output schema (the contract):**
   ```json
   {"assessment": "attack" | "no_attack" | "uncertain",
    "reason": "<one sentence>",
    "contain": ["<node-key>", ...]}
   ```
   `contain` elements are **workload node keys copied verbatim** from the containment-options
   section (entry and/or downstream workloads). Empty array = leave everything running.
   `attack` + empty `contain` is **valid** ("attack, but no cut warranted") and routes to the
   human-proposal fallback. Internal type: `IncidentDecision { assessment: Assessment, reason:
   String, cuts: Vec<ChosenCut> }`, `ChosenCut { node: NodeKey, action: ProposedAction,
   cut_signature: String }` — cuts are resolved by the engine from `contain`, never carried as
   model text.

2. **The 4-value `Verdict` collapses to a 3-value `Assessment`** (`attack` / `no_attack` /
   `uncertain`). `Confirmed` vs `Exploitable` encoded a *deterministic* fact (is there a live
   signal) into the model's vocabulary; that fact lives in `ProvenChain::corroborated` and
   never needed the model to restate it. Fewer output values = fewer temp>0 boundary flips.

3. **Tolerant parser, skeptic default.** Extract first `{`…last `}`; any JSON failure →
   `(uncertain, no cuts)`. Then: `assessment` out of range → uncertain/no-cuts; `contain`
   absent → `[]`; non-array or non-string element → uncertain/no-cuts; normalize each element
   (trim, strip echoed `<<< >>>` fencing) and **exact-match the selectable menu set** — any
   non-member degrades the **whole** decision to uncertain/no-cuts (a partially hallucinated
   list is ungrounded reasoning); dedup+sort; `assessment ∈ {no_attack, uncertain}` with
   non-empty `contain` → uncertain/no-cuts + re-judge. **Every degradation is `Uncertain` —
   never `Refuted`, never a hidden line of evidence (ADR-0029).**

4. **The menu render (advisory input, pure reuse).** Per entry-incident, one selectable line
   per containable on-path workload: the **entry line** (mechanism = `containment_for`'s
   ladder result — surgical edge-cut if an additive-reversible one exists, else
   `QuarantineEntry`), and one **downstream line** per evidence-bearing workload
   `quarantine_targets_on_path` marks (mechanism = `QuarantineWorkload`). Entry-exclusion from
   the workload-quarantine set preserved (ADR-0022). Each line: fenced node key, fixed-string
   mechanism (`ProposedAction::describe` — no untrusted text in action words), and a
   `predict_blast_radius` note (advisory; the actuator's blast gate still runs
   post-decision). Only additive-live + reversible + labeled targets are **selectable**;
   evidence-bearing-but-uncontainable nodes get one aggregate **non-selectable** line so the
   model isn't baited into naming them. Deterministic render (sorted, deduped, same snapshot)
   ⇒ the menu is part of the full-state prompt ⇒ `prompt_cache_key` covers it: a mapping
   change is a prompt change is a re-judge (ADR-0023 unchanged).

5. **Grounding guards (all ADR-0029-admissible; all → Uncertain + re-judge, never Refuted):**
   menu-membership (structural, §3); **per-node containment grounding** — a contained
   *downstream* node whose own block is "no evidence observed" downgrades (the "never contain
   a merely-reached node" rule enforced as citation-grounding; the *entry* is exempt — any
   evidence on its path grounds containing the front door, per ADR-0022); CVE/tag grounding
   (`guard_fabricated_cve` / `guard_fabricated_reachability_tag` over the entry+downstream
   union, unchanged); assessment↔cuts consistency (§3). `guard_unsupported_exploitable`
   (zero-anchor → Refuted) is grandfathered by ADR-0029's scope note.

6. **Ledger consumption (strengthened Q5).** `MitigationLedger::reconcile` takes per-entry
   decisions as input. Desired set = model-chosen cuts whose entry still has a proven
   justifying chain (they clear the auto-action gate), **plus** `containment_for`
   fallback proposals for every breach-relevant entry with *no current decisive decision*
   (model unavailable / uncertain / parse-degraded), stamped `adjudicated=false` so they can
   never auto-apply. The deterministic `quarantine_targets` desired-set insertion in
   `reconcile` is **deleted** (completing the ADR-0032 auto-fire removal). `containment_for`
   is thereby demoted to exactly the human-proposal fallback.

7. **Retirement asymmetry (safety-critical).** A cut self-retires when (a) no proven chain
   justifies it, or (b) a **fresh decisive decision** for its entry omits it. A fresh
   `Uncertain` retires **nothing** and cuts nothing — the skeptic default is inert in both
   directions, so a transient model outage can neither open a live attack path nor sever one.

8. **Journal schema v2 (replay can't repoint a cut).** New tagged variant `IncidentDecision {
   entry, objectives, assessment, reason, cuts:[{node, action, cut_signature}], menu_hash,
   fingerprint }` — cuts resolved *at decision time*. Two locks: re-seeding the cache requires
   the current full-prompt `fingerprint` to match (fingerprint ⊇ menu, so a shifted mapping
   cold-re-judges); re-arming a cut requires the *recomputed* node→action resolution to yield
   the stored `cut_signature` byte-identically (a label/ladder drift drops the cut and
   cold-re-judges). Old `Breach` lines replay display-only; entries cold-re-judge for cuts
   (accepted ~20-min startup cost).

9. **Prompt shape.** Holistic single document, **no few-shot, no numbered procedure**.
   The containment-options section goes **last, immediately before the output instruction**
   (recency maximizes copy fidelity). The word "quarantine" appears only inside fixed mechanism
   strings, never in the instructions (— don't make the cut words the most-primed
   n-grams). `incident/` module dir keeps every file < 1000 lines.

10. **Transport unchanged; constrained decoding is escalation step 1, not a dependency.** Keep
    the current call + tolerant parser. If T2b's failing bar is *JSON validity* (not content),
    the first escalation is Ollama grammar-constrained structured output (native `format`
    schema), A/B'd like any prompt change. Only if *content* fails does the model tier escalate
    (4B → 8B), → recorded in ADR-0033.

## Consequences

- **T3** builds against a fixed target (D1–D9); its Option-A description is
  superseded. **T2b** extends the bakeoff to score assessment (ground truth remapped
  4→3), cut-set (exact-set primary), the refute traps (incl. downstream-CVE-only must not
  appear in `contain`), minimality, and **temp-0.8 over-cut mass** (the one metric guards
  can't backstop), and gates the judge on the deployed 1.7B before wiring.
- **The residual risk is grounded over-cut** — a reversible, blast-gated, shadow-default
  proposal in the worst case. The rails (shadow-default, blast/alive-collateral gate,
  reversible/additive + self-revert, enforceScope) hold; the bench is what tells us whether
  1.7B's over-cut mass is acceptable.
- **Model unavailable** ⇒ fallback proposals only; standing cuts persist until chain-clear
  (§7's deliberate asymmetry).
- **ADR-0034 supersedes ADR-0009's corroboration-alone auto-cut**: under enforce mode with no
  live model, determinism only *proposes* (the `containment_for` fallback, stamped
  `adjudicated=false`) — nothing auto-cuts on live corroboration by itself anymore. Only a
  model's decisive `attack` naming a node (§1/§6) arms an auto-eligible cut now.
- Refines [ADR-0032](0032-model-is-incident-responder.md) §3 (mechanism-menu → target-choice)
  and its 4-value output (→ 3-value). Judge tier remains [ADR-0033] (pending T2b).
- Deferred: edge-granular downstream cuts (no actuator lever — the schema versions forward via
  an optional qualifier, so B forecloses nothing); model-chosen mechanism (revisit only if the
  vocabulary ever holds two incomparable mechanisms for one target); internal-only incidents
  stay propose-only (ADR-0032).
