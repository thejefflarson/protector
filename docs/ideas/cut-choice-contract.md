# Idea — the incident-responder cut-choice contract

**Status:** decided (2026-07-28). Realized by [ADR-0034](../adr/0034-cut-choice-contract.md);
refines [ADR-0032](../adr/0032-model-is-incident-responder.md) §3. Sprint tickets:
(bench) (build) (shadow+arm), plus the new `incident/` module chunk.

## Idea

Fix the output shape + machinery by which the model decides **what to cut** along an
internet-facing attack path — the [ADR-0032](../adr/0032-model-is-incident-responder.md)
keystone left open. Settle the "minimality fork" so T3 can build it and T2b can score it.

## Problem & context

ADR-0032 commits protector to "the model is the incident responder" but left the decision
contract's exact shape open, sketched as a *menu of mechanisms* (Option A). The re-scoped
constraint (**qwen3:1.7b-first**, escalate only on measured failure) invalidates the
parent idea's "plan of record: 4B." The contract must be one a **1.7B CPU judge can emit
reliably**, or the refactor lands unarmed. Everything around it is settled: per-node
downstream evidence in the prompt (live), the uniform auto-action gate (
live in `respond/mod.rs::is_live_corroborated`), the delta/cache gate (ADR-0023),
grounding-guard doctrine (ADR-0029). Only the decision output and its consumers remain.

## Assumptions challenged

1. **"A menu-of-mechanisms is what ADR-0032's authority requires" — overclaimed.** ADR-0032's
   own rail: the model chooses *what*; the rails bound *how*. Mechanism (edge-cut vs
   quarantine) is *how*. The model's authority is over *what is an attack / what to cut /
   what to leave* — **targets**, not which NetworkPolicy shape severs them.
2. **"Mechanism choice involves judgment" — false for the current actuator vocabulary.** For
   any one target, minimality is **monotone and deterministically computable**: for the
   entry, surgical edge-cut ⊂ entry-quarantine (the existing `containment_for` ladder); for a
   downstream compromised workload, `QuarantineWorkload` is the *only* additive-live lever.
   No two incomparable mechanisms exist for one target → no judgment left to delegate. Asking
   a 1.7B to pick the mechanism is asking it to re-derive a theorem, at tail-flip risk, for
   zero authority gained.
3. **"1.7b can produce the cut contract" — shaky but shapeable.** It provably does the 4-value
   verdict (14/15 this session; ADR-0026 12/12). Its documented failures are n-gram parroting
   of primed instruction phrases and size-correlated tail-flips at temp>0
   (ADR-0029). Both hit an *opaque-id, mechanism-comparing* output (A) far harder than a
   *copy-the-node-key-you-just-analyzed* output (B). Choose the contract that sits inside what
   it provably does; T2b decides whether it holds.

## Approaches considered

- **A — model chooses cuts from a mechanism menu** (`cuts:[menu-id…]`). Rejected: output space
  explodes from 4 verdict values to 2^N cut subsets (every temp>0 flip has N places to land);
  "fewest/narrowest" is exactly the comparative instruction small models drop; and crucially
  **the menu-membership guard has no teeth against over-cut** — every menu entry is legal by
  construction, so "select the whole list" (the worst parrot failure) passes every check.
- **B — model names the compromised nodes; determinism maps node → narrowest legal action**
  (`contain:[node-key…]`). The selector is a node key the model just reasoned over in that
  node's own evidence block (copy-from-attended-context — the one structured act small
  transformers do reliably). Output space is the on-path node set (~2–6), not mechanism×node.
  The grounding guard gains real teeth: *a contained downstream node must carry evidence in
  its own block* (closed membership, ADR-0029-admissible) — catches most over-cut
  mechanically. **Chosen.**
- **C — two calls (assess, then cut).** Rejected: re-carries full evidence (same context
  cost), doubles CPU latency per positive, splits the cache/delta machinery, and breaks the
  single-document holism the parent idea already chose.

## Decision — B, with the menu rendered into the prompt as *advisory* context

The model **sees** a deterministic per-node containment menu (resolved mechanism +
blast-radius note — a responder should weigh collateral), but its **output names targets, not
mechanisms**. Not a hedge — it's B with honest inputs. It wins on all three axes in priority
order: (1) smallest delta from the proven 4-value contract → 1.7B-viable; (2) genuine
north-star authority (the model decides what's an attack, which nodes are in it, what to
leave, and that empty-set is legal — determinism only renders each chosen target into its
narrowest actuator-legal object, the *how* ADR-0032 already assigns to the rails); (3)
node keys are the most content-derived ids possible → replay-safe. Closed vocabulary
throughout; no free-form action ever. "Edge-cut the entry, don't quarantine it" is preserved:
`contain:[entry]` resolves through the ladder to the surgical edge-cut when one exists.

See [ADR-0034](../adr/0034-cut-choice-contract.md) for the full contract (schema, parser,
menu render, guards, ledger, journal v2, prompt shape, file plan) — reproduced there as the
authoritative record.

## The one genuinely open risk

**Grounded over-cut** — the model contains a node that *is* evidenced but should have been
left running. No guard can catch it (it passes every grounding check); only the **temp-0.8
over-cut-mass** metric sees it, and the worst case is a reversible, blast-gated,
shadow-default *proposal* — the rails hold. This is exactly what T2b's bench measures on the
deployed 1.7B; it is the honest gate on "does 1.7B hold or do we escalate."

## Sequence

1. `incident/` module (types / menu resolver / parser / guards) — **pure, exhaustively
   unit-tested, no engine wiring; unblocked NOW** (depends on the contract, not the judge
   tier).
2. Prompt splice + bakeoff sync + **T2b bench on the deployed 1.7B → ADR-0033** (the gate,
   *before* wiring).
3. Engine wiring: `adj_pass` folds `IncidentDecision`; `reconcile` consumes decisions +
   `containment_for` demotion + delete the deterministic quarantine desired-path.
4. Journal v2 + replay locks.
5. Shadow bake with a model-chosen-vs-`containment_for` comparator; arm per class (ADR-0021).

## Handoff

Tracker tickets already exist for this work — this brief **reconciles** them to B rather than
creating new ones; the one addition is the pure `incident/` module as the unblocked first
chunk. The Option-A description above is superseded by ADR-0034.
