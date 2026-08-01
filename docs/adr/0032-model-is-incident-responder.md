# 0032. The model is the incident responder: it decides the cut from a proven action menu

- Status: Proposed
- Date: 2026-07-27
- Refined by [ADR-0034](0034-cut-choice-contract.md): §3's *mechanism-menu* (`cuts:[menu-id]`)
  becomes **target-choice** (`contain:[node-key]` — the model names the compromised nodes,
  determinism resolves each to its narrowest legal cut), and the 4-value verdict collapses to
  a 3-value assessment. This ADR's vocabulary/shapes/ladder/entry-exclusion all survive as the
  resolver + proposal fallback.

## Context

The thesis ([ADR-0013](0013-proof-winnows-model-decides.md), reaffirmed
[ADR-0029](0029-adjudication-verdict-is-authoritative.md)) is "proof winnows, the model
decides." The code honors it for the entry lane and violates it downstream in three verified
ways: (1) the adjudication prompt is entry-scoped — a popped pod two hops in is invisible to
the judge; (2) `RemotelyExploitable` (reachability + CVE *presence*) and `ActivelyExploited`
(a deterministic live signal) both auto-fire via `is_live_corroborated`'s unconditional
`true` for `QuarantineWorkload` — the model is never consulted (see the amendment to
[ADR-0022](0022-quarantine-the-entry-is-the-default-containment.md)); (3) the model emits
only a 4-value verdict and chooses no cut (scope is the deterministic `containment_for`
precedence). Operator rationale: *"if determinism worked, someone would have solved this
problem already"* — extends ADR-0029's anti-deterministic-override argument to the cut
decision itself. The VISION north star names this: the model is the incident responder.

## Decision

1. **The model is the incident responder.** Per internet-facing entry, it judges the whole
   proven attack path and decides containment. Determinism **proves + enriches + feeds +
   bounds; it does not decide the cut.**
2. **It sees the whole incident** — per-node evidence blocks (loaded-at-runtime CVEs, exposed
   secrets, on-box behavior) for the entry *and* each downstream workload on a proven path
   (via the existing `entry_evidence`/`entry_findings` accessors), plus the objectives list.
3. **Decision is menu-choice, not free-form.** Determinism enumerates the *legal* cuts
   (`QuarantineEntry`, `QuarantineWorkload`-per-node, `DenyNetworkPath` edge-cut,
   leave-alone) — each a menu line with a content-derived id, mechanism, target, and a
   deterministic blast-radius note; only actuator-legal (additive-live, reversible, labeled)
   entries are selectable. Model output: `{assessment: attack|no_attack|uncertain, reason,
   cuts:[menu-id…]}`, instructed to the fewest/narrowest cuts (empty = leave everything).
4. **Grounding guards** (ADR-0029-admissible; downgrade to `Uncertain`, never `Refuted`):
   cited CVE/tag must exist in *that node's* evidence; every cut id must be in the menu;
   assessment↔cuts inconsistency → `Uncertain` + re-judge. Membership checks are grounding,
   not verdict overrides.
5. **Determinism demoted:** `quarantine_targets_on_path` stops deciding — it marks
   evidence-bearing path nodes and seeds the menu. `containment_for` becomes the
   **human-proposal fallback** when the model is unavailable/uncertain (nothing auto-fires
   without the model). The `is_live_corroborated` unconditional-`true` branch is **deleted**.
6. **Internal-only actively-exploited pods (no internet path) → propose-only** — outside the
   north star's two lanes; retires the auto-cut asymmetry in the north-star
   direction.
7. **Rails unchanged (deterministic):** shadow-default + per-class arming + `enforceScope`
   ([ADR-0021](0021-two-setting-operating-posture.md)); blast-radius/alive-collateral gate;
   reversible/additive-only + self-revert ([ADR-0017](0017-isolation-persists-on-the-breach-condition.md));
   zero-egress; fenced/budgeted untrusted text; view-never-gates
   ([ADR-0016](0016-severity-vs-urgency.md)).

Supersedes **[ADR-0022](0022-quarantine-the-entry-is-the-default-containment.md)'s
amendment *as a decision procedure*** (the per-pod deterministic bar is no longer the
auto-action trigger; internal-only pods become propose-only) — its containment vocabulary,
additive/reversible shapes, and precedence ladder survive as the menu's ordering/annotation
and the proposal fallback. **Evolves [ADR-0009](0009-asymmetric-action-bar.md)**: the
adjudicator moves from a one-way veto over a deterministically-selected action to the
*selector* of the cut; the `corroborated ∧ adjudicated` auto-gate survives and is extended to
the whole path (the `QuarantineWorkload` unconditional auto-fire that bypassed it is removed).
Resolves ****. The responder **judge tier** is deferred to **ADR-0033**
pending the extended bakeoff (do **not** assume qwen3:1.7b; expected qwen3:4b).

## Consequences

- The model decides what to cut over the whole path — the north star realized. Worst case of
  a wrong decision is unchanged: a transient, reversible, blast-gated cut of one workload
  (the rails hold).
- **New failure class:** a tail-flip changes *which cut* is armed, not just a verdict —
  bounded by additive/reversible/self-revert + decisive-only caching + journaled decisions.
- **The Q5 invariant strengthens:** active controls = the model-chosen subset of cuts
  currently justified by proven chains (self-retire on chain-clear *or* a fresh decision
  dropping it).
- The prompt grows per evidence-bearing downstream node (bounded by evidence-only blocks +
  per-incident budgets); the wide-entry case (~110 objectives) is a required bakeoff fixture.
- **Journal schema v2** — decision + menu-id mapping stored together so a replay can't
  silently repoint a cut; old entries cold-re-judge (a known ~20-min startup cost).
- Model-capacity: the responder task is larger than today's verdict; this ADR does **not**
  keep qwen3:1.7b by default — the judge is chosen by ADR-0033 after the extended bakeoff.
