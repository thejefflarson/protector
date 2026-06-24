# 0017. Isolation persists on the breach condition: chain ∧ enrichment fingerprint

- Status: Accepted
- Date: 2026-06-24
- Amends: [0016](0016-severity-vs-urgency.md) (§3 — refines "persists until (1) or (2) clears"), [0009](0009-asymmetric-action-bar.md) (the revert condition is the breach condition, not a fixed timer)

## Context

[ADR-0016](0016-severity-vs-urgency.md) §3 says the isolation cut "persists until (1)
or (2) clears" — the chain is removed *or* the enrichment clears — and
[ADR-0009](0009-asymmetric-action-bar.md) established the action as self-reverting (the
revert condition is the breach condition, not a fixed timer). Both state the *what*.
This ADR fixes the *how*: precisely what the mitigation ledger keys its revert on, and
how the change-driven loop ([ADR-0002](0002-change-driven-ir-loop.md)) detects that the
breach condition no longer holds.

The gap is concrete. Today `respond/mod.rs::MitigationLedger::reconcile` reverts on the
**chain** alone: the active set "becomes exactly the mitigations justified by a current
proven chain," so a cut retires when the proving chain vanishes (config/comms change so
the path no longer proves). That is conjunct (1). It does **not** yet revert on conjunct
(2) — the *enrichment* clearing (the CVE is patched, the runtime behavior stops) while
the chain still proves. A workload whose chain still holds but whose concerning signal
has gone is no longer a breach by ADR-0016's own definition (neither conjunct alone is a
breach), yet the cut would persist. We need the revert condition to be the full breach
condition, and we want to express it **without adding a parallel state store** — the
engine already computes a stable evidence digest for exactly this kind of "have the
facts that matter changed?" question.

That digest exists: `entry_fingerprint` in `engine/src/engine/reason/adjudicate.rs`.
[ADR-0015](0015-advisory-evidence-egress.md) §5 made it the **stable evidence digest**
the verdict cache keys on — it hashes the entry's exploited/critical CVEs (with their
stable advisory fields — CWE, fix reference, capped summary — no timestamps), its COARSE
runtime-behavior keys, and its reachable-objective set with reach tags ([JEF-79]). It is
deliberately built to change **once** when the evidence that would change the model's
call changes, and stay stable across passes otherwise. That is precisely the property a
breach-condition revert key needs: it moves when enrichment (2) meaningfully changes and
is otherwise quiet.

## Decision

We will make an isolation's revert condition the **breach condition**:

> **breach condition = (the proven chain still holds) ∧ (the enrichment fingerprint
> still shows a concerning signal)**

and the ledger reverts the cut when **either conjunct goes false** on a later
change-driven pass.

### 1. The revert key is the evidence digest (`entry_fingerprint`)

The enrichment half (2) of the breach condition is keyed on the existing
`entry_fingerprint` (`adjudicate.rs`), not a new state store. When the model promotes a
chain to an isolation, the fingerprint that was in force at promotion — the CVEs +
runtime behaviors + objectives + reach tags that constituted the concerning signal — is
the breach-condition key the mitigation ledger holds alongside the cut. Reusing the
existing digest, rather than adding a parallel store, keeps one source of truth for "what
evidence is this verdict standing on" and inherits ADR-0015's stability guarantee for
free (it busts once on real change, not per pass — the [JEF-63] budget).

### 2. Conjunction semantics

The cut persists **iff both** conjuncts hold:

- **(1) the chain still holds** — a current proven chain still justifies the cut. This
  is what `reconcile` already enforces via `cut_signature` / `Justification`: no
  justifying chain ⇒ retire.
- **(2) the enrichment fingerprint still shows a concerning signal** — the
  breach-condition key still resolves to "concerning." If the CVE is patched out or the
  behavior stops, the entry's evidence re-hashes to a fingerprint that no longer carries
  that signal.

The cut **lifts when either conjunct goes false**. Equivalently, the breach condition is
a conjunction and its negation (revert) is the disjunction — chain gone **or** signal
gone — matching ADR-0016 §3's "persists until (1) **or** (2) clears."

### 3. How the change-driven loop detects "(2) cleared"

The detection mechanism is the [ADR-0002](0002-change-driven-ir-loop.md) loop plus the
fingerprint, with **no polling and no timer**:

- A cluster change (an image bumped to a patched version, a behavioral signal that stops
  recurring, a misconfig closed) drives a pass.
- On that pass the engine recomputes `entry_fingerprint` for the entry from the
  now-current evidence. Because the patched CVE / stopped behavior no longer contributes
  its key, the recomputed fingerprint **differs from the breach-condition key** the
  ledger is holding.
- The ledger sees the breach condition no longer holds — conjunct (2) is false even
  though the chain (1) may still prove — and **lifts the cut** (self-reverts, per
  ADR-0009). The reverse direction, conjunct (1) going false, is the existing
  chain-vanished retire path; this ADR adds the (2) half so both conjuncts revert.

The fingerprint's "change once, then stable" property (ADR-0015 §5) is load-bearing
here: it guarantees the revert fires on the *first* pass after the signal clears, and
doesn't thrash or flap the cut on mundane churn in between.

This refines ADR-0016 §3 (which named the two clearing conditions but not the key or the
detection mechanism) and ADR-0009 (the self-reverting action — the revert condition is
the breach condition, tied to the live proof+enrichment, not a fixed timer). The
implementation of the revert is [JEF-134]'s revert portion; this ADR is the decision
record only.

## Consequences

Easier / better:

- **The cut lifts on a patch, not just on a topology change.** A workload whose chain
  still proves but whose CVE is patched (or whose live behavior stops) self-heals on the
  next pass — closing the ADR-0016 gap where a still-proving chain with cleared
  enrichment would have kept the cut.
- **One source of truth for evidence.** The revert reuses `entry_fingerprint`, so there
  is no parallel "what was the breach standing on" store to keep in sync with the verdict
  cache. The digest that decides *when to re-judge* is the same digest that decides *when
  to revert*.
- **No timer, no polling.** Revert is change-driven, inheriting the ADR-0002 loop and the
  fingerprint's stability — the cut lasts exactly as long as the breach condition does.

Harder / accepted:

- **Revert latency tracks the loop and the operator's snapshot cadence.** "(2) cleared"
  is detected when a pass recomputes the fingerprint after the evidence changes. For CVE
  patch status this is gated by the operator's advisory-snapshot sync cadence (the zero-
  egress trade from ADR-0015) and image-version observation; for behavior it is gated by
  the telemetry signal aging out. The cut over-persists at worst until the next pass that
  observes the cleared signal — acceptable, since over-persisting a reversible, additive,
  blast-radius-gated cut fails safe.
- **The ledger now carries the breach-condition key per active isolation.** A small
  amount of state (the fingerprint at promotion) rides with each cut in the ledger. This
  is the minimum needed to compare against on later passes and is strictly less than a
  parallel store; it is the same digest already computed for the verdict cache.

## Alternatives considered

- **Fixed-timer revert (TTL on the cut).** Rejected: a timer reverts on the clock, not
  on the breach — it would lift a still-active breach or persist a cleared one, exactly
  the failure ADR-0009 ruled out. The breach condition is the only correct revert trigger.
- **A parallel breach-condition state store.** Rejected: it would duplicate the evidence
  digest the verdict cache already maintains and risk the two drifting. Reusing
  `entry_fingerprint` (ADR-0015's stable digest) keeps one source of truth.
- **Revert on the chain alone (status quo).** Rejected: it ignores conjunct (2), so a
  patched-but-still-reachable workload keeps its cut indefinitely, contradicting
  ADR-0016's definition that neither conjunct alone is a breach.
