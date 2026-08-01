# 0037. Shadow-bake arm-readiness: the exit criterion that gates the human `enforce` flip

- Status: Proposed
- Date: 2026-08-01

## Context

[ADR-0035](0035-per-cut-class-arming-ladder.md) named the shadow→arm path this project is
building toward — "bake a model-vs-deterministic cut comparator in shadow, then arm the
**narrowest** cut first in one namespace after the bake clears" — but left the bake bar itself
unwritten. [ADR-0021](0021-two-setting-operating-posture.md) already settled *that* arming is a
single, explicit, human-read act (never automatic): `audit` is the default, and flipping to
`enforce` is "a single, explicit, documented flip" an operator makes after watching the
would-deny findings. What was missing is *what the operator reads* before making that flip for
the FIRST namespace under the ADR-0035 ladder's narrowest rung (the surgical `DenyNetworkPath`
edge-cut alone).

The instrument that now exists to read is the cut-divergence comparator (`engine::cut_divergence`,
the `state::DivergenceLog` it feeds, and the durable journal's `CutDivergence` lines): for every
breach-relevant entry with a decisive cut-choice decision, it classifies the model's chosen
cut-set against the deterministic fallback set `respond::containment_for` +
`respond::quarantine_workload_link` would themselves have proposed for the same chains — `agree`,
`model_over_cut`, `model_under_cut`, or `mixed`. It is read-only end to end (ADR-0016):
computing, journaling, and viewing a classification cannot arm or mutate anything.

## Decision

**The bar is human-read, not auto-evaluated.** No code in this repository is authorized to flip
`PROTECTOR_MODE` from `audit` to `enforce`, or to widen `enforceScope`/the ADR-0035 ladder
position, based on the comparator's output — that would reintroduce exactly the auto-arming
ADR-0021 rejected. The comparator's `DivergenceLog::class_counts()` summary (and the
`/api/divergence.json` view it backs) exist so an operator has one place to read the following
checklist before making that single, documented, human flip — for the FIRST namespace, at the
ADR-0035 edge-cut rung alone:

1. **Bake duration.** The comparator has been running continuously, in shadow, against the
   target namespace for at least **14 days** — long enough to cross a weekly traffic cycle and
   at least one deploy. A gap in coverage (the readiness row's runtime/model inputs stalling, or
   a journal rotation losing the window) restarts the clock: the bar is a continuous window, not
   a cumulative count.
2. **Zero unexplained `model_over_cut` against a clean workload.** Every `model_over_cut`
   classification in the window is reviewed by a human against the entry's actual evidence
   (`/api/findings.json`'s drill-in, the verbatim judgement prompt/reply). A `model_over_cut`
   where the model named a workload with NO CVE and NO behavioral signal is a live false-positive
   risk under `enforce` (it would sever a clean workload's traffic) and fails the bar outright,
   full stop, regardless of the other counts. A `model_over_cut` where the model additionally
   grounded a *real* signal `containment_for`'s narrower ladder simply didn't reach (e.g. it
   also caught a live behavioral alert the deterministic entry-only rung doesn't look at) does
   not fail the bar on its own, but the ADR-0035 first arm still only enables the *narrowest*
   (`DenyNetworkPath`) rung — a `model_over_cut` that depends on a `QuarantineWorkload`/
   `QuarantineEntry` cut the ladder hasn't armed yet stays a proposal regardless.
3. **Over-cut mass under the [ADR-0033](0033-cut-choice-judge-tier.md) bench threshold.** The
   bench's own regression-tracked `--flip` over-cut-mass score, run on the deployed judge, shows
   no regression against the last recorded baseline for the prompt version live during the bake
   window. This is the ADR-0033 measurement, not a new one — the bake doesn't pass on a bench
   number that predates the bake window's prompt.
4. **`model_under_cut` reviewed, not just counted.** A sample of the window's `model_under_cut`
   and `mixed` rows (at minimum, every one on a chain with a live behavioral signal) is read by a
   human and confirmed to be a defensible `no_attack`/`uncertain` call, not the model silently
   missing a real breach. This is a spot-check, not an automated gate — `model_under_cut` alone
   is not disqualifying (a model that is *more* conservative than blanket determinism is the
   ADR-0034 minimality story working as intended); it only fails the bar when the review finds a
   miss.
5. **No standing coverage gap.** The readiness row shows the target namespace's runtime/model
   inputs live (not `stalled`/`blind`) for the whole window — a comparator that ran blind for part
   of the bake measured nothing for that stretch, and the window in (1) has to be continuous
   coverage, not continuous wall-clock time with gaps papered over.

**Clearing all five is a necessary, not sufficient, condition to flip.** It tells the operator the
comparator agrees with (or is more conservative than) blanket determinism on THIS namespace over
THIS window; it says nothing about a namespace or workload shape the bake window didn't cover. The
flip itself remains exactly the ADR-0021 act: `PROTECTOR_MODE=enforce`, a **non-empty**
`enforceScope` naming only the baked namespace, and — per ADR-0035 — the ladder position left at
its narrowest (edge-cut only) rung. Escalating to the `QuarantineEntry`/`QuarantineWorkload` rung,
or widening `enforceScope` to a second namespace, is a SEPARATE decision that re-reads this same
checklist against its own bake window; clearing the bar once does not pre-clear it for a wider
scope.

## Consequences

- The comparator (`engine::cut_divergence`, `state::DivergenceLog`, the journal's `CutDivergence`
  lines, `/api/divergence.json`) is now load-bearing for an operator decision, but remains,
  by construction, incapable of making that decision itself — every function in the path takes
  its inputs by shared reference and returns owned data; there is no write path back into the
  ledger, the actuator, or `EnabledActions`.
- A future ticket may aggregate the checklist into a single dashboard readiness row (mirroring the
  existing `Readiness`/`ReadinessRow` coverage aggregation) so an operator doesn't have to compute
  (1)–(5) by hand from the raw journal; that aggregation is out of scope here and, like everything
  it would aggregate, must stay read-only.
- This ADR does not change `PROTECTOR_MODE`'s two-value contract
  ([ADR-0021](0021-two-setting-operating-posture.md)) or the arming ladder's shape
  ([ADR-0035](0035-per-cut-class-arming-ladder.md)) — it only writes down what a human reads
  before using them.
