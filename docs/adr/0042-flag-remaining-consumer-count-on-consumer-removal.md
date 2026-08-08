# 0042. Flag a shared layer's remaining live-consumer count when a PR removes a consumer

- Status: Accepted
- Date: 2026-08-08
- Relates to: [0024](0024-no-redundant-by-construction-predicates.md)

## Context

PR #189 (`perf(model): cache all ollama completions in one bounded client middleware`)
added a bounded LRU cache in front of `chat()`, deliberately keyed at the model-client
boundary "so EVERY model consumer is covered by one mechanism" — its two consumers at
the time were the adjudicator (ADR-0013) and the model-backed hypothesis stage
(`ModelHypothesizer`). Reviewed alone, it is a clean shared-layer change: one cache,
two call sites, no gap.

Eight minutes later, PR #190 (`refactor(engine): remove the model-backed hypothesis
stage — deterministic proof only`) deleted `ModelHypothesizer` entirely: `proof::prove`
already enumerated every structurally-proven chain by exhaustive walk, so the
hypothesis stage discovered nothing and only burned a completion per pass. Reviewed
alone, it is also a clean deletion — the commit message even names the consequence
correctly ("The ONLY remaining Ollama consumer is the adjudicator").

Neither PR was wrong on its own, and neither review caught what their conjunction
did: PR #190 deleted one of the cache's two consumers, dropping PR #189's
just-added shared layer to a single caller. With one consumer, the LRU stopped
being a *shared* cache and became a redundant wrapper around a cache that already
existed one layer up — the deterministic verdict store (ADR keyed on the exact
prompt hash) already short-circuited `chat()` on a hit; the LRU added nothing on a
miss but a *correctness hazard*, because it cached any HTTP 200 including replies
that parse to `Uncertain`, while the verdict store deliberately never caches
`Uncertain` (it must retry). The bug shipped, then had to be found and reverted in
PR #191 (`revert(model): drop the ollama completion cache — redundant +
Uncertain-pinning hazard`), less than an hour after PR #190 merged.

The root cause was not a defect in either diff. It was that **per-PR review has no
view of a neighboring PR's effect on the same abstraction.** PR #189's reviewer
had no reason to open `hypothesis.rs`; PR #190's reviewer had no reason to open
`model/cache.rs`. The redundancy existed only in the two PRs' conjunction, and nothing
in either diff, or in CI, surfaced it. This is the same failure family
[ADR-0024](0024-no-redundant-by-construction-predicates.md) names for a single PR
(a predicate whose result is already fixed by an existing arm is dead code, however
tidy and tested) — except here the fixing arm and the redundant layer landed as *two
separate, individually-reasonable* PRs, which is exactly the case ADR-0024's per-PR
framing cannot catch.

## Decision

**When a PR removes a consumer of a shared layer or abstraction (a cache, a port, a
shared middleware, a common helper used by more than one call site), the PR
description states the layer's remaining live-consumer count in one line** — e.g.
"the model-client cache now has 1 remaining consumer (the adjudicator)." This is a
statement of fact the author already has (they just read the call sites to make the
deletion), not new analysis.

A remaining count of **one** is flagged in review as a refactor smell, not merged
silently: a layer built to serve multiple consumers that now serves one is either (a)
no longer earning its abstraction — inline it or fold it into its sole caller, or (b)
still justified (a real seam the count will grow back into) — in which case the PR
description says so in the same line. Either way the reviewer sees the number and
makes the call explicitly, instead of the drop-to-one passing unnoticed because the
diff itself looks like a clean, unrelated deletion.

This is a review-time discipline, not a new automated check: no tool here reliably
knows what counts as "a shared layer" or enumerates its call sites across the whole
tree on every consumer-deletion diff. It is enforced the way ADR-0024's rule is
enforced — a reviewer checklist item and a citable ADR to point at.

## Consequences

Easier:
- The exact failure PR #189/#190/#191 hit is caught at review time on the
  consumer-removal PR, before merge, instead of being found by a later revert.
- Reviewers get a one-line, low-cost signal (a count, not a design review) that
  surfaces the cross-PR case ADR-0024 already covers for the single-PR case.
- A drop-to-one that *is* still justified gets its justification recorded in the PR
  description at the moment it happens, rather than reconstructed later from git
  archaeology.

Harder / accepted:
- This depends on the PR author actually running the count and writing the line;
  nothing in CI enforces it (see Scope, below). Accepted: this repo's review
  discipline is documented as reviewer checklist items elsewhere (ADR-0024, this
  ADR) rather than as tooling, and a one-line prompt is cheap enough to expect a
  reviewer to ask for it when it's missing.
- Does not by itself detect the case in reverse — a PR that *adds* a second consumer
  to a layer built for one is not this ADR's concern; that is ordinary code reuse and
  is not the redundancy failure mode observed here.
- Scope: catching redundancy that spans a whole review *batch* (not just a single
  consumer-removal PR against the tree at merge time) is a workflow-tooling concern,
  not a repo convention — out of scope for this ADR.

## References

- [0024](0024-no-redundant-by-construction-predicates.md) — the sibling rule for the
  single-PR case (a predicate whose result is already fixed by an existing arm is not
  defense in depth, it is dead code); this ADR extends the same discipline across a
  two-PR conjunction that no single diff shows.
- PR #189 (`perf(model): cache all ollama completions in one bounded client
  middleware`) — added the shared cache "so EVERY model consumer is covered."
- PR #190 (`refactor(engine): remove the model-backed hypothesis stage —
  deterministic proof only`) — deleted one of the cache's two consumers eight
  minutes later, dropping it to one.
- PR #191 (`revert(model): drop the ollama completion cache — redundant +
  Uncertain-pinning hazard`) — the revert that found the conjunction, less than an
  hour after PR #190 merged.
