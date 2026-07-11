# 0024. Corroboration shapes must be load-bearing when merged, not deferred-dead

- Status: Accepted
- Date: 2026-07-11
- Relates to: [0011](0011-positive-judgement.md), [0014](0014-behavioral-telemetry-ebpf.md)

## Context

JEF-319 (retire-Falco G4) proposed two entry-scoped corroboration shapes on
`corroborated_for`: **cross-tenant lateral** and **reverse-shell**. The corroboration
predicate is not cosmetic — flipping `corroborated` can gate a quarantine (ADR-0009 /
ADR-0011) — so what it admits is load-bearing and what it *cannot* admit is dead weight.

The reverse-shell shape (`notable exec → outbound egress within 60s`) was
**redundant-by-construction**: the existing blanket notable-exec arm (JEF-117) already
returns `true` for ANY objective whenever a notable exec is present. A shape that fires
only when a notable exec is present is therefore strictly narrower than a condition that
already holds — it could not independently change the `corroborated_for` boolean. It was
proposed as documented, unit-tested-in-isolation code kept "for when the blanket exec arm
is later narrowed."

This is exactly the shape the Fable audit (JEF-363/364/367…) was called to excise: a
tidy, well-tested, in-code-documented construct whose output was already determined by
another arm, which survived review *because* it was tidy and tested. Redundant-by-
construction code that "works" is still a defect (Hickey: incidental complexity;
CLAUDE.md: the repo is acutely averse to it). Its unit tests assert the behavior of a
predicate that changes no observable output, so they cannot fail in a way that matters —
they rot silently, and the next reader mistakes documented-dead for live.

## Decision

**We do not merge a corroboration shape that cannot flip `corroborated_for` given the
current predicate.** A shape whose value is contingent on a *future* narrowing of another
arm lands **with** that narrowing — so it arrives load-bearing, with a test that can
actually fail — not ahead of it on the promise of future need.

Concretely for JEF-319:
- **Cross-tenant lateral is merged.** A bare in-cluster `NetworkConnection` does not
  blanket-corroborate, so `is_cross_tenant` is the only thing that can flip
  `corroborated_for` for that shape; it is genuinely load-bearing and tested end-to-end
  through `corroborated_for` (positive; same-ns negative; non-foothold negative).
- **Reverse-shell is stripped**, along with its isolated predicate tests. A follow-up
  ticket tracks implementing it **when** the blanket notable-exec arm (JEF-117) is
  narrowed as part of retiring Falco; at that point the exec+egress-timing correlation
  becomes the load-bearing reverse-shell signal and lands with a test that can fail.

The general rule: a predicate whose result is already fixed by an existing arm is not
"defense in depth," it is dead code with a documentation comment. Land it when it bites.

## Consequences

Easier:
- The corroboration surface stays honest: every arm present can change an outcome, so its
  tests are meaningful and a reader can trust that documented ⇒ live.
- The Fable lesson is codified, not re-learned: reviewers have an ADR to point at when a
  "keep it for later" redundant predicate appears.

Harder / accepted:
- When the blanket exec arm is narrowed, the reverse-shell shape must be re-added (its
  removed predicate + tests are recoverable from this PR's history). Accepted: re-adding a
  small, now-load-bearing predicate is cheaper than carrying dead code that silently rots.
- Slightly more integration-time friction: a shape's load-bearingness must be demonstrated
  (it flips `corroborated_for` in a test), not asserted. That friction is the point.
