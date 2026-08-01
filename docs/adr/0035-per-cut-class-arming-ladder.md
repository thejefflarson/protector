# 0035. Per-cut-class arming granularity: an ordered ladder under `enforce`

- Status: Proposed
- Date: 2026-07-31

## Context

[ADR-0021](0021-two-setting-operating-posture.md) collapsed enforcement to two settings —
`mode` (`audit`=shadow default; `enforce`) plus `enforceScope` — and deliberately killed the
per-surface toggle sprawl that preceded it. [ADR-0032](0032-model-is-incident-responder.md)
§7 names "per-class arming" as a rail but never defines its granularity.

Today a single `mode: enforce` flip arms **all three** network cuts at once — the surgical
`DenyNetworkPath` edge-cut, `QuarantineEntry`, and `QuarantineWorkload` — because they map to
one `network` class (`engine/src/main.rs` `engine_arming`; `engine/src/engine/respond/actuator/mod.rs`
`actions_from_name`). The shadow→arm path this sprint builds toward — bake a
model-vs-deterministic cut comparator in shadow, then arm the **narrowest** cut first in one
namespace after the bake clears — has nothing to arm one-class-at-a-time against: the first
flip is maximally wide, arming the broad quarantines simultaneously with the surgical cut.
That is the load-bearing blocker for a safe first arm.

The tension to resolve: arming granularity is legitimate (ADR-0032 §7 calls for it), but it
must **not** reintroduce the independent multi-toggle drift ADR-0021 removed.

## Decision

`enforce` gains an **ordered arming ladder** over cut classes — a single position, not a menu
of independent toggles:

- The surgical **`DenyNetworkPath` edge-cut is armable alone** — the narrowest, most-reversible
  cut. Arm-narrowest-first is the entire point of a shadow→arm path.
- The broader **`QuarantineEntry` / `QuarantineWorkload`** quarantines require an **explicit
  second opt-in** beyond the edge-cut rung.
- The ladder is **ordered**: a rung implies its narrower predecessors are eligible, so it is a
  single "how far up the cut-severity ladder are you armed" position — **not** N free toggles.
  This preserves ADR-0021's anti-drift intent (there is still one thing to reason about, not a
  matrix of surfaces).
- **`enforceScope` is unchanged** and remains the sole *where* dial. The ladder is the
  *how-far* (cut-severity) dial, orthogonal to scope.
- **Default stays `audit`** — nothing armed, byte-identical shadow behavior.

ADR-0021's "single explicit, documented flip" becomes "a single explicit, documented **position
on the ladder**" — still one operator decision, still the sole act gate; determinism and the
model still only *propose* below the armed rung.

## Consequences

- A safe first arm becomes possible: bake the comparator, then arm the **edge-cut class alone**
  in one namespace, escalating to the quarantine rung only after further confidence.
- Shadow-default and `enforceScope` semantics are unchanged; `audit` arms nothing.
- **Implementation:** a small arming-ladder module (not bolted onto the already-large
  `respond/mod.rs`); `EnabledActions` stays the pure armed-classes type. The chart gains the
  ladder position — the deployed cluster chart is a fork, so that value must be hand-ported.
- **Anti-drift:** because the ladder is one ordered position rather than independent per-cut
  flags, it does not recreate the per-surface toggle sprawl ADR-0021 removed. This is *not* a
  `PROTECTOR_*_ENABLE`-style detection toggle (those remain forbidden) — it is a rung on the
  single enforcement gate.
- Supersedes the implicit "all-network arms together" behavior; the implementing change flips
  this ADR to Accepted.
