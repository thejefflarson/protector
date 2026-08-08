# Idea brief — Narrow the blanket notable-exec corroboration arm to shapes

**Status:** settled → ticketed via `/plan-sprint`. Load-bearing decisions recorded in
[ADR-0041](../adr/0041-narrow-blanket-notable-exec-corroboration.md).

## The idea (as posed)

`corroborates()` in `engine/src/engine/reason/proof/corroborate.rs` has a **blanket arm**:
any `ProcessExec` classified as `is_interactive_shell()` or `is_package_manager()`
corroborates **every** objective on an internet-facing entry. That arm was the Falco-parity
floor (the direct replacement for Falco's "terminal shell / package-management in
container" criticals). Because it fires on the exec alone, no *exec-correlated* corroboration
shape can independently flip `corroborated_for` — so
[ADR-0024](../adr/0024-no-redundant-by-construction-predicates.md) (no
redundant-by-construction predicates) rightly blocks landing the deferred reverse-shell
(exec↔egress-timing) shape until the blanket arm is narrowed. This brief designs that
narrowing.

## The reframing that redirects the idea

The original worry — *"the blanket arm floods the judge's evidence with 'corroborated' on
every objective"* — is **factually wrong in this codebase**, and correcting it is the whole
point of the design pass:

- **The model never sees `corroborated`.** The incident prompt carries per-behavior evidence
  lines rendered by `observe::exec_class::annotated_summary` (e.g. *"executed /bin/bash
  (interactive shell in container)"*). The `corroborated` flag appears in
  `reason/adjudicate/incident/` only in comments explaining why it is *deliberately excluded*
  — [ADR-0034](../adr/0034-cut-choice-contract.md)'s 4→3 verdict collapse removed the model's
  restatement of that deterministic fact. Narrowing `corroborates()` changes **nothing the
  model reads**. (Evidence lines also carry no inter-event timestamps, so the model cannot
  self-derive the exec↔egress correlation — only determinism can.)
- **`corroborated` is still load-bearing post-[ADR-0032](../adr/0032-model-is-incident-responder.md)/[ADR-0034](../adr/0034-cut-choice-contract.md), in three *deterministic* places:**
  1. **The auto-apply gate** — a model-chosen cut auto-applies only through
     `(corroborated || promoted) && adjudicated && breach_relevant` (`respond/mod.rs`).
     `corroborated` is half of the deterministic AND-gate on actuation.
  2. **Lane selection** (`adj_pass.rs`) — a corroborated chain sits in the *veto* lane
     (auto-eligible unless the model demurs); an uncorroborated chain needs an affirmative
     verdict **plus the opt-in arming class** to become auto-eligible.
  3. **Presentation/telemetry** — latent-vs-live, the finding-disposition strings in
     `state/findings.rs`, chain logs and metrics the operator reads during the
     [ADR-0037](../adr/0037-shadow-bake-arm-readiness.md) arm-readiness bake.

**So narrowing buys:** precision of the deterministic auto-apply gate, honest latent-vs-live
presentation during the bake, and the unmasking of every exec-correlated shape
([ADR-0024](../adr/0024-no-redundant-by-construction-predicates.md)). It does **not** buy
model-input precision — that was never at stake.

## Assumptions corrected

- **Falco is still live** (`charts/protector/values.yaml`: `falco.enabled: true`). Falco
  criticals arrive as `Behavior::Alert` and corroborate via the *Alert* arm regardless of the
  exec arm. While Falco coexists, the exec arm is a **redundant second floor** — so **now
  (coexistence + `audit` default) is the cheapest, safest window to narrow**: zero
  operational recall change, because the Alert arm still backstops.
- **Only exec-correlated shapes are masked.** The drop-then-execute shape fires on
  *non-notable* execs of a recently-written path (independent flips exist); the
  privilege-escalation shape keys on `PrivilegeChange`, never in the blanket arm. So "what
  replaces the net" is *mostly already built* — seven entry-scoped shapes + the alarming-write
  and Alert blankets + the per-objective arms.
- **Narrowing does not reopen the parity gap much.** Post-[ADR-0034](../adr/0034-cut-choice-contract.md)
  nothing auto-cuts without a decisive model `attack`; a bare-shell compromise still reaches
  the decision path as annotated model evidence, as `observe::alarm_class::is_alarming_now`
  (which marks the pod actively-exploited and seeds the downstream `contain` menu line), and
  via the Alert arm while Falco runs. The residual is one lane shift (below).

## Recommended approach — narrow the flat arm to shapes

- **`Behavior::ProcessExec → false` in the flat corroboration arm.** A bare shell/pkg-mgr exec
  becomes **model evidence, not corroboration** — restoring exact symmetry with
  `PrivilegeChange` / `PtraceAttach` / `ModuleLoad` (all of which already defer to
  entry-scoped shapes) and restoring [ADR-0011](../adr/0011-positive-judgement.md)'s on-call-
  engineer false-positive guard that the blanket had suspended.
- **Add one entry-scoped shape, `reverse_shell_on_foothold`** — an `is_interactive_shell` exec
  and an internet `NetworkConnection` within a **symmetric 60s window** (covers both
  exec-then-connect and connect-back-then-spawn), **foothold-gated** (`entry.is_foothold`, the
  house pattern every sibling shape follows), corroborating **any objective** (a live C2
  session evidences intrusion on every chain from that entry — the blanket's semantic, now in
  shaped form). This is the deferred reverse-shell shape, now load-bearing.
- **Package managers are excluded from the shape** — they *always* egress (fetching packages),
  so including them re-creates a blanket for that class. Real installs corroborate via
  `alarming_write` (writes under `/usr/bin`, `/lib`, …); a no-op pkg-mgr exec stays model
  evidence.

Approaches rejected: **(A) don't narrow, add timing as model-evidence enrichment** — leaves
the deterministic gate low-precision and makes the [ADR-0024](../adr/0024-no-redundant-by-construction-predicates.md)
friction permanent (every future exec-correlated shape stays unbuildable); **(C) tier
corroboration weak/strong** — adds a concept to `ProvenChain`/journal/ledger against the grain
of [ADR-0034](../adr/0034-cut-choice-contract.md)'s vocabulary collapse, for a weak tier whose
only consumer is presentation the evidence pane already serves.

## Key decisions (see [ADR-0041](../adr/0041-narrow-blanket-notable-exec-corroboration.md))

1. Flat arm → `false`; `ProcessExec` joins the "model-evidence-only, shapes at the entry-scoped
   seam" family.
2. `reverse_shell_on_foothold`: interactive-shell exec + internet `NetworkConnection`,
   symmetric `|Δt| ≤ 60s` from `provenance.observed_at`, foothold-gated, corroborates any
   objective. Constant beside the drop-then-execute window.
3. Interactive shells only — package managers excluded.
4. **`observe::alarm_class::is_alarming_now` / `exec_class` / menu seeding / the zero-anchor
   guard are untouched** — the model keeps its "hands-on-keyboard happened" signal and its
   ability to name a shelled downstream pod in `contain`. A drift-guard test asserts a notable
   exec still satisfies `is_alarming_now` after the flat arm narrows.
5. Foothold gate on the shape, with the revisit trigger named: a no-CVE app-level RCE reverse
   shell on an exposed-but-not-compromisable entry stops *deterministically* corroborating
   (the model lane still covers it). Un-gating is a one-line, shadow-measurable change if the
   parity matrix shows it biting.
6. A **narrowing-delta counter** — emitted when an entry has a notable exec in `runtime` but
   its chain is uncorroborated (exactly the cases the old blanket would have corroborated).
   This is the retire-Falco parity-matrix input and the bake instrument (the `cut_divergence`
   comparator is the read-only-bake-instrument precedent, [ADR-0037](../adr/0037-shadow-bake-arm-readiness.md)).
7. Tests must **flip `corroborated_for`** ([ADR-0024](../adr/0024-no-redundant-by-construction-predicates.md)'s
   own bar): shape-positive, bare-shell negative, pkg-mgr negative, window-expiry negative,
   non-foothold negative.
8. No config toggle, no wire change, no tier (repo convention: fix noise by scope, not a flag).

## The one real behavioral change — the lane shift

In `enforce` mode **without** the opt-in arming class, a shell-only + decisive-`attack`
incident becomes a **proposal instead of an auto-cut**. This is deliberate — a bare shell with
zero secondary signal *is* the [ADR-0011](../adr/0011-positive-judgement.md) on-call-engineer
scenario, and auto-severing on it is the false positive that ADR exists to prevent. It is
**inert under today's `audit` default**, but the arming-ladder operator must read it, so the
ADR states it explicitly.

## What we are explicitly NOT doing

- **Not retiring Falco / the Alert arm** — that is gated on the bake this work enables, not
  part of it. The Alert arm stays the live floor through coexistence.
- **Not touching `is_alarming_now`** — narrowing it would strip the downstream `contain` menu
  lines and the actively-exploited marking. Leave it.
- **Not adding wire enrichment** (tty/argv/ppid, pid-linked exec↔flow attribution) — the only
  path to a materially better shape discriminator, but its own agent-side design; deferred.
- **No weak/strong tier, no config toggle, no un-gating the foothold requirement** now.

## Residuals & risks (bake-measured)

- The shape's false-positive set is a strict *subset* of the blanket's, not empty — an
  sh-entrypoint foothold pod that egresses at startup, or an on-call shell into a routinely-
  egressing foothold pod, still fires (the wire type carries no tty/argv, so process-linked
  discrimination needs a wire change — deferred). Strict improvement, imperfect; the
  narrowing-delta counter measures it.
- `RuntimeEvents` eviction (`MAX_EVENTS`/TTL) can drop the exec before the egress lands on a
  chatty pod, missing the correlation — the same accepted risk profile as drop-then-execute.
- One genuinely open item to settle during the build: verify the assessment→`promotes()`
  mapping so the uncorroborated + decisive-attack lane behaves as assumed (read/add one test).

## Rough shape & sequence

1. **ADR-0041** (this brief's decisions; amends the Falco-parity-floor stance; clears the
   ADR-0024 gate for the shape; names the lane shift + the retire-Falco measurement bar).
2. **One PR** (must land together per [ADR-0024](../adr/0024-no-redundant-by-construction-predicates.md)):
   flat-arm narrowing + `reverse_shell_on_foothold` + flip-capable tests + doc updates in
   `corroborate.rs`/`exec_class.rs`.
3. **Small PR:** the narrowing-delta counter (+ optionally a bake read).
4. **Not in scope:** the bake window → the Falco-parity matrix → the Falco-retirement decision.

## HANDOFF TO PLAN-SPRINT

Theme: **"Shape the corroboration floor — narrow the blanket notable-exec arm to the
reverse-shell shape while Falco still backstops it."** Plan against one ADR + one load-bearing
engine PR (flat-arm narrowing + `reverse_shell_on_foothold` + flip tests, landing together per
ADR-0024) + one observability PR (the narrowing-delta counter feeding the retire-Falco parity
matrix). Everything is engine-internal (`engine/src/engine/reason/proof/`, `observe/`), ships
in `audit` mode with the Falco `Alert` arm as the unchanged safety floor. Panel: **architect +
devops** — no product-surface change beyond finding-disposition labels; no data-schema change
beyond one counter.
