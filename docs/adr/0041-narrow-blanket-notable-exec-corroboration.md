# 0041. Narrow the blanket notable-exec corroboration arm to shapes

- Status: Proposed
- Date: 2026-08-06

## Context

`corroborates()` (`engine/src/engine/reason/proof/corroborate.rs`) carries a **blanket arm**:
any `ProcessExec` classified as `is_interactive_shell()` or `is_package_manager()` corroborates
**every** objective on an internet-facing entry. It was introduced as the Falco-parity floor —
the direct replacement for Falco's "terminal shell / package-management in container" criticals
— deliberately broad while Falco is being retired, and it is the one place where a *bare*
notable exec (as opposed to `PrivilegeChange` / `PtraceAttach` / `ModuleLoad`, which are
non-corroborating on their own) flips `corroborated_for`.

Two problems follow. **(1)** Because the arm fires on the exec alone, no *exec-correlated*
corroboration shape can independently flip `corroborated_for`; the deferred reverse-shell
(exec↔egress-timing) shape is therefore **redundant-by-construction**, and
[ADR-0024](0024-no-redundant-by-construction-predicates.md) rightly blocks landing it until the
blanket arm is narrowed. **(2)** The arm's precision is exactly the
[ADR-0011](0011-positive-judgement.md) on-call-engineer false positive: an operator's
`kubectl exec -it … bash` flips every chain on that entry to corroborated/live.

### The reframing this ADR resolves

A tempting but **false** framing is that the blanket arm "floods the model's evidence with
'corroborated' on every objective." Verified against the code, it does not:

- **The model never sees `corroborated`.** The incident prompt carries per-behavior evidence
  lines (`observe::exec_class::annotated_summary`); the `corroborated` flag was *removed* from
  the model's view by [ADR-0034](0034-cut-choice-contract.md)'s 4→3 verdict collapse and now
  appears in `reason/adjudicate/incident/` only in comments explaining its exclusion. Narrowing
  `corroborates()` changes nothing the model reads.
- **`corroborated` remains load-bearing in three *deterministic* places** post-[ADR-0032](0032-model-is-incident-responder.md)/[ADR-0034](0034-cut-choice-contract.md):
  the auto-apply gate `(corroborated || promoted) && adjudicated && breach_relevant`
  (`respond/mod.rs`); lane selection (`adj_pass.rs` — corroborated → veto/auto-eligible lane;
  uncorroborated → needs an affirmative verdict + the opt-in arming class); and
  presentation/telemetry (latent-vs-live, disposition strings, the
  [ADR-0037](0037-shadow-bake-arm-readiness.md) bake read).

So narrowing buys **deterministic-gate precision + honest latent/live presentation + the
unmasking of every exec-correlated shape** — not model-input precision.

## Decision

**A shell exec is *evidence*; a shell exec with a correlated C2-shaped egress is
*corroboration*.** Narrow the flat blanket arm and re-home exec-based corroboration in
entry-scoped shapes.

1. **Flat arm → `false`.** `Behavior::ProcessExec` no longer corroborates on its own — it joins
   `PrivilegeChange` / `PtraceAttach` / `ModuleLoad` as **model-evidence-only; shapes live at
   the entry-scoped seam.** This restores [ADR-0011](0011-positive-judgement.md) as stated
   (bare interactive shell = the on-call-engineer case, not corroboration) rather than as the
   parity-driven suspension it had been.

2. **New shape `reverse_shell_on_foothold`.** An `is_interactive_shell` `ProcessExec` and an
   internet `NetworkConnection` on the same entry within a **symmetric 60s window**
   (`|Δt| ≤ 60s` over `provenance.observed_at`, both directions — covers `bash -i >& /dev/tcp/…`
   exec-then-connect and connect-back-then-spawn), **foothold-gated** (`entry.is_foothold`, the
   pattern every sibling shape follows), corroborating **any objective** (a live C2 session
   evidences intrusion on every chain from that entry — the blanket's semantic, now in shaped
   form). Window constant sits beside the drop-then-execute constant. This lands the previously
   deferred reverse-shell shape as load-bearing.

3. **Package managers are excluded from the shape.** They always egress (fetching packages), so
   including them re-creates a blanket for that class. Real installs corroborate via
   `alarming_write` (writes under `/usr/bin`, `/lib`, …); a no-op package-manager exec stays
   model evidence.

4. **`observe::alarm_class::is_alarming_now`, `exec_class`, the incident-menu seeding, and the
   zero-anchor guard are untouched.** The model keeps its "hands-on-keyboard happened" evidence
   line, its actively-exploited marking, and its ability to name a shelled downstream pod in
   `contain` ([ADR-0034](0034-cut-choice-contract.md) §4). A drift-guard test asserts a notable
   exec still satisfies `is_alarming_now` after the flat arm narrows.

5. **Foothold gate on the shape**, with the revisit trigger named: a no-CVE app-level RCE
   reverse shell on an exposed-but-not-compromisable entry stops *deterministically*
   corroborating (the model lane still covers it — [ADR-0034](0034-cut-choice-contract.md)
   already requires a decisive model `attack` for any cut). Un-gating is a one-line,
   shadow-measurable change if the Falco-parity matrix shows the gap biting.

6. **A narrowing-delta counter** — a structured log + counter emitted when an entry has a
   notable exec in `runtime` but its chain is uncorroborated (exactly the cases the old blanket
   would have corroborated). This is the retire-Falco parity-matrix input and the bake
   instrument; the model-vs-deterministic `cut_divergence` comparator is the read-only-bake
   precedent ([ADR-0037](0037-shadow-bake-arm-readiness.md)).

7. **Tests must flip `corroborated_for`** ([ADR-0024](0024-no-redundant-by-construction-predicates.md)'s
   bar): shape-positive (shell + egress corroborates where a bare shell would not), bare-shell
   negative, package-manager negative, window-expiry negative, non-foothold negative.

8. **No config toggle, no wire change, no tier.** Repo convention: fix noise by scope, not a
   flag; [ADR-0034](0034-cut-choice-contract.md) just *collapsed* corroboration vocabulary, so a
   weak/strong tier would cut against the grain for a benefit presentation already serves.

### Why now — and the safety floor

Falco ingest is still live (`charts/protector/values.yaml`: `falco.enabled: true`), so Falco
criticals corroborate via the **`Behavior::Alert` arm regardless of the exec arm**. While Falco
coexists, the exec arm is a *redundant* second floor — so narrowing now, in `audit` (the default
posture, pre-arming), changes **zero operational recall**: the Alert arm still backstops. The
Falco-retirement decision then consumes the narrowing-delta counter over a continuous bake
([ADR-0037](0037-shadow-bake-arm-readiness.md)) against the parity matrix *before* the Alert
floor is ever removed. Narrowing after Falco retires would be strictly riskier; this is the
cheapest safe window.

## Consequences

- The deferred exec-correlated shapes become buildable ([ADR-0024](0024-no-redundant-by-construction-predicates.md)
  gate cleared): `reverse_shell_on_foothold` lands here; future exec↔X shapes can follow.
- The deterministic auto-apply gate and the latent-vs-live presentation gain precision — a bare
  admin shell no longer marks every chain on an entry corroborated/live during the arm-readiness
  bake.
- **The one real behavioral change — a lane shift:** in `enforce` mode *without* the opt-in
  arming class, a shell-only + decisive-`attack` incident becomes a **proposal instead of an
  auto-cut**. Deliberate ([ADR-0011](0011-positive-judgement.md) — a bare shell with no
  secondary signal is the on-call false positive), **inert under the `audit` default**, and
  called out here so the arming-ladder operator reads it before flipping `enforce`. Amends
  [ADR-0009](0009-asymmetric-action-bar.md)'s action-bar corroboration input; the
  `corroborated ∧ adjudicated` auto-gate itself is unchanged.
- **Residual, bake-measured:** the shape's false-positive set is a strict *subset* of the
  blanket's, not empty — an sh-entrypoint foothold pod egressing at startup, or an on-call shell
  into a routinely-egressing foothold pod, still fires (the wire type carries no tty/argv, so
  process-linked discrimination needs a wire change — deferred). `RuntimeEvents` eviction can
  also drop the exec before the egress on a chatty pod (same profile as drop-then-execute). The
  narrowing-delta counter measures both.
- Reversible: re-widening the flat arm is a one-line change, measured in shadow.

## References

- `docs/ideas/corroboration-floor-narrowing.md` — the design brief this ADR records.
- [ADR-0024](0024-no-redundant-by-construction-predicates.md) — the governing constraint
  (shapes must be load-bearing when merged); this ADR clears its gate for the reverse-shell
  shape.
- [ADR-0011](0011-positive-judgement.md) — the on-call-engineer false positive that keeps bare
  exec non-corroborating; restored here.
- [ADR-0014](0014-behavioral-telemetry-ebpf.md) — the corroboration port; the Falco-parity bar
  = measured decision-path coverage, which the narrowing-delta counter feeds.
- [ADR-0032](0032-model-is-incident-responder.md) / [ADR-0034](0034-cut-choice-contract.md) —
  the model decides; `corroborated` feeds determinism (auto-apply gate + lane), not the model.
- [ADR-0037](0037-shadow-bake-arm-readiness.md) — the read-only shadow-bake instrument pattern
  the narrowing-delta counter follows.
- [ADR-0009](0009-asymmetric-action-bar.md) — the action bar this amends.
