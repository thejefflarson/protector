# 0036. Disarm is a real, fast kill switch: the armed set gates revert too; a break-glass file narrows in one pass with no restart

- Status: Accepted
- Date: 2026-08-01
- Amends: [0021](0021-two-setting-operating-posture.md) (adds the fast disarm path to the
  enforcement gate), [0017](0017-isolation-persists-on-the-breach-condition.md) (adds a third
  revert trigger alongside the breach condition)

## Context

[ADR-0021](0021-two-setting-operating-posture.md) made `mode: audit`/`mode: enforce` the one
enforcement switch. Two gaps remained, both about what happens when an operator actually needs
to pull that switch back to `audit` *during* a live incident:

1. **The self-revert loop never checked the armed set.** `ActionLog::reconcile` (the closed
   loop behind [0017](0017-isolation-persists-on-the-breach-condition.md)) reverted a standing
   cut on health divergence or when no proven chain still justified it — but never when the
   *posture that armed it in the first place* narrowed. A workload's chain typically still
   proves right after an operator flips `enforce`→`audit` (nothing about the graph changed,
   only the mode), so the standing `NetworkPolicy`/`AdminNetworkPolicy` would sit there,
   invisible to the engine, silently severing live traffic — the opposite of "reversible."
2. **The only lever for that flip is GitOps.** `mode` is a `PROTECTOR_MODE` env var, read once
   at process boot ([`main.rs`](../../engine/src/main.rs) `Posture::from_env`); changing it
   means editing the chart value, an ArgoCD sync, and a pod restart. A GitOps sync pipeline is
   infrastructure with its own failure modes (a stuck controller, a blocked rollout, a broken
   sync) — routing an emergency disarm through the same pipeline that can independently wedge
   makes the kill switch only as reliable as everything upstream of it, which is backwards for
   a control whose entire job is to work when something else already has.

## Decision

### 1. The armed set is a revert trigger, not just an apply gate

[`ActionLog::reconcile`](../../engine/src/engine/respond/actuator/log.rs) now takes the
current pass's [`EnabledActions`](../../engine/src/engine/respond/actuator/mod.rs) and reverts
any tracked action whose OWN class is no longer enabled — independent of health or chain
justification, which keep gating their own reverts unchanged. `super::decide` already refused
to arm a *new* application once a class isn't enabled; this closes the matching hole on the
already-applied side, so a narrower armed set — enforce→audit, or the break-glass clamp below —
drives every standing cut it used to permit into reverting on the very next pass, not just
stops new ones.

### 2. A break-glass flag file: the fast, GitOps-independent disarm

[`engine::break_glass::BreakGlass`](../../engine/src/engine/break_glass.rs) watches a fixed,
always-on mount path (`PROTECTOR_BREAK_GLASS_FILE`, default
`/var/lib/protector/break-glass/disarm` — the same fixed-path-with-escape-hatch pattern the
KEV/EPSS/ASN feeds already use). Its presence clamps the running engine's effective armed
classes to `EnabledActions::none()` for that pass — feeding BOTH the auto-apply decision and
the reconcile check from (1) — so engaging it drives every standing cut to revert within one
pass, with **no image rebuild and no GitOps sync**: an operator with `kubectl` access (already
the credential of last resort in any cluster incident) creates or removes the file, and a
background poller (2s interval) wakes the driving loop on the transition even on an otherwise-
quiet cluster.

It **only ever narrows**: the engine's own `active: EnabledActions` (the `mode`/`enforceScope`
it booted with) is never mutated by the flag — engaging it computes a disarmed *view* for that
pass; clearing it restores exactly the configured arming, byte-identical to running without
the flag at all. There is no path by which the flag can arm a class `mode: audit` didn't
already permit, satisfying ADR-0021's single-enforcement-gate invariant: break-glass is a
second, faster DOOR onto the same gate, never a second gate.

Every engage/clear transition is logged at `warn`/`info` and mirrored to an OTLP gauge
(`protector.engine.break_glass_engaged`) plus a cumulative, alert-able counter
(`protector.engine.break_glass_transitions{state=engaged|cleared}`), recorded once per edge —
not per pass — so an operator can page on the transition itself.

### Why a file, not a local admin endpoint

The ticket asked for whichever is simplest and safest here. A file wins on both:

- **No new listener, no new auth surface.** An admin HTTP endpoint needs its own
  authentication story to avoid becoming an unauthenticated actuation surface — even reusing
  the dashboard/MCP's OIDC verifier ([0030](0030-app-level-oidc-verification-supersedes-edge-trust.md))
  means the disarm path now depends on that verifier, the network path to it, and (for OIDC) a
  reachable IdP. A file depends on none of that.
- **Works even when the rest of the stack doesn't.** If the dashboard, the mesh, or the OIDC
  issuer is itself part of the outage, an admin endpoint may be exactly what's unreachable when
  it's needed most. `kubectl` access to touch a file in a mounted volume is a strictly weaker
  precondition than "the app-level auth path is healthy."
- **No injection surface.** The file's content is never read or parsed — only existence is
  significant — so whoever can touch it can only toggle the same narrow disarm any operator
  can, never anything wider.

The cost is real and accepted: it requires `kubectl exec`/`cp` or a ConfigMap-patch RBAC grant
on the pod/namespace, which some operators may not carry day-to-day. That is a strict subset of
the access an operator already needs to hand-fix an incident by editing `NetworkPolicy` objects
directly, so it is not a new floor.

### What is explicitly out of scope here

Wiring an actual ConfigMap + volume mount for this path into the deployed cluster chart is a
chart-level follow-up — the cluster chart is a diverged fork of this repo's chart, ported by
hand. This ADR and its implementation only cover the engine watching a local path; the engine
degrades safely (never engaged) if nothing is mounted there, exactly like an unset KEV/EPSS/ASN
feed file does today.

## Consequences

Easier / safer:

- `enforce`→`audit` (via a restart) and break-glass (via the flag) now share ONE revert
  mechanism — a narrower armed set always reverts standing cuts, regardless of which path
  narrowed it.
- An emergency disarm no longer depends on the GitOps pipeline being healthy.
- The default (no flag mounted, or mounted but absent) is byte-identical to today — proven by
  tests that assert a never-engaged `BreakGlass` behaves exactly as no `BreakGlass` at all.

Harder / accepted:

- The break-glass poller adds one more background task per engine process (aborted on
  shutdown, like the feed reloaders and the model keep-warm task) — negligible cost, a `stat`
  call every 2 seconds.
- Break-glass does not (and must not) affect judgement, adjudication, or proof — a chain can
  still be judged and PROPOSED while disarmed; only actuation clamps. This is deliberate:
  disarm narrows what the engine *does*, never what it *sees*.

## Alternatives considered

- **A local admin HTTP endpoint (mesh-auth/OIDC-gated).** Rejected as the primary mechanism —
  see above; it adds a listener and an auth dependency the file avoids, without a
  countervailing benefit for a boolean "disarm now" signal.
- **Restoring the full `ActionLog` from the durable journal on every restart, so `enforce`→
  `audit` alone (no break-glass) always self-heals a standing cut.** The journal's `Apply` line
  only ever recorded a cut's signature, not its full `Mitigation` (labels, endpoints); a
  restart's own `MitigationLedger::reconcile` already RE-DERIVES the same `Mitigation` (with
  correct labels) from the current graph whenever the justifying chain still proves — which is
  the common "operator disarms mid-incident" case — but a chain that has ALSO vanished across
  the restart cannot be reconstructed this way. Break-glass sidesteps the whole question: it
  never requires a restart, so the in-memory `ActionLog` is never wiped in the first place.
  Closing the narrower across-a-restart gap (a cut whose chain vanished exactly during the
  restart window) is a follow-up, not required for a fast, reliable disarm.
