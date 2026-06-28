# 0020. Dashboard v2 — a single-page, typed-verdict, text-attack-path rewrite

- Status: Accepted
- Date: 2026-06-28

## Context

The v1 dashboard answered too many questions at once. It had grown into five tabbed
surfaces — findings, the would-have-acted report, the admission/policy log, the raw
judgements "why" view, and a MITRE ATT&CK attack-vectors matrix — plus a vendored
1.5 MB `beautiful-mermaid` bundle that rendered each attack path as a client-side graph.
That breadth came at a cost:

- **No single answer.** An operator opening the dashboard could not tell at a glance the
  one thing that matters: *is anything actually compromised right now, and if not, am I
  covered or blind?* The answer was spread across tabs.
- **Posture re-derived from prose, four times over.** The model emits a typed `Verdict`
  (`Confirmed` / `Exploitable` / `Refuted` / `Uncertain`), but the view threw the type away
  and string-matched the verdict *summary* ("does it start with 'exploitable'?") in four
  separate places. They diverged, and the match silently missed `Confirmed` — a real breach
  reading as SAFE.
- **A graph renderer for a path that is a list.** A proven attack path is a linear hop
  sequence (entry → … → objective). Rendering it with a 1.5 MB graph-layout engine was weight
  and a client-side-rendering dependency for what is fundamentally text.
- **Incrementalism had run out.** Successive tickets had patched the IA (collapse this, demote
  that, relabel the calm row) without changing the premise that the dashboard is a set of
  co-equal tabs. The premise was the problem.

The platform was sound: server-rendered `maud` with the ADR-0019 `view_model → component`
split, fed by the engine state the dashboard already reads (findings, the typed verdict store,
per-entry evidence, readiness/coverage, the admission decision log, reversions, the bake). The
problem was everything above that platform.

## Decision

We will replace the v1 dashboard with a ground-up **single dense page, no tabs** (JEF-255).
The page answers ONE question; the four kept capabilities become layers of it:

1. A one-line **status line** — `● N BREACH · M endpoints · K awaiting · model live (pass
   <age>) · coverage X%`. It reads GREEN only when it is honestly all-clear AND covered; a
   model that is down reads as a **blind** state, never calm (ADR-0016: unjudged ≠ cleared).
2. A loud **BREACH queue**, rendered only when there is ≥1 breach.
3. The dense **ENDPOINTS table** (the core): one row per exposed entry — posture chip,
   `entry → reaches`, the decisive verdict clause, evidence glyphs, Δ, age — each row
   expanding to the "why" detail (the verbatim model verdict + a raw-prompt expander, the
   proof/certainty rail, the evidence blocks, the attack path, and a posture-gated what-to-do).
4. A compact **ADMISSION strip** (`signed X/Y · meshed Y/Y`), leaving a seam for the future
   "if enforced" what-if (JEF-246).
5. A demoted **ENGINE-INTERNALS** disclosure (coverage detail, recent reversions, bake counts)
   behind one collapsed `<details>` that auto-opens only when a decision input is unmet.

Three structural decisions back the page:

- **Typed-verdict posture SSOT.** Posture (`Breach` / `Safe` / `Awaiting`) is derived ONCE,
  from the typed `Verdict` (`Verdict::is_confirmed()` is a breach), in `view_model::posture`.
  The data-layer twin `StoredPosture::of_verdict` mirrors it from the same typed input. The
  `Finding` now carries `Option<Verdict>` (resolved from the verdict store at snapshot time),
  not a summary `String`. No view code re-parses verdict prose. This also fixes the v1 bug
  where `Confirmed` read SAFE.
- **The attack path is a text hop-list, not a graph.** Built from the finding's proven `path`
  steps, with the single-edge cut point marked `✂ cut here (…)`. The `beautiful-mermaid`
  bundle, its `entry.mjs`/`build.mjs` build, the `mm()` sanitizer, the `/assets/
  beautiful-mermaid.js` route, and the client hydrate path are all deleted. The binary embeds
  no graph renderer.
- **One page, fewer routes.** Only `/` (HTML), `/fragment` (the incremental-poll `#live`
  region), and the self-hosted `/assets/dashboard.{css,js}` remain. The `/findings`,
  `/report(.json)`, `/policy(.json)`, `/judgements(.json)`, `/reversions`, `/readiness`, and
  `/bake` JSON/HTML routes and the attack-vectors matrix are dropped. The would-have-acted
  aggregation stays solely to feed the engine's per-pass OTLP mirror (`default_window_report`);
  no metric is broken.

The invariants are preserved: components stay pure `Props → Markup` importing no `engine::`
domain type (the ADR-0019 guard test), every value is auto-escaped at the `maud` brace (zero
`PreEscaped` outside the byte-stable `chips` constants — now its own guard test), the engine
stays shadow-by-default and zero-egress, and presentation remains a view, never a decision gate
(ADR-0016).

This ADR **complements** ADR-0019 (maud templating / the view_model→component split, which v2
keeps and leans on) and ADR-0016 (presentation is severity-not-urgency and never a gate, which
the status line's honest blind state and the posture-gated what-to-do embody). It supersedes
neither.

## Consequences

Easier:

- The dashboard answers its one question at a glance; the blind state is honest.
- Posture can never drift between the recency diff, the chip, and the queue — there is one
  typed derivation.
- The served binary is ~1.5 MB smaller and loads no graph engine; the attack path is plain,
  escapable text that is readable without JavaScript.
- The dashboard Rust shrank from ~12.7k lines (v1, including the report/policy/judgements/
  attack-vectors view_models + components) to a small set of focused modules well under the
  1,000-line cap each.

Harder / accepted downsides:

- The machine-readable JSON routes (`/findings.json`, `/report.json`, …) are gone; anything
  that scraped them must move to OTLP or be re-added deliberately. This is acceptable: they
  were unconsumed by the operator/tunnel path.
- A journal-restored entry (after a restart, before re-judgement) reads as **awaiting** rather
  than carrying its restored prose verdict, because the typed SSOT only holds a live typed
  verdict. This is the honest "not re-confirmed this run" state and matches the known
  post-restart warm-up; the entry flips to its real posture on the first re-judge.
- The MITRE attack-vectors matrix is gone. The ATT&CK technique is still proven and judged; it
  is simply no longer surfaced as a separate matrix panel.
