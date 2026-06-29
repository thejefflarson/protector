# ADR-0019 — Dashboard v3: the presentation architecture (view_model / component / page split, honesty invariants, light theme)

**Status:** Accepted

## Context

The engine is autonomous and **shadow-by-default**: it proposes, it never acts until armed
(ADR-0016 — presentation is a view, never a gate). The operator is a solo (or very small team)
platform/security engineer who checks in periodically. They have three real jobs: **trust
calibration** (is the engine's judgement sound enough to arm a class?), **triage** (which judged
breaches are real?), and **coverage** (is the engine actually equipped to decide right now?).

Two prior dashboards failed for the same root reason — the *information architecture* was wrong,
and editing an IA doesn't fix it. The specific failures this design exists to prevent:

1. **Burying "why."** The model's verdict is the product; it must be one glance + one click
   away, never a separate destination.
2. **Calm-when-blind.** A quiet green screen while the model is down or warming reads as "safe"
   when it actually means "we haven't looked." This is the cardinal sin.

The agreed v3 design (`docs/dashboard-v3-design.md`) is the synthesis of nine independent
clean-room design passes that converged on the same shape — strong evidence the IA is dictated
by the engine's data model (`engine/src/engine/state/`), not copied from a prior UI. The visual
system (`docs/STYLEGUIDE.md`) is a **light-theme** token system. This ADR records the
architectural decisions that realize them.

## Decision

### 1. Server-rendered, zero-egress, light theme

The dashboard is server-rendered with **maud**, served same-origin from the engine process.
The security graph and evidence never leave the cluster (the zero-egress invariant): the CSS and
JS are bundled via `include_str!` (no third-party CDN), and the only client-side network call is
a poll to the same-origin `/fragment`. The theme is **light** — a clean, high-contrast light
surface with dark ink; calm by default, loud only on a real breach. It terminates no TLS of its
own (it is reached through the cluster's ingress/mesh) and is **read-only**: it snapshots the
engine's output state and never mutates it, so a bad render can never affect the engine.

### 2. The React-like split (view_model → components → page → routes)

The module `engine/src/engine/dashboard/` follows the repo's canonical UI pattern:

- **`view_model/`** shapes `engine::`/`state::` domain state into plain `Props` (owned strings,
  numbers, small presentation enums). It is the **only** layer that touches domain types.
- **`components/`** are pure `maud` renderers (`Props -> Markup`). A component imports **only**
  `maud` and `view_model::props` — never a domain type. This boundary is guard-tested.
- **`page.rs`** composes components into full pages and the `/fragment` live region, and owns
  the persistent status strip + the 4-tab nav shell.
- **`mod.rs`** wires the axum routes (`/`, `/fragment`, `/assets/dashboard.css`,
  `/assets/dashboard.js`), holds `DashboardState` (the shared read-only `Arc` handles), and
  serves it (`serve_dashboard`) behind `PROTECTOR_DASHBOARD_ADDR`, wired from the watch loop.

The split keeps the honesty rules in one tested place (the view_model mapping), lets the
presentation be compiled and tested without the engine, and prevents the monolith regrowth that
sank the prior dashboards. Every file stays under the 1,000-line cap (CLAUDE.md).

### 3. The information architecture

A **primary view + secondary views, with one persistent status strip** — not a single page (one
page recreates the unreadable monolith), and not flat peers (the Findings question dominates):

| Surface | Question | Priority |
|---|---|---|
| **Status strip** (persistent, every view) | Is "quiet" really "blind"? + freshness | always-on |
| **Findings** (primary / landing) | Is anything a breach, and can I trust the call? | P0 — built |
| **Trust** (would-have-acted) | If I armed it, what would it have done? | P1 — phase 2 |
| **Readiness** (coverage detail) | Is the engine equipped to decide? | P1 — phase 2 |
| **Activity** (audit) | What did it actually do, and did it undo it? | P2 — phase 2 |

Findings drill **in place** (row → `<details>` detail panel), keyed by URL fragment; the live
poll preserves scroll/expansion. The **default sort is urgency, not severity** (ADR-0016):
corroborated-live → model-promoted → escalations → awaiting → cleared (collapsed tail). A
critical CVE on an unreachable workload is low-urgency; CVE severity is evidence in the drawer,
never the headline sort.

### 4. The honesty model — three orthogonal axes

The status strip carries three axes that must **never collapse into one signal**:
**breach vs safe** (the verdict), **decided vs awaiting** (has the model judged this?), and
**covered vs blind** (is the model up and are the feeds loaded?). **Green/calm is honest only
while `model_judging == true`.** When the model is warming or not answering, exposed paths are
*unjudged, not cleared*, and the UI says so in the matching non-green register. `Uncertain` and
`Awaiting` are never green.

## Invariants (test-enforced)

1. `!model_judging` or `warming_up` ⇒ the status strip never renders the green/all-clear path;
   the honest banner renders instead. (Render tests.)
2. `Verdict::Uncertain` and awaiting (`None`) never map to the cleared/green token. (View_model
   + render tests.)
3. Empty evidence/coverage renders an explicit "none"/"unknown", never a blank.
4. Components import no `engine::`/`state::` domain type (the view_model/component boundary).
   (Source guard.)
5. No inline `<style>`/`style=` — every visual is a class mapped to a STYLEGUIDE token. (Source
   guard.)
6. All untrusted free-text (verdict prose, CVE/finding titles, model prompts, node keys) is
   HTML-escaped at render (maud auto-escape). (Render test.)
7. No source file exceeds 1,000 lines. (`file_size_guard`.)

## Consequences

- The presentation can be unit-tested at the props boundary and the render boundary with no
  engine and no HTTP — fast, deterministic honesty guards.
- New UI work composes small components against props; it cannot regrow a monolith or smuggle a
  domain type into the render layer (the guards fail the build).
- Phase 1 ships the platform + shared components + the **Findings** view end-to-end; the Trust /
  Readiness / Activity tabs are labelled phase-2 placeholders so the nav exists and is honest
  about what is coming. The data for all four already lives in `state::`.
