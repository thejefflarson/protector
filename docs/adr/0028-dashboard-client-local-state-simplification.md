# 0028. Dashboard client: local state by default — plain useState, no store, zero runtime deps

- Status: Accepted
- Date: 2026-07-12
- Extends: [0025](0025-dashboard-v4-preact-client-render.md) and
  [0027](0027-dashboard-root-only-shell-client-strip.md) — both stand in full. This ADR refines only
  the client's INTERNAL state architecture; nothing about the Preact reconciler, the
  view_model/props serde JSON contract, the built-from-source bundle, zero-egress, or the
  server-derived honesty tokens changes.
- Reaffirms: [0016](0016-severity-vs-urgency.md) — presentation is a view, never a gate; and the
  honesty axes of [0019](0019-dashboard-v3-presentation-architecture.md)/0025/0027 (blind ≠ green).

## Context

The v4 client (ADR-0025/0027) shipped with a hand-rolled observable **store** (`store.js`) holding
the whole client state — active tab, last-good snapshot, connection status, AND every expanded
finding row / open disclosure, the last two mirrored to `sessionStorage` so they survived a soft
reload. Two mechanisms grew on top of it: a keyed-reconcile **tombstone** (`reconcile.js`) that held
a gone-while-open finding on screen for one render as a calm farewell row, and a `purge` step to trim
the persisted id sets after a tombstone cleared.

That is more machinery than the job needs. Preact already keys rows on `finding.id` and diffs them;
a native `<details>` already owns its own open state; a component's own expansion is exactly what
`useState` is for. The store centralised state that wants to be **local**, the sessionStorage
persistence imposed a constraint (open rows survive a reload) the product never actually required,
and the tombstone re-implemented, by hand, a lifecycle the framework's keyed diff performs for free.
Meanwhile the client carried two npm `dependencies` (`preact`, `esbuild-wasm`) as if they were
runtime deps, when the running engine `include_str!`s a compiled bundle and installs nothing.

## Decision

Simplify the client to **local state by default**, plain `useState`/`useEffect` only — no reducer,
no Context, no signals, no new dependency.

- **`App` owns the only shared state**, each field a plain `useState`: `activeTab`, `data` (the
  last-good snapshot), `strip` (global posture — its OWN state, decoupled from `data`), `status`
  (`first-load` | `live` | `stale`), and `lastGoodAt`. The store (`store.js`) is deleted. The status
  transitions are small updaters: a snapshot goes live + resets the freshness clock + persists the
  strip (keeping the last if a snapshot omits it — JEF-410); stale never fires before the first
  snapshot; a tab swap nulls `data` but never touches `strip`.
- **The poll is decoupled to callbacks** (`poll.js` takes `{ tab, onSnapshot, onStale, liveRegion,
  … }`), so it feeds `App`'s `useState` updaters directly with no store dependency. **The JEF-408
  fix is retained verbatim**: the default interval is `(ms, fn) => setInterval(fn, ms)` (a
  function-first handler, never a number coerced to a string and eval'd), the synchronous first
  `tick()`, the stale-on-failure paths, and the mid-selection defer guard all stand. The `App` poll
  effect keys on `[activeTab]` so a swap restarts it — an immediate refetch.
- **Expansion / disclosure is LOCAL and ephemeral.** A finding row's expansion is a `useState` in
  the row; every "show model prompt" / node-breakdown / judgement disclosure is a **native,
  uncontrolled `<details>`**; the Admission signing-row expander is a `useState` per row. None is
  persisted. Preact's keyed diff keeps an open row open across a poll for free; the sessionStorage
  persistence (open rows survive a reload) is **dropped** — an unnecessary constraint.
- **Keyed removal replaces the tombstone.** A finding that vanishes from a snapshot is removed by
  Preact's keyed diff (`key={f.id}`). `reconcile.js` and the client tombstone are deleted, with **no
  client replacement** — a future "recently cleared" cue must be **server-shipped** (the honest
  cleared-count already carries the signal).
- **Zero runtime npm deps.** `preact` and `esbuild-wasm` move to `devDependencies` (both are
  build/test-only — the bundle is compiled and `include_str!`'d, the running engine installs
  nothing). The unused `@vitest/mocker` (transitive) and top-level `vite` pin are dropped;
  `jsdom` + `@testing-library/preact` + `vitest` stay. The lockfile is regenerated so `npm ci` and
  the supply-chain guard match.

## Consequences

Easier:

- One obvious place for shared state (`App`) and the framework's own defaults everywhere else — less
  bespoke machinery to read, test, or get wrong. `store.js` + `reconcile.js` (and their tests) are
  gone; the views are pure `view`-only renders.
- The honesty contract is untouched and re-pinned: `StatusStrip`/`FindingsEmpty` still render SERVER
  tokens (green iff `strip["all-clear"]`), the strip is server-derived, and `strip.test.jsx` +
  `honesty.test.jsx` pass unchanged. The client still derives no honesty.
- The dependency surface is honest: the running engine has zero runtime npm deps; the build/test
  deps are clearly marked as such.

Harder / accepted:

- **Open rows don't survive a reload.** With the sessionStorage persistence dropped, a soft reload
  collapses expanded rows and disclosures. Accepted: expansion is an ephemeral read-affordance, not
  state worth persisting, and a reload is a deliberate act; the honesty-critical strip is unaffected.
- **A cleared finding disappears without a farewell.** Removing the tombstone means a gone finding
  simply drops from the table with no on-screen "this cleared" cue. Accepted as HONEST — the row is
  no longer a live proven path, and the strip's cleared-count carries the fact. A gentler
  "recently cleared" affordance, if wanted, is a server-shipped concern (the client derives nothing),
  not a client-held tombstone.
