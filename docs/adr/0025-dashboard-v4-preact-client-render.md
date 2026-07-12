# 0025. Dashboard v4: a bundled Preact client reconciling from same-origin JSON, superseding maud server-render

- Status: Accepted — **cutover COMPLETE** (JEF-398): rolled out per-tab behind a flag (JEF-397 /
  JEF-400), then the maud render half + the flag were deleted; the engine is Preact-only.
- Date: 2026-07-11
- Supersedes (in part): [0019](0019-dashboard-v3-presentation-architecture.md) — its
  presentation-*mechanism* decisions (§1 server-rendered maud, §2 `page.rs`/`/fragment`
  render layer). Its information architecture (§3) and honesty axes (§4) SURVIVE.
- Reaffirms: [0016](0016-severity-vs-urgency.md) — presentation is a view, never a gate.

## Context

ADR-0019 shipped the dashboard as **server-rendered maud**, served same-origin from the
engine, with a JS poll that fetches `/fragment` (a rendered HTML partial) and swaps it into
a live region via `innerHTML`. That mechanism has three concrete, recurring failures — all
of them consequences of *replacing DOM subtrees the browser owns state for*:

1. **`innerHTML` swap destroys focus and native `<details>` state.** Every poll re-parses
   the fragment and replaces the live region wholesale, so an open detail drawer collapses,
   a focused control loses focus, and text selection is dropped. The v3 client carries a
   sessionStorage shim to re-open drawers after a swap, but it cannot rehydrate focus,
   selection, or the exact scroll within a reopened drawer — the shim papers over a
   mechanism that is structurally lossy.
2. **A one-row change re-parses the whole table.** The fragment is all-or-nothing: a single
   finding flipping posture forces the browser to tear down and rebuild every row, which is
   both wasteful and the direct cause of the state loss above.
3. **Tab-switch is a full server navigation.** Moving between Findings / Alerts / Action /
   Readiness / Admission is a document load, not a view change.

A **keyed client reconciler** fixes all three at the root: it diffs against the live DOM and
touches only what changed, so focus, selection, and native `<details>` state on untouched
nodes are never disturbed, a one-row delta patches one row, and a tab-switch is a local view
swap. We adopt **Preact** (a ~4 KB React-compatible reconciler) bundled with **esbuild**,
reconciling from the same-origin, read-only JSON the engine already has the props to emit.

This is a mechanism reversal, not an IA reversal. ADR-0019's hard-won information
architecture and its three honesty axes were the *product*; they are preserved verbatim on
the new stack. What changes is *how the DOM is produced* — and every zero-egress, read-only,
and honesty invariant is restated below so the new stack inherits them explicitly rather than
by assumption.

## Decision

Replace server-rendered maud + `innerHTML`-swap-on-poll with a **bundled Preact client that
reconciles from same-origin, read-only JSON**. The engine serves a static bundle same-origin;
the client fetches a JSON snapshot per tab and keyed-reconciles the view.

### Preserved invariants, restated for the new stack

- **Zero-egress / no-CDN — scoped to the RUNNING ENGINE, not the build.** The running engine
  makes **no new outbound calls**: it serves the bundle same-origin via `include_str!`
  exactly as it serves `dashboard.css`/`dashboard.js` today, the only client network call is
  a same-origin fetch of the JSON snapshot, and the CSP stays `connect-src 'self'` (no CDN,
  no third-party origin). The bundle is **built from source at build time** — a node stage in
  the Docker build and a node step in CI — which fetches `preact` + `esbuild` from npm
  **exactly as the build already fetches cargo crates from crates.io**. The Dockerfile build
  is network-fetching, **not** air-gapped; npm-at-build-time is therefore *not a new egress
  class* and needs **no npm mirror**. Zero-egress is a property of the deployed engine in the
  cluster, never a claim that the build is offline.
- **Read-only / view-never-a-gate ([ADR-0016](0016-severity-vs-urgency.md) REAFFIRMED).** The
  JSON is a **snapshot** of the engine's output state under the same authorization as the
  page. It carries **no gating, auth, or decision field**; the client cannot mutate the
  engine, arm a class, or influence a verdict. A bad render — or a hostile client — can change
  nothing in the engine. Presentation remains strictly downstream of the decision.
- **Untrusted text is escaped.** Preact **auto-escapes** all interpolated text (CVE titles,
  verdict prose, model prompts, node/relation keys), the same guarantee maud gave.
  **`dangerouslySetInnerHTML` is BANNED** in `engine/web/src/` — enforced by a source guard,
  the direct analogue of the v3 "never `PreEscaped` for untrusted text" rule.
- **The client performs NO honesty derivation.** Every honesty signal is **derived on the
  server** and shipped as an explicit boolean/token in the JSON — `all_clear`, `watching`,
  and the per-row posture — computed by the retained `view_model` layer. The client is a
  **dumb renderer**: it displays the server's tokens and never recomputes "is this green?"
  from raw fields. This is the cardinal rule: re-deriving honesty in untested JavaScript is
  exactly how a **false-green leaks in front of a blind model**. Honesty stays where it is
  tested — in the props layer — and the wire format carries the answer, not the inputs.
- **Calm-when-blind first paint.** The persistent status strip stays **server-rendered** in
  the initial document so the honest banner (`!model_judging` / `warming_up` ⇒ never green,
  ADR-0019 §4) paints before any JS runs and is never subject to a blank-until-hydrated gap.
- **No inline style / script (ADR-0019 §5).** Carries over unchanged — every visual is a
  STYLEGUIDE class, no inline `<style>`/`style=` — and is now additionally **CSP-required**
  (`style-src`/`script-src` without `'unsafe-inline'`), since the bundle is served under a
  strict same-origin CSP.
- **File-size cap (CLAUDE.md, 1,000 lines).** Extended to `engine/web/src/` — the Preact
  source obeys the same hard cap and same-split-into-modules discipline as the Rust tree.

### What ADR-0019 becomes

ADR-0019's **presentation-mechanism** decisions are **Superseded by ADR-0025**:

- **§1 (server-rendered maud, `include_str!` CSS/JS, `/fragment` poll)** — superseded. maud
  no longer renders the views; the `/fragment` HTML-partial route is replaced by a JSON
  snapshot endpoint per tab.
- **§2 (the `page.rs` / component maud render layer, `Props -> Markup`)** — the *maud render
  half* is superseded; the **`view_model`/props half is RETAINED and elevated**.

ADR-0019's **§3 information architecture** (primary Findings + secondary tabs + one
persistent status strip; urgency-not-severity sort) and **§4 honesty axes** (breach-vs-safe,
decided-vs-awaiting, covered-vs-blind; green honest only while `model_judging`) **SURVIVE
unchanged** — they are the product this rewrite preserves. The JEF-281 amendment
(finding detail shows *all* proven paths, not one) survives as a data/IA requirement: the
JSON carries every proven path and the client renders them as keyed, collapsible staircases.

The **`view_model` layer is RETAINED and elevated to the JSON contract.** The wire format is
the existing `*ViewProps` structs (`FindingsViewProps`, `AlertsViewProps`, `ActionViewProps`,
`ReadinessViewProps`, `AdmissionViewProps`, `StatusStripProps`) made `serde`-serializable —
**NOT a new parallel DTO**. There is one shape of the truth; serde serializes it. The honesty
tests move from the **maud-render boundary** to the **JSON-props boundary** — they assert the
serialized props (the bytes the client receives), so the guarantee is tested at the exact
seam the client consumes.

### Recorded decisions

- **(a) serde-props-as-contract.** The JSON wire format is the serde serialization of the
  existing `view_model` `*ViewProps` types — no second DTO layer. Honesty tests assert on the
  serialized props. This keeps a single source of truth and prevents drift between "what the
  server decided" and "what the client shows."
- **(b) build-from-source, gitignored, node is an engine build dep, no npm mirror.** The
  bundle is built from `engine/web/src/` at build time (Docker node stage + CI node step);
  **node becomes a build dependency of the engine** alongside cargo. The **built bundle is
  gitignored and never committed** — source is the single truth, mirroring how compiled Rust
  artifacts are never committed. (This reverses the v3 stopgap of vendoring the committed
  bundle in `engine/web/dist`.) **No npm mirror** is introduced: the build fetches from npm
  the same way it fetches crates from crates.io.
- **(c) JS file-size cap.** The CLAUDE.md 1,000-line hard cap extends to `engine/web/src/`;
  the client is written as small, single-purpose modules from the start.
- **(d) no-JS progressive enhancement is DROPPED.** Without JavaScript the page renders the
  server status strip and then a blank body — there is no `<noscript>` full render. This is a
  **conscious** trade for an in-cluster operator tool reached through the cluster's own
  ingress by a platform/security engineer with a modern browser; it is **not** a silent
  regression. The status strip's calm-when-blind first paint (above) means the *safety-critical*
  honesty signal never depends on JS; only the detailed views do.

## Consequences

Easier:

- Focus, selection, and native `<details>` state survive a poll — the reconciler patches
  only changed nodes, so the sessionStorage rehydration shim is deleted, not extended.
- A one-row posture flip patches one row; a tab-switch is a local view swap, not a document
  load.
- The JSON-props contract is testable without a browser: honesty guards assert on serialized
  props, and the client is a thin renderer over a contract the server already owns.

Harder / accepted:

- **Node joins the engine build.** The Docker build and CI gain a node stage/step, and the
  bundle must be built (not committed) before the engine can `include_str!` it. Accepted:
  npm-at-build-time is the same trust class the build already accepts for crates.io, and a
  built-from-source, gitignored bundle is honest where a committed vendored blob was opaque.
- **No-JS users get a blank body.** Accepted for an in-cluster tool (decision (d)); the
  safety-critical status strip still paints server-side.
- **A new "false-green in JS" failure mode must be actively prevented.** The client must never
  re-derive honesty. Mitigated by decision (a) (honesty is server-derived and shipped as
  tokens) plus the `dangerouslySetInnerHTML` ban and the JSON-props honesty tests — the same
  discipline ADR-0019 §4 enforced, relocated to the props boundary.

## Cutover status (JEF-398 — COMPLETE)

The migration ran in five parts. JEF-395 stood up the read-only `/api/*.json` snapshots from the
serde view-model and relocated the honesty guards to the JSON-props boundary; JEF-396 built the
bundle from source (gitignored) and added the source/bundle guards; JEF-397 and JEF-400 ported all
five views to Preact behind a per-tab flag (`PROTECTOR_DASHBOARD_PREACT_TABS`), rolling out live in
prod. **JEF-398 completed the cutover:** with the honesty invariants proven on the new stack, it
**deleted the maud render half** (the `components/*_view.rs` / `finding_*` / `evidence.rs` body
renderers, the `/fragment` route, and the fragment composition in `page.rs`/`mod.rs`) and
**removed the per-tab flag** (`preact_flags.rs`, the `PROTECTOR_DASHBOARD_PREACT_TABS` env read, and
all `PreactTabs` gating). The engine is now **Preact-only, flag-free**: `page.rs` emits, for every
tab, the server-rendered shell — head + persistent status strip + 5-tab nav + the Preact
`#dash-root` mount — and the client reconciles every view body from `/api/{tab}.json`. What stays
server-rendered is only the calm-when-blind first paint (strip + nav). The client intercepts every
tab-swap (no maud fallback), so `data-preact-tabs` is gone. (The cluster chart still sets the now-
ignored `PROTECTOR_DASHBOARD_PREACT_TABS`; the main loop removes that dead env after this deploys.)
