# 0027. Dashboard: the server emits a ROOT-ONLY shell; the status strip + nav render in the client

- Status: Accepted
- Date: 2026-07-12
- Supersedes (in part): [0025](0025-dashboard-v4-preact-client-render.md) — its decision that the
  persistent **status strip** and the **tab nav** stay SERVER-RENDERED for a calm-when-blind first
  paint. Everything else in 0025 (Preact reconciler, view_model/props as the serde JSON contract,
  built-from-source bundle, zero-egress, server-derived honesty tokens) stands.
- Reaffirms: [0016](0016-severity-vs-urgency.md) — presentation is a view, never a gate; and the
  honesty axes of [0019](0019-dashboard-v3-presentation-architecture.md)/0025 (blind ≠ green).

## Context

Under ADR-0025 the engine went Preact-only for every view *body*, but kept TWO parts server-rendered
in maud — the status strip and the tab nav — so the honest calm-when-blind banner would paint before
any JS ran. That split had two concrete costs that surfaced in production (JEF-408):

1. **A dead recurring poll masqueraded as a working one.** `poll.js` called its injected interval as
   `(ms, fn)`, but the default was native `setInterval` (`(fn, ms)`), so `setInterval(POLL_MS, tick)`
   handed the *number* 5000 as the handler. The recurring poll never fired — only the initial tick —
   so a client tab-swap blanked the view forever ("clicking does nothing"). Worse, the browser
   coerced the numeric handler to the string `"5000"` and took the legacy string-handler path, which
   compiles the string as code (an eval); the strict CSP (`script-src 'self'`, no `unsafe-eval`)
   correctly blocked it. One reversed-args bug, three symptoms.

2. **Two rendering stacks for the same honesty derivation.** The maud `status_strip.rs` and the
   (client) view bodies both had to agree on the judging axis, kept in sync by hand. Any maud-only
   strip meant the strip and the body could drift, and the shell carried body HTML the client would
   have to reconcile around.

The calm-when-blind justification for a server-rendered strip is weaker than it first appears: a
blank document before the first fetch is *honest* (absent is not a green all-clear), and the strip's
honesty is a **derivation**, not a render — as long as that derivation stays server-side, WHERE the
strip DOM is produced is immaterial to the honesty contract.

## Decision

We will move ALL body HTML — the status strip and the tab nav included — to the Preact client, and
have the server emit a **ROOT-ONLY** document shell.

- **Server shell (`page.rs`):** the body is just `<div id="dash-root" data-tab=…>` + the deferred
  bundle `<script>`. The `<head>` keeps the cluster-labelled `<title>` + css link (head metadata is
  not body HTML). The retired maud `components/status_strip.rs` + `components/nav.rs` (and the whole
  `dashboard/components/` module) are deleted.
- **Client strip (`strip.jsx`):** a faithful port of `status_strip.rs`, reusing the existing
  `dashboard.css` classes verbatim (no new palette). The judging axis is chosen by a single
  SERVER-DERIVED token, `judging-state` ∈ {`all-clear`, `watching`, `judging`, `warming`, `no-model`,
  `blind`}, added to the strip props' hand-written `Serialize` alongside `all-clear`/`watching` and
  computed from the SAME branch logic. The client only SWITCHES on the token — it performs zero
  honesty derivation (the ADR-0025 contract).
- **The poll bug:** the default interval becomes `(ms, fn) => setInterval(fn, ms)` — correct arg
  order — which fixes the dead poll, the blank tab-swaps, AND the CSP eval violation at once (there
  is no longer a string handler to eval). A client tab-swap also restarts the poll so the new tab
  refetches immediately. **The CSP stays strict** (`script-src 'self'`, no `unsafe-eval`); the bug was
  our reversed args, not the policy.

## Consequences

- **Honesty is preserved.** Green renders ONLY when `judging-state === "all-clear"`; watching /
  warming / no-model / blind and any awaiting/uncertain counts are non-green. A blank before the
  first fetch is honest (absent ≠ green — the connection banner already says "connecting…"), and the
  honesty tokens stay server-derived, so the client can never invent a green.
- **One rendering stack, no drift.** The strip and the view bodies are now the same Preact tree over
  the same serde JSON; the maud/Preact sync burden and the `components/` boundary guards are gone.
- **Deferred: SSR/hydration of the strip.** The pre-first-fetch blank is honest but not instant; a
  follow-up may server-render the strip's initial HTML (from the same tokens) and hydrate it to close
  the gap. Noted, not done here — the honesty contract does not require it.
- **Downside accepted:** first meaningful paint of the strip now waits for the bundle + first fetch
  (previously the strip painted with the document). This is an acceptable latency trade for an
  in-cluster, authenticated, low-latency operator dashboard, and the blank it shows is honest.
