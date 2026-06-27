# 0019. maud for the server-rendered dashboard, in a React-like component split

- Status: Accepted
- Date: 2026-06-26
- Relates to: [0009](0009-asymmetric-action-bar.md)/[0016](0016-severity-vs-urgency.md)
  (the read-only view the dashboard renders — presentation is a view, never a decision
  gate), [0015](0015-advisory-evidence-egress.md)/[0018](0018-operator-configured-redacted-breach-notifier.md)
  (the zero-egress posture: the renderer pulls in no remote template and makes no
  outbound call)

## Context

The dashboard is rendered server-side as a single `Html<String>` per route. It grew to
a ~7,800-line `dashboard.rs` of `format!`-string HTML concatenation, which became
unreadable, unreviewable, and a real security liability:

- **The XSS surface was every interpolation site.** Each `format!("…{x}…")` that
  embedded an untrusted value (a CVE id/title, a model verdict, a prompt, an advisory
  summary) had to remember to call `escape()`. The invariant "untrusted text is escaped
  at render" (see [ADR-0016](0016-severity-vs-urgency.md)) was enforced only by
  reviewer vigilance across hundreds of `format!` calls — exactly the kind of audit that
  doesn't hold over time.
- **The views are logic-heavy.** Markup is the *tail* of Rust control flow here: which
  tier a finding sorts into, whether the model is judging, whether a cut is in force.
  String concatenation buries that logic in escaped-quote noise and gives no
  compile-time check that the HTML is even well-formed.
- The file blew past the repo's 1,000-line cap, and the monolith made it impossible to
  state — let alone enforce — which code is allowed to touch engine domain state.

We want a templating approach that is compile-time-checked, escapes by default, loads
nothing at runtime, and lets us split presentation from data the way a component
framework does — without adding a runtime template engine or any egress.

## Decision

**We will adopt [`maud`](https://maud.lang.rs) for the server-rendered dashboard**, and
structure the dashboard as a React-like split.

### Why maud

- **Compile-time-checked HTML-in-Rust.** The `html! { … }` macro is checked at compile
  time; malformed markup is a build error, not a runtime surprise. Route handlers keep
  returning `Html<String>` via `markup.into_string()`, so route signatures and the JSON
  contracts are byte-stable.
- **Auto-escapes every `{ }` interpolation.** This is the load-bearing reason. maud
  HTML-escapes every value spliced through a `( )`/`{ }` brace. That **shrinks the XSS
  surface from "every `format!` site" to an auditable allowlist**: the only way to emit
  un-escaped markup is `maud::PreEscaped`, which is greppable and reviewable in one pass.
- **Zero runtime template loading, zero egress.** Templates are compiled into the binary;
  there is no template directory to read, no remote include, no outbound fetch — it
  preserves the zero-egress posture ([ADR-0015](0015-advisory-evidence-egress.md),
  [ADR-0018](0018-operator-configured-redacted-breach-notifier.md)).

### The `PreEscaped` allowlist (the audited rule)

`maud::PreEscaped` is an **audited allowlist**. It is the *only* sanctioned way to emit
un-escaped HTML, and it may be used **only** for:

1. **already-rendered child `Markup`** — composing a component's output into a parent
   (the value is itself maud output, already escaped at its own braces); and
2. **`mm()`-sanitized Mermaid source** — the graph diagram text, which is passed through
   the existing `mm()` sanitizer that strips HTML metacharacters before it reaches the
   client-side renderer.

Any other `PreEscaped` use is a review-blocking finding. Every other value — CVE id,
advisory title, model verdict, prompt, objective/workload key — goes through a normal
auto-escaping brace.

### The component split (the canonical UI pattern)

The dashboard becomes a module tree with three layers, mirrored in `CLAUDE.md`:

- **`view_model/` — the DATA layer.** Pure functions mapping engine domain state
  (`ClusterStatus`/`Readiness`/`ModelHealth`/nav inputs/`Finding`s) into plain `Props`
  data structs. No maud, no markup.
- **`components/` — the PRESENTATION layer.** Pure `maud` renderers (`Props -> Markup`).
  A presentational component **must not import any `engine::` domain type** — it receives
  only its `Props` (plus the shared `components/chips` primitives and maud). This is the
  enforced boundary that keeps the domain out of the view.
- **`page.rs`** composes components (and, transitionally, the not-yet-migrated panels)
  into full pages and the `/fragment` live region; **`mod.rs`** wires the axum routes and
  `DashboardState` and is the **only** layer that touches engine domain state.

`components/chips.rs` holds the shared presentational primitives (the posture tag, the
attention-tier chip, the CVE severity/KEV badge) that the table, cards, and report reuse.

### Migration

The migration is incremental so each step is reviewable and byte-stable. The nav and the
status banner are migrated end-to-end first as the proof-of-pattern; the remaining panels
(findings table/cards, report, judgements, readiness) stay in a transitional `legacy`
module — still the old string-concat helpers, but split into sub-1,000-line files — and
migrate onto the maud components in follow-up tickets. The legacy `escape()` helper stays
until the last string-concat caller is gone; `mm()` stays permanently (it backs the
Mermaid `PreEscaped` allowance).

## Consequences

Easier / better:

- The XSS surface is an auditable `PreEscaped` allowlist instead of every `format!` site,
  and well-formed HTML is a compile-time guarantee.
- Presentation logic reads as Rust control flow with real components; the `engine::`
  domain can no longer leak into a renderer (the boundary is structural and tested).
- No runtime template engine, no template files, no new egress; route signatures and JSON
  contracts are unchanged.

Harder / accepted:

- A new dependency (`maud` + its proc-macro) in the build.
- A multi-ticket migration during which the dashboard is **mixed**: maud components for
  nav/banner alongside transitional `legacy` string-concat panels. The split files and
  the `PreEscaped` rule contain the risk until the migration completes.
- `PreEscaped` remains a sharp edge; it is mitigated by the narrow, greppable allowlist
  (child `Markup` or `mm()`-sanitized Mermaid) rather than removed.

## Alternatives considered

- **Keep `format!`-string concatenation.** Rejected: the XSS surface is every
  interpolation, there is no compile-time check, and the monolith is unreviewable and
  over the line-cap.
- **A runtime template engine (Tera/Askama-with-files/Handlebars).** Rejected: runtime
  template loading adds a file/loader surface and runs counter to the compiled-in,
  zero-egress posture; logic-in-templates is weaker than logic-in-Rust for these
  logic-heavy views. (Askama is compile-time but keeps markup in separate template files;
  maud keeps the checked markup inline with the Rust control flow it depends on.)
- **A client-side SPA.** Rejected: it would ship the cluster's security graph to the
  browser and add a build/runtime/egress surface the local-first posture forbids.
