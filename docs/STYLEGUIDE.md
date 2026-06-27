# protector dashboard style guide

The dashboard is an operator's situation board, not a marketing page. This guide is the
source of truth for its visual system: the design tokens, the component→token map, and the
accessibility gate the tests assert. It was introduced by JEF-203, which extracted the
formerly inline CSS/JS into self-hosted static assets and layered a token system over the
existing palette **with zero behavior change**. JEF-208 completed the raw-value→token sweep:
every raw hex now lives ONLY in the `:root` primitive palette, and a guard test enforces it.

## Where the code lives

- `engine/web/dist/dashboard.css` — the single stylesheet (consolidated from the three
  former inline `<style>` blocks: the `/` page, `/report`, `/judgements`). Embedded in the
  binary via `include_str!` and served same-origin at `/assets/dashboard.css`.
- `engine/web/dist/dashboard.js` — the page module (Mermaid hydrate, `<details>`/row
  persistence, the same-origin `/fragment` poll). Embedded + served at `/assets/dashboard.js`.
- `engine/src/engine/dashboard/` — the maud component tree (ADR-0019) that renders the HTML
  and links the two assets (`<link rel="stylesheet" …>` + `<script type="module" src="…">`):
  `page.rs` composes the page/fragment, `components/` are the pure maud renderers, and
  `view_model/` shapes the engine data into their `Props`.

**Zero egress.** No web fonts, no CDNs, no third-party CSS/JS. The graph renderer
(beautiful-mermaid + ELK) is vendored into `web/dist` and served same-origin too. The font
stacks are the system stacks only (`system-ui, sans-serif` and `ui-monospace, monospace`).

## Principles

1. **Legible density.** Pack the screen with scannable signal — small type, tight spacing,
   flat tables. An operator should see the whole posture at a glance, not scroll a feed.
2. **Status is a word; color only reinforces.** Every state (breach / watch / safe /
   awaiting / isolated / warming) is named in text and carries an a11y role. Color is the
   second channel, never the only one — colorblind operators read the words.
3. **Flat and square.** No shadows, no large radii. `--radius-0` (square) is the default;
   chips get a hairline `--radius-chip: 2px`. Borders, not elevation, separate regions.

## Design tokens (`:root`)

The token block at the top of `dashboard.css` is the palette's source of truth. It is two
layers: a **small primitive palette** (deduped from the ~34 ad-hoc hexes the three inline
blocks carried — near-duplicate greys/reds/ambers collapsed) and **semantic tokens** layered
over it. As of JEF-208 the sweep is complete: **every** rule body consumes a token, and a
raw hex appears ONLY in the `:root` primitive palette — the
`no_raw_hex_outside_root_in_dashboard_css` guard test fails the build otherwise. Every AA
value is preserved verbatim.

The neutral greys span a primitive ramp: `--c-grey-1 #555` (AA on white) · `--c-grey-2 #666`
· `--c-grey-3 #6a6a6a` (the muted token) · `--c-grey-4 #888` (expanded-chip outline / verdict
accent border) · `--c-grey-5 #999` (the decorative entry→ arrow only) · `--c-grey-6 #bbb`
(low-emphasis border) · `--c-grey-line #ccc` · `--c-grey-border #ddd` · `--c-grey-hair-2 #eee`
(hairline border / inline-code fill) · `--c-grey-hair #f0f0f0`.

### Colors — surfaces

| token | value | use |
|---|---|---|
| `--color-bg` | `#fff` | page background / `body` ink base is `--c-ink` `#111` |
| `--color-surface` | `#f4f4f4` | `code`, inline fills, neutral chips |
| `--color-border` | `#ddd` | default hairline borders |
| `--color-muted` | `#6a6a6a` | de-emphasized text — **AA ≥4.5:1 on white** |
| `--color-link` | `#06c` | links / interactive affordances |

### Colors — state triads (line/border · text-on-tint · tint background)

| state | `…` (line) | `…-text` | `…-tint` |
|---|---|---|---|
| breach | `--color-breach` `#b00000` | `--color-breach-text` `#7a0000` | `--color-breach-tint` `#fdecec` |
| watch / awaiting-decision | `--color-watch` `#9a5b00` | `--color-watch-text` `#7a4a00` | `--color-watch-tint` `#fbf6ee` |
| safe / calm | `--color-safe` `#1a7f37` | `--color-safe-text` `#155f29` | `--color-safe-tint` `#eef7f0` |
| awaiting / neutral | `--color-awaiting` `#555` | `--color-awaiting-text` `#555` | `--color-awaiting-tint` `#f4f4f4` |

The `-text` value of each triad is chosen to pass AA on its own `-tint` background. These
pairs are the JEF-180 AA values, preserved verbatim — **do not regress them.**

### Colors — severity scale

The severity scale maps onto the triads, introducing **no new hues**:

| severity | maps to |
|---|---|
| `--color-sev-critical*` | the breach triad |
| `--color-sev-high*` | the watch triad |
| `--color-sev-medium*` / `--color-sev-low*` | the awaiting/neutral triad |

### Typography

A 6-step scale plus the system stacks (no web fonts):

`--fs-xs` `.72rem` · `--fs-sm` `.78rem` · `--fs-md` `.85rem` · `--fs-lg` `.92rem` ·
`--fs-xl` `1.05rem` · `--fs-2xl` `1.2rem`. Fonts: `--font-sans` (`system-ui, sans-serif`),
`--font-mono` (`ui-monospace, monospace`).

### Spacing, radii, borders

Spacing is a `.25rem` grid: `--sp-1 … --sp-8` (`.25rem` … `2rem`). Radii: `--radius-0` (`0`,
the flat/square default) and `--radius-chip` (`2px`). Border widths: `--border-1/2/3`.

## Component → token map

| component | tokens it consumes |
|---|---|
| **banner** (`.banner`, `.banner-ok/-breach/-isolated/-warming/-unjudged`) | the state triads — `.banner-ok` → safe, `.banner-breach`/`.banner-isolated` → breach, `.banner-unjudged` → watch, `.banner-warming` → muted/awaiting; border `--color-border`, square `--radius-0` |
| **findings table** (`table.findings`) | `--color-border`, `--c-grey-line`/`--c-grey-hair` rules, calm row → `--color-safe`, hover → page fill |
| **chips** (`.chip`, `.chip-breach/-safe/-awaiting`) | the matching triad (text-on-tint + tint + line), `--font-mono`, `--fs-xs`, `--radius-chip` |
| **trust rail** (`.rail`, `.rail-cap`) | `--color-safe` / `--color-safe-text` (it's the "left alone" evidence) |
| **evidence** (`.ev`, `.ev-cve`, `.ev-runtime`, `.ev-crit`, `.ev-live`) | watch for CVE, breach for runtime/critical/live |
| **severity badges** (`.sev-critical/-high/-medium/-low`, `.kev`) | the severity scale → triads |
| **details / expanders** (`details.diag/.howto/.legend-d`, `.raw`) | `--color-link` summaries, square, flat |
| **nav** (`.nav`, `.nav a`) | `--color-link`; current page → `--c-ink` underline |
| **/report page** (`h3`, `.sum`, `.sustained`, `.shortlived`, `.verdict-cell`) | breach for sustained, watch for short-lived |
| **/judgements page** (`.meta`, `.raw`, `.raw-cap`, `.vline`, `.vwords`, chips) | shared base + the chip triads; `.meta` → `--c-grey-1` |
| **readiness** (`ol.readiness`, `.r-state-*`, `.r-weak`, `.r-cold`) | ok→safe, absent→breach, degraded→watch |

## Accessibility gate

The render tests (`engine/src/engine/dashboard/tests`) assert the AA contract — they don't
just eyeball it. Specifically, `render_html_uses_aa_contrast_tokens` asserts, for each AA pair,
**(a)** the token is defined as its AA value in `:root`, AND **(b)** the high-traffic class
consumes that token (not a raw hex):

- `--color-muted` is `#6a6a6a` (≥4.5:1 on white); `.muted` and `.verdict.muted` consume it.
- the legend / Mermaid-fallback grey is `#555` (`--c-grey-1`); `.mermaid` consumes it.
- the calm green is `#1a7f37` (`--c-green`); the safe text-on-tint is `#155f29`
  (`--c-green-text` / `--color-safe-text`).
- the warming-banner word/glyph consume `--color-muted` (`#6a6a6a`), not the old failing
  `#777`.

The old failing values are asserted **absent** from both the served CSS and the rendered
HTML (no `.muted{color:#777}`, no Mermaid `color:#999`). Every state also carries its status
as a **word** plus an ARIA role (`role="status" aria-live="polite"` on the banner; rendered
graphs get `role="img"` + an `aria-label`), so the a11y contract never depends on color
alone. The XSS/escape contract is now carried by maud's auto-escaping braces (ADR-0019) —
the legacy `escape()` helper is gone; the only un-escaped sink is `mm()`-sanitized Mermaid
source. A dashboard guard test additionally fails the build if a raw hex escapes `:root`, an
inline `<style>` reappears in a render path, or a presentational component imports an
`engine::` domain type. The no-`ADR-`/`JEF-`-leak contract is likewise test-gated.
