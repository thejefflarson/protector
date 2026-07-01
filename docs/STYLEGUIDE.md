# Protector dashboard — style guide

The dashboard is an operator's **situation board**, not a marketing page. This is the source
of truth for its visual system: the design tokens, the component→token map, and the
accessibility gate the tests assert. Pairs with [`dashboard-v3-design.md`](dashboard-v3-design.md)
(the IA/UX). **Light theme:** a clean, high-contrast light surface with dark ink — dense and
calm by default, loud only on a real breach.

## Principles

1. **Honesty over reassurance.** The overall green/all-clear is shown ONLY when the model has
   *affirmatively cleared everything it is looking at* — judging AND covered AND zero breaches
   AND zero entries still awaiting judgement AND zero uncertain. If any entry is still awaiting
   or uncertain, the model isn't yet sure, so the posture is the elevated **"watching"** state
   (calm but not green), never all-clear. Unknown and awaiting are never green. (Test-enforced —
   see the gate.)
2. **Posture ≠ severity.** The model's verdict is the loud channel; CVE severity is a cooler,
   subordinate channel. A wall of critical CVEs must never look like a wall of breaches.
3. **Meaning never by colour alone.** Every status carries colour **+ glyph + word**.
4. **Density with discipline.** Monospace/tabular for all machine data so columns align; one
   restrained type scale and a small palette so density never becomes noise.
5. **Calm by default, loud on breach.** Saturated colour is a scarce resource on the light
   surface — spent only on a real breach.

## Design tokens

### Colour — surfaces & ink (light)
| Token | Value | Use |
|---|---|---|
| `--bg` | `#FCFCFD` | page background |
| `--surface` | `#FFFFFF` | cards, table |
| `--surface-raised` | `#F4F6F8` | expanded row, header strip |
| `--surface-hover` | `#F0F2F5` | row hover |
| `--border` | `#E2E6EB` | hairlines, grid |
| `--ink-1` | `#1A1F26` | primary text (≈15:1 on `--surface`) |
| `--ink-2` | `#5A6473` | secondary text (≈6:1) |
| `--ink-3` | `#6B7280` | tertiary / muted (≈4.6:1) |

### Colour — posture (the model's `Verdict`; the loud channel)
| Token | Value | Glyph | Word | Rail |
|---|---|---|---|---|
| `--posture-breach` | `#D92D20` | ● filled | BREACH / EXPLOITABLE | 3px solid |
| `--posture-cleared` | `#067647` | ○ open | no exploit evidence | 2px solid |
| `--posture-uncertain` | `#B54708` | ◐ half | uncertain | 2px **dashed** |
| `--posture-awaiting` | `#9A6B2E` | ◌ dotted | awaiting judgement | 2px **dotted** |

Uncertain is a stronger amber-brown; **awaiting is a softer, muted ochre — slightly elevated,
clearly *below* uncertain's intensity**. Neither is ever the cleared green. An un-judged exposed
path reads as "pending the model's call / mild attention," not "fine" and not "uncertain." A
subtle ochre tint backs the awaiting row/chip (`--posture-awaiting-tint: #FBF6EC`). Dashed/dotted
rails make "not decided" texturally distinct even in greyscale.

### Colour — severity (CVE/`ScanFinding`; subordinate, muted)
| Token | Value | Cue |
|---|---|---|
| `--sev-critical` | `#B42318` | ▲▲ `CRIT` |
| `--sev-high` | `#B54708` | ▲ `HIGH` |
| `--sev-medium` | `#854A0E` | ◆ `MED` |
| `--sev-low` | `#6B7280` | · `LOW` |
| `--kev` | `#D92D20` (filled badge) | `KEV` — the one severity-side signal allowed to be loud |

### Colour — recency Δ, coverage, mode
| Token | Value | | Token | Value |
|---|---|---|---|---|
| `--delta-new` | `#1570EF` | | `--cov-present` | `#067647` |
| `--delta-up` | `#D92D20` | | `--cov-degraded` | `#B54708` |
| `--delta-down` | `#067647` | | `--cov-absent` | `#6B7280` |
| `--delta-restored` | `#6B7280` | | `--mode-shadow` | `#667085` |
| | | | `--mode-enforce` | `#1570EF` |

### Colour — signing posture (ADR-0020; the Admission signing inventory)
Every image's observed signing posture, always one of these — **never n/a** — each carrying
colour **+ glyph + word** (meaning never by colour alone). `invalid signature` is the loud channel;
plain `not signed` is calm (no baseline yet), never green. The "if enforced" cell is always the
binary would-admit / would-block.
| Token | Value | Glyph | Word |
|---|---|---|---|
| `--sign-signed` (`--cov-present`) | `#067647` | ✓ | signed |
| `--sign-invalid` (`--posture-breach`) | `#D92D20` | ✕ | invalid signature |
| `--sign-notsigned` (`--ink-3`) | `#6B7280` | ○ open | not signed |
| `--sign-checking` (`--posture-awaiting`) | `#9A6B2E` | ◌ dotted | checking… |

### Space (4px base)
`--space-1:4 · --space-2:8 · --space-3:12 · --space-4:16 · --space-6:24 · --space-8:32`

### Type
```
--font-ui:   Inter, system-ui, sans-serif      /* chrome, prose, labels */
--font-data: "JetBrains Mono", ui-monospace, monospace  /* ALL data: keys, CVEs, paths, counts */
--text-display: 22/28 600   --text-h2: 16/24 600   --text-body: 14/20 400
--text-data:    13/18 400   --text-data-strong: 13/18 600
--text-micro:   11/16 500   /* uppercase, tracked: column headers, chip text */
```
Two weights only (400/600). Emphasis via weight + ink value, not a third weight.

### Geometry
`--row-h:36 · --radius-chip:3 · --radius-panel:6 · --rail-strong:3px · --rail-soft:2px · --focus-ring:2px solid #1570EF`

## Component → token map
| Component | Tokens |
|---|---|
| Page / app frame | `--bg`, `--font-ui` |
| Status strip | `--surface-raised`; posture-* count chips; green all-clear (`--posture-cleared`) only when judging+covered+nothing breach/awaiting/uncertain; elevated "watching" (judged+covered but still awaiting/uncertain) and the blind/warming banner use `--posture-awaiting`/`--posture-uncertain`, **never** `--posture-cleared` |
| Finding row | `--surface`, `--row-h`, `--border` grid; entry/path `--font-data` `--text-data` |
| Posture cell | `--posture-*` (rail style: solid=decisive, dashed=uncertain, dotted=awaiting) + glyph + word |
| Severity chip | `--sev-*` border (muted); KEV → `--kev` fill |
| Δ cell | `--delta-*` glyph, or `--ink-3` age text for `Unchanged` |
| Detail panel | `--surface-raised`, `--space-4`; verdict prose `--text-body`, posture left-rule |
| CVE table | `--font-data` `--text-micro`, right-aligned numerics |
| Coverage row | `--cov-*` dot + glyph + label; `weakens_decisions` + absent → amber keyline |
| Reversion log | `--posture-cleared` toned (a self-revert is the system working) |
| Signing inventory | `--sign-*` chip (glyph + word); `invalid` → `--posture-breach` keyline (loud), `not signed` calm; ref/signer single-line ellipsis (never `break-all`), full value in the `<details>` panel + `title=`; "if enforced" → `--cov-present` would-admit / `--posture-breach` would-block |
| Empty states | `--ink-2`; posture-coloured only when honestly earned (model judging) |

## Accessibility gate (test-enforced)
1. **Contrast:** body/status text ≥ **4.5:1** on its surface; chips/rails/glyphs ≥ **3:1**.
2. **Meaning not by colour alone:** every posture / severity / Δ / coverage / **signing posture**
   state renders a non-empty **glyph + text label** in addition to colour. (Assert each
   enum→(glyph,label).) The signing posture is always one of signed / invalid signature / not
   signed / checking — **never n/a** — and its "if enforced" cell is always would-admit / would-block.
3. **Honest-calm invariant:** the overall green/all-clear resolves to `--posture-cleared`/green
   ONLY when the model has affirmatively cleared everything — `model_judging == true` AND not
   `warming_up` AND **covered** AND **zero breaches AND zero awaiting AND zero uncertain**. If
   `model_judging == false` OR `warming_up`, the honest blind/warming banner renders. If the
   model is judging+covered but **any** entry is still awaiting or uncertain, the strip renders
   the elevated **"watching"** state (`--posture-awaiting` toned, calm — *not* green): the model
   hasn't finished, so quiet is not clearance. `Verdict::Uncertain` and awaiting (`None`) never
   map to the cleared/green token.
4. **No implied-absent blanks:** any empty evidence/coverage field renders explicit
   "none"/"unknown".
5. **Escaping:** all untrusted free-text (verdict prose, CVE/finding titles, model prompts,
   node keys) is HTML-escaped at render (maud auto-escape; no `PreEscaped` outside an audited
   allowlist).
6. **Keyboard/semantics:** findings are a real `<table>`; row expanders are `<button>`s with
   `aria-expanded`; focus order = visual order; focus ring always visible.
