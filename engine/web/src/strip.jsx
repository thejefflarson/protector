// The persistent status strip (ADR-0025 / JEF-408) — a 1:1 Preact port of the retired maud
// `components/status_strip.rs`. It carries the three honesty axes — decided / judging / covered —
// on EVERY view. Its load-bearing rule (invariant #1, ADR-0016/0019): a blind / warming / watching
// state must NEVER read as a calm green all-clear.
//
// The client performs ZERO honesty derivation: the JUDGING AXIS is chosen by the server-derived
// `judging-state` token (all-clear | watching | judging | warming | no-model | blind), each mapping
// to its exact class + glyph + text (the same branch logic the maud `judging_axis` used). The client
// only SELECTS the honest copy from a token the server already decided — it never recomputes
// "is this green?". All text is auto-escaped by Preact; there is no raw-HTML escape hatch.
//
// The classes are the SAME `dashboard.css` classes the maud strip used (`.strip`, `.strip-top`,
// `.pill`, `.axis`, `.judging`, `.cov`, `.headline`, `.count-*`) — no new palette, no new classes.

/**
 * @param {{ strip: any }} props the view's `strip` props (serde kebab-case), carrying the
 *   server-derived `judging-state` token, the coverage chips, the headline counts, and the raw
 *   cluster / armed / freshness fields.
 */
export function StatusStrip({ strip }) {
  // Before the first snapshot lands there is no strip — render nothing (absent is honest; blank is
  // never a green all-clear, and the connection banner already carries the "connecting…" state).
  if (!strip) return null;
  return (
    <header class="strip">
      <div class="strip-top">
        <div class="strip-cluster">
          <span class="brand">protector</span>
          <span class="sep">{"▸"}</span>
          <span class="cluster">{strip.cluster}</span>
        </div>
        <ModePill armed={strip.armed} />
      </div>
      <div class="strip-axes">
        <JudgingAxis state={strip["judging-state"]} />
        <CoverageAxes coverage={strip.coverage || []} />
        {strip["last-pass"] ? (
          <span class="axis freshness">last pass {strip["last-pass"]}</span>
        ) : (
          <span class="axis freshness muted">no pass yet</span>
        )}
      </div>
      <Headline strip={strip} />
    </header>
  );
}

/**
 * The shadow/enforce mode pill. SHADOW is a WARNING posture (proposing, not protecting) — amber
 * with a ⚠; ENFORCE is the calm intended state. Always shown so the operator sees which mode.
 */
function ModePill({ armed }) {
  const { cls, word, sub, glyph } = armed
    ? { cls: "pill mode-enforce", word: "ENFORCE", sub: "acting", glyph: "" }
    : { cls: "pill mode-shadow warn", word: "SHADOW", sub: "proposes, never acts", glyph: "⚠" };
  return (
    <span class={cls}>
      {glyph ? (
        <span class="pill-glyph" aria-hidden="true">
          {glyph}
        </span>
      ) : null}
      <span class="pill-text">
        <span class="pill-word">{word}</span>
        <span class="pill-sub">{sub}</span>
      </span>
    </span>
  );
}

/**
 * The decided/judging axis, chosen by the SERVER-DERIVED `judging-state` token. Each token maps to
 * exactly the class + glyph + text the maud `judging_axis` emitted. Only `all-clear` is the honest
 * green (`.judging.ok` with a filled dot); `watching`/`warming`/`no-model`/`blind` are non-green.
 * `judging` (model up, a breach loud in the headline) is the calm green-dot "model judging".
 */
function JudgingAxis({ state }) {
  switch (state) {
    case "all-clear":
      return (
        <span class="axis judging ok">
          <span class="dot" />
          {"model judging — all clear"}
        </span>
      );
    case "watching":
      return (
        <span class="axis judging watching">
          <span class="glyph">{"◌"}</span>
          {"model judging — watching (not yet all-clear)"}
        </span>
      );
    case "judging":
      return (
        <span class="axis judging ok">
          <span class="dot" />
          {"model judging"}
        </span>
      );
    case "warming":
      return (
        <span class="axis judging warming">
          <span class="glyph">{"◌"}</span>
          {"warming up — exposed paths are unjudged, not cleared"}
        </span>
      );
    case "no-model":
      return (
        <span class="axis judging blind">
          <span class="glyph">{"◐"}</span>
          {"no model — nothing is judged exploitable"}
        </span>
      );
    default: // "blind" — model attached but not answering
      return (
        <span class="axis judging blind">
          <span class="glyph">{"◐"}</span>
          {"model not answering — exposed paths are unjudged, not cleared"}
        </span>
      );
  }
}

/** The covered axis: one chip per enrichment feed, each carrying colour + glyph + word. */
function CoverageAxes({ coverage }) {
  return (
    <span class="axis coverage">
      {coverage.map((chip, i) => (
        <CoverageChip key={i} chip={chip} />
      ))}
    </span>
  );
}

/** One coverage chip. present / degraded / absent are distinct AND carry a glyph + feed word. */
function CoverageChip({ chip }) {
  const { cls, glyph } = chip.present
    ? { cls: "cov cov-present", glyph: "✓" } // ✓
    : chip.degraded
      ? { cls: "cov cov-degraded", glyph: "◐" } // ◐
      : { cls: "cov cov-absent", glyph: "—" }; // —
  return (
    <span class={cls}>
      <span class="cov-label">{chip.label}</span>
      <span class="cov-glyph">{glyph}</span>
    </span>
  );
}

/**
 * The findings headline: breach / awaiting / uncertain / cleared counts + the Δ escalation chip +
 * the standing signing-regression chip. The breach count is the only loud chip; counts are honest
 * even at zero (never blank). The regression chip is why the strip is not green — surfaced explicitly.
 */
function Headline({ strip }) {
  const escalated = strip["escalated-count"] || 0;
  const regressions =
    (strip["signing-regression-breach"] || 0) + (strip["signing-regression-uncertain"] || 0);
  return (
    <div class="headline">
      <span class="count count-breach">{strip["breach-count"]} breach</span>
      <span class="count count-awaiting">{strip["awaiting-count"]} awaiting</span>
      <span class="count count-uncertain">{strip["uncertain-count"]} uncertain</span>
      <span class="count count-cleared">{strip["cleared-count"]} cleared</span>
      {escalated > 0 ? (
        <span class="count count-escalated">
          <span class="glyph">{"▲"}</span>
          {escalated} escalated since last pass
        </span>
      ) : null}
      {regressions > 0 ? (
        <span class="count count-breach count-regression">
          <span class="glyph" aria-hidden="true">
            {"●"}
          </span>
          {regressions} {regressions === 1 ? "signing regression" : "signing regressions"}
        </span>
      ) : null}
    </div>
  );
}
