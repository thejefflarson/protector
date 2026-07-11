// The honest Findings empty-state (ADR-0025 / JEF-397) — a 1:1 Preact port of maud
// `findings_view::empty_state`. This is the load-bearing honesty case (invariant #1): an empty
// findings list must NEVER read as a generic "no findings" / false all-clear. It reads GREEN only
// when the SERVER says `all-clear`; otherwise it renders the matching non-green register —
// watching / warming-up / no-model / model-not-answering.
//
// The client performs ZERO honesty derivation: `all-clear` and `watching` are server-derived tokens
// on the strip props; blind/warming come from the strip's raw `warming-up` / `model-attached`
// booleans. The client only SELECTS which honest copy to show from tokens the server already
// decided — it never recomputes "is this green?".

/**
 * @param {{ strip: any }} props the Findings view's `strip` props (serde kebab-case), carrying the
 *   server-derived `all-clear` / `watching` tokens and the raw `warming-up` / `model-attached`
 *   booleans.
 */
export function FindingsEmpty({ strip }) {
  // GREEN all-clear ONLY when the server affirmatively cleared everything.
  if (strip["all-clear"]) {
    return (
      <div class="empty empty-clear">
        <p class="empty-head">all clear</p>
        <p class="empty-sub muted">
          no breach-relevant exposed paths — the model is judging and found nothing exploitable.
        </p>
      </div>
    );
  }
  // Model up but not fully covered (a feed degraded): calm but NOT green — the elevated "watching".
  if (strip.watching) {
    return (
      <div class="empty empty-watching">
        <p class="empty-head">watching</p>
        <p class="empty-sub muted">
          no breach-relevant exposed paths yet, but a decision feed is degraded — the model is
          judging but not fully equipped to clear. This is not an all-clear.
        </p>
      </div>
    );
  }
  // Model down/warming: an empty list is NOT a clearance — say so, LOUD (non-green).
  const { cls, head, sub } = blindState(strip);
  return (
    <div class={cls}>
      <p class="empty-head">{head}</p>
      <p class="empty-sub muted">{sub}</p>
    </div>
  );
}

/** Select the blind/warming register from the strip's raw booleans (mirrors the maud match arms). */
function blindState(strip) {
  if (strip["warming-up"]) {
    return {
      cls: "empty empty-warming",
      head: "warming up",
      sub: "no pass has completed yet — verdicts are still loading (slow on a CPU model). This is not an all-clear.",
    };
  }
  if (!strip["model-attached"]) {
    return {
      cls: "empty empty-blind",
      head: "no model configured",
      sub: "nothing is judged exploitable without a model — exposed paths are unjudged, not cleared.",
    };
  }
  return {
    cls: "empty empty-blind",
    head: "model not answering",
    sub: "the model timed out or is down — exposed paths are unjudged, not cleared. This is not an all-clear.",
  };
}
