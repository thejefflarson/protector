// One judgement in the Action tab's judgement-audit section (ADR-0025 / JEF-400 / JEF-411) — a 1:1
// Preact port of maud `judgement_entry`: a native `<details>` disclosure whose summary is the entry
// + objectives, opening to the verbatim prompt and reply. Honest when the prompt (the pre-filter
// decided) or reply (the model timed out) is absent.
//
// The disclosure is NATIVE and UNCONTROLLED (JEF-411): the DOM owns its open state, so an operator
// reading a long prompt keeps it open across a poll (Preact's keyed diff never disturbs it) with no
// client bookkeeping. The prompt / reply / verdict are UNTRUSTED third-party text, rendered as JSX
// text (Preact auto-escapes).

/**
 * @param {object} props
 * @param {any} props.j the judgement props (serde kebab-case).
 */
export function JudgementEntry({ j }) {
  return (
    <li class="judgement-entry">
      <details class="model-prompt">
        <summary class="why-toggle" role="button">
          <span class="judgement-entry-key t-data-strong">{j.entry}</span>
          <span class="judgement-entry-meta t-micro muted">
            {" \u{00B7} reaches "}
            {j.objectives} objective{j.objectives !== 1 ? "s" : ""}
          </span>
        </summary>
        <div class="prompt-body">
          {j.verdict ? (
            <p class="prompt-verdict t-data">
              {"final verdict: "}
              <span class="mono">{j.verdict}</span>
            </p>
          ) : (
            <p class="muted t-data">no verdict recorded for this call</p>
          )}
          <h3 class="detail-h">prompt</h3>
          {j.prompt ? (
            <pre class="prompt-text">{j.prompt}</pre>
          ) : (
            <p class="muted t-data">
              no prompt {"\u{2014}"} the deterministic pre-filter decided without asking the model
            </p>
          )}
          <h3 class="detail-h">reply</h3>
          {j.reply ? (
            <pre class="prompt-text">{j.reply}</pre>
          ) : (
            <p class="muted t-data">no reply {"\u{2014}"} the model was unavailable (timed out)</p>
          )}
        </div>
      </details>
    </li>
  );
}
