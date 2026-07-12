// One judgement in the Action tab's judgement-audit section (ADR-0025 / JEF-400) — a 1:1 Preact
// port of maud `judgement_entry`: a native `<details>` disclosure whose summary is the entry +
// objectives, opening to the verbatim prompt and reply. Honest when the prompt (the pre-filter
// decided) or reply (the model timed out) is absent.
//
// The disclosure's open state is KEYED COMPONENT STATE (persisted in the store under
// `action:judgement-<i>`) so an operator reading a long prompt keeps it open across a poll — the
// same survives-reconcile guarantee the Findings "show model prompt" disclosure has. The prompt /
// reply / verdict are UNTRUSTED third-party text, rendered as JSX text (Preact auto-escapes).

/**
 * @param {object} props
 * @param {number} props.i the judgement's index (the disclosure's stable key seed, matching the
 *   maud `judgement-{i}`).
 * @param {any} props.j the judgement props (serde kebab-case).
 * @param {import("../store.js").Store} props.store the client store (disclosure open state).
 */
export function JudgementEntry({ i, j, store }) {
  const key = `action:judgement-${i}`;
  const open = store.isDisclosureOpen(key);
  return (
    <li class="judgement-entry">
      <details
        class="model-prompt"
        open={open}
        onToggle={(e) => store.setDisclosureOpen(key, e.currentTarget.open)}
      >
        <summary class="why-toggle" role="button" aria-expanded={String(open)}>
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
