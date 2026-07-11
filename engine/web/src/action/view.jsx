// The Action view (ADR-0025 / JEF-400) — a 1:1 Preact port of maud `action_view.rs`: the engine's
// whole action story in LIFECYCLE order — the headline summary, then three stacked sections:
// (1) PROPOSED CUTS (still-standing would-act proposals + the cuts that self-reverted), (2) LEFT
// ALONE (proven paths the model cleared), (3) JUDGEMENT AUDIT (the verbatim prompt/reply behind
// each model call, as collapsed disclosures).
//
// Reconcile keying (the only per-view variation): each row keys on its stable anchor — a would-act
// / left-alone entry on its `entry` key, a reversion on `(cut, age)`, a judgement on its `entry`
// (paired with index for stability). Preact patches each row in place across a poll, and the
// judgement `<details>` open state is KEYED COMPONENT STATE (persisted in the store) so an operator
// reading a prompt keeps it open. Every untrusted string (entry / verdict / cut / reason / prompt /
// reply) renders via JSX text interpolation (Preact auto-escapes).

import { JudgementEntry } from "./judgement.jsx";

/**
 * @param {object} props
 * @param {any} props.view the Action view props (serde kebab-case).
 * @param {import("../store.js").Store} props.store the client store (disclosure state).
 */
export function ActionView({ view, store }) {
  return (
    <main class="view view-action">
      <Headline v={view} />
      <ProposedCuts v={view} />
      <LeftAlone v={view} />
      <JudgementAudit v={view} store={store} />
    </main>
  );
}

/** The headline: the window, the proposed-cut count (with its subsets), and the left-alone count.
 *  Counts honest at zero. */
function Headline({ v }) {
  return (
    <section class="trust-summary" aria-label="action summary">
      <h2 class="section-h t-h2">action {"\u{2014}"} last {v["window-human"]}</h2>
      <p class="section-sub t-body muted">
        in shadow the engine only proposes; this is the whole action story {"\u{2014}"} what it WOULD
        have cut (and what self-reverted), what it proved out and left alone, and the model
        judgements behind each call.
      </p>
      <div class="trust-counts">
        <span class="count count-wouldact t-data-strong">
          {v["would-act-count"]} would have cut
        </span>
        {v["short-lived-count"] > 0 ? (
          <span class="count count-shortlived t-data">
            {v["short-lived-count"]} likely false positive
          </span>
        ) : null}
        {v["coverage-gap-count"] > 0 ? (
          <span class="count count-covgap t-data">
            {v["coverage-gap-count"]} scrutinise first
          </span>
        ) : null}
        {v["reverted-count"] > 0 ? (
          <span class="count count-leftalone t-data">{v["reverted-count"]} self-reverted</span>
        ) : null}
        <span class="count count-leftalone t-data">{v["left-alone-count"]} left alone</span>
      </div>
    </section>
  );
}

/** Section 1 — Proposed cuts: the still-standing would-act proposals, then the self-reverted cuts.
 *  The honest journal-empty state is distinct from "none in this window". */
function ProposedCuts({ v }) {
  const journalEmpty = v["journal-empty"] === true;
  return (
    <section class="activity-section action-proposed" aria-label="proposed cuts">
      <h2 class="section-h t-h2">proposed cuts</h2>
      <p class="section-sub t-body muted">
        the lifecycle of a would-be cut {"\u{2014}"} what the engine would sever now, and the cuts
        that stood briefly then self-reverted when the breach condition lifted.
      </p>
      {journalEmpty ? (
        <JournalEmpty />
      ) : (
        <>
          <WouldActBlock v={v} />
          <RevertedBlock v={v} />
        </>
      )}
    </section>
  );
}

function WouldActBlock({ v }) {
  const wouldAct = Array.isArray(v["would-act"]) ? v["would-act"] : [];
  if (wouldAct.length === 0) {
    return (
      <p class="col-empty t-body muted">
        none in the last {v["window-human"]} {"\u{2014}"} no path reached an exploitable verdict in
        this window.
      </p>
    );
  }
  return (
    <ul class="trust-list">
      {wouldAct.map((w, i) => (
        <WouldActEntry key={`${w.entry} ${i}`} w={w} />
      ))}
    </ul>
  );
}

/** One would-act entry: the entry key, its lifecycle status tags (colour + glyph + word), the
 *  frequency/lifetime, and the model's verbatim "why it would have cut". */
function WouldActEntry({ w }) {
  const decisions = w["would-act-decisions"];
  return (
    <li class="trust-entry" data-open={String(w.open)}>
      <div class="trust-entry-head">
        <span class="trust-entry-key t-data-strong">{w.entry}</span>
        <WouldActTags w={w} />
      </div>
      <p class="trust-entry-meta t-micro muted">
        {w.episodes} episode{w.episodes !== 1 ? "s" : ""} {"\u{00B7}"} {decisions} affirming
        decision{decisions !== 1 ? "s" : ""} {"\u{00B7}"} longest {w["max-lifetime"]}
      </p>
      <p class="trust-entry-verdict t-data">{w["last-verdict"]}</p>
    </li>
  );
}

/** The lifecycle status tags: would-cut OPEN (loud), short-lived (likely FP, calm), or sustained;
 *  plus the coverage-gap "scrutinise" tag. Glyph + text on every chip (a11y — never colour alone). */
function WouldActTags({ w }) {
  return (
    <span class="trust-tags">
      {w.open ? (
        <span class="trust-tag tag-open">
          <span class="glyph" aria-hidden="true">
            {"\u{2702}"}
          </span>
          would cut {"\u{00B7}"} still standing
        </span>
      ) : w["short-lived"] ? (
        <span class="trust-tag tag-shortlived">
          <span class="glyph" aria-hidden="true">
            {"\u{25CB}"}
          </span>
          likely false positive
        </span>
      ) : (
        <span class="trust-tag tag-sustained">
          <span class="glyph" aria-hidden="true">
            {"\u{25B2}"}
          </span>
          sustained
        </span>
      )}
      {w["coverage-gap"] ? (
        <span
          class="trust-tag tag-covgap"
          title="affirmed exploitability with no CVE/behavioral backing"
        >
          <span class="glyph" aria-hidden="true">
            {"\u{25D0}"}
          </span>
          scrutinise {"\u{2014}"} no backing
        </span>
      ) : null}
    </span>
  );
}

function RevertedBlock({ v }) {
  const reversions = Array.isArray(v.reversions) ? v.reversions : [];
  if (reversions.length === 0) {
    return (
      <p class="col-empty t-body muted">
        no cuts reverted yet {"\u{2014}"} nothing has been applied-then-self-reverted.
      </p>
    );
  }
  return (
    <ul class="revert-list">
      {reversions.map((r, i) => (
        <RevertedEntry key={`${r.cut} ${r.age} ${i}`} r={r} />
      ))}
    </ul>
  );
}

function RevertedEntry({ r }) {
  return (
    <li class="revert-entry">
      <div class="revert-head">
        <span class="revert-tag t-micro">
          <span class="glyph" aria-hidden="true">
            {"\u{21BA}"}
          </span>
          reverted
        </span>
        <span class="revert-age t-micro muted">{r.age} ago</span>
      </div>
      <p class="revert-cut">
        <code>{r.cut}</code>
      </p>
      <p class="revert-reason t-body">{r.reason}</p>
    </li>
  );
}

/** Section 2 — Left alone (cleared): proven paths the model deliberately cleared. Honest "none in
 *  window" when empty. */
function LeftAlone({ v }) {
  const leftAlone = Array.isArray(v["left-alone"]) ? v["left-alone"] : [];
  return (
    <section class="activity-section action-leftalone" aria-label="left alone (cleared)">
      <h2 class="section-h t-h2">left alone (cleared)</h2>
      <p class="section-sub t-body muted">
        proven paths the model judged not exploitable and deliberately left alone {"\u{2014}"} the
        trust half of the diff.
      </p>
      {leftAlone.length === 0 ? (
        <p class="col-empty t-body muted">
          none in the last {v["window-human"]} {"\u{2014}"} no proven path was cleared in this
          window.
        </p>
      ) : (
        <ul class="trust-list">
          {leftAlone.map((l, i) => (
            <LeftAloneEntry key={`${l.entry} ${i}`} l={l} />
          ))}
        </ul>
      )}
    </section>
  );
}

function LeftAloneEntry({ l }) {
  return (
    <li class="trust-entry trust-cleared">
      <div class="trust-entry-head">
        <span class="trust-tag tag-cleared">
          <span class="glyph" aria-hidden="true">
            {"\u{25CB}"}
          </span>
          cleared
        </span>
        <span class="trust-entry-key t-data-strong">{l.entry}</span>
      </div>
      <p class="trust-entry-verdict t-data">{l.verdict}</p>
    </li>
  );
}

/** Section 3 — Judgement audit (model debug): the verbatim prompt/reply per model call, as
 *  collapsed disclosures. Honest about an absent prompt/reply. */
function JudgementAudit({ v, store }) {
  const judgements = Array.isArray(v.judgements) ? v.judgements : [];
  return (
    <section class="activity-section judgements" aria-label="judgement audit">
      <h2 class="section-h t-h2">judgement audit</h2>
      <p class="section-sub t-body muted">
        the recent calls to the adjudicator {"\u{2014}"} the verbatim prompt and reply behind each
        verdict, for debugging the model.
      </p>
      {judgements.length === 0 ? (
        <p class="activity-empty t-body muted">
          no judgements recorded {"\u{2014}"} the model has not been asked yet (warming, or no
          proven path reached it).
        </p>
      ) : (
        <ul class="judgement-list">
          {judgements.map((j, i) => (
            <JudgementEntry key={`${j.entry} ${i}`} i={i} j={j} store={store} />
          ))}
        </ul>
      )}
    </section>
  );
}

/** The honest journal-empty state: distinct from "none in this window". Never read as "all safe". */
function JournalEmpty() {
  return (
    <div class="empty trust-empty">
      <p class="empty-head t-h2">no decisions journaled yet</p>
      <p class="empty-sub t-body muted">
        the durable journal holds no breach decisions {"\u{2014}"} the engine has not yet judged a
        proven path, or the journal is in-memory only and reset on restart. This is not an
        all-clear; enable a durable journal to build would-have-acted history.
      </p>
    </div>
  );
}
