// The expand-in-place "why" panel for a finding (ADR-0025 / JEF-397 / JEF-411) — a 1:1 Preact port
// of the maud `finding_detail.rs`: the verbatim verdict (+ the LOUD blind-node caveat), the
// alarming-now signals, the proven-path chain staircase(s), the evidence tables, the proposed cut,
// and the "show model prompt" disclosure. All free text is auto-escaped (Preact); every disclosure
// is a NATIVE, UNCONTROLLED `<details>` — keyboard-safe for free, its open state DOM-owned so the
// keyed reconcile never disturbs it mid-read (no client bookkeeping, ephemeral by design).

import { EvidenceTables } from "./evidence.jsx";

const CHAIN_STEP_MAX = 6;
const PATHS_SHOWN_OPEN = 3;

/**
 * @param {object} props
 * @param {any} props.f the finding props (serde kebab-case).
 */
export function DetailPanel({ f }) {
  return (
    <div class={`detail rail-${f.posture}`}>
      <VerdictBlock f={f} />
      <AlarmingNow alerts={f.alerts} />
      <PathBlock f={f} />
      <EvidenceTables ev={f.evidence} />
      <CutBlock cut={f.cut} />
      <ModelPrompt judgement={f.judgement} />
    </div>
  );
}

function VerdictBlock({ f }) {
  const caveat = f["blind-node-caveat"];
  return (
    <section class="detail-section verdict-block">
      <h3 class="detail-h">verdict</h3>
      {f["verdict-summary"] ? (
        <p class="verdict-prose">{f["verdict-summary"]}</p>
      ) : (
        <p class="verdict-prose muted">
          awaiting judgement — the model has not judged this entry yet
        </p>
      )}
      {caveat ? (
        <p class="verdict-caveat blind-node-caveat" role="note">
          <span class="caveat-glyph" aria-hidden="true">
            {"\u{26A0} "}
          </span>
          {caveat}
        </p>
      ) : null}
    </section>
  );
}

function AlarmingNow({ alerts }) {
  if (!Array.isArray(alerts) || alerts.length === 0) return null;
  return (
    <section class="detail-section alarming-now-block">
      <h3 class="detail-h">alarming activity observed</h3>
      <ul class="alarming-now-list">
        {alerts.map((a, i) => (
          <li class="alarming-now-item" key={i}>
            <span class={`alert-kind kind-${a.kind}`}>{a.kind}</span>
            <span class="alarming-now-signal">{a.signal}</span>
            <span class="alarming-now-where muted">
              {" on "}
              {a.workload}
              {" ("}
              {a.recency}
              {")"}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function PathBlock({ f }) {
  const paths = (f.paths || []).filter((p) => Array.isArray(p) && p.length > 0);
  const multi = paths.length > 1;
  return (
    <section class="detail-section path-block">
      <h3 class="detail-h">{multi ? "proven paths" : "proven path"}</h3>
      {paths.length === 0 ? (
        <p class="muted">no path recorded</p>
      ) : multi ? (
        <>
          <PathsSummary n={paths.length} hasCut={f.cut != null} />
          <StackedPaths paths={paths} truncated={f["paths-truncated"]} />
        </>
      ) : (
        <ChainDiagram path={paths[0]} />
      )}
    </section>
  );
}

function PathsSummary({ n, hasCut }) {
  return (
    <p class="paths-summary">
      {"reachable via "}
      <span class="paths-count">{n}</span>
      {" redundant paths"}
      {hasCut
        ? " — one shared edge severs all (marked \u{2702})"
        : " — no single edge severs the objective"}
    </p>
  );
}

function StackedPaths({ paths, truncated }) {
  const shown = Math.min(paths.length, PATHS_SHOWN_OPEN);
  const rest = paths.length - shown;
  return (
    <div class="paths">
      {paths.slice(0, shown).map((p, i) => (
        <LabelledPath key={i} n={i + 1} path={p} />
      ))}
      {rest > 0 ? (
        <details class="more-paths">
          <summary class="why-toggle" role="button" aria-expanded="false">
            {`show ${rest} more path${rest !== 1 ? "s" : ""}`}
          </summary>
          <div class="more-paths-body">
            {paths.slice(shown).map((p, i) => (
              <LabelledPath key={shown + i} n={shown + i + 1} path={p} />
            ))}
            {truncated ? (
              <p class="muted more-paths-note">+ more proven paths exist (bounded)</p>
            ) : null}
          </div>
        </details>
      ) : truncated ? (
        <p class="muted more-paths-note">+ more proven paths exist (bounded)</p>
      ) : null}
    </div>
  );
}

function LabelledPath({ n, path }) {
  return (
    <div class="path-alt">
      <span class="path-alt-label">{`path ${n}`}</span>
      <ChainDiagram path={path} />
    </div>
  );
}

const stepClass = (step) => `chain-step-${Math.min(step, CHAIN_STEP_MAX)}`;

function ChainDiagram({ path }) {
  return (
    <ol class="chain" aria-label="proven attack path, entry to objective">
      <ChainNode glyph={path[0]["from-glyph"]} label={path[0].from} step={0} entry objective={false} />
      {path.flatMap((hop, i) => [
        <ChainEdge key={`e${i}`} hop={hop} step={i + 1} />,
        <ChainNode
          key={`n${i}`}
          glyph={hop["to-glyph"]}
          label={hop.to}
          step={i + 1}
          entry={false}
          objective={i === path.length - 1}
        />,
      ])}
    </ol>
  );
}

function ChainNode({ glyph, label, step, entry, objective }) {
  const depth = stepClass(step);
  const cls = objective
    ? `chain-node chain-objective ${depth}`
    : entry
      ? `chain-node chain-entry ${depth}`
      : `chain-node ${depth}`;
  return (
    <li class={cls}>
      <span class="chain-dot" aria-hidden="true" />
      <span class="chain-glyph">{glyph}</span>
      <span class="chain-label">{label}</span>
      {objective ? <span class="chain-tag">objective</span> : entry ? <span class="chain-tag">entry</span> : null}
    </li>
  );
}

function ChainEdge({ hop, step }) {
  const depth = stepClass(step);
  let cls = hop["is-cut"]
    ? `chain-edge chain-edge-cut ${depth}`
    : hop.structural
      ? `chain-edge chain-edge-structural ${depth}`
      : `chain-edge ${depth}`;
  if (hop.shared) cls += " chain-edge-shared";
  return (
    <li class={cls}>
      <span class="chain-rel">
        <span class="chain-rel-line" aria-hidden="true">
          {"\u{2500}["}
        </span>
        {hop.relation}
        <span class="chain-rel-line" aria-hidden="true">
          {"]\u{2192}"}
        </span>
      </span>
      {hop["is-cut"] ? (
        <span class="chain-cut" title="minimal cut severs this edge">
          <span class="chain-cut-glyph">{"\u{2702}"}</span>
          <span class="chain-cut-label">cut here</span>
        </span>
      ) : hop.shared ? (
        <span class="chain-shared" title="on every proven path — a shared bottleneck">
          shared
        </span>
      ) : null}
    </li>
  );
}

function CutBlock({ cut }) {
  return (
    <section class="detail-section cut-block">
      <h3 class="detail-h">proposed cut</h3>
      {cut != null ? (
        <p class="cut-sig">
          <code>{cut}</code>
        </p>
      ) : (
        <p class="muted">no single-edge cut — this chain is not severable by one network edge</p>
      )}
    </section>
  );
}

function ModelPrompt({ judgement }) {
  const j = judgement || {};
  return (
    // Native uncontrolled `<details>` (JEF-411): the DOM owns the open state, so it survives a poll
    // for free (Preact's keyed diff never disturbs it) with no client bookkeeping.
    <details class="model-prompt">
      <summary class="why-toggle" role="button">
        show model prompt
      </summary>
      <div class="prompt-body">
        {j.verdict ? (
          <p class="prompt-verdict">
            {"final verdict: "}
            <span class="mono">{j.verdict}</span>
          </p>
        ) : (
          <p class="muted">no verdict recorded for this entry</p>
        )}
        <h4 class="detail-h">prompt</h4>
        {j.prompt ? (
          <pre class="prompt-text">{j.prompt}</pre>
        ) : (
          <p class="muted">no prompt — the deterministic pre-filter decided without asking the model</p>
        )}
        <h4 class="detail-h">reply</h4>
        {j.reply ? (
          <pre class="prompt-text">{j.reply}</pre>
        ) : (
          <p class="muted">no reply — the model was unavailable (timed out)</p>
        )}
      </div>
    </details>
  );
}
