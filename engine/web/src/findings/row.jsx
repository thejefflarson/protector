// One Findings-table row (ADR-0025 / JEF-397) — a 1:1 Preact port of maud `finding_row.rs`: the
// two-row structure (a summary `<tr.row>` whose expander button drives a paired `<tr.row-detail>`),
// keyed on the STABLE `finding.id`. Preact's keyed diff keeps this row's exact DOM across a poll —
// focus, open disclosures, selection — so the reconcile "just works": the boring default IS the
// whole point of the rewrite (ADR-0025).
//
// The expander is a real `<button aria-expanded aria-controls>` and the detail row keeps its
// `id=detail-{id}` target, so the a11y contract (STYLEGUIDE gate) is preserved. Expansion state
// comes from the store (persisted across reloads), not from a swap-and-rebind shim.

import { posture, DELTA } from "./glyphs.js";
import { DetailPanel } from "./detail.jsx";

const DASH = "\u{2014}"; // —

/**
 * @param {object} props
 * @param {any} props.f the finding props (serde kebab-case).
 * @param {boolean} props.expanded whether this row is expanded (from the store).
 * @param {() => void} props.onToggle toggle this row's expansion (persists in the store).
 * @param {boolean} props.promptOpen whether the row's model-prompt disclosure is open.
 * @param {(open: boolean) => void} props.onPromptToggle persist the disclosure's open state.
 */
export function FindingRow({ f, expanded, onToggle, promptOpen, onPromptToggle }) {
  const detailId = `detail-${f.id}`;
  return (
    <>
      <tr
        class={expanded ? "row open" : "row"}
        id={f.id}
        data-finding={f.id}
        data-posture={f.posture}
        onClick={onToggle}
      >
        <td class="cell cell-expand">
          <button
            class="expander"
            type="button"
            aria-expanded={String(expanded)}
            aria-controls={detailId}
            aria-label="expand finding detail"
          >
            <span class="expander-glyph" aria-hidden="true">
              {expanded ? "\u{2212}" : "+"}
            </span>
          </button>
        </td>
        <td class="cell cell-delta">
          <DeltaCell delta={f.delta} />
        </td>
        <td class="cell cell-posture">
          <PostureCell posture={f.posture} liveTag={f["live-tag"]} />
        </td>
        <td class="cell cell-entry">
          <EntryObjective f={f} />
        </td>
        <td class="cell cell-path">
          <PathSummary f={f} />
        </td>
        <td class="cell cell-evidence">
          <EvidenceCluster s={f["evidence-summary"]} />
        </td>
        <td class="cell cell-disposition">
          <span class="disp">{f.disposition}</span>
        </td>
      </tr>
      <tr class="row-detail" id={detailId} data-detail-for={f.id}>
        <td class="detail-host" colspan="7">
          {expanded ? (
            <DetailPanel f={f} promptOpen={promptOpen} onPromptToggle={onPromptToggle} />
          ) : null}
        </td>
      </tr>
    </>
  );
}

/**
 * The one-shot TOMBSTONE row for a finding that cleared while the operator had it open (ADR-0025 /
 * JEF-397). Calm and muted — it is not an alarm; it says the model no longer sees this path — and it
 * renders exactly once before the id is dropped and purged. Keyed on the same id so Preact patches
 * the departing row in place rather than tearing the table.
 * @param {{ id: string }} props
 */
export function TombstoneRow({ id }) {
  return (
    <tr class="row row-tombstone" id={id} data-finding={id} data-tombstone="true">
      <td class="cell" colspan="7">
        <span class="tombstone muted">
          this finding cleared — the model no longer sees this path
        </span>
      </td>
    </tr>
  );
}

function DeltaCell({ delta }) {
  const kind = delta?.kind;
  const spec = kind ? DELTA[kind] : null;
  if (spec) {
    return (
      <span class={`delta delta-${spec.token}`} title={deltaLabel(delta)}>
        <span class="glyph">{spec.glyph}</span>
      </span>
    );
  }
  // Steady (`unchanged`): show the muted age, never an alarm glyph.
  const age = kind === "unchanged" && delta.age ? delta.age : DASH;
  return (
    <span class="delta delta-steady" title={deltaLabel(delta)}>
      {age}
    </span>
  );
}

/** Mirrors `DeltaProps::label` for the title/screen-reader text. */
function deltaLabel(delta) {
  switch (delta?.kind) {
    case "new":
      return "new this pass";
    case "escalated":
      return "escalated";
    case "de-escalated":
      return "de-escalated";
    case "restored":
      return "restored";
    case "unchanged":
      return delta.age ? `steady · ${delta.age}` : "steady";
    default:
      return "steady";
  }
}

function PostureCell({ posture: tag, liveTag }) {
  const p = posture(tag);
  return (
    <span class={`posture rail-${tag}`}>
      <span class={`posture-chip chip-${tag}`}>
        <span class="glyph">{p.glyph}</span>
        <span class="posture-word">{p.word}</span>
        <LiveTag tag={liveTag} />
      </span>
    </span>
  );
}

function LiveTag({ tag }) {
  if (tag === "live") return <span class="subtag subtag-live">live</span>;
  if (tag === "judged") return <span class="subtag subtag-judged">judged</span>;
  return null;
}

function EntryObjective({ f }) {
  return (
    <span class="eo">
      <span class="entry">
        <span class="kind-glyph">{f["entry-glyph"]}</span>
        <span class="entry-label">{f.entry}</span>
        {f.replicas != null ? (
          <span class="replica-count" title="pod replicas of this workload, collapsed">
            {` \u{00D7}${f.replicas}`}
          </span>
        ) : null}
      </span>
      <span class="arrow">{" \u{2192} "}</span>
      {f.fanout != null ? (
        <span class="objective fanout">{`\u{00D7}${f.fanout} reachable`}</span>
      ) : (
        <span class="objective">{f.objective}</span>
      )}
    </span>
  );
}

function PathSummary({ f }) {
  return (
    <span class="path-summary">
      {f.entry}
      <span class="hop-arrow">{" \u{2500}\u{2192} "}</span>
      {f.cut != null ? (
        <>
          <span class="cut-mark" title="severable here">
            {"\u{2702}"}
          </span>
          {" "}
        </>
      ) : null}
      {f.objective}
    </span>
  );
}

function EvidenceCluster({ s }) {
  if (!s || (s["cve-count"] === 0 && !s.kev && s["runtime-alerts"] === 0 && s["exposed-secrets"] === 0)) {
    return null;
  }
  return (
    <span class="evidence-cluster">
      {s.kev ? <span class="ev ev-kev">KEV</span> : null}
      {s["runtime-alerts"] > 0 ? (
        <span class="ev ev-runtime">
          <span class="glyph">{"\u{26A1}"}</span>
          {s["runtime-alerts"]}
        </span>
      ) : null}
      {s["exposed-secrets"] > 0 ? (
        <span class="ev ev-secret">
          <span class="glyph">{"\u{1F511}"}</span>
          {s["exposed-secrets"]}
        </span>
      ) : null}
    </span>
  );
}
