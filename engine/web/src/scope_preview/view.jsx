// The pre-arm scope-simulation preview panel (ADR-0021, ADR-0016): an operator types a
// CANDIDATE `enforceScope` (namespaces / labels — the same vocabulary as
// `PROTECTOR_ENFORCE_SCOPE_NAMESPACES`/`_LABELS`) and previews what would fire, and what
// live traffic it would sever, if that scope were armed right now — before ever flipping
// `mode: enforce`. Mounted inside the Action view (ADR-0021's enforcement story lives
// there), but a genuinely separate, self-contained, on-demand fetch: it is NOT part of the
// 5s tab poll (`poll.js`), it fetches only on submit. Computing the preview NEVER applies,
// arms, or mutates anything (ADR-0016 — presentation is a view, never a decision gate); the
// server route is a pure read of state the engine already produced.
//
// Same-origin only (the strict CSP `connect-src 'self'` is the hard floor, mirroring
// `poll.js`'s rule): the URL is always the relative `/api/scope_preview.json`.

import { useCallback, useState } from "preact/hooks";

/**
 * @param {object} [props]
 * @param {typeof fetch} [props.fetchImpl] injectable fetch (tests pass a stub; default is global).
 */
export function ScopePreviewPanel({ fetchImpl = typeof fetch !== "undefined" ? fetch : undefined } = {}) {
  const [namespaces, setNamespaces] = useState("");
  const [labels, setLabels] = useState("");
  const [result, setResult] = useState(null);
  const [errored, setErrored] = useState(false);

  const preview = useCallback(
    async (e) => {
      e.preventDefault();
      setErrored(false);
      const params = new URLSearchParams();
      if (namespaces.trim()) params.set("namespaces", namespaces.trim());
      if (labels.trim()) params.set("labels", labels.trim());
      try {
        const res = await fetchImpl(`/api/scope_preview.json?${params.toString()}`, {
          headers: { accept: "application/json" },
        });
        if (!res.ok) {
          setErrored(true);
          return;
        }
        setResult(await res.json());
      } catch {
        setErrored(true);
      }
    },
    [namespaces, labels, fetchImpl],
  );

  return (
    <section class="activity-section scope-preview" aria-label="pre-arm scope preview">
      <h2 class="section-h t-h2">pre-arm scope preview</h2>
      <p class="section-sub t-body muted">
        try a candidate enforceScope before flipping mode: enforce {"\u{2014}"} what fires, and
        what live traffic it would sever, at THIS scope right now. computing this applies
        nothing.
      </p>
      <form class="scope-preview-form" onSubmit={preview}>
        <label class="scope-preview-field">
          <span class="t-micro muted">namespaces (comma-separated)</span>
          <input
            type="text"
            value={namespaces}
            onInput={(e) => setNamespaces(e.currentTarget.value)}
            placeholder="app,data"
          />
        </label>
        <label class="scope-preview-field">
          <span class="t-micro muted">labels (key=value, comma-separated)</span>
          <input
            type="text"
            value={labels}
            onInput={(e) => setLabels(e.currentTarget.value)}
            placeholder="tier=prod"
          />
        </label>
        <button type="submit" class="scope-preview-submit">
          preview
        </button>
      </form>
      {errored ? (
        <p class="col-empty t-body muted">could not compute the preview {"\u{2014}"} try again.</p>
      ) : null}
      {result ? <ScopePreviewResult result={result} /> : null}
    </section>
  );
}

function ScopePreviewResult({ result }) {
  const wouldFire = Array.isArray(result["would-fire"]) ? result["would-fire"] : [];
  const held = Array.isArray(result["held-out-of-scope"]) ? result["held-out-of-scope"] : [];
  const empty = result["candidate-is-empty"] === true;
  return (
    <div class="scope-preview-result">
      {empty ? (
        <p class="col-empty t-body muted">
          no namespaces or labels entered {"\u{2014}"} nothing would fire (an honest zero, not
          "everything").
        </p>
      ) : wouldFire.length === 0 ? (
        <p class="col-empty t-body muted">nothing standing would fire in this scope.</p>
      ) : (
        <ul class="trust-list">
          {wouldFire.map((f, i) => (
            <FiringCutEntry key={`${f.cut} ${i}`} f={f} />
          ))}
        </ul>
      )}
      {held.length > 0 ? (
        <p class="section-sub t-body muted">
          {held.length} standing cut{held.length !== 1 ? "s" : ""} outside this scope would stay
          proposals, not armed:
        </p>
      ) : null}
      {held.length > 0 ? (
        <ul class="trust-list">
          {held.map((h, i) => (
            <HeldCutEntry key={`${h.cut} ${i}`} h={h} />
          ))}
        </ul>
      ) : null}
    </div>
  );
}

/** One cut that would arm under the candidate scope, with its predicted collateral (or the
 *  honest "collateral unknown" caveat — never collapsed into an empty, implied-safe reading). */
function FiringCutEntry({ f }) {
  const collateral = Array.isArray(f["alive-collateral"]) ? f["alive-collateral"] : [];
  const unknown = f["collateral-unknown"] === true;
  return (
    <li class="trust-entry" data-open="true">
      <div class="trust-entry-head">
        <span class="trust-tag tag-open">
          <span class="glyph" aria-hidden="true">
            {"\u{2702}"}
          </span>
          would fire
        </span>
        <span class="trust-entry-key t-data-strong">{f.cut}</span>
      </div>
      <p class="trust-entry-meta t-micro muted">{f.action}</p>
      {unknown ? (
        <p class="trust-entry-verdict t-data">
          collateral unknown {"\u{2014}"} reachability wasn't fully modeled; never assume safe.
        </p>
      ) : collateral.length === 0 ? (
        <p class="trust-entry-verdict t-data">no live collateral known.</p>
      ) : (
        <p class="trust-entry-verdict t-data">
          would sever {collateral.length} live peer{collateral.length !== 1 ? "s" : ""}:{" "}
          {collateral.join(", ")}
        </p>
      )}
    </li>
  );
}

/** One otherwise-actionable cut the candidate scope excludes — the gate would hold it as a
 *  proposal rather than arm it. */
function HeldCutEntry({ h }) {
  return (
    <li class="trust-entry trust-cleared">
      <div class="trust-entry-head">
        <span class="trust-tag tag-cleared">
          <span class="glyph" aria-hidden="true">
            {"\u{25CB}"}
          </span>
          held {"\u{00B7}"} out of scope
        </span>
        <span class="trust-entry-key t-data-strong">{h.cut}</span>
      </div>
      <p class="trust-entry-meta t-micro muted">{h.action}</p>
    </li>
  );
}
