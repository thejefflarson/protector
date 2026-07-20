// The per-image signing inventory (ADR-0025 / JEF-262 / ADR-0020 / JEF-400) — a 1:1 Preact port of
// maud `signing_inventory`: ONE aligned `<table>` for the whole inventory (columns line up across
// every repo), grouped under repo group-header rows, with the loud regression / calm exception /
// loud provenance-change rows above each group's image rows. Two hard operator rules preserved: the
// posture is never n/a (always signed / invalid / not-signed / … / checking), and the "if enforced"
// cell is always a definite continuity verdict (would-admit / would-block / uncertain).
//
// Reconcile keying: image + regression/exception/provenance-change rows key on their server-supplied
// `dom-id`, and each row's expand-in-place detail is a button-driven expander backed by LOCAL
// component state (a plain `useState` per row — JEF-411), ephemeral by design. Preact's keyed diff
// keeps the open row open across a poll (the boring default). Every untrusted string (image ref /
// signer identity / issuer / builder / source) renders via JSX text (Preact auto-escapes; the
// raw-HTML escape hatch is banned by the guard). The `data-*` tokens are fixed `[a-z0-9-]`, never
// derived from untrusted text.

import { useState } from "preact/hooks";
import {
  posture,
  provenance,
  enforcement,
  strength,
  isInvalid,
  regression,
} from "./signing_glyphs.js";
import {
  SigningDetail,
  RegressionDetail,
  ProvenanceChangeDetail,
  ExceptionDetail,
} from "./signing_detail.jsx";

const COLSPAN = 7;

/**
 * @param {object} props
 * @param {any[]} props.signing the per-repo signing inventory (serde kebab-case).
 */
export function SigningInventory({ signing }) {
  const repos = Array.isArray(signing) ? signing : [];
  return (
    <section class="signing-inventory" aria-label="signing inventory">
      <h3 class="col-h t-h2">signing inventory</h3>
      <p class="section-sub t-body muted">
        the observed signing posture of every image {"\u{2014}"} signed, invalid signature, or not
        signed (or a transient check while a registry is unreachable). This is observation, not a
        gate; the 'if enforced' column is the what-if a signature-continuity gate would apply
        {"\u{2014}"} a calm, consistent posture would admit, only a regression against the repo's
        established baseline would block (a cold-baseline regression reads uncertain, not blocked).
      </p>
      {repos.length === 0 ? (
        <SigningEmpty />
      ) : (
        <table class="signing">
          <thead>
            <tr>
              <th class="col-expand t-micro" scope="col" />
              <th class="t-micro" scope="col">
                signature
              </th>
              <th class="t-micro" scope="col">
                image
              </th>
              <th class="t-micro" scope="col">
                signer
              </th>
              <th class="t-micro" scope="col">
                provenance
              </th>
              <th class="t-micro" scope="col">
                baseline
              </th>
              <th class="t-micro" scope="col">
                if enforced
              </th>
            </tr>
          </thead>
          <tbody>
            {repos.map((g) => (
              <SigningGroup key={`repo-${g.repo}`} g={g} />
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

/** One repo group: a spanning group-header row, then (when present) the loud regression / calm
 *  exception / loud provenance-change rows, then the repo's image rows. */
function SigningGroup({ g }) {
  const images = Array.isArray(g.images) ? g.images : [];
  return (
    <>
      <tr class="signing-group">
        <th class="signing-group-head t-data-strong" colspan={COLSPAN} scope="colgroup">
          {g.repo}
        </th>
      </tr>
      {g.regression ? <RegressionRow r={g.regression} /> : null}
      {g.exception ? <ExceptionRow r={g.exception} /> : null}
      {g["provenance-change"] ? <ProvenanceChangeRow r={g["provenance-change"]} /> : null}
      {images.map((img) => (
        <SigningRow key={img["dom-id"]} r={img} strength={g.strength} />
      ))}
    </>
  );
}

/** A row expander button + the paired detail row's open state, backed by LOCAL component state (a
 *  plain `useState` — JEF-411, ephemeral by design). Returns `{ detailId, open, expander }`. */
function useRowDisclosure(domId, label) {
  const detailId = `detail-${domId}`;
  const [open, setOpen] = useState(false);
  const expander = (
    <button
      class="expander"
      type="button"
      aria-expanded={String(open)}
      aria-controls={detailId}
      aria-label={label}
      onClick={() => setOpen((v) => !v)}
    >
      <span class="expander-glyph" aria-hidden="true">
        {open ? "\u{2212}" : "+"}
      </span>
    </button>
  );
  return { detailId, open, expander };
}

/** One image row: a findings-style summary row (posture chip · image · signer · provenance ·
 *  baseline · continuity verdict) paired with a hidden full-width detail row. An invalid signature
 *  is the loud attention case (a breach keyline). */
function SigningRow({ r, strength: repoStrength }) {
  const { detailId, open, expander } = useRowDisclosure(
    r["dom-id"],
    "expand image signing detail",
  );
  const attention = isInvalid(r.posture);
  const p = posture(r.posture);
  const prov = provenance(r.provenance);
  const enf = enforcement(r.enforcement);
  const s = strength(repoStrength);
  const provInfo = r["provenance-info"];
  return (
    <>
      <tr
        // `open` is load-bearing: the detail row is `.row-detail { display: none }`, revealed only
        // by the CSS sibling selector `.row.open + .row-detail`. Without it, clicking the expander
        // toggles state but the detail stays hidden (the findings rows already do this).
        class={`row signing-row${attention ? " signing-row-attention" : ""}${open ? " open" : ""}`}
        id={r["dom-id"]}
        data-signing={r["dom-id"]}
        data-posture={p.token}
      >
        <td class="cell cell-expand">{expander}</td>
        <td class="cell cell-gate">
          <span class={`gate-chip sign-${p.token}`}>
            <span class="glyph" aria-hidden="true">
              {p.glyph}
            </span>
            <span class="gate-word">{p.word}</span>
          </span>
        </td>
        <td class="cell cell-image">
          <span class="signing-ref t-data-strong" title={r.image}>
            {r.label}
          </span>
          {r.count > 1 ? (
            <span
              class="signing-count t-micro muted"
              title="distinct image observed this many times"
            >
              {"\u{00D7}"}
              {r.count}
            </span>
          ) : null}
        </td>
        <td class="cell cell-signer">
          {r.signer ? (
            <span class="signing-by t-micro" title={r.signer["identity-full"]}>
              {r.signer["identity-short"]}
              {r.signer["issuer-badge"] ? (
                <>
                  {" \u{00B7} "}
                  <span class="issuer-badge">{r.signer["issuer-badge"]}</span>
                </>
              ) : null}
            </span>
          ) : (
            <span class="t-micro muted" title="no trusted signer for this image">
              {"\u{2014}"}
            </span>
          )}
        </td>
        <td class="cell cell-provenance" data-provenance={prov.token}>
          {r.provenance === "absent" ? (
            // Almost no image ships a SLSA build-provenance attestation, so an "absent" chip would
            // shout "no provenance" on nearly every row — pure noise. The calm default reads as a
            // quiet muted dash (mirroring the no-signer cell); the loud chip is kept only for the
            // meaningful states (verified / unverifiable / checking). The expandable detail still
            // explains the absence for anyone who looks.
            <span
              class="t-micro muted"
              title="no SLSA build-provenance attestation for this image — calm, not an alarm"
            >
              {"\u{2014}"}
            </span>
          ) : (
            <>
              <span class={`gate-chip prov-${prov.token}`}>
                <span class="glyph" aria-hidden="true">
                  {prov.glyph}
                </span>
                <span class="gate-word">{prov.word}</span>
              </span>
              {provInfo ? (
                <span class="provenance-by t-micro" title={provInfo["builder-full"]}>
                  {" \u{00B7} "}
                  {provInfo["builder-short"]}
                </span>
              ) : null}
            </>
          )}
        </td>
        <td class="cell cell-baseline">
          {repoStrength === "unknown" ? (
            <span class="t-micro muted" title="no signing baseline learned for this repo yet">
              {"\u{2014}"}
            </span>
          ) : (
            <span
              class="signing-strength t-micro muted"
              data-strength={s.token}
              title="whether the public transparency log corroborates this repo's signing history (JEF-266)"
            >
              {s.word}
            </span>
          )}
        </td>
        <td class="cell cell-enforced">
          <span class={`enforced-chip enforced-${enf.token}`}>
            <span class="glyph" aria-hidden="true">
              {enf.glyph}
            </span>
            <span class="enforced-word">{enf.word}</span>
          </span>
        </td>
      </tr>
      <tr class="row-detail" id={detailId} data-detail-for={r["dom-id"]}>
        <td class="detail-host" colspan={COLSPAN}>
          {open ? <SigningDetail r={r} strength={repoStrength} /> : null}
        </td>
      </tr>
    </>
  );
}

/** The honest baseline-strength phrase for a banner: established (strong) vs cold (a weak lead). */
function baselineWord(established) {
  return established ? "established baseline" : "weak baseline \u{2014} treat as a lead";
}

/**
 * A repo-level banner row (regression / provenance-change / exception) + its paired detail row. The
 * three differ only in CSS prefix (`signing-regression`/`signing-exception`), glyph, headline, the
 * `data-*` attribute, the `role`, and the detail body — everything else (the expander cell, the
 * "image: <mono>" tail, the colspans) is identical, so it lives here once.
 * @param {object} props
 * @param {string} props.domId  the row's stable dom id.
 * @param {string} props.headClass  the CSS prefix (`signing-regression` | `signing-exception`).
 * @param {string} props.rowClass  the summary `<tr>` class (loud attention vs calm).
 * @param {Record<string,string>} props.dataAttr  the single `data-*` attribute (fixed token).
 * @param {string} [props.role]  `"alert"` for the loud banners, omitted for the calm exception.
 * @param {string} props.glyph  the leading glyph.
 * @param {any} props.head  the headline word content (inside `{headClass}-word`).
 * @param {boolean} props.established  drives the sibling baseline-strength phrase.
 * @param {string} props.image  the untrusted image ref (rendered as JSX text).
 * @param {string} props.label  the expander's aria-label.
 * @param {(open: boolean) => any} props.detail  renders the detail body when open.
 */
function BannerRow({
  domId,
  headClass,
  rowClass,
  dataAttr,
  role,
  glyph,
  head,
  established,
  image,
  label,
  detail,
}) {
  const { detailId, open, expander } = useRowDisclosure(domId, label);
  return (
    <>
      {/* `open` gates the CSS sibling selector `.row.open + .row-detail` that reveals the detail. */}
      <tr
        class={open ? `${rowClass} open` : rowClass}
        id={domId}
        data-signing={domId}
        role={role}
        {...dataAttr}
      >
        <td class="cell cell-expand">{expander}</td>
        <td class="cell cell-regression" colspan="6">
          <span class={`${headClass}-head`}>
            <span class="glyph" aria-hidden="true">
              {glyph}
            </span>
            <span class={`${headClass}-word t-data-strong`}>{head}</span>
            <span class={`${headClass}-strength t-micro muted`}>({baselineWord(established)})</span>
          </span>
          <span class={`${headClass}-image t-data`}>
            {" image: "}
            <span class="mono">{image}</span>
          </span>
        </td>
      </tr>
      <tr class="row-detail" id={detailId} data-detail-for={domId}>
        <td class="detail-host" colspan="7">
          {open ? detail() : null}
        </td>
      </tr>
    </>
  );
}

/** The loud signing-regression row: a breach-keyline banner with the loud "signing regression"
 *  word (`role="alert"`). */
function RegressionRow({ r }) {
  const kind = regression(r.kind);
  return (
    <BannerRow
      domId={r["dom-id"]}
      headClass="signing-regression"
      rowClass="row signing-row signing-row-attention"
      dataAttr={{ "data-regression": kind.token }}
      role="alert"
      glyph={"\u{25CF}"}
      head={kind.word}
      established={r.established}
      image={r.image}
      label="expand signing regression detail"
      detail={() => <RegressionDetail r={r} />}
    />
  );
}

/** The loud build-provenance-change row: like the regression row but for a builder/source drift. */
function ProvenanceChangeRow({ r }) {
  return (
    <BannerRow
      domId={r["dom-id"]}
      headClass="signing-regression"
      rowClass="row signing-row signing-row-attention"
      dataAttr={{ "data-provenance": "changed" }}
      role="alert"
      glyph={"\u{25CF}"}
      head={<>build provenance change {"\u{2014}"} unexpected builder/source</>}
      established={r.established}
      image={r.image}
      label="expand build-provenance change detail"
      detail={() => <ProvenanceChangeDetail r={r} />}
    />
  );
}

/** The CALM exception-accepted row: a muted banner with the distinct word "exception accepted"
 *  (never green-cleared), kept visible. */
function ExceptionRow({ r }) {
  const kind = regression(r.kind);
  return (
    <BannerRow
      domId={r["dom-id"]}
      headClass="signing-exception"
      rowClass="row signing-row"
      dataAttr={{ "data-exception": kind.token }}
      glyph={"\u{25C8}"}
      head={<>exception accepted {"\u{2014}"} {kind.word}</>}
      established={r.established}
      image={r.image}
      label="expand exception-accepted detail"
      detail={() => <ExceptionDetail r={r} />}
    />
  );
}

/** The honest empty inventory: no images observed yet — explicitly NOT an all-clear. */
function SigningEmpty() {
  return (
    <div class="empty signing-empty">
      <p class="empty-head t-h2">no images observed yet</p>
      <p class="empty-sub t-body muted">
        the signing sweep has not recorded any image postures in this window. This is not an
        all-clear {"\u{2014}"} it means nothing has been inspected yet, not that every image is
        signed.
      </p>
    </div>
  );
}
