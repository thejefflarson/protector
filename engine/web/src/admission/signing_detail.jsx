// The expand-in-place detail panels for the signing inventory rows (ADR-0025 / JEF-400) — 1:1
// Preact ports of the maud `signing_detail` / `signing_regression_detail` / `provenance_change_detail`
// / `signing_exception_detail`. Each shows the FULL untrusted identities (image ref, Fulcio SAN,
// issuer, builder, source) so the operator sees EXACTLY what stands / changed. Every such string is
// UNTRUSTED and rendered as JSX text (Preact auto-escapes; the raw-HTML escape hatch is banned by
// the guard) — never an attribute-interpolated `class`/CSS value.

import { strength, regression } from "./signing_glyphs.js";

/** The image row's detail: the FULL image ref, the FULL signer identity + issuer (or posture prose
 *  for a non-signed image), the build provenance, and the repo baseline detail. */
export function SigningDetail({ r, strength: repoStrength }) {
  const s = strength(repoStrength);
  return (
    <div class={`detail detail-sign-${postureToken(r.posture)}`}>
      <section class="detail-section">
        <h3 class="detail-h">image</h3>
        <p class="t-data">
          <span class="mono">{r.image}</span>
        </p>
      </section>
      <section class="detail-section">
        <h3 class="detail-h">signer</h3>
        <SignerDetail r={r} />
      </section>
      <section class="detail-section">
        <h3 class="detail-h">build provenance</h3>
        <ProvenanceDetail r={r} />
      </section>
      <section class="detail-section">
        <h3 class="detail-h">baseline</h3>
        <p class="t-data muted">{s.detail}</p>
      </section>
    </div>
  );
}

/** The posture CSS token from the wire tag (`not-signed`→`notsigned`, `signed-key-based`→`signedkey`).
 *  Matches the maud detail rail class. */
function postureToken(tag) {
  switch (tag) {
    case "signed-key-based":
      return "signedkey";
    case "not-signed":
      return "notsigned";
    case "signed":
    case "unverifiable":
    case "invalid":
    case "checking":
      return tag;
    default:
      return "checking";
  }
}

function SignerDetail({ r }) {
  if (r.signer) {
    return (
      <>
        <p class="t-data">
          identity: <span class="mono">{r.signer["identity-full"]}</span>
        </p>
        {r.signer["issuer-full"] ? (
          <p class="t-data">
            issuer: <span class="mono">{r.signer["issuer-full"]}</span>
          </p>
        ) : (
          <p class="t-data muted">issuer: none recorded</p>
        )}
      </>
    );
  }
  return r.detail ? (
    <p class="t-data">{r.detail}</p>
  ) : (
    <p class="t-data muted">no signature artifact present for this image</p>
  );
}

function ProvenanceDetail({ r }) {
  const prov = r["provenance-info"];
  if (prov) {
    return (
      <>
        <p class="t-data">
          source: <span class="mono">{prov["source-full"]}</span>
        </p>
        <p class="t-data">
          builder: <span class="mono">{prov["builder-full"]}</span>
        </p>
      </>
    );
  }
  if (r.provenance === "absent") {
    return (
      <p class="t-data muted">
        no SLSA build-provenance attestation for this image {"\u{2014}"} calm, not an alarm, but not
        a verified build either
      </p>
    );
  }
  if (r.provenance === "unverifiable") {
    return (
      <p class="t-data muted">
        a provenance attestation is present but was not verified against our trust root (or carried
        no builder identity) {"\u{2014}"} not a trusted build
      </p>
    );
  }
  return <p class="t-data muted">build provenance not yet known (registry/log unreachable)</p>;
}

/** A before→after identity/builder detail block: the "before" list (honest when empty) shared by the
 *  regression / exception / provenance-change panels. */
function BeforeList({ singular, items }) {
  const list = Array.isArray(items) ? items : [];
  if (list.length === 0) {
    return (
      <>
        <h3 class="detail-h">{`before \u{2014} ${singular}`}</h3>
        <p class="t-data muted">{`${singular} not recorded`}</p>
      </>
    );
  }
  return (
    <>
      <h3 class="detail-h">
        {`before \u{2014} ${singular}`}
        {list.length !== 1 ? "s" : ""}
      </h3>
      <ul class="signing-regression-before">
        {list.map((x, i) => (
          <li class="t-data" key={i}>
            <span class="mono">{x}</span>
          </li>
        ))}
      </ul>
    </>
  );
}

/** The regression row's detail: the before→after with BOTH identities in FULL and the reason. */
export function RegressionDetail({ r }) {
  const after = r["after-identity"];
  return (
    <div class="detail detail-sign-regression">
      <section class="detail-section">
        <h3 class="detail-h">what changed</h3>
        <p class="t-data">
          image: <span class="mono">{r.image}</span>
        </p>
        <p class="t-data">{regressionWord(r.kind)}</p>
      </section>
      <section class="detail-section">
        <BeforeList singular="baseline signer" items={r["before-identities"]} />
      </section>
      <section class="detail-section">
        <h3 class="detail-h">after</h3>
        {after ? (
          <>
            <p class="t-data">now signed by:</p>
            <p class="t-data">
              <span class="mono">{after}</span>
            </p>
            {r["after-issuer"] ? (
              <p class="t-data muted">
                issuer: <span class="mono">{r["after-issuer"]}</span>
              </p>
            ) : null}
          </>
        ) : (
          <p class="t-data">{regressionAfter(r.kind)}</p>
        )}
      </section>
    </div>
  );
}

/** The provenance-change row's detail: the before→after builders in FULL + the deviating source. */
export function ProvenanceChangeDetail({ r }) {
  return (
    <div class="detail detail-sign-regression">
      <section class="detail-section">
        <h3 class="detail-h">what changed</h3>
        <p class="t-data">
          image: <span class="mono">{r.image}</span>
        </p>
        <p class="t-data">built by an unexpected builder / from an unexpected source</p>
      </section>
      <section class="detail-section">
        <BeforeList singular="baseline builder" items={r["before-builders"]} />
      </section>
      <section class="detail-section">
        <h3 class="detail-h">after</h3>
        <p class="t-data">now built by:</p>
        <p class="t-data">
          <span class="mono">{r["after-builder"]}</span>
        </p>
        <p class="t-data muted">
          source: <span class="mono">{r["after-source"]}</span>
        </p>
      </section>
    </div>
  );
}

/** The exception-accepted row's detail: what was accepted, before baseline signer(s) + (for an
 *  identity change) the accepted new identity in FULL. */
export function ExceptionDetail({ r }) {
  const after = r["after-identity"];
  return (
    <div class="detail">
      <section class="detail-section">
        <h3 class="detail-h">accepted exception</h3>
        <p class="t-data">
          image: <span class="mono">{r.image}</span>
        </p>
        <p class="t-data muted">
          a scoped, recorded exception admits this drift for THIS repo/image only; a different
          subsequent change re-flags.
        </p>
      </section>
      <section class="detail-section">
        <BeforeList singular="baseline signer" items={r["before-identities"]} />
      </section>
      {after ? (
        <section class="detail-section">
          <h3 class="detail-h">accepted {"\u{2014}"} new signer</h3>
          <p class="t-data">
            <span class="mono">{after}</span>
          </p>
        </section>
      ) : null}
    </div>
  );
}
/** The regression headline word + "after" prose (pure lookups over the glyphs table). */
function regressionWord(kind) {
  return regression(kind).word;
}
function regressionAfter(kind) {
  return regression(kind).after;
}
