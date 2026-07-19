// Admission view tests (ADR-0025 / JEF-400 / JEF-411): decision rows key on the
// `(subject, image, decision)` TUPLE so the dedup `count` updates IN PLACE across a poll (no tear),
// a signing-inventory row's expand-in-place detail (LOCAL useState) stays open across a poll, the
// honest empty states render, and an XSS subject/image/signer renders inert. The view is `view`-only
// now (no store — JEF-411); a poll is modelled by re-rendering with a new `view` prop.

import { describe, it, expect, beforeEach } from "vitest";
import { render, fireEvent, cleanup } from "@testing-library/preact";
import { AdmissionView } from "../src/admission/view.jsx";
import { decisionKey } from "../src/keys.js";
import { admissionView, decisionRow, signingRow, signingRepo } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

describe("Admission tuple keying — count updates in place", () => {
  it("keeps the same row node and updates the ×count across a poll", () => {
    const row = decisionRow({ subject: "Deployment/web", image: "registry/web:1", decision: "audit", count: 2 });
    const { container, rerender } = render(
      <AdmissionView view={admissionView({ rows: [row], total: 2, audited: 2 })} />,
    );

    const rowNode = container.querySelector(".decision-row");
    expect(rowNode).toBeTruthy();
    rowNode.dataset.probe = "kept";
    expect(container.querySelector(".decision-count").textContent).toContain("2");

    // A new pass: the SAME tuple, count now 5 → same node reconciled in place, count bumped.
    rerender(<AdmissionView view={admissionView({ rows: [{ ...row, count: 5 }], total: 5, audited: 5 })} />);
    const after = container.querySelector(".decision-row");
    expect(after.dataset.probe).toBe("kept"); // reconciled in place
    expect(container.querySelector(".decision-count").textContent).toContain("5");
  });

  it("derives a stable key for the same tuple and a distinct one when the tuple differs", () => {
    const r = { subject: "Deployment/web", image: "registry/web:1", decision: "allow" };
    expect(decisionKey(r)).toBe(decisionKey({ ...r }));
    expect(decisionKey(r)).not.toBe(decisionKey({ ...r, decision: "deny" }));
    expect(decisionKey(r)).not.toBe(decisionKey({ ...r, image: "registry/web:2" }));
  });
});

describe("Admission signing-row expansion survives a poll", () => {
  it("keeps an expanded signing row open across a poll", () => {
    const repo = signingRepo("registry/app", [signingRow("img-a"), signingRow("img-b")]);
    const { container, rerender } = render(<AdmissionView view={admissionView({ signing: [repo] })} />);

    const expander = container.querySelector('tr[data-signing="img-a"] .expander');
    fireEvent.click(expander);
    expect(expander.getAttribute("aria-expanded")).toBe("true");
    expect(container.querySelector("#detail-img-a .detail")).toBeTruthy();

    // A poll re-delivers the inventory; the expanded detail must remain mounted (local useState kept
    // by the keyed diff on the row's dom-id).
    rerender(
      <AdmissionView
        view={admissionView({ signing: [signingRepo("registry/app", [signingRow("img-a", { count: 3 }), signingRow("img-b")])] })}
      />,
    );
    expect(container.querySelector("#detail-img-a .detail")).toBeTruthy();
    expect(container.querySelector('tr[data-signing="img-a"] .expander').getAttribute("aria-expanded")).toBe("true");
  });
});

describe("Admission honesty", () => {
  it("renders the honest empty decisions state (never all-clear)", () => {
    const { container } = render(<AdmissionView view={admissionView({ rows: [] })} />);
    expect(container.textContent).toContain("no admission decisions recorded yet");
    expect(container.textContent).toContain("not an all-clear");
  });

  it("renders the honest empty signing inventory (never all-clear)", () => {
    const { container } = render(<AdmissionView view={admissionView({ signing: [] })} />);
    expect(container.textContent).toContain("no images observed yet");
  });

  it("keyline-flags a would-deny decision row", () => {
    const { container } = render(
      <AdmissionView view={admissionView({ rows: [decisionRow({ decision: "audit", "would-admit": false })], total: 1, audited: 1 })} />,
    );
    expect(container.querySelector(".decision-row-attention")).toBeTruthy();
    expect(container.textContent).toContain("would deny");
  });
});

describe("Provenance column is quiet by default", () => {
  // Almost no image ships a SLSA attestation, so an "absent" chip on every row is pure noise — the
  // calm default reads as a muted dash, never the loud "no provenance" chip.
  it("renders an ABSENT-provenance image as a muted dash, not the no-provenance chip", () => {
    const { container } = render(
      <AdmissionView
        view={admissionView({ signing: [signingRepo("registry/app", [signingRow("img-a", { provenance: "absent" })])] })}
      />,
    );
    const cell = container.querySelector('tr[data-signing="img-a"] .cell-provenance');
    expect(cell).toBeTruthy();
    expect(cell.getAttribute("data-provenance")).toBe("absent"); // still honestly tagged
    expect(cell.querySelector(".gate-chip")).toBeNull(); // but no loud chip
    expect(cell.textContent).not.toContain("no provenance");
    expect(cell.textContent).toContain("—"); // a quiet dash
  });

  it("still renders the loud chip for a VERIFIED build provenance", () => {
    const { container } = render(
      <AdmissionView
        view={admissionView({
          signing: [
            signingRepo("registry/app", [
              signingRow("img-a", {
                provenance: "verified",
                "provenance-info": { "builder-short": "org/repo", "builder-full": "https://github.com/org/repo/.github/workflows/x.yml" },
              }),
            ]),
          ],
        })}
      />,
    );
    const cell = container.querySelector('tr[data-signing="img-a"] .cell-provenance');
    expect(cell.querySelector(".gate-chip.prov-verified")).toBeTruthy();
    expect(cell.textContent).toContain("org/repo");
  });
});

describe("Admission escaping", () => {
  it("renders an XSS subject/image/signer identity as inert text", () => {
    window.__pwned = undefined;
    const XSS = '<img src=x onerror="window.__pwned=1">';
    const { container } = render(
      <AdmissionView
        view={admissionView({
          rows: [decisionRow({ subject: XSS, image: XSS, reason: XSS })],
          total: 1,
          signing: [signingRepo("registry/app", [signingRow("img-a", { image: XSS, label: XSS, signer: { "identity-short": XSS, "identity-full": XSS, "issuer-badge": XSS, "issuer-full": XSS } })])],
        })}
      />,
    );
    fireEvent.click(container.querySelector('tr[data-signing="img-a"] .expander'));
    expect(container.querySelector("img")).toBeNull();
    expect(window.__pwned).toBeUndefined();
    expect(container.textContent).toContain(XSS);
  });
});
