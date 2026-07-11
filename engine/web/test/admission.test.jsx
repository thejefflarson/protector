// Admission view tests (ADR-0025 / JEF-400): decision rows key on the `(subject, image, decision)`
// TUPLE so the dedup `count` updates IN PLACE across a poll (no tear), a signing-inventory row's
// expand-in-place detail (KEYED store state) stays open across a poll, the honest empty states
// render, and an XSS subject/image/signer renders inert.

import { describe, it, expect, beforeEach } from "vitest";
import { render, fireEvent, cleanup, act } from "@testing-library/preact";
import { useState, useEffect } from "preact/hooks";
import { Store } from "../src/store.js";
import { AdmissionView } from "../src/admission/view.jsx";
import { decisionKey } from "../src/keys.js";
import { admissionView, decisionRow, signingRow, signingRepo } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

function Harness({ store }) {
  const [, force] = useState(0);
  useEffect(() => store.subscribe(() => force((n) => n + 1)), [store]);
  const data = store.getState().data;
  return data ? <AdmissionView view={data} store={store} /> : null;
}

describe("Admission tuple keying — count updates in place", () => {
  it("keeps the same row node and updates the ×count across a poll", () => {
    const store = new Store();
    const row = decisionRow({ subject: "Deployment/web", image: "registry/web:1", decision: "audit", count: 2 });
    store.applySnapshot(admissionView({ rows: [row], total: 2, audited: 2 }));
    const { container } = render(<Harness store={store} />);

    const rowNode = container.querySelector(".decision-row");
    expect(rowNode).toBeTruthy();
    rowNode.dataset.probe = "kept";
    expect(container.querySelector(".decision-count").textContent).toContain("2");

    // A new pass: the SAME tuple, count now 5 → same node reconciled in place, count bumped.
    act(() =>
      store.applySnapshot(
        admissionView({ rows: [{ ...row, count: 5 }], total: 5, audited: 5 }),
      ),
    );
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
    const store = new Store();
    const repo = signingRepo("registry/app", [signingRow("img-a"), signingRow("img-b")]);
    store.applySnapshot(admissionView({ signing: [repo] }));
    const { container } = render(<Harness store={store} />);

    const expander = container.querySelector('tr[data-signing="img-a"] .expander');
    fireEvent.click(expander);
    expect(store.isDisclosureOpen("admission:img-a")).toBe(true);
    expect(container.querySelector("#detail-img-a .detail")).toBeTruthy();

    // A poll re-delivers the inventory; the expanded detail must remain mounted (keyed store state).
    act(() =>
      store.applySnapshot(
        admissionView({ signing: [signingRepo("registry/app", [signingRow("img-a", { count: 3 }), signingRow("img-b")])] }),
      ),
    );
    expect(container.querySelector("#detail-img-a .detail")).toBeTruthy();
    expect(container.querySelector('tr[data-signing="img-a"] .expander').getAttribute("aria-expanded")).toBe("true");
  });
});

describe("Admission honesty", () => {
  it("renders the honest empty decisions state (never all-clear)", () => {
    const { container } = render(<AdmissionView view={admissionView({ rows: [] })} store={new Store()} />);
    expect(container.textContent).toContain("no admission decisions recorded yet");
    expect(container.textContent).toContain("not an all-clear");
  });

  it("renders the honest empty signing inventory (never all-clear)", () => {
    const { container } = render(<AdmissionView view={admissionView({ signing: [] })} store={new Store()} />);
    expect(container.textContent).toContain("no images observed yet");
  });

  it("keyline-flags a would-deny decision row", () => {
    const store = new Store();
    store.applySnapshot(admissionView({ rows: [decisionRow({ decision: "audit", "would-admit": false })], total: 1, audited: 1 }));
    const { container } = render(<Harness store={store} />);
    expect(container.querySelector(".decision-row-attention")).toBeTruthy();
    expect(container.textContent).toContain("would deny");
  });
});

describe("Admission escaping", () => {
  it("renders an XSS subject/image/signer identity as inert text", () => {
    window.__pwned = undefined;
    const XSS = '<img src=x onerror="window.__pwned=1">';
    const store = new Store();
    store.applySnapshot(
      admissionView({
        rows: [decisionRow({ subject: XSS, image: XSS, reason: XSS })],
        total: 1,
        signing: [signingRepo("registry/app", [signingRow("img-a", { image: XSS, label: XSS, signer: { "identity-short": XSS, "identity-full": XSS, "issuer-badge": XSS, "issuer-full": XSS } })])],
      }),
    );
    const { container } = render(<Harness store={store} />);
    fireEvent.click(container.querySelector('tr[data-signing="img-a"] .expander'));
    expect(container.querySelector("img")).toBeNull();
    expect(window.__pwned).toBeUndefined();
    expect(container.textContent).toContain(XSS);
  });
});
