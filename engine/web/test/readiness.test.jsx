// Readiness view tests (ADR-0025 / JEF-400): the per-node `<details>` disclosure (KEYED component
// state) stays open across a poll, rows key on `id` (patched in place), a blind node is surfaced
// loudly (server-derived state token), and an XSS node name renders inert.

import { describe, it, expect, beforeEach } from "vitest";
import { render, fireEvent, cleanup, act } from "@testing-library/preact";
import { useState, useEffect } from "preact/hooks";
import { Store } from "../src/store.js";
import { ReadinessView } from "../src/readiness/view.jsx";
import { readinessRow, nodeRow, readinessView } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

function Harness({ store }) {
  const [, force] = useState(0);
  useEffect(() => store.subscribe(() => force((n) => n + 1)), [store]);
  const data = store.getState().data;
  return data ? <ReadinessView view={data} store={store} /> : null;
}

/** Open a native <details> the way a user would. */
function openDetails(details) {
  details.open = true;
  fireEvent(details, new Event("toggle"));
}

const rowWithNodes = (id, nodes, over = {}) => readinessRow(id, { nodes, ...over });

describe("Readiness state preservation + keying", () => {
  it("keeps an opened per-node breakdown open across a poll", () => {
    const store = new Store();
    const row = rowWithNodes("runtime-corroboration", [nodeRow("node-1"), nodeRow("node-2")]);
    store.applySnapshot(readinessView([row]));
    const { container } = render(<Harness store={store} />);

    const details = container.querySelector('li[data-input="runtime-corroboration"] details.cov-nodes');
    expect(details).toBeTruthy();
    openDetails(details);
    expect(store.isDisclosureOpen("readiness:runtime-corroboration")).toBe(true);

    // A poll updates the row's detail; the disclosure must stay open (keyed state survives).
    act(() =>
      store.applySnapshot(
        readinessView([rowWithNodes("runtime-corroboration", [nodeRow("node-1"), nodeRow("node-2")], { detail: "2 signals" })]),
      ),
    );
    const after = container.querySelector('li[data-input="runtime-corroboration"] details.cov-nodes');
    expect(after.open).toBe(true);
  });

  it("keys rows on id and patches an updated row in place", () => {
    const store = new Store();
    store.applySnapshot(readinessView([readinessRow("model"), readinessRow("kev")]));
    const { container } = render(<Harness store={store} />);
    const modelRow = container.querySelector('li[data-input="model"]');
    modelRow.dataset.probe = "kept";

    act(() => store.applySnapshot(readinessView([readinessRow("model", { detail: "last call ok" }), readinessRow("kev")])));
    const after = container.querySelector('li[data-input="model"]');
    expect(after.dataset.probe).toBe("kept");
    expect(after.textContent).toContain("last call ok");
  });
});

describe("Readiness honesty (blind nodes)", () => {
  it("surfaces a blind node loudly (server-derived state token, not a client derivation)", () => {
    const store = new Store();
    const row = rowWithNodes("runtime-corroboration", [
      nodeRow("node-1", { state: "healthy" }),
      nodeRow("node-2", { state: "blind", detail: "no live sensor" }),
    ]);
    store.applySnapshot(readinessView([row]));
    const { container } = render(<Harness store={store} />);
    const summary = container.querySelector(".cov-nodes-summary");
    expect(summary.textContent).toContain("1 blind");
    const blindRow = container.querySelector('tr[data-state="blind"]');
    expect(blindRow.textContent).toContain("BLIND");
  });

  it("flags a weakening absent input with the amber-keyline gap class + enable action", () => {
    const store = new Store();
    const gap = readinessRow("model", { state: "absent", "weakens-decisions": true, enable: "PROTECTOR_MODEL_URL" });
    store.applySnapshot(readinessView([gap]));
    const { container } = render(<Harness store={store} />);
    const row = container.querySelector('li[data-input="model"]');
    expect(row.classList.contains("cov-row-gap")).toBe(true);
    expect(container.querySelector(".cov-enable-action")).toBeTruthy();
    expect(container.textContent).toContain("enable with");
  });
});

describe("Readiness escaping", () => {
  it("renders an XSS node name as inert text", () => {
    window.__pwned = undefined;
    const XSS = '<img src=x onerror="window.__pwned=1">';
    const row = rowWithNodes("runtime-corroboration", [nodeRow(XSS, { detail: XSS })]);
    const store = new Store();
    store.applySnapshot(readinessView([row]));
    const { container } = render(<Harness store={store} />);
    openDetails(container.querySelector("details.cov-nodes"));
    expect(container.querySelector("img")).toBeNull();
    expect(window.__pwned).toBeUndefined();
    expect(container.textContent).toContain(XSS);
  });
});
