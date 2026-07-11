// The ACCEPTANCE HEART of JEF-397 / JEF-351 (ADR-0025): across a data refresh, an expanded row, an
// open native `<details>` disclosure, AND keyboard focus PERSIST. This is exactly what the v3
// innerHTML swap destroyed and the keyed reconcile fixes — so it is tested end-to-end in jsdom.
//
// The harness renders the real Findings view keyed on `finding.id`, mutates the DOM the way an
// operator would (expand a row, open the disclosure, focus the expander), then feeds a NEW snapshot
// through the SAME store (a poll tick) and asserts nothing the operator touched was disturbed.

import { describe, it, expect, beforeEach } from "vitest";
import { render, fireEvent, cleanup, act } from "@testing-library/preact";
import { useState, useEffect } from "preact/hooks";
import { Store } from "../src/store.js";
import { FindingsView } from "../src/findings/table.jsx";
import { finding, findingsView } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

/** A harness that re-renders the Findings view whenever the store applies a new snapshot — i.e. it
 *  models the live poll driving the reconcile. */
function Harness({ store }) {
  const [, force] = useState(0);
  useEffect(() => store.subscribe(() => force((n) => n + 1)), [store]);
  const data = store.getState().data;
  return data ? <FindingsView view={data} store={store} /> : null;
}

/** Open a native <details> the way a user would: set `open`, then fire the `toggle` event that the
 *  component listens for. Wrapped in act via fireEvent's flush. */
function openDetails(details) {
  details.open = true;
  fireEvent(details, new Event("toggle"));
}

describe("state preservation across a refresh (the JEF-351 acceptance heart)", () => {
  it("keeps an expanded row, an open disclosure, and focus after a poll", async () => {
    const store = new Store();
    store.applySnapshot(findingsView([finding("a"), finding("b")]));
    const { container } = render(<Harness store={store} />);

    // Expand row 'a' by clicking its row (the whole row is the toggle, like the maud path).
    const rowA = container.querySelector('tr.row[data-finding="a"]');
    fireEvent.click(rowA);
    expect(store.isExpanded("a")).toBe(true);

    // The detail panel is now rendered; open its native <details> "show model prompt".
    const details = container.querySelector("#detail-a details.model-prompt");
    expect(details).toBeTruthy();
    openDetails(details);
    expect(store.isPromptOpen("a")).toBe(true);

    // Focus the expander button inside row 'a'.
    const expander = container.querySelector('tr.row[data-finding="a"] .expander');
    expander.focus();
    expect(document.activeElement).toBe(expander);

    // A poll lands a NEW snapshot: 'a' unchanged, 'b' changed disposition, a new 'c' inserted.
    act(() =>
      store.applySnapshot(
        findingsView([
          finding("a"),
          finding("b", { disposition: "auto-eligible" }),
          finding("c"),
        ]),
      ),
    );

    // Expansion survived — row 'a' still open, its detail panel still mounted.
    const rowAafter = container.querySelector('tr.row[data-finding="a"]');
    expect(rowAafter.classList.contains("open")).toBe(true);
    expect(container.querySelector("#detail-a .detail")).toBeTruthy();

    // The open disclosure survived — same DOM node, still open.
    const detailsAfter = container.querySelector("#detail-a details.model-prompt");
    expect(detailsAfter.open).toBe(true);

    // Focus survived — the SAME expander button is still the active element (the whole point).
    expect(document.activeElement).toBe(
      container.querySelector('tr.row[data-finding="a"] .expander'),
    );

    // The new finding 'c' was inserted collapsed and did NOT steal focus.
    const rowC = container.querySelector('tr.row[data-finding="c"]');
    expect(rowC).toBeTruthy();
    expect(rowC.classList.contains("open")).toBe(false);
  });

  it("shows a one-shot tombstone when an expanded finding clears, then drops it", async () => {
    const store = new Store();
    store.applySnapshot(findingsView([finding("a"), finding("b")]));
    const { container } = render(<Harness store={store} />);

    fireEvent.click(container.querySelector('tr.row[data-finding="a"]'));
    expect(store.isExpanded("a")).toBe(true);

    // 'a' clears (the model no longer sees this path) while it was expanded.
    act(() => store.applySnapshot(findingsView([finding("b")])));

    // A calm tombstone stands in for 'a' this render.
    const tomb = container.querySelector('tr[data-finding="a"][data-tombstone="true"]');
    expect(tomb).toBeTruthy();
    expect(tomb.textContent).toContain("this finding cleared");

    // The purge fires on the next tick; a following poll (no 'a') drops the tombstone entirely.
    await act(() => new Promise((r) => setTimeout(r, 0)));
    act(() => store.applySnapshot(findingsView([finding("b")])));
    expect(container.querySelector('[data-finding="a"]')).toBeNull();
    expect(store.isExpanded("a")).toBe(false); // its id was purged from the persisted set
  });

  it("hard-removes a cleared finding SILENTLY when it was never opened", () => {
    const store = new Store();
    store.applySnapshot(findingsView([finding("a"), finding("b")]));
    const { container } = render(<Harness store={store} />);

    // 'b' clears without ever being expanded — no tombstone, just gone.
    act(() => store.applySnapshot(findingsView([finding("a")])));
    expect(container.querySelector('[data-finding="b"]')).toBeNull();
    expect(container.querySelector('[data-tombstone="true"]')).toBeNull();
  });
});
