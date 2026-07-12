// The ACCEPTANCE HEART of JEF-351 / JEF-411 (ADR-0025 / ADR-0028): across a data refresh, an
// expanded row, an open native `<details>` disclosure, AND keyboard focus PERSIST. This is exactly
// what the v3 innerHTML swap destroyed and the keyed reconcile fixes — so it is tested end-to-end in
// jsdom.
//
// Post-JEF-411 the expansion is LOCAL component state (a plain `useState` in FindingRow) and the
// "show model prompt" disclosure is a NATIVE, UNCONTROLLED `<details>`. Neither is persisted; both
// survive a poll purely because Preact's keyed diff (`key={f.id}`) keeps the row's DOM in place. The
// harness re-renders the Findings view with a NEW `view` prop keyed by id (a poll tick), then
// asserts nothing the operator touched was disturbed.

import { describe, it, expect, beforeEach } from "vitest";
import { render, fireEvent, cleanup } from "@testing-library/preact";
import { FindingsView } from "../src/findings/table.jsx";
import { finding, findingsView } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

/** Open a native <details> the way a user would: set `open`, then fire the `toggle` event. */
function openDetails(details) {
  details.open = true;
  fireEvent(details, new Event("toggle"));
}

describe("state preservation across a refresh (the JEF-351 acceptance heart)", () => {
  it("keeps an expanded row, an open disclosure, and focus after a poll", () => {
    const { container, rerender } = render(
      <FindingsView view={findingsView([finding("a"), finding("b")])} />,
    );

    // Expand row 'a' by clicking its row (the whole row is the toggle, like the maud path).
    const rowA = container.querySelector('tr.row[data-finding="a"]');
    fireEvent.click(rowA);
    expect(rowA.classList.contains("open")).toBe(true);

    // The detail panel is now rendered; open its native <details> "show model prompt".
    const details = container.querySelector("#detail-a details.model-prompt");
    expect(details).toBeTruthy();
    openDetails(details);
    expect(details.open).toBe(true);

    // Focus the expander button inside row 'a'.
    const expander = container.querySelector('tr.row[data-finding="a"] .expander');
    expander.focus();
    expect(document.activeElement).toBe(expander);

    // A poll lands a NEW snapshot: 'a' unchanged, 'b' changed disposition, a new 'c' inserted.
    rerender(
      <FindingsView
        view={findingsView([
          finding("a"),
          finding("b", { disposition: "auto-eligible" }),
          finding("c"),
        ])}
      />,
    );

    // Expansion survived — row 'a' still open (local useState kept by the keyed diff), detail mounted.
    const rowAafter = container.querySelector('tr.row[data-finding="a"]');
    expect(rowAafter.classList.contains("open")).toBe(true);
    expect(container.querySelector("#detail-a .detail")).toBeTruthy();

    // The open native disclosure survived — same DOM node, still open.
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

  it("removes a gone finding via the keyed diff (no client tombstone — JEF-411)", () => {
    const { container, rerender } = render(
      <FindingsView view={findingsView([finding("a"), finding("b")])} />,
    );
    // Expand 'a' so we prove even an OPEN row is simply removed when it clears (no farewell row).
    fireEvent.click(container.querySelector('tr.row[data-finding="a"]'));
    expect(container.querySelector('tr.row[data-finding="a"]').classList.contains("open")).toBe(
      true,
    );

    // 'a' clears from the snapshot — Preact's keyed diff drops it; 'b' stays in place.
    rerender(<FindingsView view={findingsView([finding("b")])} />);
    expect(container.querySelector('[data-finding="a"]')).toBeNull();
    expect(container.querySelector('[data-tombstone="true"]')).toBeNull();
    expect(container.querySelector('tr.row[data-finding="b"]')).toBeTruthy();
  });
});
