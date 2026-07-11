// Action view tests (ADR-0025 / JEF-400): a judgement-audit `<details>` (KEYED component state)
// stays open across a poll, entry rows key on their stable entry (patched in place), the honest
// journal-empty state renders, and an XSS verdict/prompt renders inert.

import { describe, it, expect, beforeEach } from "vitest";
import { render, fireEvent, cleanup, act } from "@testing-library/preact";
import { useState, useEffect } from "preact/hooks";
import { Store } from "../src/store.js";
import { ActionView } from "../src/action/view.jsx";
import { actionView, wouldAct, judgement } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

function Harness({ store }) {
  const [, force] = useState(0);
  useEffect(() => store.subscribe(() => force((n) => n + 1)), [store]);
  const data = store.getState().data;
  return data ? <ActionView view={data} store={store} /> : null;
}

function openDetails(details) {
  details.open = true;
  fireEvent(details, new Event("toggle"));
}

describe("Action state preservation + keying", () => {
  it("keeps an opened judgement disclosure open across a poll", () => {
    const store = new Store();
    store.applySnapshot(actionView({ judgements: [judgement("web")] }));
    const { container } = render(<Harness store={store} />);

    const details = container.querySelector(".judgement-entry details.model-prompt");
    expect(details).toBeTruthy();
    openDetails(details);
    expect(store.isDisclosureOpen("action:judgement-0")).toBe(true);

    // A poll re-delivers the ring (same entry order); the disclosure must stay open.
    act(() => store.applySnapshot(actionView({ judgements: [judgement("web", { verdict: "Cleared" })] })));
    const after = container.querySelector(".judgement-entry details.model-prompt");
    expect(after.open).toBe(true);
  });

  it("keys a would-act entry on its stable entry and patches in place", () => {
    const store = new Store();
    store.applySnapshot(actionView({ "would-act": [wouldAct("web"), wouldAct("api")] }));
    const { container } = render(<Harness store={store} />);
    const rows = container.querySelectorAll(".trust-list .trust-entry");
    expect(rows.length).toBe(2);
    rows[0].dataset.probe = "kept";

    act(() =>
      store.applySnapshot(
        actionView({ "would-act": [wouldAct("web", { "last-verdict": "still exploitable" }), wouldAct("api")] }),
      ),
    );
    const after = container.querySelectorAll(".trust-list .trust-entry")[0];
    expect(after.dataset.probe).toBe("kept");
    expect(after.textContent).toContain("still exploitable");
  });
});

describe("Action honesty", () => {
  it("renders the honest journal-empty state (distinct from none-in-window)", () => {
    const { container } = render(<ActionView view={actionView({ "journal-empty": true })} store={new Store()} />);
    expect(container.textContent).toContain("no decisions journaled yet");
    expect(container.textContent).toContain("not an all-clear");
  });

  it("renders honest 'none in window' when the journal has history but nothing this window", () => {
    const { container } = render(<ActionView view={actionView({ "journal-empty": false })} store={new Store()} />);
    expect(container.textContent).toContain("none in the last");
  });
});

describe("Action escaping", () => {
  it("renders an XSS verdict/prompt/entry as inert text", () => {
    window.__pwned = undefined;
    const XSS = '<img src=x onerror="window.__pwned=1">';
    const store = new Store();
    store.applySnapshot(
      actionView({
        "would-act": [wouldAct(XSS, { "last-verdict": XSS })],
        judgements: [judgement(XSS, { verdict: XSS, prompt: XSS, reply: XSS })],
      }),
    );
    const { container } = render(<Harness store={store} />);
    openDetails(container.querySelector(".judgement-entry details.model-prompt"));
    expect(container.querySelector("img")).toBeNull();
    expect(window.__pwned).toBeUndefined();
    expect(container.textContent).toContain(XSS);
  });
});
