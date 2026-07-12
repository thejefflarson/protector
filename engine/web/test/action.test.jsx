// Action view tests (ADR-0025 / JEF-400 / JEF-411): a judgement-audit `<details>` (NATIVE,
// UNCONTROLLED) stays open across a poll, entry rows key on their stable entry (patched in place),
// the honest journal-empty state renders, and an XSS verdict/prompt renders inert. The view is
// `view`-only now (no store — JEF-411); a poll is modelled by re-rendering with a new `view` prop.

import { describe, it, expect, beforeEach } from "vitest";
import { render, fireEvent, cleanup } from "@testing-library/preact";
import { ActionView } from "../src/action/view.jsx";
import { actionView, wouldAct, judgement } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

function openDetails(details) {
  details.open = true;
  fireEvent(details, new Event("toggle"));
}

describe("Action state preservation + keying", () => {
  it("keeps an opened judgement disclosure open across a poll", () => {
    const { container, rerender } = render(
      <ActionView view={actionView({ judgements: [judgement("web")] })} />,
    );

    const details = container.querySelector(".judgement-entry details.model-prompt");
    expect(details).toBeTruthy();
    openDetails(details);
    expect(details.open).toBe(true);

    // A poll re-delivers the ring (same entry order); the native disclosure must stay open.
    rerender(<ActionView view={actionView({ judgements: [judgement("web", { verdict: "Cleared" })] })} />);
    const after = container.querySelector(".judgement-entry details.model-prompt");
    expect(after.open).toBe(true);
  });

  it("keys a would-act entry on its stable entry and patches in place", () => {
    const { container, rerender } = render(
      <ActionView view={actionView({ "would-act": [wouldAct("web"), wouldAct("api")] })} />,
    );
    const rows = container.querySelectorAll(".trust-list .trust-entry");
    expect(rows.length).toBe(2);
    rows[0].dataset.probe = "kept";

    rerender(
      <ActionView
        view={actionView({ "would-act": [wouldAct("web", { "last-verdict": "still exploitable" }), wouldAct("api")] })}
      />,
    );
    const after = container.querySelectorAll(".trust-list .trust-entry")[0];
    expect(after.dataset.probe).toBe("kept");
    expect(after.textContent).toContain("still exploitable");
  });
});

describe("Action honesty", () => {
  it("renders the honest journal-empty state (distinct from none-in-window)", () => {
    const { container } = render(<ActionView view={actionView({ "journal-empty": true })} />);
    expect(container.textContent).toContain("no decisions journaled yet");
    expect(container.textContent).toContain("not an all-clear");
  });

  it("renders honest 'none in window' when the journal has history but nothing this window", () => {
    const { container } = render(<ActionView view={actionView({ "journal-empty": false })} />);
    expect(container.textContent).toContain("none in the last");
  });
});

describe("Action escaping", () => {
  it("renders an XSS verdict/prompt/entry as inert text", () => {
    window.__pwned = undefined;
    const XSS = '<img src=x onerror="window.__pwned=1">';
    const { container } = render(
      <ActionView
        view={actionView({
          "would-act": [wouldAct(XSS, { "last-verdict": XSS })],
          judgements: [judgement(XSS, { verdict: XSS, prompt: XSS, reply: XSS })],
        })}
      />,
    );
    openDetails(container.querySelector(".judgement-entry details.model-prompt"));
    expect(container.querySelector("img")).toBeNull();
    expect(window.__pwned).toBeUndefined();
    expect(container.textContent).toContain(XSS);
  });
});
