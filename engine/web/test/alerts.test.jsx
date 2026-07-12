// Alerts view tests (ADR-0025 / JEF-400): the content-hash reconcile key (an identical alarm
// persisting across passes does NOT flicker; a genuinely new alarm appears as a new node), the
// honesty states (LOUD blind caveat vs calm empty — SERVER-DERIVED, the client selects only), and
// escaping (an XSS payload in a signal/workload renders inert).

import { describe, it, expect, beforeEach } from "vitest";
import { render, cleanup, act } from "@testing-library/preact";
import { useState, useEffect } from "preact/hooks";
import { Store } from "../src/store.js";
import { AlertsView } from "../src/alerts/view.jsx";
import { alertKey } from "../src/keys.js";
import { alert, alertsView } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

/** A harness re-rendering the Alerts view whenever the store applies a new snapshot (a poll tick). */
function Harness({ store }) {
  const [, force] = useState(0);
  useEffect(() => store.subscribe(() => force((n) => n + 1)), [store]);
  const data = store.getState().data;
  return data ? <AlertsView view={data} /> : null;
}

describe("Alerts content-hash reconcile keying", () => {
  it("keeps an identical persisting alarm as the SAME node (no flicker) across a poll", () => {
    const store = new Store();
    const a = alert({ signal: "notable exec: bash", workload: "web" });
    store.applySnapshot(alertsView([a]));
    const { container } = render(<Harness store={store} />);

    const cardBefore = container.querySelector(".alert-card");
    expect(cardBefore).toBeTruthy();
    // Tag the node so we can prove it is the SAME DOM element after the poll (keyed reconcile).
    cardBefore.dataset.probe = "kept";

    // A new pass returns the SAME alarm (same kind/signal/workload/on-chain) → same content key.
    act(() => store.applySnapshot(alertsView([alert({ signal: "notable exec: bash", workload: "web" })])));

    const cardAfter = container.querySelector(".alert-card");
    expect(cardAfter.dataset.probe).toBe("kept"); // reconciled in place, not torn down
  });

  it("renders a genuinely new alarm as a NEW node", () => {
    const store = new Store();
    store.applySnapshot(alertsView([alert({ signal: "notable exec: bash" })]));
    const { container } = render(<Harness store={store} />);
    expect(container.querySelectorAll(".alert-card").length).toBe(1);

    // A different signal → a different content hash → a second, distinct node.
    act(() =>
      store.applySnapshot(
        alertsView([alert({ signal: "notable exec: bash" }), alert({ signal: "contacted cloud-metadata" })]),
      ),
    );
    expect(container.querySelectorAll(".alert-card").length).toBe(2);
  });

  it("derives distinct keys for distinct content and a stable key for identical content", () => {
    const a = alert({ kind: "exec", signal: "x", workload: "w", "on-chain": "c" });
    expect(alertKey(a)).toBe(alertKey({ ...a }));
    expect(alertKey(a)).not.toBe(alertKey({ ...a, signal: "y" }));
    // A null on-chain must not collide with a different-workload alarm (field separation).
    expect(alertKey({ ...a, "on-chain": null })).not.toBe(alertKey({ ...a, "on-chain": null, workload: "z" }));
  });
});

describe("Alerts honesty (server-derived tokens; client selects only)", () => {
  it("shows the LOUD blind caveat when the server ships a blind-caveat, never the calm copy", () => {
    const { container } = render(
      <AlertsView view={alertsView([], { blindCaveat: "node-2 has no live sensor" })} />,
    );
    const text = container.textContent;
    expect(text).toContain("quiet \u{2014} but partly blind");
    expect(text).toContain("node-2 has no live sensor");
    expect(text).not.toContain("no alarming activity right now");
  });

  it("shows the CALM empty ONLY when not blind", () => {
    const { container } = render(<AlertsView view={alertsView([], { blindCaveat: null })} />);
    const text = container.textContent;
    expect(text).toContain("no alarming activity right now");
    expect(text).not.toContain("partly blind");
  });

  it("always carries the evidence-not-verdict live note", () => {
    const { container } = render(<AlertsView view={alertsView([alert()])} />);
    expect(container.textContent).toContain("not a verdict");
  });
});

describe("Alerts escaping", () => {
  it("renders an XSS payload in a signal/workload as inert text", () => {
    window.__pwned = undefined;
    const XSS = '<img src=x onerror="window.__pwned=1">';
    const { container } = render(
      <AlertsView view={alertsView([alert({ signal: XSS, workload: XSS, "on-chain": XSS })])} />,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(window.__pwned).toBeUndefined();
    expect(container.textContent).toContain(XSS);
  });
});
