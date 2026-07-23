// AuthGate + auth status-machine tests (JEF-489). Once OIDC is configured (JEF-487) the snapshot
// route can answer 401/403; the poll's `onAuthError` flips `App` into an auth state that REPLACES the
// privileged view with the interstitial. These drive `onAuthError` exactly as the real poll would
// (the poll is stubbed) and assert via the DOM — no internal state peeking.
//
// The load-bearing invariants pinned here:
//   - 401 mid-session REPLACES the view (never leaves it stale) and offers a full-page re-auth link;
//   - 401 on FIRST LOAD does not hang on "connecting…" (status set unconditionally — the silent-hang);
//   - 403 says "no access" with NO sign-in control (re-auth won't help);
//   - the interstitial is role="alert", focus moves to the heading, and the polite connection banner
//     is mutually exclusive with it.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, cleanup, act } from "@testing-library/preact";

// Capture the poll callbacks so a test can fire onAuthError / onSnapshot exactly like the poll does.
let lastOpts = null;
vi.mock("../src/poll.js", () => ({
  startPolling: (opts) => {
    lastOpts = opts;
    return () => {};
  },
}));
const { App } = await import("../src/app.jsx");

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
  lastOpts = null;
});

/** A minimal strip-props shape (the client only displays its tokens). */
const stripProps = (over = {}) => ({ "all-clear": false, "judging-state": "watching", ...over });
/** A findings snapshot carrying a strip (the shape every tab's payload has). */
const snapshot = (strip, over = {}) => ({ strip, findings: [], ...over });

function mount(initialTab = "findings") {
  const { container } = render(<App initialTab={initialTab} liveRegion={() => null} />);
  return container;
}

describe("AuthGate — unauthenticated (401)", () => {
  it("REPLACES the privileged view with 'your session expired' + a working full-page link", () => {
    const container = mount();
    // Go live first: the findings view renders.
    act(() => lastOpts.onSnapshot(snapshot(stripProps())));
    expect(container.querySelector(".view-findings")).toBeTruthy();

    // A 401 mid-session: the interstitial REPLACES the view (the privileged view is gone, not stale).
    act(() => lastOpts.onAuthError(401));
    expect(container.querySelector(".view-findings")).toBeNull();
    const gate = container.querySelector(".auth-gate");
    expect(gate).toBeTruthy();
    expect(gate.textContent).toContain("your session expired");

    // A working full-page "Sign in again" link — a real <a href> (never a fetch), same-origin.
    const link = gate.querySelector("a.auth-gate-signin");
    expect(link).toBeTruthy();
    expect(link.textContent).toContain("Sign in again");
    const href = link.getAttribute("href");
    expect(href).toBeTruthy();
    expect(href.startsWith("http")).toBe(false); // relative, same-origin — re-enters the doc flow
    // It is a plain anchor (no click handler intercepting): a full-page navigation, not an XHR.
    expect(link.tagName).toBe("A");
  });

  it("does NOT hang on 'connecting…' when the 401 lands on FIRST LOAD (status set unconditionally)", () => {
    const container = mount();
    // First-load banner is up, no snapshot has landed.
    expect(container.querySelector(".dash-conn-connecting")).toBeTruthy();

    // A 401 on the very first tick must flip to the interstitial — the silent-hang bug this fixes.
    act(() => lastOpts.onAuthError(401));
    expect(container.querySelector(".dash-conn-connecting")).toBeNull();
    expect(container.querySelector(".auth-gate")).toBeTruthy();
    expect(container.querySelector(".auth-gate").textContent).toContain("your session expired");
  });

  it("is role=alert and moves focus to the panel heading on transition", () => {
    const container = mount();
    act(() => lastOpts.onAuthError(401));
    const gate = container.querySelector(".auth-gate");
    expect(gate.getAttribute("role")).toBe("alert");
    // Focus lands on the heading (tabindex=-1) so a keyboard / screen-reader operator is taken to it.
    const head = gate.querySelector(".empty-head");
    expect(head.getAttribute("tabindex")).toBe("-1");
    expect(document.activeElement).toBe(head);
  });
});

describe("AuthGate — forbidden (403)", () => {
  it("says 'no access to this dashboard' with NO sign-in control", () => {
    const container = mount();
    act(() => lastOpts.onSnapshot(snapshot(stripProps())));
    act(() => lastOpts.onAuthError(403));

    const gate = container.querySelector(".auth-gate");
    expect(gate).toBeTruthy();
    expect(gate.textContent).toContain("no access to this dashboard");
    // 403 = signed in but not allowed — re-auth won't help, so there is NO sign-in control.
    expect(gate.querySelector("a.auth-gate-signin")).toBeNull();
    // The privileged view is still replaced.
    expect(container.querySelector(".view-findings")).toBeNull();
  });
});

describe("AuthGate — mutual exclusion with the connection banner", () => {
  it("never co-renders the polite stale/connecting banner while the interstitial is up", () => {
    const container = mount();
    act(() => lastOpts.onSnapshot(snapshot(stripProps())));
    // A stale tick would normally show the polite banner…
    act(() => lastOpts.onStale());
    expect(container.querySelector(".dash-conn-stale")).toBeTruthy();

    // …but once an auth error lands, the interstitial takes over and the banner is suppressed.
    act(() => lastOpts.onAuthError(401));
    expect(container.querySelector(".auth-gate")).toBeTruthy();
    expect(container.querySelector(".dash-conn-stale")).toBeNull();
    expect(container.querySelector(".dash-conn-connecting")).toBeNull();
    expect(container.querySelector(".dash-conn-msg")).toBeNull();
    // The persistent strip is held — the interstitial copy covers that it may be out of date.
    expect(container.querySelector(".strip")).toBeTruthy();
  });
});
