// App-shell tab-swap refetch test (JEF-408 / JEF-411): a client tab-swap must trigger an IMMEDIATE
// refetch of the new tab, not wait up to POLL_MS for the next interval (which left the swapped-to
// view blank). The App restarts the poll when `activeTab` changes; startPolling fetches once
// synchronously on start, so a restart == an immediate refetch. This would FAIL if the effect did
// not key on `activeTab` (the poll would never restart, so the swap would wait for the stale
// interval).

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, fireEvent, cleanup, act } from "@testing-library/preact";

// Spy the real startPolling so we can count restarts, assert the tab it repoints to, AND capture the
// onSnapshot callback (to drive a same-tab snapshot), without firing real intervals. Each call
// records the tab getter + opts; the returned stop is a no-op.
const startCalls = [];
let lastOpts = null;
vi.mock("../src/poll.js", () => ({
  startPolling: (opts) => {
    startCalls.push(opts.tab());
    lastOpts = opts;
    return () => {};
  },
}));
const { App } = await import("../src/app.jsx");

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
  startCalls.length = 0;
  lastOpts = null;
});

describe("tab-swap immediate refetch (JEF-408)", () => {
  it("restarts the poll (repointed to the new tab) on a client swap", () => {
    const { container } = render(<App initialTab="findings" liveRegion={() => null} />);

    // Mounted once, polling findings.
    expect(startCalls).toEqual(["findings"]);

    // Swap to Alerts — the effect re-runs because activeTab changed, restarting the poll on alerts
    // (an immediate refetch), rather than leaving the alerts view blank until the next interval.
    const link = container.querySelector('a.tab[href="/?tab=alerts"]');
    fireEvent.click(link);
    expect(container.querySelector('a.tab[href="/?tab=alerts"]').getAttribute("aria-current")).toBe(
      "page",
    );
    expect(startCalls).toContain("alerts");
    expect(startCalls.length).toBeGreaterThan(1);
  });

  it("does not restart the poll when a fresh snapshot lands on the SAME tab", () => {
    render(<App initialTab="findings" liveRegion={() => null} />);
    expect(startCalls).toEqual(["findings"]);

    // A new snapshot on the SAME tab must NOT restart the poll — that would refetch on every tick.
    // The effect keys on activeTab (unchanged) + memoized callbacks, so applying a snapshot (which
    // only moves data/strip/status/lastGoodAt) does not re-run the poll effect.
    act(() => lastOpts.onSnapshot({ strip: { "all-clear": false }, findings: [] }));
    expect(startCalls).toEqual(["findings"]);
  });
});
