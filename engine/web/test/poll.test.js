// Unit tests for the poll engine (ADR-0025 / JEF-397 / JEF-411): same-origin URL construction, the
// defer-apply-while-text-selection rule (ported from v3), and stale-not-blank on a failed poll. The
// poll takes plain `onSnapshot` / `onStale` callbacks now (no store dependency — JEF-411); tests
// spy those directly.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { snapshotUrl, startPolling, hasLiveSelection, POLL_MS } from "../src/poll.js";

describe("snapshotUrl", () => {
  it("is always a relative, same-origin path per tab", () => {
    expect(snapshotUrl("findings")).toBe("/api/findings.json");
    expect(snapshotUrl("alerts")).toBe("/api/alerts.json");
    expect(snapshotUrl("findings").startsWith("http")).toBe(false);
  });
});

/** A fetch stub returning one JSON payload, then holding. */
const okFetch = (payload) =>
  vi.fn().mockResolvedValue({ ok: true, json: async () => payload });

/** Run one immediate tick (the poll fetches once on start) with a never-firing interval. */
function startOnce(opts) {
  const noopInterval = () => 0;
  return startPolling({ setIntervalImpl: noopInterval, clearIntervalImpl: () => {}, ...opts });
}

describe("startPolling", () => {
  it("hands a fetched snapshot to onSnapshot (goes live), never onStale", async () => {
    const onSnapshot = vi.fn();
    const onStale = vi.fn();
    startOnce({
      tab: () => "findings",
      onSnapshot,
      onStale,
      liveRegion: () => null,
      fetchImpl: okFetch({ findings: [{ id: "a" }] }),
    });
    await vi.waitFor(() => expect(onSnapshot).toHaveBeenCalledTimes(1));
    expect(onSnapshot).toHaveBeenCalledWith({ findings: [{ id: "a" }] });
    expect(onStale).not.toHaveBeenCalled();
  });

  it("calls onStale (not onSnapshot) on a non-ok response", async () => {
    const onSnapshot = vi.fn();
    const onStale = vi.fn();
    startOnce({
      tab: () => "findings",
      onSnapshot,
      onStale,
      liveRegion: () => null,
      fetchImpl: vi.fn().mockResolvedValue({ ok: false, status: 503 }),
    });
    await vi.waitFor(() => expect(onStale).toHaveBeenCalledTimes(1));
    expect(onSnapshot).not.toHaveBeenCalled();
  });

  it("calls onStale on a thrown transport error", async () => {
    const onStale = vi.fn();
    startOnce({
      tab: () => "findings",
      onSnapshot: vi.fn(),
      onStale,
      liveRegion: () => null,
      fetchImpl: vi.fn().mockRejectedValue(new Error("offline")),
    });
    await vi.waitFor(() => expect(onStale).toHaveBeenCalledTimes(1));
  });

  // JEF-489: once OIDC is configured, /api/*.json answers 401/403 — a distinct signal from a stale
  // connection. The auth statuses route to onAuthError (with the code), NEVER onStale/onSnapshot.
  it("routes a 401 to onAuthError(401) — not onStale, not onSnapshot", async () => {
    const onStale = vi.fn();
    const onSnapshot = vi.fn();
    const onAuthError = vi.fn();
    startOnce({
      tab: () => "findings",
      onSnapshot,
      onStale,
      onAuthError,
      liveRegion: () => null,
      fetchImpl: vi.fn().mockResolvedValue({ ok: false, status: 401 }),
    });
    await vi.waitFor(() => expect(onAuthError).toHaveBeenCalledWith(401));
    expect(onStale).not.toHaveBeenCalled();
    expect(onSnapshot).not.toHaveBeenCalled();
  });

  it("routes a 403 to onAuthError(403) — not onStale, not onSnapshot", async () => {
    const onStale = vi.fn();
    const onAuthError = vi.fn();
    startOnce({
      tab: () => "findings",
      onSnapshot: vi.fn(),
      onStale,
      onAuthError,
      liveRegion: () => null,
      fetchImpl: vi.fn().mockResolvedValue({ ok: false, status: 403 }),
    });
    await vi.waitFor(() => expect(onAuthError).toHaveBeenCalledWith(403));
    expect(onStale).not.toHaveBeenCalled();
  });

  it("treats an opaque redirect (stray server 302 under redirect:manual) as a 401", async () => {
    const onStale = vi.fn();
    const onAuthError = vi.fn();
    const fetchImpl = vi.fn().mockResolvedValue({ type: "opaqueredirect", status: 0, ok: false });
    startOnce({
      tab: () => "findings",
      onSnapshot: vi.fn(),
      onStale,
      onAuthError,
      liveRegion: () => null,
      fetchImpl,
    });
    await vi.waitFor(() => expect(onAuthError).toHaveBeenCalledWith(401));
    expect(onStale).not.toHaveBeenCalled();
    // The fetch is made with redirect:"manual" so a 302 surfaces as an opaque redirect (not followed
    // — the CSP would block the IdP hop anyway) rather than a silent stale.
    expect(fetchImpl.mock.calls[0][1]).toMatchObject({ redirect: "manual" });
  });

  it("still routes a non-auth non-ok (503) to onStale — auth handling is 401/403 only", async () => {
    const onStale = vi.fn();
    const onAuthError = vi.fn();
    startOnce({
      tab: () => "findings",
      onSnapshot: vi.fn(),
      onStale,
      onAuthError,
      liveRegion: () => null,
      fetchImpl: vi.fn().mockResolvedValue({ ok: false, status: 503 }),
    });
    await vi.waitFor(() => expect(onStale).toHaveBeenCalledTimes(1));
    expect(onAuthError).not.toHaveBeenCalled();
  });

  it("DEFERS applying a snapshot while a selection is anchored in the live region", async () => {
    const onSnapshot = vi.fn();
    const onStale = vi.fn();
    const region = document.createElement("div");
    region.textContent = "some selectable model verdict";
    document.body.appendChild(region);

    // Anchor a real, non-collapsed selection inside the region.
    const range = document.createRange();
    range.selectNodeContents(region);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    expect(hasLiveSelection(region)).toBe(true);

    startOnce({
      tab: () => "findings",
      onSnapshot,
      onStale,
      liveRegion: () => region,
      fetchImpl: okFetch({ findings: [{ id: "x" }] }),
    });
    // The fetch resolves but the apply is deferred — neither callback fires (not live, not stale).
    await new Promise((r) => setTimeout(r, 5));
    expect(onSnapshot).not.toHaveBeenCalled();
    expect(onStale).not.toHaveBeenCalled();

    sel.removeAllRanges();
    document.body.removeChild(region);
  });
});

// JEF-408 regression: the DEFAULT setIntervalImpl must adapt native `setInterval` (whose signature
// is `(fn, ms)`) to the `(ms, fn)` shape this module calls it with. The pre-fix default passed native
// `setInterval` directly, so `setInterval(POLL_MS, tick)` handed the NUMBER 5000 as the handler — the
// recurring poll never fired (dead poll / blank tab-swaps) AND the browser coerced the number to the
// string "5000" and took the legacy string-handler eval path, which the strict CSP (`script-src
// 'self'`, no unsafe-eval) correctly BLOCKED. Both symptoms have the same root cause: reversed args.
describe("startPolling default interval (JEF-408 regression)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("re-fires the recurring poll MORE THAN ONCE with the DEFAULT setIntervalImpl", async () => {
    // No setIntervalImpl override — exercise the real default over fake timers. Pre-fix this ticked
    // exactly once (only the initial tick()); the recurring interval was dead.
    const fetchImpl = okFetch({ findings: [] });
    const stop = startPolling({
      tab: () => "findings",
      onSnapshot: () => {},
      onStale: () => {},
      liveRegion: () => null,
      fetchImpl,
    });
    // Initial tick fires synchronously on start.
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    // Advance three intervals — the recurring poll must fire each time.
    await vi.advanceTimersByTimeAsync(POLL_MS * 3);
    expect(fetchImpl.mock.calls.length).toBeGreaterThan(1);
    expect(fetchImpl.mock.calls.length).toBe(4); // 1 initial + 3 recurring
    stop();
  });

  it("hands native setInterval a FUNCTION handler (never a number/string — no eval)", () => {
    // Spy on the global the default closes over. The reversed-args bug passed POLL_MS (a number) as
    // the handler; coerced to the string "5000", native setInterval evals it — the CSP violation the
    // operator reported. Assert the FIRST arg to native setInterval is a function, not a number/string.
    const setIntervalSpy = vi.spyOn(globalThis, "setInterval");
    const stop = startPolling({
      tab: () => "findings",
      onSnapshot: () => {},
      onStale: () => {},
      liveRegion: () => null,
      fetchImpl: okFetch({ findings: [] }),
      // No setIntervalImpl override — the default adapter must call native setInterval as (fn, ms).
    });
    expect(setIntervalSpy).toHaveBeenCalledTimes(1);
    const [handler, delay] = setIntervalSpy.mock.calls[0];
    expect(typeof handler).toBe("function"); // never a number/string — no legacy string-eval path
    expect(delay).toBe(POLL_MS);
    stop();
    setIntervalSpy.mockRestore();
  });
});
