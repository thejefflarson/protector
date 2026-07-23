// Access view tests (JEF-490 / ADR-0031 §4): the tier chip carries colour + glyph + WORD (never
// colour alone; glyph aria-hidden); Section 2 is a real semantic <table> with headers; a raw pull
// row carries the loud keyline; untrusted identity/target strings render inert (escaped); and the
// empty state honestly distinguishes an in-memory (resets on restart) from a durable log.

import { describe, it, expect, beforeEach } from "vitest";
import { render, cleanup } from "@testing-library/preact";
import { AccessView } from "../src/access/view.jsx";
import { accessView, accessReveal, accessPull } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

describe("Access — your tier chip", () => {
  it("carries word + glyph (aria-hidden), never colour alone", () => {
    const { container } = render(
      <AccessView view={accessView({ tier: "raw", reveals: [accessReveal("raw", { held: true })] })} />,
    );
    // The caller's chip appears (in the section sub-line) with the WORD always present.
    const chip = container.querySelector(".access-tier-raw");
    expect(chip).toBeTruthy();
    expect(chip.querySelector(".access-tier-word").textContent).toBe("raw");
    // The glyph is decorative — aria-hidden so the WORD carries it for a screen reader.
    expect(chip.querySelector(".access-tier-glyph").getAttribute("aria-hidden")).toBe("true");
  });

  it("marks the tier the caller holds with a badge (not colour alone)", () => {
    const { container } = render(
      <AccessView
        view={accessView({
          tier: "forensic",
          reveals: [accessReveal("redacted", { held: true }), accessReveal("raw", { held: false })],
        })}
      />,
    );
    const held = container.querySelector('li[data-tier="redacted"]');
    expect(held.classList.contains("access-reveal-held")).toBe(true);
    expect(held.querySelector(".access-reveal-badge").textContent).toContain("your tier");
    const notHeld = container.querySelector('li[data-tier="raw"]');
    expect(notHeld.classList.contains("access-reveal-held")).toBe(false);
  });
});

describe("Access — the forensic/raw pulls table", () => {
  it("is a real <table> with column headers", () => {
    const { container } = render(<AccessView view={accessView({ pulls: [accessPull()] })} />);
    const table = container.querySelector("table.access-pulls");
    expect(table).toBeTruthy();
    const headers = [...table.querySelectorAll("thead th[scope=col]")].map((th) =>
      th.textContent.trim(),
    );
    expect(headers).toEqual(["when", "who", "tool", "tier", "target-class"]);
  });

  it("gives a raw pull row the loud keyline; a forensic row stays calm", () => {
    const { container } = render(
      <AccessView
        view={accessView({
          pulls: [
            accessPull({ raw: true, tier: "raw" }),
            accessPull({ raw: false, tier: "forensic", who: "bob@corp.example" }),
          ],
        })}
      />,
    );
    const rows = container.querySelectorAll("tr.access-pull-row");
    expect(rows[0].classList.contains("access-pull-raw")).toBe(true);
    expect(rows[1].classList.contains("access-pull-raw")).toBe(false);
  });

  it("renders an XSS-laden subject/target as inert text, never live HTML", () => {
    window.__pwned = undefined;
    const XSS = '<img src=x onerror="window.__pwned=1">';
    const { container } = render(
      <AccessView view={accessView({ pulls: [accessPull({ who: XSS, target: XSS })] })} />,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(window.__pwned).toBeUndefined();
    expect(container.textContent).toContain(XSS);
  });
});

describe("Access — honest empty state", () => {
  it("an in-memory log carries the resets-on-restart caveat (never 'nobody ever pulled')", () => {
    const { container } = render(<AccessView view={accessView({ pulls: [], durable: false })} />);
    expect(container.querySelector(".empty-access-calm")).toBeTruthy();
    expect(container.textContent).toContain("no forensic or raw pulls recorded");
    expect(container.textContent).toContain("resets on restart");
  });

  it("a durable log omits the resets caveat (the log is authoritative)", () => {
    const { container } = render(<AccessView view={accessView({ pulls: [], durable: true })} />);
    expect(container.querySelector(".empty-access-calm")).toBeTruthy();
    expect(container.textContent).toContain("no forensic or raw pulls recorded");
    expect(container.textContent).not.toContain("resets on restart");
  });
});
