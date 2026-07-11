// The proof-of-life shell component (ADR-0025) — mounts, fetches the same-origin JSON
// snapshot, and renders one value. It tolerates the snapshot endpoint (JEF-395) not being
// merged yet: a 404 (or any fetch failure) renders "connecting…" rather than throwing, so
// the pipeline proof stands whether or not `/api/findings.json` exists.
//
// The client performs NO honesty derivation (ADR-0025): it displays a count the server
// already computed. It never recomputes "is this green?" — that stays in the tested
// props layer. This shell only proves the transport; the real keyed views land later.

import { useEffect, useState } from "preact/hooks";

// The same-origin snapshot the client reconciles from (JEF-395 owns the route). Relative,
// so it is always same-origin — the CSP `connect-src 'self'` forbids anything else.
const SNAPSHOT_URL = "/api/findings.json";

/**
 * @typedef {"loading" | "ready" | "unavailable"} Phase
 */

export function Shell() {
  const [phase, setPhase] = useState(/** @type {Phase} */ ("loading"));
  const [count, setCount] = useState(0);

  useEffect(() => {
    let live = true;
    fetch(SNAPSHOT_URL, { headers: { accept: "application/json" } })
      .then((res) => (res.ok ? res.json() : Promise.reject(res.status)))
      .then((snapshot) => {
        if (!live) return;
        // Read whatever count the server shipped; default to 0 if the shape isn't final
        // yet (this is a transport proof, not the real view).
        const findings = Array.isArray(snapshot?.findings) ? snapshot.findings : [];
        setCount(findings.length);
        setPhase("ready");
      })
      .catch(() => {
        // 404 (endpoint not merged yet) or any transport failure: stay calm, don't throw.
        if (live) setPhase("unavailable");
      });
    return () => {
      live = false;
    };
  }, []);

  return (
    <div class="dash-shell" data-phase={phase}>
      {phase === "loading" && <p class="dash-shell-status">connecting…</p>}
      {phase === "unavailable" && (
        <p class="dash-shell-status">connecting… (snapshot unavailable)</p>
      )}
      {phase === "ready" && (
        <p class="dash-shell-status">
          dashboard v4 client mounted — {count} finding{count === 1 ? "" : "s"} in snapshot
        </p>
      )}
    </div>
  );
}
