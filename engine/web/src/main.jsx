// Dashboard v4 client entry (ADR-0025) — proof-of-life shell, NOT a real view yet.
//
// This is Foundation #2: it proves the whole pipeline end to end — esbuild bundles
// Preact from source, the engine serves the bundle same-origin via `include_str!`, the
// bundle mounts under a strict same-origin CSP, and it reconciles from the same-origin,
// read-only JSON snapshot (`/api/findings.json`, owned by JEF-395). The real keyed views
// land in later parts of the rewrite; here we only demonstrate mount + fetch + render.
//
// Zero-egress (ADR-0025): the ONLY network call is a same-origin fetch of the JSON
// snapshot. No CDN, no third-party origin — enforced by the CSP `connect-src 'self'` and
// the built-bundle guard. Preact auto-escapes all interpolated text; raw-HTML injection
// (the banned Preact escape hatch) is forbidden in src/ by a source guard.

import { render } from "preact";
import { Shell } from "./shell.jsx";

// The maud document keeps a server-rendered mount point (`div id="dash-root"`) inside the
// live region. If JS is disabled the server status strip still paints (ADR-0025 (d)); only
// this detailed shell needs the mount. Mount only when the target exists so the bundle is
// inert on any maud page that hasn't opted in yet.
const root = document.getElementById("dash-root");
if (root) {
  render(<Shell />, root);
}
