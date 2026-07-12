// Dashboard v4 client entry (ADR-0025). Mounts the Preact app into the server-rendered mount point
// the page emits on EVERY tab (`<div id="dash-root" data-tab="…">`). The status strip above the
// mount stays SERVER-RENDERED, so the calm-when-blind first paint (and the honest banner) never
// depends on this JS running.
//
// The engine is Preact-only after the v4 cutover (JEF-398): every tab is client-rendered, so the
// client intercepts every tab-swap — there is no maud-vs-Preact special case.
//
// Zero-egress (ADR-0025): the ONLY network call is a same-origin fetch of the JSON snapshot
// (`/api/{tab}.json`), enforced by the CSP `connect-src 'self'`. Preact auto-escapes all
// interpolated text; the raw-HTML escape hatch is banned in src/ by a source guard (the JEF-396
// test). Mount only when the target exists, so the bundle is inert if the mount is absent.

import { render } from "preact";
import { Store } from "./store.js";
import { App } from "./app.jsx";

const root = document.getElementById("dash-root");
if (root) {
  // The server stamps the mounted tab via `data-tab` so the first paint's active tab matches the
  // document without waiting for the first fetch.
  const store = new Store({ activeTab: root.dataset.tab || "findings" });
  render(<App store={store} />, root);
}
