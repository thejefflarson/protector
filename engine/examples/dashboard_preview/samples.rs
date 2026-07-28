//! Sample model prompt/reply + the dev-livereload client (example-only).

/// The dev-only livereload client, appended to the served `dashboard.js`. It polls
/// `/dev/reload` ~once a second and reloads the page when the token changes. NEVER written to
/// the repo's `dashboard.js` — it lives only in the example's served response.
pub(crate) const DEV_LIVERELOAD_JS: &str = r#"
/* dashboard_preview dev-livereload — example-only, not part of dashboard.js */
(function () {
  var last = null;
  function poll() {
    fetch('/dev/reload', { cache: 'no-store' })
      .then(function (r) { return r.text(); })
      .then(function (token) {
        if (last === null) { last = token; return; }
        if (token !== last) { location.reload(); }
      })
      .catch(function () { /* server restarting — keep polling */ });
  }
  setInterval(poll, 1000);
  poll();
})();
"#;

/// A representative model prompt, so the "show model prompt" disclosure has real content.
pub(crate) const SAMPLE_PROMPT: &str = "\
DECISION PROCEDURE — adjudicate whether the proven attack path is EXPLOITABLE.

ENTRY: deployment/edge/api-gateway  (internet-facing front door: yes)
OBJECTIVE: secret/payments/stripe-live-key
PROVEN PATH:
  deployment/edge/api-gateway -[reaches/Tcp/5432]-> statefulset/payments/ledger-db
  statefulset/payments/ledger-db -[mounts]-> secret/payments/stripe-live-key

CVE EVIDENCE (severity/reachability input — not on its own the breach call):
  - CVE-2024-3094  critical  cvss 10.0  KEV: yes  EPSS 94%  reachability: loaded-at-runtime
    fix available: 5.6.0 to 5.6.1
    title: xz/liblzma backdoor — pre-auth RCE via sshd

RUNTIME EVIDENCE (live corroboration):
  - ALERT: Reverse shell spawned in container
  - exec: /bin/sh
  - connection: 185.220.101.4:9001 (internet)

Answer with one of: confirmed | exploitable | refuted | uncertain, then a one-line reason.";

/// The matching model reply.
pub(crate) const SAMPLE_REPLY: &str = "\
exploitable — the KEV-listed, runtime-loaded RCE plus the already-fired reverse shell make this \
a live path; the single Tcp/5432 edge to the ledger DB reaches the mounted live Stripe key. \
Propose the network cut.";
