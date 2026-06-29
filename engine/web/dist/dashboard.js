// Protector dashboard — zero-dependency client script (served same-origin).
//
// Two jobs, both observational (the dashboard never acts):
//   1. Persist which <details> "why" panels are expanded across live-poll swaps, keyed by the
//      finding id (data-finding), so a refresh doesn't collapse what the operator opened.
//   2. Poll /fragment for the active tab and swap the live region IN PLACE, preserving scroll
//      position, expansion state, and the current tab/filter query — so a model that just went
//      down flips the honest banner without the operator losing their place (design brief §7).
//
// No third-party code, no egress: it only talks to its own origin's /fragment.

(function () {
  "use strict";

  var LIVE_ID = "live";
  var POLL_MS = 5000;
  var STORE_KEY = "protector.expanded";

  // The set of expanded finding ids, persisted to sessionStorage so it survives a swap and a
  // soft reload but not a new session.
  function loadExpanded() {
    try {
      return new Set(JSON.parse(sessionStorage.getItem(STORE_KEY) || "[]"));
    } catch (e) {
      return new Set();
    }
  }
  function saveExpanded(set) {
    try {
      sessionStorage.setItem(STORE_KEY, JSON.stringify(Array.from(set)));
    } catch (e) {
      /* sessionStorage unavailable — degrade to in-memory only */
    }
  }

  var expanded = loadExpanded();

  // Wire every <details data-finding> to record its open/closed state on toggle.
  function bindDetails(root) {
    var nodes = root.querySelectorAll("details[data-finding]");
    for (var i = 0; i < nodes.length; i++) {
      (function (el) {
        var id = el.getAttribute("data-finding");
        // Restore prior state on (re)bind.
        if (expanded.has(id)) {
          el.open = true;
        }
        el.addEventListener("toggle", function () {
          if (el.open) {
            expanded.add(id);
          } else {
            expanded.delete(id);
          }
          saveExpanded(expanded);
          syncAria(el);
        });
        syncAria(el);
      })(nodes[i]);
    }
  }

  // Keep the summary's aria-expanded in sync with the details state (accessibility gate §6).
  function syncAria(details) {
    var summary = details.querySelector("summary");
    if (summary) {
      summary.setAttribute("aria-expanded", details.open ? "true" : "false");
    }
  }

  // The active tab's fragment URL, preserving the current query (tab/filter), so a poll stays
  // on the operator's view and is back-button correct.
  function fragmentUrl() {
    var params = window.location.search || "";
    return "/fragment" + params;
  }

  // Poll /fragment and swap the live region's inner HTML, preserving scroll + expansion.
  function poll() {
    fetch(fragmentUrl(), { headers: { "X-Requested-With": "fragment" } })
      .then(function (res) {
        if (!res.ok) {
          throw new Error("fragment " + res.status);
        }
        return res.text();
      })
      .then(function (html) {
        var live = document.getElementById(LIVE_ID);
        if (!live) {
          return;
        }
        var scrollY = window.scrollY;
        live.innerHTML = html;
        bindDetails(live);
        // Restore scroll — the swap reflows the list but the operator's position is kept.
        window.scrollTo(0, scrollY);
      })
      .catch(function () {
        // A failed poll (dashboard can't reach the engine, or a transient error) is left for
        // the next tick — the last good render stays. The honest banner will follow once a
        // fragment lands.
      });
  }

  function start() {
    var live = document.getElementById(LIVE_ID);
    if (live) {
      bindDetails(live);
    }
    window.setInterval(poll, POLL_MS);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
