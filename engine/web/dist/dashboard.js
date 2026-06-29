// Protector dashboard — zero-dependency client script (served same-origin).
//
// Two jobs, both observational (the dashboard never acts):
//   1. Persist which finding rows are expanded across live-poll swaps, keyed by the finding id
//      (data-finding), so a refresh doesn't collapse what the operator opened. The whole
//      summary row is the toggle; the first cell's +/- button mirrors the open state.
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

  // Apply the open/closed state of one finding row to the DOM: toggle the row's `open` class
  // (CSS reveals the paired .row-detail), swap the +/- glyph, and keep aria-expanded honest.
  function applyState(row, isOpen) {
    if (isOpen) {
      row.classList.add("open");
    } else {
      row.classList.remove("open");
    }
    var btn = row.querySelector(".expander");
    if (btn) {
      btn.setAttribute("aria-expanded", isOpen ? "true" : "false");
      var glyph = btn.querySelector(".expander-glyph");
      if (glyph) {
        glyph.textContent = isOpen ? "−" : "+"; // − when open, + when closed
      }
    }
  }

  // Flip one row's expanded state, persist it, and reflect it in the DOM.
  function toggleRow(row) {
    var id = row.getAttribute("data-finding");
    if (!id) {
      return;
    }
    var nowOpen = !expanded.has(id);
    if (nowOpen) {
      expanded.add(id);
    } else {
      expanded.delete(id);
    }
    saveExpanded(expanded);
    applyState(row, nowOpen);
  }

  // Wire every summary row (tr.row[data-finding]) as a click/keyboard toggle for its detail row,
  // restoring the persisted open state on each (re)bind so a poll swap doesn't lose it.
  function bindDetails(root) {
    var rows = root.querySelectorAll("tr.row[data-finding]");
    for (var i = 0; i < rows.length; i++) {
      (function (row) {
        var id = row.getAttribute("data-finding");
        // Restore prior state on (re)bind.
        applyState(row, expanded.has(id));
        // The whole row is the toggle (the expander button lives inside it, so a click there
        // bubbles up to here too — one handler covers both).
        row.addEventListener("click", function () {
          toggleRow(row);
        });
        // Keyboard activation on the expander button (Enter/Space) goes through the click event
        // a <button> already synthesizes, so no extra keydown wiring is needed.
      })(rows[i]);
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
