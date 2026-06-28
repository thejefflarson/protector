// protector dashboard — self-hosted page script (JEF-203, rewritten for the v2 single-page
// dashboard, JEF-255).
//
// The v1 client-side graph-renderer hydrate path is GONE — the attack path is rendered
// server-side as a text hop-list now, so there is no third-party graph bundle to load (the
// 1.5 MB vendored renderer was retired). This module is just three behaviors, all same-origin
// (zero egress): persist <details> open-state, expand/collapse a dense table row, and poll the
// #live region for an incremental refresh that preserves scroll, focus, and open-state.

// A STABLE key for a <details> so its open/closed state survives an incremental swap: the
// <summary> text plus its index among same-text siblings. Content is stable pass-to-pass, so
// the same disclosure maps to the same key.
function detailsKey(d) {
  const s = d.querySelector(':scope > summary');
  const label = (s ? s.textContent : '').replace(/\s+/g, ' ').trim().slice(0, 80);
  let n = 0;
  for (let p = d.previousElementSibling; p; p = p.previousElementSibling) {
    if (p.tagName === 'DETAILS' && p.querySelector(':scope > summary')
      && p.querySelector(':scope > summary').textContent.replace(/\s+/g, ' ').trim().slice(0, 80) === label) n++;
  }
  return 'det:' + label + '#' + n;
}
function saveDetails(d) { try { localStorage.setItem(detailsKey(d), d.open ? '1' : '0'); } catch (e) {} }
function restoreDetails(root) {
  for (const d of root.querySelectorAll('details')) {
    let v = null; try { v = localStorage.getItem(detailsKey(d)); } catch (e) {}
    if (v === '1') d.open = true; else if (v === '0') d.open = false;
  }
}

// The dense endpoints table's row-expand is a <button aria-controls> over a hidden detail <tr>
// (a bare <details> wrapping a <tr> is invalid table markup), keyed by the STABLE aria-controls
// id (derived from the entry key, so the same endpoint maps to the same key pass-to-pass and
// survives the /fragment swap).
function rowKey(btn) { return 'row:' + (btn.getAttribute('aria-controls') || ''); }
function setRow(btn, open) {
  btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  const id = btn.getAttribute('aria-controls');
  const detail = id && document.getElementById(id);
  if (detail) detail.hidden = !open;
  try { localStorage.setItem(rowKey(btn), open ? '1' : '0'); } catch (e) {}
}
function restoreRows(root) {
  for (const btn of root.querySelectorAll('button.row-toggle')) {
    let v = null; try { v = localStorage.getItem(rowKey(btn)); } catch (e) {}
    if (v === '1') setRow(btn, true); else if (v === '0') setRow(btn, false);
  }
}

// (Re)wire a subtree: persist <details> AND row-toggle state. Idempotent and scoped to `root`
// so it runs on load AND after each incremental swap without double-wiring (swapped nodes are
// fresh; their old listeners are discarded with the replaced DOM).
function hydrate(root) {
  for (const d of root.querySelectorAll('details')) {
    d.addEventListener('toggle', () => saveDetails(d));
  }
  for (const btn of root.querySelectorAll('button.row-toggle')) {
    btn.addEventListener('click', () => setRow(btn, btn.getAttribute('aria-expanded') !== 'true'));
  }
}
restoreDetails(document); restoreRows(document); hydrate(document);

// Incremental refresh: poll the SAME-ORIGIN /fragment (zero new egress) and swap ONLY the
// #live region; restore <details> + row open-state from localStorage, re-wire the new DOM, and
// keep scroll + focus.
async function poll() {
  let html;
  try {
    const r = await fetch('/fragment', { headers: { 'Accept': 'text/html' } });
    if (!r.ok) return; html = await r.text();
  } catch (e) { return; }
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const focusKey = (() => {
    const a = document.activeElement; if (!a) return null;
    if (a.classList && a.classList.contains('row-toggle')) return rowKey(a);
    const d = a.closest && a.closest('details');
    return (a.tagName === 'SUMMARY' && d) ? detailsKey(d) : null;
  })();
  const sx = window.scrollX, sy = window.scrollY;
  const cur = document.getElementById('live'), next = doc.getElementById('live');
  if (cur && next) cur.replaceWith(next);
  const region = document.getElementById('live');
  if (region) { restoreDetails(region); restoreRows(region); hydrate(region); }
  if (focusKey && region) {
    for (const b of region.querySelectorAll('button.row-toggle')) {
      if (rowKey(b) === focusKey) { b.focus({ preventScroll: true }); break; }
    }
    for (const d of region.querySelectorAll('details')) {
      if (detailsKey(d) === focusKey) {
        const s = d.querySelector(':scope > summary'); if (s) s.focus({ preventScroll: true }); break;
      }
    }
  }
  window.scrollTo(sx, sy);
}
setInterval(poll, 30000);
