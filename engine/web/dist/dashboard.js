// protector dashboard — self-hosted page script (JEF-203).
//
// Extracted verbatim (behavior-identical) from the former inline <script type="module">
// in render_html. Now that this is a real .js module, ordinary `//` line comments are
// safe — the old inline form collapsed to one line, so a `//` would have commented out
// the rest of the page; that footgun is gone with the extraction.
//
// The graph renderer is beautiful-mermaid (ELK layout), vendored + bundled into web/dist
// and served SAME-ORIGIN at /assets — never a third-party CDN (zero egress).
import { renderMermaidSVG } from '/assets/beautiful-mermaid.js';

// Render one Mermaid <pre> into an SVG, carrying the path summary as the a11y label.
function renderPre(pre) {
  const aria = pre.getAttribute('data-aria');
  try {
    const svg = renderMermaidSVG(pre.textContent, { font: 'system-ui, sans-serif', accent: '#b00000', padding: 16, nodeSpacing: 28, layerSpacing: 52 });
    const g = document.createElement('div'); g.className = 'graph'; g.innerHTML = svg;
    const el = g.querySelector('svg') || g;
    el.setAttribute('role', 'img');
    if (aria) el.setAttribute('aria-label', aria);
    pre.replaceWith(g);
  } catch (e) { /* leave the source text as a fallback */ if (aria) { pre.setAttribute('role', 'img'); pre.setAttribute('aria-label', aria); } }
}

// A graph laid out inside a closed <details> OR a hidden row (display:none) measures
// to zero, so DEFER those to first reveal; render every visible graph immediately. A
// row's detail <tr> carries [hidden] until its row-toggle opens it, and a context row
// is hidden until its group opens, so a closest('[hidden]') ancestor defers too.
function hiddenAncestor(pre) { if (pre.closest('[hidden]')) return pre.closest('[hidden]'); let d = pre.closest('details'); while (d) { if (!d.open) return d; d = d.parentElement && d.parentElement.closest('details'); } return null; }

// A STABLE key for a <details> so its open/closed state can survive an incremental
// swap: the <summary> text plus its index among same-text siblings. Card content
// is stable pass-to-pass, so the same card maps to the same key.
function detailsKey(d) {
  const s = d.querySelector(':scope > summary');
  const label = (s ? s.textContent : '').replace(/\s+/g, ' ').trim().slice(0, 80);
  let n = 0; for (let p = d.previousElementSibling; p; p = p.previousElementSibling) {
    if (p.tagName === 'DETAILS' && p.querySelector(':scope > summary') && p.querySelector(':scope > summary').textContent.replace(/\s+/g, ' ').trim().slice(0, 80) === label) n++;
  }
  return 'det:' + label + '#' + n;
}
function saveDetails(d) { try { localStorage.setItem(detailsKey(d), d.open ? '1' : '0'); } catch (e) {} }
function restoreDetails(root) { for (const d of root.querySelectorAll('details')) { let v = null; try { v = localStorage.getItem(detailsKey(d)); } catch (e) {} if (v === '1') d.open = true; else if (v === '0') d.open = false; } }

// The dense findings table's row-expand is a <button aria-controls> (a bare <details>
// wrapping a <tr> is invalid table markup), so it gets its OWN persistence keyed by the
// STABLE aria-controls id (derived from the entry key, so the same endpoint maps to the
// same key pass-to-pass and survives the /fragment swap). A context group toggles every
// .ctx-row in its table at once.
function rowKey(btn) { return 'row:' + (btn.getAttribute('aria-controls') || btn.getAttribute('data-ctx-group') || ''); }
function renderIn(el) { for (const pre of el.querySelectorAll('pre.mermaid')) { if (!hiddenAncestor(pre)) renderPre(pre); } }
function setRow(btn, open) {
  btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  if (btn.classList.contains('ctx-toggle')) {
    const tbl = btn.closest('table'); if (tbl) for (const r of tbl.querySelectorAll('tr.ctx-row')) r.hidden = !open;
  } else {
    const id = btn.getAttribute('aria-controls'); const detail = id && document.getElementById(id);
    if (detail) { detail.hidden = !open; if (open) renderIn(detail); }
  }
  try { localStorage.setItem(rowKey(btn), open ? '1' : '0'); } catch (e) {}
}
function restoreRows(root) { for (const btn of root.querySelectorAll('button.row-toggle')) { let v = null; try { v = localStorage.getItem(rowKey(btn)); } catch (e) {} if (v === '1') setRow(btn, true); else if (v === '0') setRow(btn, false); } }

// (Re)hydrate a subtree: render visible graphs now, defer hidden ones to first reveal,
// persist <details> AND row-toggle state, and re-render any graph revealed by opening.
// Idempotent and scoped to `root` so it can run on load AND after each incremental swap
// without double-wiring (swapped nodes are fresh; their old listeners are discarded).
function hydrate(root) {
  for (const pre of root.querySelectorAll('pre.mermaid')) { if (!hiddenAncestor(pre)) renderPre(pre); }
  for (const d of root.querySelectorAll('details')) {
    d.addEventListener('toggle', () => { saveDetails(d); if (!d.open) return; for (const pre of d.querySelectorAll('pre.mermaid')) { if (!hiddenAncestor(pre)) renderPre(pre); } });
  }
  for (const btn of root.querySelectorAll('button.row-toggle')) {
    btn.addEventListener('click', () => { setRow(btn, btn.getAttribute('aria-expanded') !== 'true'); });
  }
}
restoreDetails(document); restoreRows(document); hydrate(document);

// Incremental refresh: replaces the old 30s full-page reload, which reset
// scroll, focus, and every <details>. Poll the SAME-ORIGIN `/fragment` (zero new
// egress) and swap ONLY the banner + findings region; restore <details> open-state
// from localStorage, re-hydrate Mermaid for the new DOM, and keep scroll + focus.
async function poll() {
  let html; try { const r = await fetch('/fragment', { headers: { 'Accept': 'text/html' } }); if (!r.ok) return; html = await r.text(); } catch (e) { return; }
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const focusKey = (() => { const a = document.activeElement; if (!a) return null; if (a.classList && a.classList.contains('row-toggle')) return rowKey(a); const d = a.closest && a.closest('details'); return (a.tagName === 'SUMMARY' && d) ? detailsKey(d) : null; })();
  const sx = window.scrollX, sy = window.scrollY;
  for (const id of ['banner-region', 'findings-region']) {
    const cur = document.getElementById(id), next = doc.getElementById(id);
    if (cur && next) cur.replaceWith(next);
  }
  const region = document.getElementById('findings-region');
  if (region) { restoreDetails(region); restoreRows(region); hydrate(region); }
  if (focusKey && region) { for (const b of region.querySelectorAll('button.row-toggle')) { if (rowKey(b) === focusKey) { b.focus({ preventScroll: true }); break; } } for (const d of region.querySelectorAll('details')) { if (detailsKey(d) === focusKey) { const s = d.querySelector(':scope > summary'); if (s) s.focus({ preventScroll: true }); break; } } }
  window.scrollTo(sx, sy);
}
setInterval(poll, 30000);
