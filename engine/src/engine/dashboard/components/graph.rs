//! The attack-path graph component (JEF-205, ADR-0019): the Mermaid `flowchart` builder
//! and the `Markup` wrapper that emits the `<pre class="mermaid">` the client-side renderer
//! hydrates into an SVG.
//!
//! PRESENTATION ONLY: every function here is pure over plain strings (`&str`) — it imports
//! NO `engine::` domain type. The `graph_imports_no_engine_domain_type` test documents that
//! boundary (ADR-0019).
//!
//! ## The Mermaid XSS sink ([`mm`] before `PreEscaped`)
//!
//! The graph body is the ONE place the dashboard emits un-escaped markup
//! (`maud::PreEscaped`), because the Mermaid source is interpolated into a `<pre>` and then
//! re-parsed by the client renderer into `innerHTML`'d SVG (ADR-0019, the `PreEscaped`
//! allowlist, item 2). maud's HTML-escape does NOT replace [`mm`]'s stripping: maud only
//! escapes `< > &`, while a Mermaid label can be broken out of with a quote/backtick, and a
//! CR/LF would corrupt the line-oriented source. So every untrusted label is run through
//! [`mm`] FIRST (which strips `" \` \n \r < > &`), and only the [`mm`]-sanitized source is
//! wrapped in `PreEscaped`. [`mermaid_pre`] is the single chokepoint that enforces this
//! ordering — `mm()` first, then `PreEscaped`.

use maud::{Markup, PreEscaped, html};

/// Sanitize an untrusted label for the Mermaid source. Strips the characters that break a
/// Mermaid quoted label (`"` backtick CR LF) AND the HTML metacharacters `< > &` — the
/// source is interpolated into a `<pre>` and then re-parsed by the client renderer into
/// `innerHTML`'d SVG, so a label like `</pre><img onerror=…>` would otherwise be stored
/// XSS. Node keys/relations are RFC-1123-ish and never legitimately contain these, so
/// stripping is lossless for real data. This is the sole guard backing the Mermaid
/// `PreEscaped` allowance (ADR-0019).
pub fn mm(s: &str) -> String {
    s.replace(['"', '`', '\n', '\r', '<', '>', '&'], " ")
}

/// A short, human label for a node key — drop the kind prefix (`workload/`, …). Delegates
/// to [`NodeKey::short_of`] so the parsing lives in one place. Plain string in / out (no
/// engine domain type crosses the boundary).
pub fn short(key: &str) -> String {
    crate::engine::graph::NodeKey::short_of(key).to_string()
}

/// The node kind — the key's first path segment (`secret`, `capability`, …). Delegates to
/// [`NodeKey::kind_of`]; a keyless string has no kind prefix, so it falls back to `"node"`.
pub fn kind(key: &str) -> &str {
    match key.split_once('/') {
        Some(_) => crate::engine::graph::NodeKey::kind_of(key),
        None => "node",
    }
}

/// Mermaid node-shape delimiters by node kind (from the key prefix): secret = cylinder,
/// capability = hexagon, host = parallelogram, identity = stadium, else rectangle
/// (workload / image / endpoint).
pub fn shape(key: &str) -> (&'static str, &'static str) {
    match kind(key) {
        "secret" => ("[(", ")]"),
        "capability" => ("{{", "}}"),
        "host" => ("[/", "/]"),
        "identity" => ("([", "])"),
        _ => ("[", "]"),
    }
}

/// Accumulates a Mermaid `flowchart LR`: every distinct node key gets a stable synthetic id
/// (Mermaid ids must be identifier-safe), labeled with its short name and shaped by kind.
#[derive(Default)]
pub struct Mermaid {
    ids: std::collections::BTreeMap<String, String>,
    nodes: String,
    edges: String,
}

impl Mermaid {
    pub fn node(&mut self, key: &str) -> String {
        let label = short(key);
        self.node_labeled(key, &label)
    }

    /// Like [`node`](Self::node) but with an explicit label (the key still drives the shape
    /// + dedup identity). Used for aggregate fan-out nodes like "47 secrets".
    pub fn node_labeled(&mut self, key: &str, label: &str) -> String {
        if let Some(id) = self.ids.get(key) {
            return id.clone();
        }
        let id = format!("n{}", self.ids.len());
        let (open, close) = shape(key);
        self.nodes
            .push_str(&format!("  {id}{open}\"{}\"{close}\n", mm(label)));
        self.ids.insert(key.to_string(), id.clone());
        id
    }

    /// An edge to a node carrying an explicit label (for aggregate targets).
    pub fn edge_to_labeled(&mut self, from: &str, to_key: &str, to_label: &str, label: &str) {
        let a = self.node(from);
        let b = self.node_labeled(to_key, to_label);
        self.edges
            .push_str(&format!("  {a} -->|\"{}\"| {b}\n", mm(label)));
    }

    /// The fixed Internet source node (a circle), linked into `entry` with a bold arrow —
    /// the attacker's origin.
    pub fn add_internet(&mut self, entry: &str) {
        let net = self.ids.get("__internet__").cloned().unwrap_or_else(|| {
            let id = format!("n{}", self.ids.len());
            self.nodes.push_str(&format!("  {id}((\"Internet\"))\n"));
            self.ids.insert("__internet__".into(), id.clone());
            id
        });
        let to = self.node(entry);
        self.edges.push_str(&format!("  {net} ==> {to}\n"));
    }

    /// A labeled edge; `cut` draws it dashed (the severing action).
    pub fn edge(&mut self, from: &str, to: &str, label: &str, cut: bool) {
        let a = self.node(from);
        let b = self.node(to);
        let arrow = if cut { "-.->" } else { "-->" };
        self.edges
            .push_str(&format!("  {a} {arrow}|\"{}\"| {b}\n", mm(label)));
    }

    /// The finished Mermaid source. Every label it carries was [`mm`]-sanitized as it was
    /// added, so this string is the safe input to [`mermaid_pre`]'s `PreEscaped` wrap.
    pub fn finish(self) -> String {
        format!("flowchart LR\n{}{}", self.nodes, self.edges)
    }
}

/// The `<pre class="mermaid">` element the client hydrates into an SVG (JEF-205). `source`
/// is the [`Mermaid::finish`] output — already [`mm`]-sanitized — and `aria` is the words
/// summary applied to the rendered SVG by the page script via `data-aria`.
///
/// The body is `PreEscaped(source)`: the source is the dashboard's only sanctioned
/// un-escaped emission (ADR-0019 allowlist item 2), guarded by [`mm`] — `mm()` ran FIRST,
/// as each label was added, so the quote/backtick/CRLF stripping maud cannot do is already
/// applied. `aria` rides a normal auto-escaping maud brace (it is an attribute value, not
/// graph source), so an untrusted entry name in the aria summary is HTML-escaped.
pub fn mermaid_pre(source: &str, aria: &str) -> Markup {
    html! {
        pre class="mermaid" data-aria=(aria) { (PreEscaped(source.to_string())) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mm_strips_html_metacharacters_to_prevent_xss() {
        // A malicious label can't break out of the <pre> or inject into the SVG.
        let evil = mm("</pre><img src=x onerror=\"alert(1)\">&");
        for c in ['<', '>', '&', '"'] {
            assert!(!evil.contains(c), "mm must strip {c:?}");
        }
    }

    #[test]
    fn mermaid_pre_wraps_mm_sanitized_source_and_escapes_the_aria() {
        // The graph body is the mm()-sanitized source verbatim (PreEscaped), while the aria
        // attribute is auto-escaped by the maud brace (defence in depth on the attr value).
        let source = Mermaid::default().finish(); // "flowchart LR\n"
        let html = mermaid_pre(&source, "graph of \"web\" & <internet>").into_string();
        assert!(html.contains("flowchart LR"), "carries the graph source");
        // The aria value is HTML-escaped (a normal maud brace), so no raw markup survives.
        assert!(
            !html.contains("<internet>"),
            "aria value is escaped: {html}"
        );
        assert!(
            html.contains("&lt;internet&gt;"),
            "escaped aria form: {html}"
        );
        assert!(html.contains("&amp;"), "ampersand escaped in aria: {html}");
    }

    #[test]
    fn mermaid_pre_does_not_re_escape_the_graph_source() {
        // A source that legitimately contains nothing dangerous (mm() already stripped it)
        // is emitted verbatim — PreEscaped does not double-encode the flowchart syntax.
        let mut m = Mermaid::default();
        m.add_internet("workload/app/Pod/web");
        m.edge("workload/app/Pod/web", "secret/app/s", "mounts", false);
        let source = m.finish();
        let html = mermaid_pre(&source, "x").into_string();
        // The arrow/pipe Mermaid syntax survives intact (not entity-encoded).
        assert!(
            html.contains("-->|\"mounts\"|"),
            "graph syntax intact: {html}"
        );
        assert!(html.contains("==>"), "internet edge intact: {html}");
    }

    #[test]
    fn shape_picks_a_delimiter_per_node_kind() {
        assert_eq!(shape("secret/app/s"), ("[(", ")]"));
        assert_eq!(shape("capability/c"), ("{{", "}}"));
        assert_eq!(shape("workload/app/Pod/web"), ("[", "]"));
    }

    /// ADR-0019 boundary guard: the graph builder is pure over plain strings — no engine
    /// domain type crosses into the presentation layer.
    #[test]
    fn graph_imports_no_engine_domain_type() {
        let _: fn(&str, &str) -> Markup = mermaid_pre;
        let _: fn(&str) -> String = mm;
    }
}
