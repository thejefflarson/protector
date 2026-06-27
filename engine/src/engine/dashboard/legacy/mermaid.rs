//! Transitional legacy module (pre-ADR-0019 string-concat rendering).
//!
//! Migrated piecemeal in tickets 3–6; extracted here only so each file
//! stays under the 1,000-line cap (repo CLAUDE.md). New work goes in the
//! `components`/`view_model` maud layers, not here.
#![allow(dead_code)]

use super::*;

/// Minimal HTML escape for the few values that could contain markup-special chars.
pub(crate) fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A short, human label for a node key — drop the kind prefix (`workload/`, …).
/// Delegates to [`NodeKey::short_of`] so the parsing lives in one place.
pub(crate) fn short(key: &str) -> String {
    crate::engine::graph::NodeKey::short_of(key).to_string()
}

/// The node kind — the key's first path segment (`secret`, `capability`, …).
/// Delegates to [`NodeKey::kind_of`]; a keyless string has no kind prefix, so it
/// falls back to `"node"` (matching the prior behaviour).
pub(crate) fn kind(key: &str) -> &str {
    match key.split_once('/') {
        Some(_) => crate::engine::graph::NodeKey::kind_of(key),
        None => "node",
    }
}

/// Sanitize an untrusted label for the Mermaid source. Strips the characters that
/// break a Mermaid quoted label (`"` backtick CR LF) AND the HTML metacharacters
/// `< > &` — the source is interpolated into a `<pre>` and then re-parsed by the
/// client renderer into `innerHTML`'d SVG, so a label like `</pre><img onerror=…>`
/// would otherwise be stored XSS. Node keys/relations are RFC-1123-ish and never
/// legitimately contain these, so stripping is lossless for real data.
pub(crate) fn mm(s: &str) -> String {
    s.replace(['"', '`', '\n', '\r', '<', '>', '&'], " ")
}

/// Mermaid node-shape delimiters by node kind (from the key prefix): secret =
/// cylinder, capability = hexagon, host = parallelogram, identity = stadium, else
/// rectangle (workload / image / endpoint).
pub(crate) fn shape(key: &str) -> (&'static str, &'static str) {
    match kind(key) {
        "secret" => ("[(", ")]"),
        "capability" => ("{{", "}}"),
        "host" => ("[/", "/]"),
        "identity" => ("([", "])"),
        _ => ("[", "]"),
    }
}

/// Accumulates a Mermaid `flowchart LR`: every distinct node key gets a stable
/// synthetic id (Mermaid ids must be identifier-safe), labeled with its short name
/// and shaped by kind.
#[derive(Default)]
pub(crate) struct Mermaid {
    ids: BTreeMap<String, String>,
    nodes: String,
    edges: String,
}

impl Mermaid {
    pub(crate) fn node(&mut self, key: &str) -> String {
        let label = short(key);
        self.node_labeled(key, &label)
    }

    /// Like [`node`](Self::node) but with an explicit label (the key still drives the
    /// shape + dedup identity). Used for aggregate fan-out nodes like "47 secrets".
    pub(crate) fn node_labeled(&mut self, key: &str, label: &str) -> String {
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
    pub(crate) fn edge_to_labeled(
        &mut self,
        from: &str,
        to_key: &str,
        to_label: &str,
        label: &str,
    ) {
        let a = self.node(from);
        let b = self.node_labeled(to_key, to_label);
        self.edges
            .push_str(&format!("  {a} -->|\"{}\"| {b}\n", mm(label)));
    }

    /// The fixed Internet source node (a circle), linked into `entry` with a bold
    /// arrow — the attacker's origin.
    pub(crate) fn add_internet(&mut self, entry: &str) {
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
    pub(crate) fn edge(&mut self, from: &str, to: &str, label: &str, cut: bool) {
        let a = self.node(from);
        let b = self.node(to);
        let arrow = if cut { "-.->" } else { "-->" };
        self.edges
            .push_str(&format!("  {a} {arrow}|\"{}\"| {b}\n", mm(label)));
    }

    pub(crate) fn finish(self) -> String {
        format!("flowchart LR\n{}{}", self.nodes, self.edges)
    }
}
