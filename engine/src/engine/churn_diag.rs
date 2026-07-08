//! ADJ-MISS-DIAG — the per-re-judge churn-attribution diagnostic (JEF-387).
//!
//! Every cache MISS (an entry the engine is about to re-judge) emits ONE compact, structured
//! log line here. Over a 24h `kubectl logs` window `scripts/churn_analysis.py` ingests these
//! lines and attributes each re-judge to the EXACT prompt section that changed — with no
//! full-prompt dump and no fuzzy text-diffing.
//!
//! Line shape (tracing's default `key=value` field format, all values space-free):
//!
//! ```text
//! <ts>  INFO protector::engine::churn_diag: ADJ-MISS-DIAG entry=<key> fp=<hash> chain=<hash> \
//!   sec_runtime=<h> sec_cves=<h> sec_secrets=<h> sec_posture=<h> sec_objectives=<h> sec_entry=<h>
//! ```
//!
//! Field meanings the collector relies on:
//! - `entry`  — the entry key: the per-entry timeline key.
//! - `fp`     — the FULL-STATE prompt hash (the verdict-cache key; excludes the delta-only
//!   "Changes since…" section, JEF-391). UNCHANGED from the entry's prior line ⇒ an
//!   Uncertain-retry (JEF-234: model verdict churn, not prompt). CHANGED ⇒ state churn,
//!   attributed to whichever `sec_*` field moved.
//! - `chain`  — the objective/technique-SET shape hash: entries with the same shape group.
//! - `sec_*`  — the six per-section fingerprints; the one that changed between two consecutive
//!   lines for an entry IS the attributed cause.
//!
//! The heavy full-prompt dump stays available for spot-checks behind `PROTECTOR_ADJ_DIAG_FULL`
//! (any non-empty value) as a second `ADJ-MISS-DIAG-FULL` line — off by default.

use super::PendingEntry;

/// Emit the compact ADJ-MISS-DIAG line for one entry about to be re-judged, plus the optional
/// full-prompt dump when `PROTECTOR_ADJ_DIAG_FULL` is set. See the module docs for the format.
pub(super) fn log_rejudge(pending: &PendingEntry) {
    let sections = &pending.sections;
    tracing::info!(
        entry = %pending.entry_key,
        fp = %pending.fingerprint,
        chain = %pending.chain,
        sec_runtime = %sections.runtime,
        sec_cves = %sections.cves,
        sec_secrets = %sections.secrets,
        sec_posture = %sections.posture,
        sec_objectives = %sections.objectives,
        sec_entry = %sections.entry,
        "ADJ-MISS-DIAG"
    );
    if std::env::var_os("PROTECTOR_ADJ_DIAG_FULL").is_some_and(|v| !v.is_empty()) {
        tracing::info!(
            entry = %pending.entry_key,
            fp = %pending.fingerprint,
            prompt = ?pending.prompt,
            "ADJ-MISS-DIAG-FULL"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::NodeKey;
    use crate::engine::graph::attack::EXPLOIT_PUBLIC_FACING;
    use crate::engine::reason::adjudicate::PromptSections;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    /// A `MakeWriter` that captures the formatted log line into a shared buffer so the test
    /// can assert on the EXACT bytes the churn collector (`scripts/churn_analysis.py`) parses.
    #[derive(Clone)]
    struct BufWriter(Arc<Mutex<Vec<u8>>>);
    impl Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for BufWriter {
        type Writer = BufWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// JEF-387: the compact ADJ-MISS-DIAG line the collector depends on carries every field
    /// as space-free `key=value`. This LOCKS that contract — if the field set or a value's
    /// rendering changes, `scripts/churn_analysis.py` breaks, and this fails first.
    #[test]
    fn compact_line_carries_every_field_space_free() {
        let pending = PendingEntry {
            entry_key: "workload/app/Pod/web".into(),
            entry: NodeKey("workload/app/Pod/web".into()),
            objectives: vec![(
                NodeKey("secret/app/session-key".into()),
                EXPLOIT_PUBLIC_FACING,
            )],
            prompt: "unused in the compact line".into(),
            fingerprint: "fp123".into(),
            sections: PromptSections {
                runtime: "r1".into(),
                cves: "c1".into(),
                secrets: "s1".into(),
                posture: "p1".into(),
                objectives: "o1".into(),
                entry: "e1".into(),
            },
            chain: "ch1".into(),
            surface: crate::engine::reason::adjudicate::JudgedSurface::default(),
            idxs: vec![],
        };

        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(BufWriter(buf.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || log_rejudge(&pending));

        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(out.contains("ADJ-MISS-DIAG"), "marker missing: {out}");
        // Every field the collector reads, each as a space-free `key=value` token.
        for token in [
            "entry=workload/app/Pod/web",
            "fp=fp123",
            "chain=ch1",
            "sec_runtime=r1",
            "sec_cves=c1",
            "sec_secrets=s1",
            "sec_posture=p1",
            "sec_objectives=o1",
            "sec_entry=e1",
        ] {
            assert!(out.contains(token), "missing `{token}` in: {out}");
        }
    }
}
