//! The breach notifier (JEF-144): the **one** sanctioned outbound path (ADR-0018).
//!
//! Surfacing is otherwise pull-only — a breach decision lands in the findings snapshot and the
//! durable journal ([`super::journal`]), but a solo operator never *learns* of it
//! unless actively reading that state. This notifier POSTs a breach decision to an
//! operator-configured URL (`PROTECTOR_ENGINE_NOTIFY_URL`) — the outbound inverse of the
//! behavioral ingest — documented to target an in-cluster sink (Alertmanager /
//! ntfy / gotify).
//!
//! Posture, per ADR-0018:
//! - **Off by default.** Unset/empty URL ⇒ a disabled notifier whose `notify` is a
//!   no-op and which makes ZERO outbound calls — behaviour is byte-identical to today.
//!   There is no default sink and no hosted phone-home target.
//! - **Redacted by default.** The payload carries only the *decision summary*: the
//!   decision (verdict kind), the entry workload (a workload key — not a secret), the
//!   ATT&CK outcome (the distinct tactic/technique IDs reached + an objective COUNT),
//!   the sanitized verdict text, and the enforcement posture. It NEVER carries the full
//!   topology, secret names, the peer-by-peer reachability graph, or the CVE inventory.
//!   Richer detail (the per-objective ATT&CK list) is gated behind an explicit opt-in
//!   (`PROTECTOR_ENGINE_NOTIFY_VERBOSE`) and still excludes secrets/peers/CVEs.
//! - **Verdict prose is sanitized before egress.** The verdict text can carry untrusted
//!   third-party text (trivy's CVE title, JEF-66); it is run through
//!   [`super::reason::adjudicate::sanitize`] before it leaves the cluster.
//! - **Deduped on the decision identity** (the journal's, JEF-141): the caller fires
//!   this only when it appends a *new* breach line, so one decision is one notification.
//! - **Shadow vs armed is explicit:** "would isolate" (shadow) vs "isolated" (armed).
//! - **Bounded + fail-safe.** Reuses the timeout-only client from [`super::model`] (never
//!   an unbounded `reqwest::Client::new()`), so a hung sink can't stall the engine loop;
//!   a POST failure is logged once and dropped — it never touches a verdict or actuation.

use serde_json::{Value, json};

use super::graph::attack::AttackRef;
use super::reason::adjudicate::Verdict;
// The redaction primitives are shared with the read-only MCP server (ADR-0031); they live in
// `super::redact` so the two egress paths cannot drift in what they consider safe to emit.
use super::redact::{redacted_attack_outcome, sanitize, scrub_cve_tokens, scrub_decision_names};

/// Total timeout (seconds) for one notification POST. Short by design: this is a
/// fire-and-forget alert, not a request whose answer we need, so it must give up fast
/// rather than risk holding up the (single) engine loop on a slow sink. Overridable via
/// `PROTECTOR_ENGINE_NOTIFY_TIMEOUT_SECS`.
const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Hard cap on distinct ATT&CK references surfaced in the redacted payload. The set is
/// already low-cardinality (the handful of tactics protector models), but a cap bounds
/// the payload regardless and keeps the redacted summary a summary.
const ATTACK_CAP: usize = 16;

/// Whether protector acted on the decision or only would have — the shadow-vs-armed
/// distinction ADR-0018 requires to be unambiguous in the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// An action class is armed: a confirming breach decision isolates the workload.
    Armed,
    /// Default posture: nothing is armed, so protector only *would* isolate.
    Shadow,
}

impl Enforcement {
    /// `Armed` when any action class is enabled, else `Shadow`. The same `armed` flag the
    /// readiness aggregation reports as arm-state drives the notifier wording.
    pub fn from_armed(armed: bool) -> Self {
        if armed { Self::Armed } else { Self::Shadow }
    }

    /// The unambiguous verb for the message: "isolated" (acted) vs "would isolate".
    fn action_phrase(self) -> &'static str {
        match self {
            Enforcement::Armed => "isolated",
            Enforcement::Shadow => "would isolate",
        }
    }

    /// A stable, low-cardinality posture tag for the structured payload.
    fn label(self) -> &'static str {
        match self {
            Enforcement::Armed => "armed",
            Enforcement::Shadow => "shadow",
        }
    }
}

/// One breach decision to notify on — the *inputs* to redaction, assembled by the engine
/// at the point it journals a new breach line. Holds borrowed slices so the engine builds
/// it without cloning the whole subgraph; redaction extracts only the summary fields.
pub struct BreachNotice<'a> {
    /// The internet-facing entry that was judged (a workload key — not a secret).
    pub entry: &'a str,
    /// The model's verdict for this entry.
    pub verdict: &'a Verdict,
    /// The (objective, technique) set this entry reaches. Used ONLY for the objective
    /// COUNT and the distinct ATT&CK outcome — the per-objective *targets* (secret names,
    /// peer nodes) are never surfaced in the redacted payload.
    pub objectives: &'a [(super::graph::NodeKey, AttackRef)],
    /// Whether an action class is armed (drives shadow-vs-armed wording).
    pub enforcement: Enforcement,
}

/// Which runtime-coverage transition to notify on (JEF-427). The counts-only operator push that
/// fires when protector's OWN runtime sensors collapse (a was-covering fleet goes fully dark past
/// the debounce) or recover — the gap the breach notifier can't cover (it fires only on breach
/// *decisions*, and a blind engine makes none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageEvent {
    /// A was-covering runtime fleet has gone fully blind past the stall debounce (JEF-421). One push.
    Degraded,
    /// A previously stalled runtime fleet is reporting again. One push.
    Restored,
}

/// One runtime-coverage transition to notify on (JEF-427) — the inputs to the counts-only redacted
/// push. UNLIKE [`BreachNotice`], this carries NO cluster-derived strings at all: the feed label is
/// our own `'static` constant and everything else is a COUNT, so there is no topology, secret, peer,
/// or CVE surface to redact — the ADR-0018 posture is upheld by construction.
pub struct CoverageNotice {
    /// Whether the fleet just went dark or just recovered.
    pub event: CoverageEvent,
    /// Expected sensor-node count (M) — the size of the runtime fleet in scope this pass.
    pub expected: usize,
    /// Blind node count (N). Equals `expected` at a full collapse; `< expected` on recovery.
    pub blind: usize,
    /// A coarse "N ago" for when the fleet was last observed live — surfaced on `Degraded` only.
    pub last_observation: Option<String>,
}

impl From<super::state::CoverageEdge> for CoverageNotice {
    /// Map the cross-pass coverage transition (JEF-421 edge) onto the redaction inputs: a collapse
    /// → `Degraded` (carrying the last-observed time), a recovery → `Restored`.
    fn from(edge: super::state::CoverageEdge) -> Self {
        use super::state::CoverageEdge;
        match edge {
            CoverageEdge::Collapsed {
                blind,
                expected,
                last_observation,
            } => Self {
                event: CoverageEvent::Degraded,
                expected,
                blind,
                last_observation,
            },
            CoverageEdge::Recovered { blind, expected } => Self {
                event: CoverageEvent::Restored,
                expected,
                blind,
                last_observation: None,
            },
        }
    }
}

/// Build the **redacted** JSON payload for a runtime-coverage transition (JEF-427). Counts only —
/// no node names, no topology, no secrets, no CVEs — so it is redacted by construction (there is no
/// untrusted cluster string in it to sanitize). Pure and unit-tested for a stable wire shape.
pub fn redacted_coverage_payload(notice: &CoverageNotice) -> Value {
    let (event, message) = match notice.event {
        CoverageEvent::Degraded => (
            "runtime_coverage_degraded",
            format!(
                "protector runtime coverage degraded — {} of {} sensor node{} blind (protector's own sensors went dark; paths on these nodes are no longer watched)",
                notice.blind,
                notice.expected,
                if notice.expected == 1 { "" } else { "s" },
            ),
        ),
        CoverageEvent::Restored => (
            "runtime_coverage_restored",
            format!(
                "protector runtime coverage restored — {} of {} sensor node{} reporting again",
                notice.expected.saturating_sub(notice.blind),
                notice.expected,
                if notice.expected == 1 { "" } else { "s" },
            ),
        ),
    };
    let mut payload = json!({
        // A stable, low-cardinality event tag — never free text.
        "event": event,
        // The feed this concerns — our own constant, mirrors the strip's `Runtime` chip.
        "feed": "Runtime",
        // Counts only: how many of how many expected sensor nodes are blind.
        "blind": notice.blind,
        "expected": notice.expected,
        // A ready-to-read line for a human sink (ntfy/gotify).
        "message": message,
    });
    // Only meaningful for the degradation event — when the fleet was last live.
    if notice.event == CoverageEvent::Degraded
        && let Some(last) = &notice.last_observation
    {
        payload["last_observation"] = json!(last);
    }
    payload
}

/// Build the **redacted** JSON payload for a breach decision (ADR-0018 §2). Pure and
/// unit-tested: given the decision, it surfaces the decision summary ONLY — never the
/// topology, secret names, the peer graph, or the CVE list. `verbose` adds the
/// per-objective ATT&CK list (still no secrets/peers/CVEs); the default is the summary.
///
/// The verdict text is sanitized ([`sanitize`]) before it lands in the payload, so
/// untrusted third-party prose (trivy's CVE title, JEF-66) can't smuggle structure into the
/// sink.
pub fn redacted_payload(notice: &BreachNotice<'_>, verbose: bool) -> Value {
    // Distinct ATT&CK references reached — the "outcome" as low-cardinality IDs, never the
    // per-objective targets (the shared counts-only reducer, ADR-0031 §2).
    let attack_outcome = redacted_attack_outcome(
        notice.objectives.iter().map(|(_objective, a)| a),
        ATTACK_CAP,
    );

    // The verdict text can carry untrusted third-party prose (trivy's CVE title, JEF-66) —
    // sanitize it before egress so it's inert data in the operator's sink. `sanitize` strips
    // STRUCTURE (fences/braces) but not SEMANTICS: the model can echo a secret/peer name
    // or a CVE id it was shown into its free-text reason, which would then egress around
    // the ADR-0018 redaction. So also scrub those names/tokens out (Fix 6), composing the
    // shared name + CVE scrubbers exactly as the MCP `redacted` tier does.
    let verdict_text = scrub_cve_tokens(&scrub_decision_names(
        &sanitize(&notice.verdict.summary()),
        &decision_names(notice),
    ));

    let mut payload = json!({
        // The decision kind — a stable, low-cardinality label, never free text.
        "decision": notice.verdict.label(),
        // The internet-facing front door's workload identity. A workload key, NOT a secret.
        "entry": sanitize(notice.entry),
        // The ATT&CK outcome: distinct tactic/technique IDs reached.
        "attack": attack_outcome,
        // A COUNT of objectives reached — never the per-objective targets (which would
        // name secrets / peer nodes). Breadth without the crown-jewel inventory.
        "objectives_reached": notice.objectives.len(),
        // The model's one-line reason, sanitized.
        "verdict": verdict_text,
        // Shadow vs armed, both as a stable tag and in the human message.
        "enforcement": notice.enforcement.label(),
        // A ready-to-read line for a human sink (ntfy/gotify), unambiguous on action.
        "message": format!(
            "protector {} {} ({})",
            notice.enforcement.action_phrase(),
            sanitize(notice.entry),
            verdict_text,
        ),
    });

    // The explicit opt-in (ADR-0018 §2): add the per-objective ATT&CK list. This is the
    // techniques reached, NOT the objective targets — still no secret names, no peer
    // graph, no CVE list. Bounded by the same ATT&CK cap.
    if verbose {
        let per_objective: Vec<Value> = notice
            .objectives
            .iter()
            .take(ATTACK_CAP)
            .map(|(_objective, a)| {
                json!({
                    "tactic": a.tactic.id(),
                    "technique_id": a.technique_id,
                    "technique": sanitize(a.technique),
                })
            })
            .collect();
        payload["attack_detail"] = json!(per_objective);
    }

    payload
}

/// The decision's own names to scrub from the model's free-text verdict prose (Fix 6): the
/// entry workload key, each objective `NodeKey` (the decision's targets), AND the bare last
/// `/`-segment of each key (the secret/peer name, e.g. `db-password`). This is the
/// notifier's domain knowledge of the decision's shape; it hands the flat name list to the
/// shared [`scrub_decision_names`], which knows only "replace these strings." The shared
/// scrubber orders them longest-first, so a full key is removed before its bare suffix.
fn decision_names<'a>(notice: &'a BreachNotice<'a>) -> Vec<&'a str> {
    let mut names: Vec<&str> = Vec::new();
    names.push(notice.entry);
    for (objective, _attack) in notice.objectives {
        names.push(&objective.0);
        if let Some((_, bare)) = objective.0.rsplit_once('/') {
            names.push(bare);
        }
    }
    names
}

/// The breach notifier. `Some(url)` when `PROTECTOR_ENGINE_NOTIFY_URL` is configured,
/// `None` (disabled) otherwise — in which case [`notify`](Self::notify) is a no-op and
/// the engine makes zero outbound calls (byte-identical to today). The client is the
/// **bounded** timeout-only client from [`super::model`]; we never construct an unbounded
/// `reqwest::Client::new()`, so a hung sink can't stall the engine loop.
#[derive(Default)]
pub struct BreachNotifier {
    /// The operator-configured sink URL, or `None` when disabled.
    url: Option<String>,
    /// Opt-in richer payload (`PROTECTOR_ENGINE_NOTIFY_VERBOSE`). Default false (redacted).
    verbose: bool,
    /// The bounded HTTP client — built only when a URL is configured.
    client: Option<reqwest::Client>,
}

impl BreachNotifier {
    /// A disabled notifier — notifies nothing, makes no outbound calls. The honest
    /// default when no URL is configured.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Build from the configured URL with a bounded client. An empty/blank URL ⇒
    /// [`disabled`](Self::disabled). If even the bounded client can't be built, degrades
    /// to disabled (logged) rather than risk an unbounded fallback.
    pub fn new(url: impl Into<String>, verbose: bool) -> Self {
        let url = url.into();
        if url.trim().is_empty() {
            return Self::disabled();
        }
        // Zero-egress is structural (Fix 5 / CLAUDE.md): the sink must be in-cluster
        // unless PROTECTOR_ALLOW_EXTERNAL_NOTIFY=1 explicitly opts into an external one.
        // Fail closed (disabled) for an external sink without the opt-in rather than POST
        // a (redacted) breach summary off-cluster.
        let allow_external = super::model::external_opt_in("PROTECTOR_ALLOW_EXTERNAL_NOTIFY");
        if let Err(reason) = super::model::validate_in_cluster_endpoint(url.trim(), allow_external)
        {
            tracing::error!(
                url = %url.trim(),
                "{reason}; disabling the breach notifier (set PROTECTOR_ALLOW_EXTERNAL_NOTIFY=1 to override)"
            );
            return Self::disabled();
        }
        let timeout = std::env::var("PROTECTOR_ENGINE_NOTIFY_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
        match super::model::timeout_only_client(timeout) {
            Ok(client) => {
                tracing::info!(
                    url = %url, verbose,
                    "breach notifier enabled (operator-configured outbound; redacted by default)"
                );
                Self {
                    url: Some(url.trim().to_string()),
                    verbose,
                    client: Some(client),
                }
            }
            Err(error) => {
                tracing::warn!(%error, "breach notifier: could not build a bounded HTTP client; disabling");
                Self::disabled()
            }
        }
    }

    /// Build from the environment (ADR-0018): `PROTECTOR_ENGINE_NOTIFY_URL` enables it,
    /// `PROTECTOR_ENGINE_NOTIFY_VERBOSE` (truthy) opts into the richer payload. Unset/empty
    /// URL ⇒ [`disabled`](Self::disabled).
    pub fn from_env() -> Self {
        match std::env::var("PROTECTOR_ENGINE_NOTIFY_URL") {
            Ok(url) if !url.trim().is_empty() => {
                let verbose = std::env::var("PROTECTOR_ENGINE_NOTIFY_VERBOSE")
                    .map(|v| is_truthy(&v))
                    .unwrap_or(false);
                Self::new(url, verbose)
            }
            _ => Self::disabled(),
        }
    }

    /// Whether the notifier is enabled (a URL is configured).
    pub fn is_enabled(&self) -> bool {
        self.url.is_some()
    }

    /// POST a redacted breach notification, best-effort. A no-op when disabled (zero
    /// outbound calls). The caller dedupes on the decision identity (the journal's, JEF-141),
    /// so this is invoked once per *new* decision, not per pass. Failures are logged once
    /// and dropped — notification never affects a verdict, an actuation, or the journal.
    pub async fn notify(&self, notice: &BreachNotice<'_>) {
        let (Some(url), Some(client)) = (&self.url, &self.client) else {
            return; // disabled: byte-identical to today, no outbound call.
        };
        let payload = redacted_payload(notice, self.verbose);
        match client.post(url).json(&payload).send().await {
            Ok(response) if response.status().is_success() => {
                tracing::debug!(entry = %notice.entry, "breach notification delivered");
            }
            Ok(response) => {
                tracing::warn!(
                    entry = %notice.entry, status = %response.status(),
                    "breach notification rejected by sink (dropped; journal remains source of truth)"
                );
            }
            Err(error) => {
                tracing::warn!(
                    entry = %notice.entry, %error,
                    "breach notification POST failed (dropped; best-effort)"
                );
            }
        }
    }

    /// POST a redacted runtime-coverage transition (JEF-427), best-effort. A no-op when disabled
    /// (zero outbound calls — byte-identical to today). The caller fires this ONCE per edge (a
    /// was-covering fleet going dark past the debounce, or recovering), never per pass — the same
    /// edge-dedup discipline as the breach notice. Shares the same bounded client and the same
    /// fail-safe posture: a failure is logged once and dropped; it never touches a verdict, an
    /// actuation, or the journal.
    pub async fn notify_coverage(&self, notice: &CoverageNotice) {
        let (Some(url), Some(client)) = (&self.url, &self.client) else {
            return; // disabled: byte-identical to today, no outbound call.
        };
        let payload = redacted_coverage_payload(notice);
        match client.post(url).json(&payload).send().await {
            Ok(response) if response.status().is_success() => {
                tracing::debug!(?notice.event, "coverage notification delivered");
            }
            Ok(response) => {
                tracing::warn!(
                    ?notice.event, status = %response.status(),
                    "coverage notification rejected by sink (dropped; dashboard/metrics remain source of truth)"
                );
            }
            Err(error) => {
                tracing::warn!(
                    ?notice.event, %error,
                    "coverage notification POST failed (dropped; best-effort)"
                );
            }
        }
    }
}

/// A lenient truthy check for the verbose opt-in: `1`/`true`/`yes`/`on` (any case).
fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::NodeKey;
    use crate::engine::graph::attack::{CREDENTIAL_ACCESS, EXPLOIT_PUBLIC_FACING};

    /// A breach notice over an entry that reaches a secret-bearing objective. The
    /// objective NodeKey deliberately carries a secret-looking name so the redaction tests
    /// can prove that name never reaches the payload.
    fn sample_notice<'a>(
        verdict: &'a Verdict,
        objectives: &'a [(NodeKey, AttackRef)],
        enforcement: Enforcement,
    ) -> BreachNotice<'a> {
        BreachNotice {
            entry: "workload/app/Pod/web",
            verdict,
            objectives,
            enforcement,
        }
    }

    fn secret_objectives() -> Vec<(NodeKey, AttackRef)> {
        vec![
            (
                NodeKey("secret/app/Secret/session-key".into()),
                CREDENTIAL_ACCESS,
            ),
            (
                NodeKey("secret/app/Secret/db-password".into()),
                EXPLOIT_PUBLIC_FACING,
            ),
        ]
    }

    /// The redacted payload carries the decision summary and the ATT&CK outcome, but NONE
    /// of the crown jewels: no secret names, no per-peer graph (the objective targets), no
    /// CVE list. This is the core ADR-0018 redaction guarantee.
    #[test]
    fn default_payload_redacts_secret_names_peers_and_cves() {
        let verdict = Verdict::Exploitable("CVE-2021-44228 reaches the secret".into());
        let objectives = secret_objectives();
        let notice = sample_notice(&verdict, &objectives, Enforcement::Shadow);

        let payload = redacted_payload(&notice, false);
        let blob = serde_json::to_string(&payload).unwrap();

        // The entry workload (a workload key, not a secret) IS present — it's the decision.
        assert!(
            blob.contains("workload/app/Pod/web"),
            "entry workload is surfaced"
        );
        // The decision kind and ATT&CK outcome are present.
        assert_eq!(payload["decision"], "exploitable");
        assert!(
            blob.contains("T1552"),
            "the ATT&CK technique id is the outcome"
        );
        // Objective COUNT, never the per-objective targets.
        assert_eq!(payload["objectives_reached"], 2);

        // No secret NAMES.
        assert!(!blob.contains("session-key"), "secret name must not leak");
        assert!(!blob.contains("db-password"), "secret name must not leak");
        // No per-peer graph: the objective NodeKeys (the targets) are absent.
        assert!(
            !blob.contains("secret/app/Secret"),
            "objective targets (peer graph) must not leak"
        );
        // No CVE inventory field. The verdict text may mention one CVE the model named,
        // but there's no structured CVE list in the payload.
        assert!(payload.get("cves").is_none(), "no CVE inventory field");
        assert!(
            payload.get("vulnerabilities").is_none(),
            "no CVE inventory field"
        );
        assert!(payload.get("topology").is_none(), "no topology field");
        assert!(payload.get("peers").is_none(), "no peer-graph field");
    }

    /// Fix 6: the model can echo a CVE id or a secret/peer name it was shown into its
    /// free-text reason. `sanitize` strips structure but not those *semantics*, so the
    /// redacted payload must additionally scrub the decision's own names + CVE tokens —
    /// the verdict text and the human message must contain neither.
    #[test]
    fn redacted_payload_scrubs_cve_and_secret_names_from_verdict_prose() {
        // A verdict reason that parrots a real CVE id AND a secret node-key/name.
        let verdict = Verdict::Exploitable(
            "CVE-2021-44228 in web reaches secret/app/Secret/db-password (db-password)".into(),
        );
        let objectives = secret_objectives();
        let notice = sample_notice(&verdict, &objectives, Enforcement::Shadow);

        let payload = redacted_payload(&notice, false);
        let blob = serde_json::to_string(&payload).unwrap();

        assert!(!blob.contains("CVE-2021-44228"), "CVE id must be scrubbed");
        assert!(
            !blob.contains("db-password"),
            "secret name must be scrubbed from the prose"
        );
        assert!(
            !blob.contains("secret/app/Secret"),
            "objective node-key must be scrubbed from the prose"
        );
        // The placeholder is present where a name was, so the message is still readable.
        assert!(
            payload["verdict"].as_str().unwrap().contains("[redacted]"),
            "scrubbed names are replaced with a placeholder"
        );
    }

    /// BYTE-IDENTICAL guarantee (JEF-486): lifting the scrubbers into the shared
    /// `engine::redact` module must not change a single byte of what the notifier emits.
    /// These are the exact serialized payloads captured from the pre-refactor code for a
    /// fixture that exercises every scrubber (structure chars, a CVE token, a full node-key
    /// AND its bare secret name) across the default, verbose, and armed shapes. If the
    /// refactor drifts, one of these fails.
    #[test]
    fn redacted_payload_is_byte_identical_to_pre_refactor() {
        let verdict = Verdict::Exploitable(
            "CVE-2021-44228 in web reaches secret/app/Secret/db-password (db-password) see <<<x>>> `y`"
                .into(),
        );
        let objectives = secret_objectives();
        let notice = sample_notice(&verdict, &objectives, Enforcement::Shadow);

        assert_eq!(
            serde_json::to_string(&redacted_payload(&notice, false)).unwrap(),
            r#"{"attack":[{"tactic":"TA0001","technique":"Exploit Public-Facing Application","technique_id":"T1190"},{"tactic":"TA0006","technique":"Unsecured Credentials","technique_id":"T1552"}],"decision":"exploitable","enforcement":"shadow","entry":"workload/app/Pod/web","message":"protector would isolate workload/app/Pod/web (exploitable — [redacted] in web reaches [redacted] ([redacted]) see    x     y )","objectives_reached":2,"verdict":"exploitable — [redacted] in web reaches [redacted] ([redacted]) see    x     y "}"#,
        );
        assert_eq!(
            serde_json::to_string(&redacted_payload(&notice, true)).unwrap(),
            r#"{"attack":[{"tactic":"TA0001","technique":"Exploit Public-Facing Application","technique_id":"T1190"},{"tactic":"TA0006","technique":"Unsecured Credentials","technique_id":"T1552"}],"attack_detail":[{"tactic":"TA0006","technique":"Unsecured Credentials","technique_id":"T1552"},{"tactic":"TA0001","technique":"Exploit Public-Facing Application","technique_id":"T1190"}],"decision":"exploitable","enforcement":"shadow","entry":"workload/app/Pod/web","message":"protector would isolate workload/app/Pod/web (exploitable — [redacted] in web reaches [redacted] ([redacted]) see    x     y )","objectives_reached":2,"verdict":"exploitable — [redacted] in web reaches [redacted] ([redacted]) see    x     y "}"#,
        );
        let armed = sample_notice(&verdict, &objectives, Enforcement::Armed);
        assert_eq!(
            serde_json::to_string(&redacted_payload(&armed, false)).unwrap(),
            r#"{"attack":[{"tactic":"TA0001","technique":"Exploit Public-Facing Application","technique_id":"T1190"},{"tactic":"TA0006","technique":"Unsecured Credentials","technique_id":"T1552"}],"decision":"exploitable","enforcement":"armed","entry":"workload/app/Pod/web","message":"protector isolated workload/app/Pod/web (exploitable — [redacted] in web reaches [redacted] ([redacted]) see    x     y )","objectives_reached":2,"verdict":"exploitable — [redacted] in web reaches [redacted] ([redacted]) see    x     y "}"#,
        );
    }

    /// A lowercase CVE spelling in the prose is still scrubbed (case-insensitive token).
    #[test]
    fn redacted_payload_scrubs_lowercase_cve() {
        let verdict = Verdict::Exploitable("cve-2021-44228 is exploitable".into());
        let objectives = secret_objectives();
        let payload = redacted_payload(
            &sample_notice(&verdict, &objectives, Enforcement::Shadow),
            false,
        );
        let blob = serde_json::to_string(&payload).unwrap();
        assert!(
            !blob.to_ascii_uppercase().contains("CVE-2021-44228"),
            "a lowercase CVE token must still be scrubbed"
        );
    }

    /// Fix 5: an external notifier URL fails closed (disabled) without the opt-in, and is
    /// enabled with it. An in-cluster URL is enabled regardless.
    #[test]
    fn external_notify_url_fails_closed_without_opt_in() {
        // In-cluster (`.svc.cluster.local`) is always allowed.
        assert!(
            BreachNotifier::new(
                "http://alertmanager.monitoring.svc.cluster.local:9093/api",
                false
            )
            .is_enabled(),
            "an in-cluster sink must be enabled"
        );
        // External without the opt-in → disabled (fail closed).
        unsafe {
            std::env::remove_var("PROTECTOR_ALLOW_EXTERNAL_NOTIFY");
        }
        assert!(
            !BreachNotifier::new("https://evil.com/hook", false).is_enabled(),
            "an external sink must fail closed without the opt-in"
        );
        // External WITH the opt-in → enabled.
        unsafe {
            std::env::set_var("PROTECTOR_ALLOW_EXTERNAL_NOTIFY", "1");
        }
        let enabled = BreachNotifier::new("https://evil.com/hook", false).is_enabled();
        unsafe {
            std::env::remove_var("PROTECTOR_ALLOW_EXTERNAL_NOTIFY");
        }
        assert!(enabled, "the opt-in must allow an external sink");
    }

    /// The verbose opt-in adds the per-objective ATT&CK list (techniques), but STILL
    /// excludes secret names, the peer graph, and the CVE list — verbosity is bounded.
    #[test]
    fn verbose_payload_adds_attack_detail_but_still_no_secrets() {
        let verdict = Verdict::Exploitable("reaches two secrets".into());
        let objectives = secret_objectives();
        let notice = sample_notice(&verdict, &objectives, Enforcement::Shadow);

        let payload = redacted_payload(&notice, true);
        let blob = serde_json::to_string(&payload).unwrap();

        assert!(
            payload.get("attack_detail").is_some(),
            "verbose adds the per-objective ATT&CK list"
        );
        // Even verbose never names secrets or the peer graph.
        assert!(!blob.contains("session-key"));
        assert!(!blob.contains("db-password"));
        assert!(!blob.contains("secret/app/Secret"));
    }

    /// Shadow vs armed is unambiguous in the message and the structured tag.
    #[test]
    fn shadow_vs_armed_is_explicit() {
        let verdict = Verdict::Exploitable("reaches the secret".into());
        let objectives = secret_objectives();

        let shadow = redacted_payload(
            &sample_notice(&verdict, &objectives, Enforcement::Shadow),
            false,
        );
        assert_eq!(shadow["enforcement"], "shadow");
        assert!(
            shadow["message"]
                .as_str()
                .unwrap()
                .contains("would isolate"),
            "shadow must say 'would isolate'"
        );

        let armed = redacted_payload(
            &sample_notice(&verdict, &objectives, Enforcement::Armed),
            false,
        );
        assert_eq!(armed["enforcement"], "armed");
        let msg = armed["message"].as_str().unwrap();
        assert!(msg.contains("isolated"), "armed must say 'isolated'");
        assert!(
            !msg.contains("would isolate"),
            "armed must not be ambiguous"
        );
    }

    /// The verdict prose is sanitized before egress: fence/structure characters that
    /// untrusted third-party text (trivy's CVE title, JEF-66) might carry are stripped from
    /// the payload.
    #[test]
    fn verdict_text_is_sanitized_before_egress() {
        let verdict = Verdict::Exploitable("see <<<inject>>> `code`\nrun".into());
        let objectives = secret_objectives();
        let payload = redacted_payload(
            &sample_notice(&verdict, &objectives, Enforcement::Shadow),
            false,
        );
        let text = payload["verdict"].as_str().unwrap();
        for bad in ['<', '>', '`', '\n', '\r', '{', '}'] {
            assert!(
                !text.contains(bad),
                "sanitized verdict must not contain {bad:?}"
            );
        }
    }

    /// An unset URL ⇒ a disabled notifier: not enabled, and `notify` makes no outbound
    /// call. This is the "no URL = byte-identical to today, zero outbound" guarantee.
    #[tokio::test]
    async fn disabled_notifier_makes_no_outbound_call() {
        let notifier = BreachNotifier::disabled();
        assert!(!notifier.is_enabled());
        // An empty/blank URL is also disabled.
        assert!(!BreachNotifier::new("", false).is_enabled());
        assert!(!BreachNotifier::new("   ", false).is_enabled());

        // notify is a safe no-op (no client, no URL → returns immediately). If it tried to
        // POST it would need a client; the disabled notifier has none, so this can't call out.
        let verdict = Verdict::Exploitable("x".into());
        let objectives = secret_objectives();
        notifier
            .notify(&sample_notice(&verdict, &objectives, Enforcement::Shadow))
            .await;
    }

    /// A configured URL enables the notifier and builds the bounded client. The POST to an
    /// unroutable address fails fast (bounded) rather than hanging — proving the timeout-
    /// only client is in play, never an unbounded one.
    #[tokio::test]
    async fn enabled_notifier_posts_with_a_bounded_client() {
        // 10.255.255.1 is reserved/unroutable: the connect stalls, so only the timeout can
        // end the POST. A 1s timeout via the env override keeps the test quick.
        unsafe {
            std::env::set_var("PROTECTOR_ENGINE_NOTIFY_TIMEOUT_SECS", "1");
        }
        let notifier = BreachNotifier::new("http://10.255.255.1:9/notify", false);
        unsafe {
            std::env::remove_var("PROTECTOR_ENGINE_NOTIFY_TIMEOUT_SECS");
        }
        assert!(notifier.is_enabled());

        let verdict = Verdict::Exploitable("reaches the secret".into());
        let objectives = secret_objectives();
        let started = std::time::Instant::now();
        // notify swallows the error (best-effort) — the point is it returns promptly,
        // i.e. the client is bounded.
        notifier
            .notify(&sample_notice(&verdict, &objectives, Enforcement::Shadow))
            .await;
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "a bounded client must give up well under 5s, took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn truthy_parses_the_verbose_opt_in() {
        for yes in ["1", "true", "TRUE", "Yes", "on", " on "] {
            assert!(is_truthy(yes), "{yes:?} should be truthy");
        }
        for no in ["0", "false", "no", "off", "", "maybe"] {
            assert!(!is_truthy(no), "{no:?} should be falsy");
        }
    }

    /// The coverage-degradation payload (JEF-427) is COUNTS-ONLY: the event tag, the feed, N of M,
    /// the last-observed time, and a human message — and nothing else. No node names, no topology,
    /// no secrets, no CVEs (the ADR-0018 posture, upheld by construction).
    #[test]
    fn coverage_degraded_payload_is_counts_only() {
        let payload = redacted_coverage_payload(&CoverageNotice {
            event: CoverageEvent::Degraded,
            expected: 4,
            blind: 4,
            last_observation: Some("3m ago".into()),
        });
        assert_eq!(payload["event"], "runtime_coverage_degraded");
        assert_eq!(payload["feed"], "Runtime");
        assert_eq!(payload["blind"], 4);
        assert_eq!(payload["expected"], 4);
        assert_eq!(payload["last_observation"], "3m ago");
        assert!(payload["message"].as_str().unwrap().contains("4 of 4"));
        // Exactly these keys — no room for a node name / topology / secret / CVE field to ride out.
        let mut keys: Vec<&str> = payload
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "blind",
                "event",
                "expected",
                "feed",
                "last_observation",
                "message"
            ]
        );
    }

    /// The recovery payload drops `last_observation` (only meaningful for the outage) and reports
    /// the healthy count honestly (M − blind of M reporting again).
    #[test]
    fn coverage_restored_payload_reports_recovery() {
        let payload = redacted_coverage_payload(&CoverageNotice {
            event: CoverageEvent::Restored,
            expected: 4,
            blind: 1,
            last_observation: Some("ignored on recovery".into()),
        });
        assert_eq!(payload["event"], "runtime_coverage_restored");
        assert!(
            payload.get("last_observation").is_none(),
            "restored omits last_observation"
        );
        let msg = payload["message"].as_str().unwrap();
        assert!(msg.contains("3 of 4"), "3 of 4 reporting again: {msg}");
    }

    /// The JEF-421 stall edge maps onto the notice: a collapse → `Degraded` (carrying the
    /// last-observed time), a recovery → `Restored` (no last-observed).
    #[test]
    fn coverage_edge_maps_to_notice() {
        use crate::engine::state::CoverageEdge;
        let degraded: CoverageNotice = CoverageEdge::Collapsed {
            blind: 2,
            expected: 2,
            last_observation: Some("5m ago".into()),
        }
        .into();
        assert_eq!(degraded.event, CoverageEvent::Degraded);
        assert_eq!((degraded.blind, degraded.expected), (2, 2));
        assert_eq!(degraded.last_observation.as_deref(), Some("5m ago"));

        let restored: CoverageNotice = CoverageEdge::Recovered {
            blind: 0,
            expected: 3,
        }
        .into();
        assert_eq!(restored.event, CoverageEvent::Restored);
        assert_eq!((restored.blind, restored.expected), (0, 3));
        assert!(restored.last_observation.is_none());
    }

    /// A disabled notifier makes ZERO outbound calls for a coverage push too — the "no URL =
    /// byte-identical to today" guarantee extends to JEF-427. With no client it cannot call out.
    #[tokio::test]
    async fn disabled_notifier_makes_no_coverage_call() {
        let notifier = BreachNotifier::disabled();
        assert!(!notifier.is_enabled());
        notifier
            .notify_coverage(&CoverageNotice {
                event: CoverageEvent::Degraded,
                expected: 4,
                blind: 4,
                last_observation: None,
            })
            .await;
    }
}
