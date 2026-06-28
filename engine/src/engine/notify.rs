//! The breach notifier (JEF-144): the **one** sanctioned outbound path (ADR-0018).
//!
//! Surfacing is otherwise pull-only — a breach decision lands on `/findings` and the
//! durable journal ([`super::journal`]), but a solo operator never *learns* of it
//! unless watching the dashboard. This notifier POSTs a breach decision to an
//! operator-configured URL (`PROTECTOR_ENGINE_NOTIFY_URL`) — the inverse of the
//! falcosidekick ingest — documented to target an in-cluster sink (Alertmanager /
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

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::graph::attack::AttackRef;
use super::reason::adjudicate::{Verdict, sanitize};

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
    /// `Armed` when any action class is enabled, else `Shadow`. The same `armed` flag
    /// that titles the dashboard's remediations section drives the notifier wording.
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

/// Build the **redacted** JSON payload for a breach decision (ADR-0018 §2). Pure and
/// unit-tested: given the decision, it surfaces the decision summary ONLY — never the
/// topology, secret names, the peer graph, or the CVE list. `verbose` adds the
/// per-objective ATT&CK list (still no secrets/peers/CVEs); the default is the summary.
///
/// The verdict text is sanitized ([`sanitize`]) before it lands in the payload, so
/// untrusted third-party prose (trivy's CVE title, JEF-66) can't smuggle structure into the
/// sink.
pub fn redacted_payload(notice: &BreachNotice<'_>, verbose: bool) -> Value {
    // Distinct ATT&CK references reached — the "outcome", as low-cardinality IDs. A
    // BTreeSet dedups and orders them deterministically (stable payloads = stable tests).
    let mut attack: BTreeSet<(&'static str, &'static str, &'static str)> = BTreeSet::new();
    for (_objective, a) in notice.objectives {
        attack.insert((a.tactic.id(), a.technique_id, a.technique));
    }
    let attack_outcome: Vec<Value> = attack
        .into_iter()
        .take(ATTACK_CAP)
        .map(|(tactic, technique_id, technique)| {
            // The technique name is a `'static` constant from our own ATT&CK table, not
            // cluster data; sanitize it anyway so the payload is uniformly structure-safe.
            json!({
                "tactic": tactic,
                "technique_id": technique_id,
                "technique": sanitize(technique),
            })
        })
        .collect();

    // The verdict text can carry untrusted third-party prose (trivy's CVE title, JEF-66) —
    // sanitize it before egress so it's inert data in the operator's sink. `sanitize` strips
    // STRUCTURE (fences/braces) but not SEMANTICS: the model can echo a secret/peer name
    // or a CVE id it was shown into its free-text reason, which would then egress around
    // the ADR-0018 redaction. So also scrub those names/tokens out (Fix 6).
    let verdict_text = scrub_decision_names(&sanitize(&notice.verdict.summary()), notice);

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

/// The placeholder substituted for any decision-input name or CVE id scrubbed from the
/// model's free-text verdict prose before egress.
const REDACTED: &str = "[redacted]";

/// Scrub the model's free-text verdict prose (Fix 6) of the very names that fed the
/// decision — so a secret/peer name or CVE id the model *echoed* into its reason can't
/// egress around the ADR-0018 redaction. Replaces, with a placeholder:
///
/// - the entry workload key,
/// - each objective `NodeKey` (the decision's targets) AND the last `/`-segment of each
///   (the bare secret/peer name, e.g. `db-password`),
/// - any `CVE-<year>-<seq>` token (case-insensitive).
///
/// Order matters: longer, more-specific names are replaced first so a substring match
/// (`secret/app/Secret/db-password` then `db-password`) doesn't leave a fragment behind.
fn scrub_decision_names(text: &str, notice: &BreachNotice<'_>) -> String {
    // Collect the names to scrub, longest first (so a full key is removed before its
    // bare-name suffix, and no shorter name leaves a longer one half-scrubbed).
    let mut names: Vec<String> = Vec::new();
    let mut push = |s: &str| {
        let s = s.trim();
        if !s.is_empty() {
            names.push(s.to_string());
        }
    };
    push(notice.entry);
    for (objective, _attack) in notice.objectives {
        push(&objective.0);
        if let Some((_, bare)) = objective.0.rsplit_once('/') {
            push(bare);
        }
    }
    names.sort_by_key(|b| std::cmp::Reverse(b.len()));
    names.dedup();

    let mut out = text.to_string();
    for name in names {
        if out.contains(&name) {
            out = out.replace(&name, REDACTED);
        }
    }
    scrub_cve_tokens(&out)
}

/// Replace every `CVE-<4-digit year>-<4+ digit sequence>` token (case-insensitive) with
/// the redaction placeholder. The model can name a CVE it was shown in evidence; the CVE
/// inventory is crown-jewel data ADR-0018 keeps in-cluster, so it must not ride out in
/// the prose either.
fn scrub_cve_tokens(text: &str) -> String {
    static CVE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = CVE.get_or_init(|| {
        regex::Regex::new(r"(?i)CVE-\d{4}-\d{4,}").expect("static CVE regex compiles")
    });
    re.replace_all(text, REDACTED).into_owned()
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
}
