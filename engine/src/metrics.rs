use std::collections::BTreeMap;
use std::sync::Mutex;

/// Minimal, dependency-free Prometheus metrics for policy decisions.
///
/// Hand-rolled rather than pulling a metrics stack: the surface is a single
/// labeled counter, and avoiding extra crates keeps the dependency (and
/// `cargo audit`) footprint small. Scraped at `/metrics`.
#[derive(Default)]
pub struct Metrics {
    /// (policy name, decision) → count. `decision` is `"audit"` (a would-deny
    /// that was allowed because the policy is in audit mode or the workload is
    /// exempt) or `"deny"` (the request was rejected).
    violations: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a policy violation outcome. This is the discovery signal: an
    /// `audit` count rising on a policy/namespace means "things that would be
    /// rejected if you enforced".
    pub fn record_violation(&self, policy: &'static str, decision: &'static str) {
        *self
            .violations
            .lock()
            .expect("metrics mutex poisoned")
            .entry((policy, decision))
            .or_insert(0) += 1;
    }

    /// Render the metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let violations = self.violations.lock().expect("metrics mutex poisoned");
        let mut out = String::from(
            "# HELP protector_policy_violations_total Policy violations by policy and decision \
             (audit = would-deny but allowed; deny = rejected).\n\
             # TYPE protector_policy_violations_total counter\n",
        );
        for ((policy, decision), count) in violations.iter() {
            out.push_str(&format!(
                "protector_policy_violations_total{{policy=\"{policy}\",decision=\"{decision}\"}} {count}\n"
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_counts_in_prometheus_format() {
        let m = Metrics::new();
        m.record_violation("image-signature", "deny");
        m.record_violation("image-signature", "deny");
        m.record_violation("mesh-injection", "audit");
        let out = m.render();
        assert!(out.contains("# TYPE protector_policy_violations_total counter"));
        assert!(out.contains(
            "protector_policy_violations_total{policy=\"image-signature\",decision=\"deny\"} 2"
        ));
        assert!(out.contains(
            "protector_policy_violations_total{policy=\"mesh-injection\",decision=\"audit\"} 1"
        ));
    }
}
