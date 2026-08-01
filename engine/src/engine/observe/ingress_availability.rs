//! Graceful degradation for the Ingress/IngressClass RBAC ADR-0038 needs
//! (`networking.k8s.io: [ingresses, ingressclasses]`, `get/list/watch`).
//!
//! Every other watched type in [`Snapshot`](super::Snapshot) is always granted, so
//! [`run_loop::run_watch`](crate::engine::run_loop::run_watch) never had to consider
//! a permission gap on the resources it watches. The Ingress grant is the first
//! that can legitimately be missing — an operator on an older chart render, or the
//! forked cluster chart before its RBAC is hand-ported (ADR-0038's rollout note) —
//! so both the watch reflector and [`Snapshot::observe`](super::Snapshot::observe)'s
//! one-shot list must tolerate it: log once, treat the resource as absent, and let
//! [`IngressExposureAdapter`](super::adapter::IngressExposureAdapter) no-op on the
//! empty list (its existing under-promote fail direction, ADR-0038) — never abort
//! the snapshot or spin retrying a permission that isn't coming back without a
//! restart.

use std::sync::atomic::{AtomicBool, Ordering};

/// Whether `error` means the Ingress/IngressClass API is unavailable to this
/// ServiceAccount: RBAC not granted (403 Forbidden) or the resource/API group isn't
/// registered on this cluster (404 Not Found) — the two gaps ADR-0038 must degrade
/// through rather than fail on. Checked by raw HTTP status rather than
/// `Status::is_forbidden`/`is_not_found` — those only fall back to the status code
/// when `reason` is unset AND not one of the well-known reason strings, so they'd
/// miss a 403/404 whose `reason` is absent or non-standard (an odd proxy/webhook in
/// front of the apiserver). Any other error (a transient network blip, a 5xx) is NOT
/// classified here, so callers keep retrying it exactly like every other watched
/// type.
pub(crate) fn ingress_api_unavailable(error: &kube::Error) -> bool {
    matches!(error, kube::Error::Api(status) if status.code == 403 || status.code == 404)
}

/// Runs a closure at most once, ever, for the life of the value — the log-once
/// guard that keeps a standing RBAC/API gap from re-announcing itself on every
/// retry (the tight-loop 403 spam ADR-0038's rollout must not reintroduce).
pub(crate) struct LogOnce(AtomicBool);

impl LogOnce {
    pub(crate) const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Runs `f` the first time this is called; every later call is a no-op.
    pub(crate) fn call(&self, f: impl FnOnce()) {
        if self
            .0
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            f();
        }
    }
}

/// The single, process-lifetime log-once guard for the "route-transitive exposure
/// disabled" warning — shared by the watch reflector and the one-shot list path so
/// the operator sees it exactly once no matter which path hits the gap first.
pub(crate) static INGRESS_UNAVAILABLE_LOGGED: LogOnce = LogOnce::new();

/// Logs the standing warning exactly once per process (see
/// [`INGRESS_UNAVAILABLE_LOGGED`]).
pub(crate) fn warn_ingress_unavailable_once() {
    INGRESS_UNAVAILABLE_LOGGED.call(|| {
        tracing::warn!(
            "ingresses/ingressclasses (networking.k8s.io) is forbidden or absent for this \
             ServiceAccount — route-transitive internet exposure (ADR-0038) is disabled; \
             grant get/list/watch on networking.k8s.io ingresses/ingressclasses to enable it. \
             The engine's other observation and the proof loop continue normally."
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_403_and_a_404_are_unavailable_but_nothing_else_is() {
        let forbidden = kube::Error::Api(Box::new(kube::core::Status {
            code: 403,
            ..Default::default()
        }));
        let not_found = kube::Error::Api(Box::new(kube::core::Status {
            code: 404,
            ..Default::default()
        }));
        let server_error = kube::Error::Api(Box::new(kube::core::Status {
            code: 500,
            ..Default::default()
        }));
        assert!(ingress_api_unavailable(&forbidden));
        assert!(ingress_api_unavailable(&not_found));
        // A 5xx (or any other status) is a transient-looking failure, not a standing
        // permission/API gap — callers must keep retrying it, not silently degrade.
        assert!(!ingress_api_unavailable(&server_error));
    }

    #[test]
    fn log_once_runs_the_closure_exactly_once_across_repeated_calls() {
        let guard = LogOnce::new();
        let mut runs = 0;
        for _ in 0..5 {
            guard.call(|| runs += 1);
        }
        assert_eq!(runs, 1);
    }
}
