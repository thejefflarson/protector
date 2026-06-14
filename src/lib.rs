//! protector — a validating admission webhook for the cluster.
//!
//! A thin HTTPS server that the Kubernetes API server calls on every matched
//! write. It decodes the `AdmissionReview`, runs an ordered set of [`Policy`]
//! implementations against the request, and allows the request only if every
//! applicable policy allows it. The policy set is intentionally small and
//! focused (signature verification, mesh enforcement, …) rather than a generic
//! rules engine — this is not a Kyverno re-implementation.
//!
//! [`Policy`]: policy::Policy
pub mod engine;
pub mod metrics;
pub mod policies;
pub mod policy;
pub mod server;
pub mod telemetry;
