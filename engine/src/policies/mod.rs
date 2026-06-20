//! Concrete admission policies.
//!
//! Each module here implements [`crate::policy::Policy`]. They start as stubs
//! that allow everything so the webhook plumbing can be deployed and exercised
//! end to end before any real rule is enforced — flip them on one at a time.
pub mod mesh;
pub mod signature;
