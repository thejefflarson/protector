//! ELF static-linkage classification (JEF-404) — re-exported from the shared `behavior`
//! crate (JEF-407).
//!
//! The classifier used to live here, but JEF-407 needs the SAME byte logic in the
//! node-local agent (which reads `/proc/<pid>/exe` and is the prod byte source that
//! activates this feature), and the agent depends on `protector-behavior` by path, not on
//! the engine. The parser is std-only and dependency-free, so it now lives in
//! [`protector_behavior::elf`] as the single source of truth — both the engine and the
//! agent classify identically and can't drift. The engine keeps this thin re-export so the
//! `engine::observe::elf::elf_static_linkage` path (and the JEF-404 doc references) stay
//! stable.
//!
//! See [`protector_behavior::elf`] for the full rationale: a dynamically linked ELF carries
//! a `PT_INTERP` program header naming its loader; a static one does not. `Some(true)` ⇒
//! static, `Some(false)` ⇒ dynamic, `None` ⇒ unknown (never guessed). The reachability
//! consequence — a static image's unmatched CVE tags
//! [`Reachability::PresentStaticBinary`](crate::engine::graph::Reachability) rather than
//! `NotObserved` — is engine policy in the `CveReachabilityAdapter`.

pub use protector_behavior::elf::elf_static_linkage;
