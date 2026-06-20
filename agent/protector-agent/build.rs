//! Build the eBPF object and embed it (only under the `ebpf` feature).
//!
//! The userspace loader `include_bytes!`s the compiled BPF object. This compiles the
//! sibling `protector-agent-ebpf` crate (its rust-toolchain.toml pins nightly and its
//! .cargo/config sets the bpf target + build-std + bpf-linker) and copies the object
//! into OUT_DIR. Done by hand rather than via aya-build to keep the two crates
//! standalone (no shared workspace). Without the feature this is a no-op, so the
//! default (no-op observer) build needs no bpf toolchain.

use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return;
    }

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let ebpf_dir = manifest.parent().unwrap().join("protector-agent-ebpf");
    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());

    // Build the eBPF crate. Strip the toolchain/target env the OUTER cargo set so the
    // nested build honors the eBPF crate's own rust-toolchain.toml + .cargo/config
    // (otherwise RUSTUP_TOOLCHAIN/CARGO_* leak in and override the bpf target/nightly).
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--release"]).current_dir(&ebpf_dir);
    for k in [
        "RUSTUP_TOOLCHAIN",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_TARGET",
        "CARGO_TARGET_DIR",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTFLAGS",
    ] {
        cmd.env_remove(k);
    }
    let status = cmd.status().expect("spawn cargo for the eBPF crate");
    assert!(status.success(), "eBPF crate build failed");

    let obj = ebpf_dir.join("target/bpfel-unknown-none/release/protector-agent");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("protector-agent.bpf.o");
    fs::copy(&obj, &out)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", obj.display(), out.display()));
}
