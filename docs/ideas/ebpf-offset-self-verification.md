# Idea brief — eBPF offset self-verification (load-time BTF preflight)

**Status:** settled → ticketed. Load-bearing decision recorded as an amendment to
[ADR-0014](../adr/0014-behavioral-telemetry-ebpf.md).

## The idea (as posed)
Eliminate the agent's **manual eBPF struct-offset maintenance**. The eBPF crate
(`agent/protector-agent-ebpf/src/vmlinux.rs`) hand-lays kernel structs so its field reads
sit at verified kernel-7.0.0 byte offsets, with an `offset_of!` const block as a guard. The
ticket proposed either **real CO-RE** (`preserve_access_index` BTF field relocation) or
**build-time binding generation** from node BTF.

## The problem, sharpened
The `offset_of!` guard catches an *inconsistent edit* but not a *correct-looking layout that
is wrong for a new kernel*. And the failure modes are worse than "a probe fails to load":
only the `bpf_d_path(&file->f_path)` reads are verifier-checked against kernel BTF (they fail
as `loaded=N<6`); every `bpf_probe_read_kernel` chase (`i_nlink`, `s_magic`, `uid.val`,
`i_ino`, `d_name.name`, `linux_binprm.file`) at a stale offset **silently reads garbage** —
feeding *wrong corroboration signals* (anon-inode exec, tmpfs secret-read, priv-change) into
the action bar. The 6.8→6.11 `struct file` reorg already bit once (`loaded=4/6` fleet-wide),
and two offsets + one enum value are still marked ON-NODE-PENDING in the tree. The fleet is
homogeneous kernel 7.0.0 today, so the risk is **latent** — it bites on the next kernel bump
or a new arch.

## Assumptions corrected
- **"aya gives us CO-RE" — false.** rustc cannot emit BTF field relocations for Rust struct
  accesses; the `preserve_access_index` intrinsics are a pending Rust RFC (rust-lang/rfcs#3966).
  bpf-linker emits BTF func_info (which is why fentry attach works) but **not** field-access
  relocations. So CO-RE is blocked *upstream*, not a choice we can make today.
- **"Build-time codegen removes the maintenance" — shaky.** It moves the offset bake from a
  human to the *builder node's* kernel and silently assumes builder-kernel == every
  node-kernel — which breaks precisely during a rolling kernel upgrade, the exact event this
  work defends against. It also can't run off-fleet (dev/macOS, generic CI), so a checked-in
  fallback survives anyway. It automates the ritual without closing the gap.
- **Dangerous doc-rot found:** `agent/Dockerfile`, `.github/workflows/agent.yml`, and
  `docs/ebpf-testing-on-nodes.md` claim the object is "CO-RE-relocated against the node's BTF
  at load." That is **factually wrong** — `vmlinux.rs` is the only honest doc. The false
  claim invites exactly the complacency this work exists to prevent; correct it.

## Recommended approach — load-time BTF preflight (keep hand bindings; re-prove them at load)
Keep the curated hand bindings, but before attach the userspace loader verifies each
`(struct, field, expected-offset)` and the `LOADING_MODULE` enum value against the node's
**live BTF** (the loader already reads `aya::Btf::from_sys_fs()` for fentry attach). On
mismatch: log expected-vs-actual per field (the log *is* the regeneration data), attach only
the struct-free probes (connect/ptrace/module-load), and surface degraded via the existing
heartbeat/`probes_loaded`. This is the only option that checks offsets against **the kernel
the probes actually run on**, per-node — so even a heterogeneous mid-upgrade fleet degrades
honestly node-by-node. It converts "silent garbage reads / mystery `loaded=4/6` → human SSH
session" into "the agent log names the exact field, its expected offset, and the kernel's
actual offset." It is also the continuous on-node verification the two PENDING offsets need.

Approaches rejected: **CO-RE** (blocked upstream — recorded as the *successor* end state for
when the Rust toolchain lands field relocations); **build-time codegen** (bakes the builder
kernel's offsets — automates the wrong thing).

## Key decisions (see the [ADR-0014](../adr/0014-behavioral-telemetry-ebpf.md) amendment)
1. **Single source of truth:** a const offset+enum table in `agent/common` (shared `no_std`).
   The eBPF crate's `offset_of!` consts assert `bindings == table` at compile time; the loader
   asserts `table == node-BTF` at load time; transitively `bindings == kernel`. No number lives
   in two places.
2. **Fail-closed on struct-reading probes, fail-open on scalar-only probes.** A mismatched
   field disables the probes that read structs; connect/ptrace/module-load still attach. The
   agent never crash-loops on mismatch — it stays up to report (ADR-0014 degrade-gracefully).
3. **Include the enum check** (`LOADING_MODULE`) — the one constant that is a silent
   misclassification today with no verifier backstop.
4. **No toggle** (correctness guard, not a feature — repo convention).
5. **CO-RE is the recorded successor**, revisited when rustc emits BTF field relocations; the
   preflight then retires with the baked offsets. **Build-time codegen is rejected.**
6. **Correct the stale "CO-RE-relocated at load" comments** in the same change.

## Risks / open items
- aya 0.13 `Btf` API surface for member iteration — worst case a small direct parse of
  `/sys/kernel/btf/vmlinux` (aya-obj is already in the tree). Bounded; settled in the first
  hour of building.
- Anonymous-union members (`i_nlink`): the BTF walk must recurse into anon unions/structs
  accumulating offsets — unit-tested against a fixture BTF blob (plain userspace Rust,
  off-fleet testable).
- The preflight validates *offsets*, not *semantics* (a field whose meaning changes at the
  same offset slips through) — accepted; nothing short of CO-RE + kernel review fixes that.
- Agent-workspace CI is not a required check (known blind spot) — the guard is runtime so it
  doesn't depend on CI; flag making the ebpf job required as adjacent.

## HANDOFF TO PLAN-SPRINT
Theme: **"eBPF offset self-verification — load-time BTF preflight."** One infra PR: the shared
offset/enum table in `agent/common` + the loader preflight (BTF walk, anon-union recursion,
fixture-tested, per-class gating, expected/actual logging, heartbeat surfacing) + resolve the
ON-NODE-PENDING markers + the ADR-0014 amendment + correct the stale CO-RE claims. Panel:
infra (agent workspace / BTF parsing / DaemonSet observability); no product-surface or
data-model change.
