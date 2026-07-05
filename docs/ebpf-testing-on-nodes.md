# Testing eBPF probes on the homelab nodes

How to validate a new eBPF probe (e.g. the secret-read probe, ADR-0014) on the actual
cluster, given two hard constraints:

- **No SSH / no `kubectl exec` into the nodes or the prod agent.** Node-level shell and
  prod-pod exec are denied. So we cannot interactively load-test a probe on a Pi.
- **eBPF can't be compiled or load-tested locally** (macOS): no bpf-linker, and aya's
  userspace loader is Linux-only. Every iteration goes through a CI image build.

The agent itself is therefore the test vehicle, and its **stdout logs** (readable with
`kubectl logs`, a normal read) are the validation channel.

## Node facts (verified 2026-06-20)

| Fact | Value | Source |
|------|-------|--------|
| Kernel | `6.8.0-1057-raspi`, **arm64** | `kubectl get nodes -o custom-columns=...kernelVersion` |
| OS | Ubuntu 24.04.4 LTS | same |
| vmlinux BTF | **present** | the agent already mounts `/sys/kernel/btf` and runs |
| kprobe + ring buffer + BPF caps | **work** | the connect probe is deployed and capturing |

6.8 arm64 + BTF means **fentry/fexit and `bpf_d_path` are available** — modern, not the
constrained environment older Pi kernels would be.

## Mechanism for path-bearing probes (secret-read, library-load)

The secret-read probe must read the *path* of an opened file (a secret mount lives at
`…/kubernetes.io~secret/<name>/…`). Path reconstruction is kernel-side. Options, best
first for this kernel:

1. **fentry on `security_file_open(struct file *file)` + `bpf_d_path(&file->f_path,…)`**
   — BTF-aware, clean. Needs vmlinux struct bindings for `struct file` so the probe can
   take the address of `f_path` (CO-RE-relocated). Does **not** require BPF-LSM to be in
   the active `lsm=` list, which is why it's preferred over option 2.
2. **`lsm/file_open`** — simplest code, but requires `CONFIG_BPF_LSM=y` **and** `bpf` in
   the kernel's active LSM list (`/sys/kernel/security/lsm`). Ubuntu ships the config but
   whether `bpf` is in the active list is unconfirmed (couldn't read it without node
   access). Fallback if fentry's `bpf_d_path` is rejected.
3. **kprobe + manual dentry walk** — no `bpf_d_path` (it's not allowlisted for classic
   kprobes), so you'd walk `dentry`→`d_parent` by hand. Fragile; last resort.

**vmlinux bindings:** `agent/protector-agent-ebpf/src/vmlinux.rs` is a small hand-written
module declaring only the structs the probes read, each field placed at its running-kernel
byte offset. It is NOT the full `aya-tool` dump (that exceeded the 1,000-line file cap and
silently rotted across kernel upgrades). Critically there is **no CO-RE field relocation**
here — the bpf object bakes each field access as a constant offset — so the offsets in that
file MUST match the fleet kernel or `bpf_d_path` is verifier-rejected (JEF-324). Re-verify
on any kernel struct change by dumping BTF from a node (`kubectl` a hostPath-`/sys/kernel/
btf` pod, then `bpftool btf dump … format c`, or parse the raw BTF) on **every** fleet arch
and confirming the read fields share one offset. As of 2026-07-05 the fleet is `7.0.0`
(arm64 raspi + amd64 generic) and all read fields align across both arches.

## The validation loop (no exec, no SSH)

1. **Write the probe self-validating.** On attach, log `info` (`attached fentry …`). For
   the first N file opens, log the captured path at `info` *before* any filtering — this
   proves both that the probe attached on the kernel and that `bpf_d_path` returns real
   paths. Only then narrow to secret-mount paths and emit `SecretRead`.
2. **Ship it isolated, not in the prod agent path.** Gate the experiment behind an env
   flag (e.g. `PROTECTOR_AGENT_PROBE_SPIKE=1`) or a separate short-lived
   `protector-agent-spike` DaemonSet, so a probe that fails to load or floods logs can't
   disturb the live collector. The agent already degrades-not-crashloops on attach
   failure, so a bad probe leaves the pod up for inspection.
3. **CI compiles it** (`agent.yml` `ebpf` job on `protector-runners`) — catches anything
   that doesn't build for the bpf target, before it ever deploys.
4. **Deploy** (bump the agent image tag) and **read logs**:
   `kubectl -n protector logs -l app.kubernetes.io/name=protector-agent -c agent`.
   - `attached fentry on security_file_open` → the hook loaded on this kernel.
   - sample path lines → `bpf_d_path` works; confirm secret mounts show
     `…/kubernetes.io~secret/…`.
   - the engine's `runtime behavioral signals attached=N` line confirms
     the end-to-end `SecretRead`.
5. **Promote**: drop the verbose path logging, keep the secret-mount filter + emission,
   remove the spike gate.

## Open questions the first spike deploy answers

- Does `fentry` attach to `security_file_open` on `6.8.0-raspi`? (Expected yes.)
- Is `bpf_d_path` accepted by the verifier for that hook's `file` arg? (The kernel keeps
  an allowlist; this is the main thing to confirm on-node.)
- Are secret volume mounts visible as `kubernetes.io~secret` paths from the probe?

If `bpf_d_path` is rejected, fall back to `lsm/file_open` (after confirming `bpf` is in
`/sys/kernel/security/lsm`) or the manual dentry walk.
