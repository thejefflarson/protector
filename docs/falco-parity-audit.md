# Falco → agent detection-parity audit (Retire-Falco F0 / JEF-316)

Status: research + gap analysis. No code changes. This document is the up-front
enumeration of Falco's detection surface and how each class maps to protector's
first-party eBPF agent, so the Falco retirement is an informed decision, not a
blind one. It complements F6 (JEF-310), which measures corroboration coverage
*empirically* during a bake; F0 (this doc) defines the *complete target* so F6's
"agent-uncovered" count has a known denominator.

The ratified parity bar (F1 / JEF-305, ADR-0014) is **measured decision-path
corroboration coverage — not Falco rule-replication.** Everything below is scoped
to that bar: the question is never "does the agent reproduce this Falco rule?" but
"does this Falco detection ever change a protector *decision*, and if so, does the
agent (today, or via F2/F3/F4/optional) produce the equivalent corroboration?"

---

## 1. Executive summary

**What Falco actually does for protector is far narrower than what Falco can
detect.** Falco ships ~22 stable + ~70 incubating/sandbox rules across a dozen
detection classes (§3). Protector consumes exactly one thing from all of them: a
critical/alert/emergency rule firing collapses to a single `Behavior::Alert { rule }`
(`engine/src/engine/observe/runtime.rs:114-144`). Rule identity is kept for display
and cache-keying only; at the decision layer every Falco alert is an undifferentiated
"something critical is happening on this pod, now" boolean.

**The live cluster confirms the surface is tiny in practice.** Across the three
still-healthy Falco pods (`falco-c5nn2/s7sz8/vlcdk`) over the last 48h, exactly two
distinct rules fired, and only one crosses protector's critical+ ingest threshold:

| Fired rule | Priority | Count (48h) | Crosses protector's threshold? |
|---|---|---|---|
| Drop and execute new binary in container | **Critical** | 127 | **Yes** → `Behavior::Alert` |
| Contact K8S API Server From Container | Notice | 21 | No (dropped below critical) |

So on *this* cluster the entire Falco→protector corroboration signal is one rule:
container drift (drop-and-execute). That is a **GAP today** (the agent has no
file-write/exec-of-written signal) and is precisely what **F2 (JEF-306) + F3
(JEF-309)** are built to cover.

**Verdict (detail in §7):** F2 + F3 + F4 + optional priv-esc cover the
corroboration-relevant Falco critical classes. The one live signal on this cluster
(drop-and-execute) is covered by F2+F3. The remaining Falco criticals are either
covered by an existing agent probe, covered by an in-flight ticket, or legitimately
out-of-scope-by-design (crypto-mining heuristics, fileless/behavioral patterns —
model + proof-winnowing territory per ADR-0013, not corroboration). Two genuine
residual gaps are worth filing as explicit tickets (§8), neither on the retirement
critical path. **Retirement is de-risked; proceed to F6's empirical bake.**

---

## 2. Architecture findings — how Falco works (and why the agent survives where Falco dies)

### 2.1 Drivers (event sourcing)
Falco's syscall event source is produced by one of three interchangeable drivers:
- **Kernel module** (legacy `.ko`) — full kernel access, must be built/loaded per kernel.
- **Legacy eBPF probe** — pre-CO-RE, compiled against kernel headers.
- **Modern eBPF probe (CO-RE)** — bundled into the Falco binary, "Compile Once Run
  Everywhere". Requires a kernel that exposes **BTF** and **BPF ring-buffer** support
  (usually `>= 5.8`). No per-kernel build.

All three attach to **syscall tracepoints**: the modern probe hooks
`SEC("tp_btf/sys_enter")` / `SEC("tp_btf/sys_exit")` (the legacy probe uses
`BPF_PROG_TYPE_RAW_TRACEPOINT` on the same raw syscall tracepoints). This is the
crux of the retirement motivation: **Falco is fundamentally syscall-tracepoint-based.**
Its driver + libsinsp parse the raw syscall ABI, and that parsing breaks on the
`7.0.0-raspi` arm64 kernel this cluster runs — which is why 4 of the 8 Falco pods are
in `CrashLoopBackOff`.

### 2.2 libscap / libsinsp (capture + enrichment)
`libscap` talks to the driver, drains syscall events from the ring buffer. `libsinsp`
enriches them (process tree, container/k8s metadata, fd tables) and exposes the field
API that rules filter on. This is the layer whose syscall-ABI assumptions are
kernel-fragile.

### 2.3 Rules engine
A YAML rule = a `condition` (filter expression over libsinsp fields), an `output`
template, a `priority` (EMERGENCY…DEBUG), and `tags` (MITRE TTPs, `maturity_*`,
`container`/`host`). Falco evaluates every event against every enabled rule.

### 2.4 Plugins (non-syscall event sources)
libscap/libsinsp expose a plugin framework for additional event streams — these are
**audit/log-based, not syscall-based**, so they are kernel-independent:
- **k8saudit** — embeds a webserver, ingests Kubernetes API-server audit-log JSON via
  webhook. Detects RBAC abuse (cluster-admin grants), privileged/hostPath/hostNetwork
  pod creation, `exec`/`attach` into pods, secret/configmap changes, control-plane
  exfil (`kubectl cp`).
- **cloudtrail**, **okta** — AWS / identity audit streams. Not relevant to a
  node-local runtime sensor and out of scope for this cluster.

### 2.5 Outputs
Falco emits to stdout/gRPC and, in this deployment, to **falcosidekick**, which POSTs
each alert as JSON to protector's `/` ingest endpoint (`serve_runtime`,
`runtime.rs:234-241`).

### 2.6 The agent's mechanism (the survivability contrast)
Protector's first-party agent (`agent/protector-agent-ebpf/src/main.rs`) attaches to
**LSM hook functions**, not syscall tracepoints:
- one **kprobe** on `security_socket_connect` (`main.rs:148-206`), and
- four **fentry** (BTF) probes on `security_file_open`, `security_mmap_file`,
  `security_task_fix_setuid`, `security_bprm_check` (`observer.rs:504-509`).

Because it hooks the kernel's *LSM* seam rather than parsing the raw syscall ABI, it
**survives the `7.0.0-raspi` kernel where Falco's driver dies** (`main.rs:12`, "an LSM
hook stable across kernels"). If BTF is unavailable the fentry probes degrade
gracefully and the connect kprobe still runs (`observer.rs:500-524`). This is the
whole reason retirement is on the table — and it is why **F2 (JEF-306) mandates
LSM/kprobe hooks, explicitly NOT syscall tracepoints**, for the new file-write probe.

---

## 3. Falco detection catalogue (the complete target)

Grouped by detection class, with priority and the signal each keys on. The **stable**
set (`falco_rules.yaml`, shipped in the release, `maturity_stable`) is what a default
Falco deployment enforces; the **incubating** set requires explicit opt-in but
enumerates the broader capability the operator asked us to map. Protector's ingest
only ever sees **Critical/Alert/Emergency** (§4), so priority is decision-relevant.

### Class A — File-integrity / container drift
| Rule | Maturity | Priority | Keys on |
|---|---|---|---|
| Drop and execute new binary in container | stable | **CRITICAL** | exec of a binary written to the container upper layer (not in base image) |
| Directory traversal monitored file read | stable | WARNING | `../` traversal reading a monitored file |
| Modify Shell Configuration File | incubating | WARNING | write to `.bashrc`/`.profile` etc. (persistence) |
| Write below binary dir | incubating | (noisy) | write under `/bin`,`/sbin`,`/usr/bin` |
| Write below etc / rc / monitored dir | incubating | varies | write to `/etc`, cron dirs |
| Create Symlink/Hardlink Over Sensitive Files | stable | WARNING | link over `/etc/shadow` etc. |
| Adding ssh keys to authorized_keys | incubating | WARNING | write to `authorized_keys` (persistence) |
| Create files below dev | incubating | ERROR | file creation under `/dev` (rootkit) |
| Schedule Cron Jobs | incubating | NOTICE | cron dir writes |

### Class B — Process / exec anomalies
| Rule | Maturity | Priority | Keys on |
|---|---|---|---|
| Terminal shell in container | stable | NOTICE | interactive shell attached to a tty in a container |
| Run shell untrusted | stable | NOTICE | shell spawned below a protected non-shell parent |
| Fileless execution via memfd_create | stable | **CRITICAL** | exec from an anonymous memory fd (no disk artifact) |
| Execution from /dev/shm | stable | WARNING | exec from shared-memory dir |
| Launch Package Management Process in Container | incubating | ERROR | apt/yum/apk/pip etc. in a container (drift) |
| Launch Suspicious Network Tool (Container/Host) | incubating | NOTICE | nc/nmap/tcpdump recon |
| Launch Remote File Copy Tools in Container | incubating | NOTICE | curl/wget/scp exfil/ingress |
| DB program spawned process | incubating | NOTICE | shell spawned by a DB proc (SQLi aftermath) |
| System user interactive | stable | INFO | non-login system user runs interactive proc |
| Search Private Keys or Passwords | stable | WARNING | grep/find for keys/passwords |

### Class C — Privilege escalation / capabilities / container escape / ptrace
| Rule | Maturity | Priority | Keys on |
|---|---|---|---|
| Detect release_agent File Container Escapes | stable | **CRITICAL** | write to cgroup `release_agent` (escape) |
| Linux Kernel Module Injection Detected | stable | WARNING | `init_module` with CAP_SYS_MODULE |
| Debugfs Launched in Privileged Container | stable | WARNING | debugfs in privileged ctr |
| PTRACE attached to process | stable | WARNING | `PTRACE_ATTACH/SEIZE/SETREGS` (injection) |
| PTRACE anti-debug attempt | stable | NOTICE | `PTRACE_TRACEME` |
| Set Setuid or Setgid bit | incubating | NOTICE | chmod u+s/g+s |
| Non sudo setuid / Non-root→root setuid | incubating | NOTICE | setuid to root outside sudo |
| Change thread namespace (setns) | incubating | NOTICE | `setns` (container escape) |
| Change namespace privileges via unshare | incubating | NOTICE | unprivileged `unshare` |
| Mount Launched in Privileged Container | incubating | WARNING | `mount` in privileged ctr |
| Launch Privileged / Excessively Capable Container | incubating | INFO | privileged / cap-heavy container start |
| Potential Local Privesc via Env Var Misuse | incubating | NOTICE | glibc/`GLIBC_TUNABLES` exploit shape |

### Class D — Network / C2 / reverse-shell / metadata (IMDS) / API server
| Rule | Maturity | Priority | Keys on |
|---|---|---|---|
| Contact K8S API Server From Container | stable | NOTICE | outbound to kube-apiserver from non-profiled ctr |
| Netcat Remote Code Execution in Container | stable | WARNING | `nc -e`/`-c` |
| Redirect STDOUT/STDIN to Network Connection | stable | NOTICE | `dup` of stdio onto a socket (reverse-shell shape) |
| Packet socket created in container | stable | NOTICE | `AF_PACKET` (L2 sniff/spoof) |
| Disallowed SSH Connection Non Standard Port | stable | NOTICE | outbound SSH on odd port |
| Contact EC2/Cloud Instance Metadata Service | incubating | NOTICE | outbound to `169.254.169.254` IMDS |
| Network Connection outside Local Subnet | incubating | WARNING | container egress outside local subnet |
| System procs network activity | incubating | NOTICE | unexpected outbound from a system binary |
| Unexpected UDP Traffic | incubating | NOTICE | non-DNS UDP |
| Exfiltrating Artifacts via K8s Control Plane | incubating | NOTICE | `kubectl cp` exfil |

### Class E — Sensitive file reads (shadow / ssh / cloud creds)
| Rule | Maturity | Priority | Keys on |
|---|---|---|---|
| Read sensitive file untrusted | stable | WARNING | non-trusted proc reads `/etc/shadow`, etc. |
| Read sensitive file trusted after startup | stable | WARNING | trusted server reads sensitive file post-startup |
| Read ssh information | incubating | ERROR | read under `~/.ssh` |
| Find AWS Credentials | stable | WARNING | grep/find for AWS cred files |
| Read environment variable from /proc files | incubating | WARNING | read `/proc/*/environ` |
| Backdoored library loaded into SSHD (CVE-2024-3094) | incubating | WARNING | liblzma xz backdoor load |

### Class F — Defense evasion / data destruction
| Rule | Maturity | Priority | Keys on |
|---|---|---|---|
| Clear Log Activities | stable | WARNING | truncate/`>` a log file |
| Delete or rename shell history | incubating | WARNING | rm/mv of shell history |
| Remove Bulk Data from Disk | stable | WARNING | `shred`/`mkfs`/bulk delete |
| BPF Program Not Profiled | incubating | NOTICE | unprofiled BPF program load |

### Class G — Crypto-mining
No rule in the shipped default (`falco_rules.yaml`) or the incubating set. Historically
Falco shipped an outbound-to-miner-pool / `stratum` rule; it is **not** in the current
maturity_stable or incubating catalogue and is treated by the community as a
heuristic/behavioral add-on. **Out-of-scope-by-design** for corroboration (§6).

> Note on breadth: only the ~6 rules marked **CRITICAL** above (drop-and-execute,
> memfd fileless exec, release_agent escape — plus any operator-added criticals) ever
> reach protector. Everything at WARNING/NOTICE/INFO is dropped at the ingest gate and
> is therefore **decision-irrelevant** regardless of agent coverage.

---

## 4. What protector actually consumes (the corroboration path)

This is the load-bearing narrowing. Falco's whole catalogue funnels to one behavior.

**Ingest + severity gate** — `engine/src/engine/observe/runtime.rs`
- `is_critical_or_higher` (`runtime.rs:114-119`): only `critical | alert | emergency`
  pass. Rationale in-comment: lower priorities "fire constantly on benign activity — a
  postgres health-check shell trips 'Run shell untrusted' at Notice."
- `parse_falco_event` (`runtime.rs:125-145`): parses `priority`, `rule`, and the k8s
  attribution (`output_fields.k8s.ns.name` / `k8s.pod.name`); drops anything below
  critical or lacking pod attribution (`alert_without_pod_metadata_is_dropped`).
- Result: every Falco alert becomes `RuntimeObservation { behavior: Behavior::Alert
  { rule }, source: "falco", attribution }` (`runtime.rs:137-144`). **All rules
  collapse to one variant.** The comment is explicit: "the first-party eBPF agent
  posts the richer behaviors directly."

**What an Alert then *does* to a decision** — three consumers, two definitions:
1. `reason/proof/corroborate.rs:36-75` — `corroborates()`. `Behavior::Alert => true`
   for **any** objective (`:40`): a Falco critical is blanket corroboration. This sets
   the `corroborated` flag on a proven chain (shadow-only; "inert for actuation",
   `:32-35`).
2. `reason/proof/chain.rs:359-365` — `actively_exploited()` (JEF-284): true if a
   workload's runtime signals include `is_alert()` **or** `notable_exec(..)`. Feeds
   `QuarantineReason::ActivelyExploited`, which outranks the static-CVE bar
   (`chain.rs:398-444`). A live Falco critical on any pod on the chain warrants
   full-isolation quarantine independent of network reachability.
3. `reason/adjudicate/guards.rs:117-159` — `corroborating_behavior()` =
   `is_alert() || notable_exec(..)`. `guard_unsupported_exploitable` downgrades a
   model `Exploitable` verdict to `Refuted` only when there is no CVE, no exposed
   secret, **and** no corroborating behavior. A Falco alert protects an `Exploitable`
   verdict from the deterministic backstop.

**Bottom line:** the Falco signal a protector *decision* turns on is the
`Behavior::Alert` boolean (blanket corroboration + active-exploitation + verdict
anchor). Rule identity is retained only for display and the verdict-cache fingerprint,
never for decision branching. **Parity therefore means: reproduce the Alert-equivalent
corroboration for the critical classes that fire — not port the ruleset.**

---

## 5. What the agent emits today

`Behavior` enum (`behavior/src/lib.rs:21-58`), 7 variants:

| Variant | Emitted by (probe → LSM hook) | Corroboration meaning today |
|---|---|---|
| `Alert { rule }` | *(Falco only; agent emits none)* | blanket, any objective (`corroborate.rs:40`) |
| `NetworkConnection { peer, internet }` | `connect` kprobe → `security_socket_connect` | only Exfiltration, and only if `internet` (`:44-46`) |
| `SecretRead { secret, source }` | `file_open` fentry → `security_file_open` (tmpfs only) | only CredentialAccess (`:49`) |
| `LibraryLoaded { name }` | `mmap_file` fentry → `security_mmap_file` (PROT_EXEC) | only InitialAccess (`:54`) |
| `FileRead { path }` | transport stage of `file_open` | never (refined to SecretRead or dropped, `:57`) |
| `PrivilegeChange { from_uid, to_uid }` | `fix_setuid` fentry → `security_task_fix_setuid` (→root only) | **never** — model-evidence only (`:73`) |
| `ProcessExec { path }` | `bprm_check` fentry → `security_bprm_check` | blanket **iff** `notable_exec` is Some (`:67-69`) |

**Notable-exec** (`engine/src/engine/observe/exec_class.rs`, kept out of the wire type
per JEF-113) classifies on basename: `INTERACTIVE_SHELLS` (`sh,bash,zsh,ash,dash`) →
Falco "Terminal shell in container" parity; `PACKAGE_MANAGERS` (`apt,apt-get,apk,yum,
dnf,pip,pip3,gem,npm`) → Falco "package management launched" parity. A notable exec is
the agent's existing **blanket** ("any objective") corroborator — the direct analogue
of a Falco `Alert`.

Key asymmetry: the agent has **no `Alert` emitter and no `FileWrite`**. Its only
blanket corroborator is notable-exec. Everything else corroborates one tactic only.
That is exactly the surface F2/F3/F4/optional target.

---

## 6. Coverage matrix (Falco class → agent coverage)

Legend: **[E]** existing agent probe · **[F2]** JEF-306 file-write/drift ·
**[F3]** JEF-309 alarming-now classifier · **[F4]** JEF-307 engine-side peer
classification · **[opt]** JEF-314 priv-esc · **[GAP]** needs new work ·
**[OOS]** out-of-scope-by-design (model + proof, ADR-0013 — not corroboration).

| # | Falco detection class (representative critical/notable rules) | Decision-relevant? | Agent coverage | Notes |
|---|---|---|---|---|
| A1 | **Drop and execute new binary in container** (CRITICAL) — *the only critical firing on this cluster* | Yes | **[F2]+[F3]** | F2 emits `FileWrite`; F3 promotes drift-write + exec-of-just-written to blanket corroboration. This is the live gap the epic is built around. |
| A2 | Modify shell config / write below bin / write to /etc / cron / authorized_keys / symlink-hardlink over sensitive | Only at critical (mostly WARNING/NOTICE — dropped) | **[F2]+[F3]** | Covered by F2's write probe + F3's sensitive-path policy where an operator raises priority to critical. Sub-critical variants never reach protector. |
| A3 | Create files below /dev (ERROR, rootkit) | If raised to critical | **[F2]+[F3]** | Same write-probe path; niche. |
| B1 | **Terminal shell in container** / Run shell untrusted | Yes (via notable-exec) | **[E]** | `notable_exec` interactive-shell arm = blanket corroboration (`corroborate.rs:67`). Explicit parity. |
| B2 | **Launch package management in container** (ERROR) | Yes (via notable-exec) | **[E]** | `notable_exec` package-manager arm. Explicit parity. |
| B3 | **Fileless execution via memfd_create** (CRITICAL) | Yes | **[GAP]** | Agent's `bprm_check` sees `execve` of a real path; a memfd/anonymous-fd exec has no path artifact and would not classify as notable-exec or FileWrite. No single-probe equivalent today. → **new ticket (§8, G1).** |
| B4 | Suspicious network / remote-file-copy tools, DB-spawned proc, /dev/shm exec | Rarely critical | **[OOS]** / partial [E] | Named-binary heuristics; the exec is visible to `bprm_check` but only shell/pkg-mgr are notable. Behavioral-list territory — model + proof, not corroboration. |
| C1 | **release_agent container escape** (CRITICAL) | Yes | **[F2]+[F3]** | It is a *write* to the cgroup `release_agent` file — F2's write probe sees it; F3 can treat that path as sensitive. |
| C2 | **setuid → root** (privilege escalation) | Yes | **[opt]** | Agent *emits* `PrivilegeChange` (→root) but it is non-corroborating today (`corroborate.rs:73`). JEF-314 corroborates it when the entry is the proven internet-facing foothold. |
| C3 | ptrace inject / kernel-module inject / setns / unshare / mount / debugfs / privileged-container start | Mostly WARNING/INFO (dropped); a few could be raised | **[GAP]** (ptrace/kmod at critical) / **[OOS]** (the INFO posture rules) | No agent probe hooks `ptrace`/`init_module`/`setns`. Container-config postures (privileged/capable) are admission-time facts, not runtime corroboration. → **new ticket (§8, G2)** for the ptrace/kmod-inject critical shapes. |
| D1 | **Contact IMDS / cloud metadata** (169.254.169.254) | Yes | **[F4]** | Agent sees a plain `NetworkConnection`; node-local it can't know the peer is IMDS. F4 classifies engine-side (informer-backed) and corroborates the foothold. |
| D2 | **Contact K8s API server from container** — *fired 21× on this cluster (Notice → dropped)* | Only if raised to critical | **[F4]** | Same engine-side peer-classification path. Currently sub-critical so decision-irrelevant here. |
| D3 | **Reverse shell** (dup stdio→socket / `nc -e`) | Yes | **[F4]** (shape) | F4's optional reverse-shell shape: outbound from an internet-facing entry closely following a notable exec. FP risk — F4 gates it on F6 evidence. |
| D4 | Outbound outside subnet / unexpected UDP / packet socket / SSH odd port | Mostly WARNING/NOTICE | **[F4]** partial / **[OOS]** | IMDS/API/cross-tenant covered by F4; generic egress deliberately NOT widened (every workload connects — ADR-0014). |
| E1 | **Read sensitive file untrusted** (/etc/shadow etc.) | Yes | **[E]** partial + **[GAP]** | Agent's `SecretRead` covers **tmpfs-mounted** secrets (k8s secret mounts) → CredentialAccess corroboration. On-host paths like `/etc/shadow`, `~/.ssh` are **not** covered (probe filters to tmpfs superblock). → **new ticket (§8, G3).** |
| E2 | Find/read AWS creds, ssh info, /proc/environ | Mostly WARNING | **[E]** partial / **[OOS]** | Mounted cloud-cred secrets covered as SecretRead; grep/find heuristics are behavioral (OOS). |
| E3 | Library load — backdoored liblzma (CVE-2024-3094) | Yes | **[E]** | Agent `LibraryLoaded` (PROT_EXEC mmap) → InitialAccess corroboration. Vuln-pruned upstream. |
| F1 | Clear logs / delete history / bulk data destruction | WARNING (dropped) | **[OOS]** | Anti-forensics heuristics; not a corroboration anchor. Model/proof territory. |
| G1 | Crypto-mining | n/a (no shipped rule) | **[OOS]** | Behavioral/heuristic; ADR-0013 — model + proof-winnowing, explicitly not corroboration. |

---

## 7. Retirement-readiness verdict

**Does F2 + F3 + F4 + optional cover the corroboration-relevant Falco critical set?
Yes, for everything that actually changes a protector decision on this cluster and for
the shipped critical catalogue — with three small, off-critical-path residual gaps.**

Reasoning:
- **The only Falco signal live on this cluster** (drop-and-execute, 127 firings) is
  covered by **F2 + F3**. The other fired rule (K8s API contact) is Notice → dropped;
  if ever promoted to critical, **F4** covers it. So empirically, F2+F3(+F4) achieve
  parity for *what Falco is currently telling protector*.
- **The shipped CRITICAL catalogue** maps cleanly: drop-and-execute → F2+F3;
  release_agent escape → F2+F3; interactive-shell/pkg-mgr (notable) → existing agent;
  IMDS/API/reverse-shell → F4; setuid→root → optional. The **one shipped critical with
  no clean mapping is memfd fileless exec** (B3) — a real but narrow gap (§8 G1).
- **Everything Falco detects at WARNING/NOTICE/INFO never reaches protector** and is
  decision-irrelevant by construction (§4 gate). No agent work is owed for it.
- **Out-of-scope-by-design is principled, not a punt:** crypto-mining, anti-forensics,
  suspicious-tool/name heuristics, and fileless/behavioral patterns with no
  single-probe equivalent are ADR-0013 territory — the model reasons over them and
  proof-winnowing decides; they were never corroboration anchors even with Falco.

**Genuine residual gaps (all off the retirement critical path — see §8):**
1. **memfd/fileless exec** (B3) — no path artifact for `bprm_check`/FileWrite. Narrow.
2. **On-host sensitive-file reads** (E1) — `SecretRead` is tmpfs-mounted-secret only;
   `/etc/shadow`, `~/.ssh` on the host filesystem are not seen.
3. **ptrace / kernel-module injection at critical** (C3) — no agent probe on
   `ptrace`/`init_module`.

None of the three is currently firing on this cluster, none is in the default critical
set except memfd (rare), and each is a small follow-on probe/classifier — not a
blocker. **Recommendation: proceed with the retirement sequence. Let F6's empirical
bake confirm the agent-uncovered count against this known denominator, and file the
three gap tickets below so they are tracked rather than discovered at the gate.**

---

## 8. Recommended new gap tickets (to file)

These are the rows the matrix marks **[GAP]** and not already owned by F2/F3/F4/opt.
Titles + one-line problem statements; all shadow-gated, corroboration-path, LSM/kprobe
(never syscall tracepoints), zero-egress.

- **[Retire-Falco G1] Agent probe/classifier for fileless exec (memfd_create / anonymous-fd execve)**
  — Falco fires *critical* on `memfd_create`-backed execution; the agent's
  `security_bprm_check` sees a real path and an anonymous-fd exec produces no FileWrite
  or notable-exec artifact, so this critical has no corroboration equivalent.
- **[Retire-Falco G2] Agent probe for code-injection / kernel-tamper (ptrace attach, init_module)**
  — Falco flags `PTRACE_ATTACH/SETREGS` injection and `CAP_SYS_MODULE` kernel-module
  loads; no agent LSM hook covers `security_ptrace_access_check` / `security_kernel_module_request`,
  so these criticals map to nothing.
- **[Retire-Falco G3] Extend SecretRead to on-host sensitive paths (/etc/shadow, ~/.ssh)**
  — the `file_open` probe filters to the tmpfs superblock (k8s mounted secrets), so
  Falco's "read sensitive file untrusted" for host-filesystem credential files has no
  agent-side CredentialAccess corroboration.

Each is optional relative to F7's retirement gate (the live cluster fires none of
them); file them so the residue is tracked, and let F6's evidence set priority.

---

## 9. Sources

Falco:
- [Falco libs (libsinsp/libscap/drivers)](https://github.com/falcosecurity/libs)
- [Falco — Kernel event sources / drivers](https://falco.org/docs/concepts/event-sources/kernel/)
- [Falco — modern eBPF probe proposal](https://github.com/falcosecurity/libs/blob/master/proposals/20220329-modern-bpf-probe.md)
- [Falco — tracing syscalls using eBPF (tp_btf/sys_enter,sys_exit)](https://falco.org/blog/tracing-system-calls-using-ebpf-part-2/)
- [Falco — plugins](https://falco.org/docs/concepts/plugins/) · [k8saudit](https://falco.org/docs/concepts/event-sources/plugins/kubernetes-audit/)
- [falco_rules.yaml (stable default set)](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- [falco-incubating_rules.yaml (broader catalogue)](https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml)
- [Falco default rules / maturity levels](https://falco.org/docs/reference/rules/default-rules/)

Live cluster: `kubectl -n security logs {falco-c5nn2,falco-s7sz8,falco-vlcdk} -c falco --since=48h`
(only `Drop and execute new binary in container` [Critical] and `Contact K8S API Server From Container` [Notice] fired).

Protector (file:line):
- Ingest/gate: `engine/src/engine/observe/runtime.rs:114-145`, `:234-241`
- Corroboration: `engine/src/engine/reason/proof/corroborate.rs:36-98`
- Active exploitation: `engine/src/engine/reason/proof/chain.rs:359-365`, `:398-444`
- Adjudication guards: `engine/src/engine/reason/adjudicate/guards.rs:117-159`
- Behavior type: `behavior/src/lib.rs:21-58`, `:103-105`
- Notable-exec: `engine/src/engine/observe/exec_class.rs`
- Agent probes: `agent/protector-agent/src/observer.rs:86`, `:504-509`; `agent/protector-agent-ebpf/src/main.rs:148-337`
- Parity bar / non-corroboration residue: ADR-0014 (behavioral telemetry eBPF), ADR-0013 (proof winnows, model decides)

Epic tickets: F0 JEF-316 · F1 JEF-305 · F2 JEF-306 · F3 JEF-309 · F4 JEF-307 ·
optional JEF-314 · F6 JEF-310.
