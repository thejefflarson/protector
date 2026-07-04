# 0020. Supply-chain trust is signature continuity, not prefix-gated single-identity

- Status: Accepted
- Date: 2026-06-29

## Context

The admission webhook's [`SignaturePolicy`](../../engine/src/policies/signature.rs)
answers one narrow question: *are **my** images signed by **me**?* It is configured
with `PROTECTOR_GATED_PREFIXES` (the image-ref prefixes to check) and a single
`PROTECTOR_IDENTITY_REGEXP` (one trusted cosign/Fulcio signer). An image whose ref
matches a gated prefix must carry a signature from that one identity or it fails;
**every other image is `NotApplicable`** — not checked, no opinion.

That shape has three problems, and they compound:

1. **No visibility.** Because anything outside the prefix is `NotApplicable`, the
   operator cannot see the signing posture of the cluster at all. The Admission view
   shows `n/a` for almost every workload (third-party images, and everything when
   gating is unconfigured), and `n/a` + "would admit" reads like a green stamp when
   in fact nothing was inspected. There is no inventory of *which images are signed,
   and by whom*.

2. **Single-identity is the wrong trust topology.** Real clusters run images signed
   by many legitimate publishers — distroless by Google, linkerd by Buoyant,
   Chainguard images by Chainguard, our images by our own workflows. A single
   org-wide identity regexp can only ever vouch for *our* images; it has nothing to
   say about the upstream dependencies that make up most of the attack surface, so
   they all fall to `NotApplicable`.

3. **It cannot catch the actual attack.** The supply-chain threat that matters is
   **a repository that was serving signed images suddenly serving an unsigned one**
   (or one signed by a *different* identity) — the signature of an attacker who
   obtained push access to that registry/repo. A prefix-gated single-identity gate
   is structurally blind to this: an upstream repo it never gated stays `n/a` before
   and after the compromise; the signal — *loss of an established signature* — is
   exactly what the model never records and therefore can never miss-or-catch.

The current gate is a fine *enforcement primitive* but the wrong *model*. It treats
signing as a static per-image allow-rule, when the security-bearing fact is a
**change** in signing posture over time.

This is the same shape as the rest of protector. ADR-0016 established the engine's
thesis: don't alarm on static posture, **observe a baseline and treat the deviation
as the signal** — reachability is potential, the runtime/enrichment *change* is what
the model judges. Signing posture is no different: a signed→unsigned regression on an
established repo is supply-chain *drift*, the direct analogue of the behavioral drift
the runtime side already corroborates on.

A technical enabler makes the broader model feasible without a hand-built trust map
for the entire ecosystem: the `sigstore` crate already vendored for `CosignChecker`
can fetch an image's signature layers and read the **Fulcio certificate subject**
(signer identity + OIDC issuer) *without* committing to a trusted identity up front.
We can therefore record "repo `R` signed by `<identity>` via `<issuer>`" for **any**
image by observation, and let trust be *learned* (Trust On First Use) rather than
pre-declared.

## Decision

**Supply-chain trust is modeled as signature continuity, observed for every image and
learned per source — not as a prefix-gated check against one identity.** Three layers
(plus a cross-cutting transparency-log check, point 4), each a strict superset of what
the old gate did, rolled out audit-first to honor the shadow invariant (ADR-0016: the
engine proposes, it never acts by surprise).

1. **Observe every image (no trust config required).** For each image admitted *and*
   already running (the engine watches Pods; existing workloads are swept through the
   same observer, not just new admissions), record its signing posture: signed or not,
   and — when signed — the signer identity + OIDC issuer read from the cert subject.
   This is pure observation; it requires no `gated_prefixes` and no trusted identity,
   and it is what the Admission view renders as a real per-image *"signed by `<id>` /
   unsigned"* column for **all** images.

2. **Learn a per-repo baseline (TOFU).** Persist, durably (alongside the decision
   journal, so it survives restarts), a signing history keyed by **repository**
   (`registry/repo`): the identity/issuer set observed signing images from that source,
   and whether that source has an established signed history. A new *digest* under a
   repo is normal (that is every deploy); the baseline is about the *source*, not the
   tag or digest.

3. **Detect drift and decide (the breach-relevant signal).** A **signing regression**
   — an image from a repo with an established signed history that arrives *unsigned*,
   or signed by an *identity not previously seen for that repo* — is surfaced as a
   finding and, in enforced scope, blocked. Known-benign exceptions (a publisher that
   legitimately stopped signing, a deliberate signer rotation) are managed by an
   explicit pin/acknowledgement, not by disabling the signal.

4. **Verify against the public transparency log (Rekor) — sanctioned egress.** Cosign's
   keyless verification *already* checks Rekor: an image's signer identity only resolves
   if the signature's inclusion proof verifies against the public transparency log, so
   layer 1's observation inherently consults Rekor. We go further and use Rekor as an
   authoritative **history** source, in two ways that materially strengthen the model:
   (a) **bootstrap the baseline** for a repo from Rekor's append-only signing history —
   so a repo arrives with real provenance going back to day one, instead of TOFU's "trust
   whatever we first locally saw" (this is the direct fix for the cold-start weakness in
   the Consequences below); and (b) **detect registry↔log divergence** — a signature
   present in Rekor while the registry serves an unsigned/different image (or the reverse)
   is tampering that neither source reveals alone. This is a **deliberate, operator-
   accepted exception to the zero-egress posture (ADR-0015), recorded in that ADR's
   amendment.** It is the *milder* leak ADR-0015 distinguishes: a Rekor lookup keyed on an
   image digest/identity leaks *which images the cluster runs* to the public log operator —
   image identifiers that are already public (pulled from public registries) — **not** the
   cluster's vulnerability profile (the per-CVE leak ADR-0015 rejected) and **not** the
   security graph or evidence (which still never leave). A self-hosted Rekor mirror erases
   even the identifier leak for operators who want full zero-egress.

The old prefix-gated single-identity gate becomes **one pinned special case** of layer
3: "repo prefix `ghcr.io/<org>` must always be signed by identity `X`" is a manually
asserted baseline, equivalent to what TOFU would learn but declared up front. We keep
that as an available pin; we no longer make it the whole model.

Enforcement stays opt-in per scope (`PROTECTOR_ENFORCE_*`), audit-everywhere by
default, exactly as today. Signature verification continues to use the already-
sanctioned outbound path (the registry the cluster already pulls from + sigstore
TUF/Rekor) — this is the existing ADR-0015 exception for advisory/verification data,
now exercised for every distinct image rather than only gated ones, bounded by the
existing verification cache and `PROTECTOR_MAX_IMAGES` cap. The security graph and
evidence still never leave the cluster.

## Consequences

What becomes easier:

- **Real supply-chain visibility.** The operator can finally see, in audit mode, which
  images across the cluster are signed and by whom — the question the old model could
  not answer for anything outside its prefix.
- **The repo-compromise attack becomes catchable.** A signed→unsigned (or signer-change)
  regression on an established source is precisely the push-access-compromise signal,
  and it is now a first-class finding instead of structurally invisible.
- **Trust scales to the real dependency set** without a hand-maintained identity map:
  upstream publishers' identities are learned by observation; only exceptions need a pin.
- **One coherent thesis.** Signing drift joins reachability and behavioral drift under
  ADR-0016 — the model decides on a *deviation*, not on static posture — so the Admission
  surface stops being a special-case allow-list and becomes another evidence channel.

What becomes harder / the downsides we accept:

- **More verification work.** Inspecting every distinct image's signature is more
  outbound verification than gating a prefix. Bounded by the verification cache + the
  `MAX_IMAGES` cap, but it scales with the number of distinct images, not with our org.
- **TOFU cold-start is trust-on-*first*-use — but Rekor narrows it.** Absent the
  transparency-log bootstrap, an image malicious *before* protector first observed it
  looks clean: the baseline is "what we first saw," not ground truth. The Rekor history
  bootstrap (Decision §4) closes most of this gap — a repo's signing provenance is read
  from the public log going back to day one, not just our local observation window — so
  a freshly-deployed protector inherits real history instead of starting blind. What
  remains is the genuinely irreducible case: a repo with *no* public signing history at
  all (never signed anywhere), where first-local-observation is still the only baseline
  and only a pin asserts ground truth. A freshly-learned, Rekor-unbacked baseline is
  surfaced as weaker evidence than an aged or log-corroborated one.
- **False positives on legitimate change.** A publisher that stops signing, or rotates
  signing identity, trips the regression signal. We accept this and manage it with an
  explicit pin/ack, deliberately *not* a global off-switch — silencing the channel must
  be a scoped, recorded decision, never the default.
- **New durable state.** The per-repo signing baseline must persist and be reasoned
  about (keying granularity, eviction, replay on boot) — net-new state on the same
  footing as the decision journal.
- **Keying is a judgement call.** Repo-level baselines can miss a per-tag distinction
  and can over-trust a repo that legitimately serves a mix; the staged rollout starts
  at repo granularity and revisits if observation shows it is too coarse.

## Addenda (JEF-263 — durable TOFU baseline implementation)

These ratify the two implementation decisions the durable baseline (Decision §2)
required but did not pin. Both preserve the invariant that the *established* signed
history — the security-bearing state — is the thing that must never be silently lost.

1. **Eviction = per-pass full-state compaction in the journal + a bounded in-memory
   store.** Each baseline is written as a full-state, last-write-wins journal line and
   *every* live repo is re-appended each sweep pass, so a live baseline can never age
   out of the journal's rotation window (the negative-control test proves a
   write-once line does age out). In memory the store is capped at
   `DEFAULT_MAX_REPOS` (4096); when a new repo would exceed the cap, a
   **non-`established`** entry is evicted first (cheap to re-learn), least-recently-
   updated among candidates, so a matured baseline is never dropped in favour of churn.
   Full (not change-only) compaction is deliberate and load-bearing: change-only
   compaction would let an unchanged-but-live established baseline age out. The cost is
   bounded — tens-to-low-hundreds of small lines per pass — and accepted.

2. **`established` = 24h wall-clock age from `first_seen`, not a digest/observation
   count.** The first observation is the weakest evidence (it may be the attacker's
   first signed push), so trust matures over time rather than on a counter an attacker
   could inflate by burst-pushing many digests. Wall-clock age needs no extra durable
   state (`first_seen_ms` is already persisted) and is monotonic — once established, a
   later observation never un-establishes. A digest-count or distinct-day refinement
   remains a future option; `established` + `first_seen` are exposed so the render
   (JEF-262) and drift (JEF-264) work can weigh the distinction as they choose.

Follow-up to monitor (not a blocker): per-pass full compaction shares the single
decision journal with breach/admission lines, so it raises write volume and
accelerates rotation of those other line kinds. Bounded by `DEFAULT_MAX_REPOS` and
acceptable at current scale; revisit change-only or a segmented journal if a large
cluster shows rotation pressure on breach/admission history.

## Addenda (JEF-280 — drift is baseline-relative; downgrade is a first-class regression)

The honest-posture split (JEF-276) added two *calm* signing postures — `SignedKeyBased`
(a real key-based cosign signature: verified Rekor bundle, no Fulcio identity) and
`UnverifiableHere` (a signature present but unverifiable against our trust root, a
Rekor/TUF variance) — so a legitimately key-based repo (e.g. cert-manager) stops
false-alarming. But the first drift classifier read those postures **baseline-blind**:
BOTH always classified `Continuous`. That reopened the exact hole this ADR set out to
close. On an **established keyless-signed** repo (baseline = signed-by-identity-`X`), an
attacker who compromises the registry could substitute a malicious image signed
*key-based*, or verified only against a *rogue Rekor* (→ `UnverifiableHere`), and the
drift alarm stayed silent — a **detection-evasion** of the regression signal (worst in
audit mode). `unsigned→NotSigned` and `keyless→new-identity` were already caught; the
key-based / unverifiable *downgrade* was not.

These addenda ratify the fix. They change **drift classification only** — the per-image
posture and the trust/admit semantics (JEF-276) are untouched: the calm postures still
confer no trusted identity and still `would_admit() == false`.

1. **Drift is baseline-RELATIVE, ranked.** Each signing posture has a trust-strength
   **rank**: `keyless-verified > key-based > unverifiable > unsigned`. The rank of the
   strongest posture ever learned under a repo is persisted in the baseline (a new
   `#[serde(default)]` field on the baseline record + its journal line; an absent rank
   replays as `Keyless`, the honest historical value — the store only ever learned from
   keyless `Signed` postures). `Continuous` now means "did NOT drop rank vs the
   established baseline." A fresh posture whose rank is strictly **below** the baseline's
   is a downgrade.

2. **Signing downgrade is a first-class regression class.** An established **keyless**
   baseline now serving a lesser-but-calm posture (`SignedKeyBased` / `UnverifiableHere`)
   fires a new `SigningDowngrade` regression — the registry-substitution signal. It rides
   JEF-264's admission-finding path (audit-only, shadow; ADR-0016) and feeds the honesty
   model exactly as other regressions do: an **established** baseline → breach/non-green;
   a **cold / freshly-learned** one → uncertain/non-green (never silent). A repo that was
   **always** key-based (no keyless baseline was ever learned) serving key-based stays
   `Continuous` — the JEF-276 false-alarm fix is preserved, because there is no stronger
   baseline rank to drop from.

3. **TUF-staleness is surfaced, never silent.** `UnverifiableHere` is caused by a
   sigstore trust-root mismatch, so a **stale or starved** TUF root (`PROTECTOR_TUF_CACHE`)
   can *mass-blind* detection (genuine signatures read unverifiable, downgrade detection
   loses its keyless yardstick). Readiness now carries a **trust-root** row: the cache age
   (newest-mtime) with a stale warning, and a non-green degrade when a **fleet-wide spike**
   in `UnverifiableHere` this pass hints the root drifted or is being starved. This is a
   read-only readiness signal (ADR-0016), never a gate. The staleness threshold (a coarse
   wall-clock age on the cache) and the spike heuristic (a fraction of the fleet above a
   small floor) are deliberately simple; parsing the TUF expiry and tracking a historical
   unverifiable-rate delta are future refinements.

## Addenda (JEF-275 — provenance is a second continuity axis)

A cosign signature proves *who* signed an image; SLSA **build provenance** proves *how it
was built* — the source repository and the builder/workflow (a GitHub Actions OIDC
workflow) that produced it. Signature continuity (this ADR) and provenance continuity are
the same idea on two axes: **observe → learn a per-repo TOFU baseline → treat a deviation
on an established baseline as the signal.** This addendum extends the family to the
provenance axis. It changes **observation + drift only** — it adds no enforcement and no
new egress path.

1. **Observe every image's provenance posture.** The same production verifier
   (`CosignChecker`) fetches an image's cosign-attest SLSA provenance attestation on the
   SAME sanctioned registry/sigstore round trip as signature verification (§4/ADR-0015 —
   `trusted_signature_layers` already returns any attached in-toto/DSSE attestation layer;
   there is **no second verifier and no new egress**). The DSSE envelope + Fulcio cert are
   verified exactly as a signature is, and the in-toto/SLSA predicate (v0.2 and v1) is
   parsed for the source repo + `builder.id`. Every image resolves to one of four honest
   resting states, mirroring the signing split: `Verified` (the one trusted-build state),
   `Unverifiable` (attestation present but not verified here / no builder id), `Absent`
   (no provenance — the common case today), and the transient `Checking`. **Absent is
   calm, never n/a and never an alarm** — like a never-signed image — but it is likewise
   **never read as a trusted build**.

2. **TOFU-learn the provenance identity per repo.** The learned `(source_repo, builder)`
   folds into the SAME per-repo baseline record + its journal line as the signer
   identities — two new `#[serde(default)]` fields (`provenance_sources`,
   `provenance_builders`), so older journal lines replay with an empty (cold) provenance
   axis, never a fabricated one. Learning is **augment-only**: provenance folds into a
   baseline already taught by a keyless `Signed` posture; it never *creates* a baseline on
   its own, so the signature-baseline invariants (rank, `established` maturation) are
   untouched. A repo with no signing baseline therefore has a **cold** provenance axis —
   its provenance drift is a weak lead, never a silent miss.

3. **Provenance change is a drift class on JEF-264's audit channel.** A verified
   provenance whose source or builder is **not** in an established repo's learned set fires
   a **provenance-change** finding — the "built by an unexpected workflow / from an
   unexpected source" signal — distinct in reason from a signing regression (a repo can
   carry both). It rides the same admission-finding path (audit-only, shadow; ADR-0016):
   an **established** baseline → strong signal; a **cold** one → a weak lead, never silent
   — exactly the baseline-relative semantics JEF-280 established. Absent / unverifiable /
   checking never fire a change.

4. **Off by default; degrades cleanly.** The provenance sweep is opt-in
   (`PROTECTOR_PROVENANCE_ENABLE`, mirroring the Rekor lane), so the default posture adds
   **zero egress** beyond the signing sweep, and an image with no provenance (today's
   norm) simply reads `Absent`. This is safe to ship before any CI attaches provenance.

**Known limitation (DECISION NEEDED — recorded for the architect).** The pinned
`sigstore` crate (0.14) verifies DSSE bundle referrers only for the cosign `sign/v1`
predicate — `from_sigstore_bundle` rejects any other predicate type, so a **SLSA
provenance** attestation is currently *not surfaced* by `trusted_signature_layers` end to
end. The full verify → baseline → drift → render pipeline, the SLSA-predicate parser, and
the DSSE-PAE extraction are implemented and unit-tested against synthetic attestations, so
the `Verified` path is real, correct code that activates the moment the verifier surfaces a
SLSA layer; until then the production observer yields `Absent`/`Checking` — the safe,
honest degradation. Closing the gap (compose sigstore's lower-level DSSE + Fulcio + Rekor
primitives, or an upgraded `sigstore` release) is a follow-up that does not change this
addendum's contract.

## Addenda (JEF-297 — the rendered "if enforced" is CONTINUITY, not keyless-identity)

The signing inventory's **"if enforced"** column is a counterfactual: *what would a
signature gate do to this image?* Its first implementation read that column off the raw
posture — `would_admit ⇔ keyless-Fulcio Signed`, every other posture would-block. That is
the **pre-ADR-0020 single-identity gate**, and it directly contradicts the continuity
thesis of this ADR and the honest-posture split (JEF-276): the *entire* key-based-signed
homegrown fleet (and cert-manager) rendered **would-block**, even though such a repo is
perfectly calm and continuous. The JEF-280 addendum's aside that the calm postures "still
`would_admit() == false`" was itself this bug — it conflated the *inventory trust
semantic* ("this posture confers no trusted keyless identity", which is true) with the
*enforcement counterfactual* ("a continuity gate would reject this image", which is
false for a consistent repo).

This addendum corrects the render. It changes **presentation only** — no observation, no
drift classification, no enforcement, no egress changes.

1. **would-admit is the negation of a REGRESSION, not a posture test.** The counterfactual
   a signature-continuity gate (JEF-265) applies is: *block on a genuine regression from
   the repo's established baseline; admit everything continuous.* So the column is derived
   from the baseline-relative drift verdict (JEF-264/280), NOT the raw posture:
   * **would-admit** — any calm posture with no regression: keyless-verified `Signed`,
     consistent `SignedKeyBased` / `UnverifiableHere` (no keyless baseline to drop from),
     and `NotSigned` where the repo was never signed (TOFU). This is `block == regression`
     read the other way, so the column can never disagree with what enforcement blocks.
   * **would-block** — a genuine regression against an **established** baseline
     (`SigningDowngrade` / `IdentityChange` / signed→`NotSigned` / signed→invalid), OR a
     genuinely `InvalidSignature` (the reserved loud channel — a broken signature is never
     admissible independent of any baseline).
   * **uncertain** — a regression against a **cold / freshly-learned** baseline: a weak
     lead (JEF-280 cold=uncertain), non-green but never a hard block. This keeps the
     cold-baseline honesty invariant on the enforcement column too.

2. **Single source of truth = the recorded drift verdict.** The render reads the SAME
   `SigningRegression/<repo>` rows the sweep already recorded (one per regressing image),
   keyed per image — it never re-classifies against the baseline, so the "if enforced"
   column and the recorded regression a gate enforces are the same fact. The old per-posture
   `SigningPosture::would_admit()` is retired as the render input (superseding the JEF-280
   addendum's `would_admit() == false` note); the inventory trust semantic it expressed
   (`Signed` is the only *keyless-verified* posture) is unchanged and still drives the
   posture chip.

3. **No evasion.** `InvalidSignature` short-circuits to would-block regardless of baseline
   strength, so an attacker cannot downgrade a genuine failure to *uncertain* by keeping
   the repo's baseline cold. Cold-baseline regressions read *uncertain* (non-green), never
   silent and never a fabricated green admit.
