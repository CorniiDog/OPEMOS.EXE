# OPEMOS.EXE — Product Checklist

## Foundation and change policy

Commit `e0502833282ffd9055ecf46f75df82f71a9ee20f` is the current tested
foundation. It includes the macOS image workflow, managed Fedora appliances,
authenticated NVIDIA installation, USB export, installation-media welcome app,
and the first OPEMOS Core contract adapters.

Changes above this foundation must remain behaviorally close to it. Do not
remove a working path, safety check, validation step, or user-visible recovery
route until its replacement passes equivalent unit, integration, cancellation,
and failure tests. Any deliberate behavior change must be called out in the
commit that introduces it.

Required dependency direction:

```text
OPEMOS Core contracts
├── CLI
├── SteamOS Desktop Companion
├── SteamOS DRM/KMS interstitial
└── OPEMOS.EXE
```

Frontends are siblings and must never depend on one another. OPEMOS.EXE may
install an authenticated SteamOS frontend as target payload, but must not bundle
or invoke it as part of the macOS application runtime.

## Ownership boundary

Authority: [`BOUNDARIES.md`](BOUNDARIES.md). This checklist summarizes the
contract but must not redefine it.

OPEMOS.EXE owns:

- macOS windows, menus, accessibility, progress weighting, and diagnostics.
- Host QEMU and appliance lifecycle, cancellation, and cleanup.
- Recovery-image selection, normalization, overlays, partitions, and export.
- Authenticated host-to-guest transfer and USB writing.
- Independent final-image and output-manifest validation.
- The installation-media welcome UI and its narrowly scoped installer bridge.

OPEMOS Core owns:

- SteamOS/NVIDIA compatibility and release-selection policy.
- Reviewed userspace locks, trust policy, installation, verification, receipts,
  recovery, and structured progress/results.
- The installed SteamOS Desktop Companion, DRM/KMS interstitial, CLI, update
  guardian, and their backend/update contracts.
- Support build, test, packaging, publication, and device-deployment entry
  points.

The NVIDIA source repository owns NVIDIA source branches and patches. Valve
recovery images are user inputs and must never be committed or redistributed by
this repository.

## Current validated baseline

- [x] Build and run the Tauri application on macOS Apple Silicon.
- [x] Select, normalize, and inspect supported Valve recovery images without
  mutating the original.
- [x] Start disposable native and x86_64 Fedora appliances with bounded
  lifecycle control.
- [x] Resolve or locally build an exact-kernel NVIDIA artifact and verify its
  provenance, modules, userspace, firmware, and initramfs contract.
- [x] Stage normal-build packages only from the reviewed userspace lock; normal
  operation does not select newer packages from an Arch index.
- [x] Export a separately validated image and optionally write and byte-verify
  a selected whole removable USB device.
- [x] Reopen a manifest-bound existing NVIDIA image without rebuilding it.
- [x] Install the fullscreen welcome application and guarded target-disk picker
  into generated recovery media.
- [x] Preserve an opaque fallback behind the cross-platform frosted-glass UI.
- [x] Provide bounded, color-aware logs, smart diagnostic copying, monotonic
  progress, keyboard navigation, and coupled companion windows.
- [x] Add fixture-tested schema-compatible consumers for Core resolver schema 2
  and installer validation, result, progress, module-verification, and
  userspace-verification, initramfs-workspace, initramfs-verification, and
  payload-receipt and gaming-payload schema 1.

Current outputs remain `nvidia-mutation-valid`. Do not call them
`install-ready`, hardware-certified, or update-safe until the gates below pass.

## Immediate work

### Experimental Ubuntu/Debian host testing (current user priority)

This authorizes an EXE host-testing path alongside macOS, not Ubuntu/Debian
installation targets, production activation, or hardware certification.

- [x] Finish the preserved appliance-handoff test change before extending the
  host backend. On Ubuntu 24.04.4 x86_64, scheduler-limited formatting and
  warnings-as-errors Clippy pass; the complete Rust suite passes 302 tests
  (25 ignored live/helper entries), and all 74 frontend tests plus documentation,
  hygiene, and boundary integrity checks pass. Core fixtures use immutable CI
  commit `3e49323fce266af8686039fb6487918ef5a64fd9`. Fix Linux dash watchdog
  signaling, bound process-group IDs, directly signal isolated Git-runner groups,
  and stop descendant-held pipes after leader exit. Real subprocess matrices
  now work with serial test-harness output. Debian, macOS, live QEMU, physical
  media, and hardware certification are not established by this host run.
- [x] Add explicit experimental Ubuntu/Debian x86_64 host capability/dependency
  reporting and UI labels. Wire bounded RAM/cgroup readers, matched OVMF pairs,
  genisoimage seed creation, and host-aware QEMU plans into both appliance paths;
  reuse existing Unix storage, descriptor, overlay, cleanup, and export code.
  The read-only prerequisite doctor rejects missing/non-executable tools,
  mixed firmware pairs, malformed/oversized OS metadata, and unsupported hosts.
- [x] Require explicit Linux opt-in plus an accessible KVM API and a successful
  selected-accelerator QEMU smoke, or explicitly selected TCG testing. Never
  silently fall back. Keep physical-device writing unavailable. macOS HVF/native
  and Apple-Silicon-to-x86 TCG plans retain their existing behavior in tests.
- [x] On Ubuntu 24.04.4 x86_64, run the real 64 MiB paused TCG smoke with no
  networking/host disks, create a seed ISO and disposable qcow2 overlay using
  paths with spaces, and verify the raw source hash is unchanged. Through the
  shared scheduler, formatting and Clippy pass, 308 Rust tests pass (27 ignored
  live/helper entries), the explicit Linux smoke passes, and 86 frontend tests
  plus documentation/hygiene checks pass against the same immutable Core CI pin.
- [x] Harden experimental Linux cgroup budget discovery: require an existing
  directory root and distinguish genuinely absent root memory.max from lookup
  errors or dangling links. Unreadable limits must stop readiness rather than
  silently fall back to physical RAM. Disposable filesystem tests cover nested
  child/ancestor/root minima, unlimited children, the physical-memory ceiling,
  malformed/duplicate memberships, traversal, missing groups/root, malformed
  ancestor limits, dangling links, directory-valued limits, and zero RAM.
  On Ubuntu 24.04.4 through the shared scheduler, formatting and Clippy pass,
  319 Rust tests pass (27 ignored), and all 98 frontend tests plus documentation,
  hygiene, and boundary integrity pass against the unchanged Core fixture pin.
  This does not change the scheduler cap or establish managed-appliance boot.
- [ ] Validate managed Fedora appliance boot and image equivalence. The current
  2 GiB scheduler cap is below the existing 6 GiB host-budget minimum; runtime
  cgroup discovery now refuses readiness, and the live smoke verifies that
  refusal. Do not raise the cap or equate the small tool smoke with guest boot.
  KVM hardware, Debian, macOS runtime, and SteamOS hardware remain unvalidated.
- [x] Provide exact Ubuntu/Debian setup and experimental launch/package commands
  with tested-version limits. Add `dev:linux-test`, debug-only `build:linux-test`,
  and `test:package-linux`, a separate opaque Linux main-window configuration,
  and an independent test app identifier while retaining macOS bundle defaults.
  On Ubuntu 24.04.4, the local amd64 Debian package builds under the scheduler;
  it declares the observed glibc 2.39, OpenSSL 3, and liblzma requirements.
  Archive checks verify metadata, ELF architecture, staged binary hash, exactly
  Tauri's UNK-to-DEB marker transformation, shared-library resolution, normal
  archive permissions, desktop entry, and absence of maintainer scripts. Four
  marker tests cover chunk boundaries, truncation, additional changes, missing
  markers, and malformed transformations. Four launcher tests cover opt-in,
  unsupported hosts, acceleration, argument overrides, and missing displays.
  Formatting, Clippy, 308 Rust tests (27 ignored), 90 frontend tests,
  documentation, hygiene, and boundary integrity pass against the unchanged
  immutable Core CI pin. No package installation or publication occurred.
- [ ] Validate graphical development and packaged application launch/close on
  Ubuntu and Debian, including companion windows and orphan-process checks.
  This session has neither DISPLAY nor WAYLAND_DISPLAY; graphical launch has
  not been attempted. Managed-appliance lifecycle and image equivalence remain
  separately blocked by the unchanged resource minimum above. The Ubuntu
  glibc-2.39 package is not a validated Debian 12 artifact.
- [x] Add Settings → Inspect Core compatibility: a read-only host dialog for
  pasted resolver results and the existing compatible/no-artifact development
  fixtures. Reuse the same Rust Core schema-2 parser and 1 MiB byte bound;
  distinguish unverified pasted documents from non-production debug fixtures.
  Display Core status, targets, publication, pending artifact trust, reasons,
  and next actions as text without policy selection, network/guest/cache work,
  or build/activation controls. Closing, clearing, editing, and newer requests
  invalidate stale responses; native file drops cannot select images while
  the dialog is open. Three Rust tests cover exact result preservation, origin
  and fixture gating, strict request shapes, duplicate/malformed documents,
  unknown schemas, trust-field tampering, Unicode overflow, and the size edge.
  Eight frontend tests cover presentation, bounded errors/text, races, clearing,
  hostile-looking text, keyboard-event isolation, and byte limits. On Ubuntu
  24.04.4, scheduler-limited formatting, Clippy, 311 Rust tests (27 ignored),
  98 frontend tests, documentation, hygiene, and boundary integrity pass against
  unchanged Core CI commit `3e49323fce266af8686039fb6487918ef5a64fd9`.
  Native dialog rendering/focus remains part of the graphical validation gate;
  this session has no graphical display or enabled browser surface.

- [x] Extend the read-only compatibility inspector with local resolver JSON
  selection through the native file input. Enforce nonempty files, the same
  1 MiB byte bound, strict UTF-8, and unchanged document IPC/Rust validation;
  label file and pasted results Unverified document. Four new frontend tests
  cover exact size, BOM preservation, bad sizes/encoding, read failure, changed
  length, cancelled picker, repeated selection, close, and stale read success
  or failure after clear or a newer request. File names never enter IPC or
  establish trust. Native picker/rendering validation remains gated on an
  available graphical desktop; no production activation is added. On Ubuntu
  24.04.4 through the shared scheduler, formatting and Clippy pass, 319 Rust
  tests pass (27 ignored), and 102 frontend tests plus documentation, hygiene,
  and boundary integrity pass against the unchanged Core fixture pin.

### 1. Complete the OPEMOS Core migration

Production generation activation is intentionally blocked until the maintainer
supplies all five independent publication inputs below. Existing schema-1
filenames, no-redirect behavior, exact-target selection, and replay rules are
already Core contracts and are not open-ended product choices.

- [ ] Approve one production OpenPGP primary fingerprint and the exact keyring
  bytes/digest installed independently with OPEMOS.EXE.
- [ ] Approve one canonical HTTPS origin/channel and immutable release
  namespace; no mirror, redirect, or mutable-ref fallback is implied.
- [ ] Approve the first signed discovery/manifest identity and its minimum
  sequence as the independently installed bootstrap checkpoint.
- [ ] Name the authorized generation publisher/signing process and the
  immutable release evidence required before discovery advances.
- [ ] Define the separately authenticated binary/config procedure for signer
  rotation or emergency state-loss recovery. Routine data generations may
  neither rotate authority nor lower a consumer's durable high-water mark.

- [ ] Have Core publish an immutable generation through its canonical
  authenticated release channel. OPEMOS.EXE must never generate the production
  manifest, lock, signer policy, or target policy.
- [ ] Define and consume one bounded generation descriptor binding the channel
  and trust-root version, Core commit, manifest and bundle identities, supported
  contract schemas, reviewed lock identities, target matrix, and publication
  evidence.
- [ ] Discover generations with bounded retries; authenticate the descriptor and
  manifest independently, then verify every listed path, role, size, SHA-256,
  and executable mode before staging anything.
- [ ] Install each verified generation into a create-only cache directory, rehash
  it before appliance transfer, retain the last-known-good generation, and make
  activation atomic and rollback-safe across cancellation, ENOSPC, crash, replay,
  and downgrade attempts.
- [x] Add an inactive Unix host-cache substrate with private create-only
  candidates, closed-tree durability, cross-process serialization, canonical
  bounded state, revision/operation compare-and-swap, pending health approval,
  independently reverified last-known-good rollback, and cleanup of partial,
  cancelled, ENOSPC, or late-verification candidates. Hold an identity-bound,
  size-reserved cross-process lease throughout candidate population and commit.
  Require durable host-owned completion evidence before activation so an
  interrupted publication cannot be trusted. Reconcile abandoned candidates,
  orphaned evidence, and exact stale temporaries under the cache lock; preserve
  active, pending, and last-known-good identities while pruning the oldest
  unprotected generations to bounded count and byte budgets. Keep this
  disconnected from production until a compatible generation is published
  through an authenticated trust root and bootstrap checkpoint.
- [x] Add inactive test-only host acquisition using one sealed two-phase
  verifier capability. Authenticate discovery before deriving the exact
  manifest request; bind policy, keyring, authority, target, documents, and
  signatures; then stream only sealed request-plan payloads into an
  identity-pinned candidate. Freshly verify the exact disk inventory inside
  atomic cache commit without changing active state. This has no production
  transport, trust root, command, or UI entry point.
- [x] Bind inactive bootstrap activation to the host cache using only sealed
  generation/checkpoint capabilities. Authorize durable state under the cache
  lock, verify exact inventory through the pinned directory descriptor, and
  publish only pending state across replay, lineage, race, and cancellation
  tests. Production still requires root-confined installed trust; fixtures are
  never authority.
- [x] Consume Core's closed userspace-lock discovery and generation-manifest
  schema-1 models plus all 74 inactive compatibility cases and additive
  consumer handoff metadata preserved at exact local successor commit
  `f2030ab5277c18ae4320747d8e1c4f8120efd0bb`. Also consume its separate
  16-case bounded OpenPGP status matrix. Bind durable cache identity
  to `{sequence, manifestSha256}`, retain a monotonic high-water sequence, and
  keep rollback on the previously healthy generation. Provide fixture-tested,
  root-confined snapshot readers for future staged documents. This is contract
  testing, not a production trust or release pin.
- [x] Consume Core's closed bootstrap policy/checkpoint contract and exact
  49-case compatibility matrix from local commit
  `0c16ccd7ba68095ea8a6655b0d2bb8b6e97d32f3`. This adds no production key,
  keyring, endpoint, checkpoint, networking, activation, command, or UI path.
- [x] Consume Core's unchanged generation request-plan wire contract, exact
  35-case planner matrix, and sealed verifier-evidence capability with its exact
  28-case audit-record matrix from local commit
  `1fde359025031a99055763dca76e0d709486ffac`. Planning derives payload request
  identities from the authenticated manifest; downloaded-byte equality remains
  an acquisition/cache responsibility. No production path is wired.
- [ ] Show the available, selected, active, and last-known-good Core generations
  plus exact-target support in normal and maintainer UI. Preserve explicit source
  intent; never substitute a nearby target, lock, or generation.
- [x] Add an inactive descriptor-bound host-cache-to-appliance staging bridge.
  It requires the exact pending identity, operation, target, lineage, installed
  trust, and committed inventory; publishes a canonical non-executable handoff
  create-only under a destination lock; and supports exact reuse and explicit
  retirement without exposing a raw path or descriptor. It retains a canonical,
  descriptor-bound lease through handoff lifetime and synthetically reconciles
  crashes at intent, copy, seal, publication, completion, and retirement
  boundaries. Exact durable file receipts preserve ambiguous or replaced
  entries detected before the final descriptor-relative cleanup boundary.
- [x] Exercise one immutable, explicitly non-production Core generation from
  local Core commit `7f90e45c4c154fdfda81ff594611cf533e4fb894` through EXE
  acquisition, installed-trust authentication, pending activation, canonical
  appliance staging, Core guest consumption, handoff retirement, and healthy
  activation. The integration found and fixed the evidence filename and
  canonical handoff-JSON mismatches. The cross-repository test is explicitly
  opt-in until that Core commit is published, and does not activate production
  trust or the normal path.
- [x] Prefer the independently pinned 55-file canonical Core bundle for normal
  installer staging. A verified manifest is rechecked against its independent
  digest, bundle identity, commit, file set, hashes, sizes, roles, and modes;
  any authenticated integrity failure stops. The legacy 50-file inventory
  remains only as an explicit temporary availability fallback until the
  immutable Core release exists and passes live acquisition plus equivalent
  install-media and final-image tests.
- [ ] Wire staged generations into managed appliances only after Core publishes
  the guest-consumption contract and EXE passes a real subprocess/SIGKILL,
  restart, cancellation, cleanup, and ENOSPC handoff matrix. A routine compatible
  lock addition must require neither a new EXE binary nor a reimage; unknown
  schema or trust-policy versions must stop safely.
- [x] Exercise the inactive appliance handoff in real subprocesses killed at
  all 38 existing staging, partial-file-receipt, and retirement hook boundaries.
  Fresh-process restart reauthenticates installed trust, reacquires locks,
  preserves cache/trust bytes and inode identities, and either validates and
  retires the handoff or preserves ambiguous stage bytes with the stable
  recovery-required result. Only the exact unfinished lease-record temporary
  is reconciled in partial-receipt cases. This supplements synthetic fault
  tests; production wiring, durable quarantine, real storage-failure coverage,
  and macOS validation remain separate gates.
- [ ] Add an explicit authenticated maintenance action for a preserved
  `appliance-handoff-recovery-required` pre-receipt stage. Never auto-delete
  ambiguous same-UID residue after the create-to-receipt crash gap.
- [ ] Before production wiring, replace final name-based cleanup with a durable
  quarantine/retirement protocol: fsync intent, same-parent create-only rename,
  fsync parent, recheck the receipt, then delete. Preserve mismatches and test
  non-locking same-UID swaps at final file and directory retirement boundaries.
- [ ] Keep EXE binary updates and Core data-generation updates as distinct
  channels. A data-only lock update must not replace application code, broaden
  trust, or bypass the generation compatibility contract.
- [x] Consume Core resolver schema 2, `nextAction=build_exact_target`, installer
  validation/result/progress, module, userspace, initramfs, workspace, receipt,
  and gaming-payload fixtures with bounded fail-closed Rust adapters.
- [x] Consume Core source-intent and source-authorization schema 1 plus its exact
  21-case matrix from the same non-production development generation at
  `7f90e45c4c154fdfda81ff594611cf533e4fb894`. Bind every authorization to the
  canonical intent hash, exact target, action kind, resolver result/build plan,
  and reviewed project or acknowledged upstream source. Malformed, unsupported,
  substituted, and unreviewed inputs remain rejected without a build fallback.
- [ ] Route the normal source-selection path through an authenticated Core
  authorization and finish old/new behavioral equivalence; then remove only
  duplicated Core-owned release/source-selection policy. Retain Rust parsing,
  bounds, session binding, diagnostics, orchestration, and independent final-
  image verification.
- [x] Run the published Core compatibility baseline in CI from immutable commit
  `8224169`; never test against mutable Core `main`.
- [x] After Core published `1fde359025031a99055763dca76e0d709486ffac`,
  repin CI so the 74 generation, 16 OpenPGP, 49 bootstrap, 28 verifier-evidence,
  and 35 request-plan cases run remotely. A contract-fixture pin does not
  activate a candidate bundle.
- [x] Repin the immutable CI checkout to published lifecycle successor
  `3e49323fce266af8686039fb6487918ef5a64fd9` after confirming its shared
  schemas and compatibility fixtures are byte-identical to the validated
  `dfa83a01ad7d8cb915466de86229741f725c83b8` baseline. This records the
  complete published Core lifecycle without activating production trust.
- [x] Add an inactive Unix verifier-child lifecycle substrate with an exact
  executable digest, bounded output, deterministic cancellation/timeout,
  process-group descendant reaping, and descriptor-confined cleanup tests.
- [x] Add an inactive Unix installed-trust adapter that pins an exact private
  three-file policy/keyring/checkpoint inventory to independent hashes, retains
  descriptor-bound guards through sealed two-phase verification and pending
  activation, and rejects replacement, mixed lineage, cancellation, and unsafe
  filesystem inputs under adversarial tests.
- [ ] Before production wiring, provide the reviewed install/config channel that
  creates those independent pins, reject macOS ACL grants in addition to Unix
  modes, and choose a reviewed signed/platform verifier launch path. Current
  trust and pathname adapters remain test-only and cannot activate production.
- [ ] Repin or activate a generation only after Core’s complete Fedora suite and
  this repository’s unit, integration, cancellation, cleanup, malformed-input,
  lifecycle, ENOSPC, replay/downgrade, and final-image tests pass against the
  same immutable publication.

The Core-to-EXE handoff is data, never policy code: Core publishes the signed
generation descriptor, canonical manifest, reviewed locks, target decisions,
schemas, fixtures, and evidence. OPEMOS.EXE authenticates, caches, selects,
transports, and independently verifies that generation in its host cache.
Installed Core/CLI independently discovers and activates the same authenticated
generation identity in a separate device cache for install, update, and repair.
The consumers share identities, schemas, and fixtures—not updater code, physical
caches, activation state, credentials, or health state. Unknown authority or
schema, replay/downgrade, target mismatch, partial download, ENOSPC, or failed
health validation must leave each consumer's last-known-good generation active.

Core commits `510e843c9ef7fea3e1f9b0c9a3f0c8480ddc596d`,
`e3cbcd1ffaea68f2cb0a5fc737a93a831f397f4d`, and
`eff994cfa52224bfb5dd1ce1c84ad295a05831f5` add, fixture-test, and harden
restart reconciliation for the separate inactive installed-device lifecycle.
Core commit `78cf5e8ee5b4a48782afffa43b5812f7e3cf801b` additionally confines abandoned
device-cache cleanup and applies bounded retention and storage admission. Core
commit `c07de7cf5b40e1a52b1db83126436fda2fe611d4` adds a durable activation-intent
journal and restart recovery around device-side state publication. Core commit
`34ee1d22a519fadaccfd12657d56c478316c74d5` adds a development-only injected
acquisition path into a separate authenticated device download cache without
changing active state; Core commit
`22b2beb5d9e2aabe517fabf0b1e9947ed06ba408` contains transport descendants
across owner termination through a bundled watchdog. Production networking
remains inactive. Core commit
`fda5de265c685b95c3e61daeb084ed7188998f96` clarifies the shared consumer
handoff without changing schema-1 wire documents: discovery is authenticated by
canonical external OpenPGP evidence, generation payloads are non-executable
data, storage accounting includes bounded control artifacts, and persisted
discovery names are canonical. Device acquisition, health, persistence,
activation, and physical cache implementation remain Core-owned; OPEMOS.EXE
must not copy that frontend or updater.
Core commit `f2030ab5277c18ae4320747d8e1c4f8120efd0bb` preserves those wire
documents and adds the separate canonical bounded OpenPGP verifier-status
contract. It is compatibility evidence, not a production key or endpoint.
Core commit `0c16ccd7ba68095ea8a6655b0d2bb8b6e97d32f3` defines and hardens the closed
inactive bootstrap policy and checkpoint compatibility contract, including
portable immutable namespace identities. It ships no production trust material
or service location. Core commit `1fde359025031a99055763dca76e0d709486ffac`
adds the closed inactive request-plan and verifier-capability contracts without
shipping a production verifier, transport, or endpoint. Published successor
`dfa83a01ad7d8cb915466de86229741f725c83b8` preserves those shared contracts
while hardening Core-owned device acquisition staging.
Newer unpublished Core health/receipt hardening changes no shared EXE schema;
keep it inactive until Core publishes it and cross-repository tests pass.

Compatibility fixture only—never use this as a permanent global trust root:

```text
Core commit: a1c03c9658c5ed885f094b5f8e0896d818fee785
Manifest SHA-256: 34fa1dfa0351f3bfede0451632063b496ca41da3544d07296a5e4a42a9756cd1
Bundle ID: 225a5c08ebfb77b3e2ba61aa92c678ba59a13321185f3b6766194e97bf8318fa
```

### 2. Prove the generated media end to end

- [ ] Build from a fresh official recovery image and independently verify the
  final rootfs, EFI, home payloads, Holo database, modules, userspace, firmware,
  initramfs, boot arguments, welcome assets, and embedded receipt.
- [ ] Install from the generated USB onto the intended physical disk and verify
  the installed receipt matches the image-build receipt before accepting
  payload propagation.
- [ ] Boot without the recovery USB and verify Desktop Mode, Gaming Mode,
  `nvidia-smi`, module vermagic, Vulkan/GLX/EGL, games through Proton, external
  display, suspend/resume, and absence of NVIDIA Xid faults.
- [ ] Test without first-boot internet access when all required payloads are
  embedded.
- [ ] Test a SteamOS A/B update and prove Core’s guardian either installs the
  exact new-kernel driver before slot activation or retains/returns to the last
  verified slot.
- [ ] Verify recovery remains reachable when NVIDIA graphics initialization,
  networking, artifact resolution, package authentication, initramfs creation,
  or first graphical boot fails.
- [ ] Only after those checks pass, promote output classification from
  `nvidia-mutation-valid` to `install-ready`.

### 3. Idempotency and upgrades

- [ ] Inspect selected media by authenticated state and receipt—not filename—to
  distinguish stock, already-current, upgradeable, partial, and contradictory
  images.
- [ ] For an identical verified SteamOS/kernel/NVIDIA state, skip downloads,
  build, package mutation, and initramfs regeneration while still running
  independent validation.
- [ ] Treat a different valid kernel or NVIDIA version as an explicit upgrade;
  reject partial or unverifiable installations instead of overwriting them.
- [ ] Prove repeat runs leave identical media byte-for-byte unchanged and
  upgrades never modify the original source image.
- [ ] Test output-name and adjacent-manifest collisions, interrupted two-file
  finalization, stale manifests, and concurrent builds selecting the same
  source or destination.

### 4. Lifecycle and failure hardening

- [ ] Give every build, appliance, handoff, USB operation, and async worker a
  generation ID so stale completions cannot overwrite newer state.
- [x] Add the inactive descriptor-bound source/output reservation foundation:
  pinned source and parent descriptors, exclusive immutable locks, strict
  basenames, and a closed durable record that preserves torn or stale state.
- [ ] Add a cross-process exclusive lock for each source image, working image,
  output reservation, and USB target. Before activation, use one fixed private
  app-owned root, retain the source guard through descriptor-bound consumption,
  close lock-inode/verify-to-action races, and hold every lock through cleanup.
- [x] Add an inactive image-first/manifest-last publication prototype with an
  unpredictable operation identity, create-only per-file receipt chain,
  exclusive no-replace renames, descriptor-bound exact-byte resume, and
  fail-closed preservation of unreceipted or mismatched residue.
- [ ] Independently review and activate output publication only after real
  subprocess/SIGKILL, ENOSPC/EDQUOT/fsync, replacement-race, and platform
  no-replace tests pass. Add explicit recovery UI and durable quarantine before
  any restart-time deletion; never infer deletion authority from a mutable
  reservation record.
- [x] Exercise the inactive paired publication transaction in real subprocesses
  killed at every stage receipt, image rename/directory-sync/published receipt,
  and manifest rename/directory-sync/published receipt boundary. Restart tests
  prove only exact receipted states resume, incomplete pairs remain untrusted,
  source and foreign files remain unchanged, locks release, and residue stays
  bounded. Injected published-artifact/output-directory storage faults are
  covered below; real filesystem exhaustion and production activation remain
  gated.
- [x] Add test-only, thread-local storage fault injection at the inactive EXE
  image/manifest staging write and file-sync calls. Eighteen cases cover
  ENOSPC, EDQUOT, and EIO before the first byte, after a real partial write
  (including a completed image chunk), and at file sync. Failed staging removes
  only its exact unreceipted inode, never publishes the output pair, preserves
  prior image receipts, and resumes to verified exact bytes after releasing and
  reacquiring source/output locks. Two further cases swap in same-size,
  same-mode foreign stages before partial-write failure: cleanup and retry
  preserve both foreign bytes and the moved original descriptor's partial bytes.
  Source bytes/metadata and unrelated files stay unchanged. This is deterministic
  fault injection, not a real full-filesystem or power-loss test; production
  publication remains inactive. On Ubuntu 24.04.4 through the shared scheduler,
  formatting and Clippy pass, 313 Rust tests pass (27 ignored), and all 98
  frontend tests plus documentation, hygiene, and boundary integrity pass.
- [x] Require the exact validated receipt chain to be synced before inactive
  output-publication completion, including recovery of apparently complete
  pairs. A regression first reproduced recovery returning Complete after a
  failed receipt sync without retrying that sync. The final acceptance path
  now verifies each receipt's descriptor identity and bytes before and after
  syncing its file and pinned parent; it then repeats guards and final-pair
  verification. Thirty-six receipt create/zero-byte/partial-write failures
  preserve ambiguous evidence or reconstruct only a missing published receipt
  from the exact intact staged chain. Twenty-four repeated ENOSPC/EDQUOT/EIO
  file/parent-sync cases stay failed after lock reacquisition until persistence
  succeeds; an identical-byte replacement inode is rejected. All four receipt
  phases are covered. These are injected errors, not power-loss certification;
  receipt bytes/schemas and production activation remain unchanged. On Ubuntu
  24.04.4 under the shared scheduler, formatting and Clippy pass, 316 Rust tests
  pass (27 ignored), and all 98 frontend tests plus documentation, hygiene, and
  boundary integrity pass against the unchanged Core fixture pin.
- [x] Exercise inactive publication artifact and output-directory sync failures
  with test-only thread-local injection. Twelve image/manifest ENOSPC/EDQUOT/EIO
  cases fail again after lock reacquisition, retry the sync without renaming the
  exact existing final inode, and complete only after persistence succeeds.
  Eight further cases reject same-inode content changes and identical-byte
  replacement inodes after failed sync, preserving foreign files and original
  evidence across repeated retries. No premature published receipt is created;
  source bytes/metadata and staged receipts remain unchanged. These injected
  failures do not certify real filesystem exhaustion, power loss, or macOS
  runtime behavior; production publication remains inactive. On Ubuntu 24.04.4
  under the shared scheduler, formatting and Clippy pass, 318 Rust tests pass
  (27 ignored), and all 98 frontend tests plus documentation, hygiene, and
  boundary integrity pass against the unchanged Core fixture pin.
- [ ] Extend storage-failure coverage to durable quarantine/retirement and real
  filesystem failures before activation; never auto-delete ambiguous residue.
- [ ] Formalize lock ordering and prove status polling, cancellation, close,
  and worker completion cannot deadlock.
- [ ] Route normal cancellation, window close, process failure, and next-launch
  abandoned-session recovery through one idempotent cleanup contract.
- [ ] Replace user-facing string errors incrementally with stable bounded error
  codes, responsibility, retryability, and safe diagnostic detail.
- [ ] Test cancellation and injected failure during download, decompression,
  transfer, QEMU boot, Core validation, package mutation, initramfs, export, USB
  writing, USB verification, and finalization.
- [ ] On every terminal path prove: original unchanged, partial output absent,
  mounts released, guests stopped, locks released, secrets removed, and no
  partial result accepted as trusted.

### 5. Trust and release readiness

- [ ] Make Fedora image signature verification mandatory for packaged release
  builds and pin the expected Fedora signing identity.
- [ ] Version and authenticate native/x86 appliance releases independently from
  the desktop application; verify their hashes before launch.
- [ ] Complete compiler/toolchain provenance or adopt and document a reviewed
  compiler-mismatch policy for certified NVIDIA artifacts.
- [ ] Record the exact OPEMOS.EXE source commit, Core bundle identity, appliance
  identity, input image hash, selected policy, and artifact provenance in the
  output manifest without private host paths.
- [ ] Enable a restrictive production CSP and reduce Tauri dialog/opener/global
  capabilities to the minimum required per window.
- [ ] Audit licenses and redistribution obligations for bundled QEMU, firmware,
  Fedora components, NVIDIA artifacts, and other third-party material.
- [ ] Sign and notarize the macOS application, publish checksums and release
  notes, and test clean install plus upgrade on a non-development Mac.

## Focused quality work

### Application and UI

- [ ] Model the main workflow as an explicit state machine rather than scattered
  DOM state; test every allowed transition and reject impossible ones.
- [ ] Split oversized frontend workflow/log rendering code only where behavior
  can be covered by focused tests.
- [ ] Add a user-selectable image output folder and safe non-overwriting name.
- [ ] Keep advanced diagnostics accessible without exposing them by default.
- [ ] Test compact and expanded layouts, long localized text, zoom, reduced
  motion, high contrast, keyboard-only use, and display scaling.
- [ ] Keep unknown Core phases indeterminate; never infer percentages from
  heartbeats or free-form log text.

### Host and appliance

- [x] Verify host bytes and finite inode capacity before normalization,
  overlays, package and handoff staging, export, and retained-image-plus-USB
  workflows. Measure compressed output through a cancellable bounded pass,
  aggregate shared APFS allocation pools conservatively, recheck before later
  phases, and preserve a stable no-space/quota reason on write failures.
- [ ] Detect corrupt cached appliances and recover only through an authenticated
  replacement.
- [ ] Move large generated guest scripts into versioned templates when doing so
  improves reviewability without weakening fixed-operation boundaries.
- [ ] Measure decompression, transfer, VM boot, mutation, export, and USB speed;
  optimize only after correctness measurements identify the bottleneck.
- [ ] Test Apple Silicon and Intel macOS separately. A nested VM is useful for
  compatibility testing but is not a substitute for final hardware validation.

### USB safety

- [ ] Test sacrificial removable media covering unformatted disks, multiple
  partitions, busy volumes, identical devices, device renumbering, unplug and
  replug, sleep/wake, cancellation, short writes, verification errors, eject
  failure, and insufficient capacity.
- [ ] Revalidate the whole physical device, capacity, identity token, selected
  image, and destructive phrase immediately before opening it for writing.
- [ ] Keep a conspicuous “do not disconnect” warning visible throughout write,
  verification, flush, and eject.
- [ ] Never expose internal/system disks or accept a partition when a whole
  removable device is required.

## CI and test commands

Every normal code change must pass:

```bash
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
npm run test:frontend
```

Before release, also run the ignored network, QEMU, recovery-image, package,
USB, cancellation, and real x86_64 Fedora tests explicitly. Skipped live tests
must be reported; a default-suite pass does not imply hardware certification.

- [x] Add CI coverage for formatting, warnings-as-errors, Rust tests,
  frontend tests, documentation, and repository hygiene.
- [ ] Add an x86_64 Linux integration job for Core bundle, resolver, installer,
  and headless image tests without publishing or touching physical disks.
- [ ] Add bounded release-package smoke tests which start and close the packaged
  application and confirm no orphan QEMU processes remain.

## Release gates

### Alpha

- [ ] One fresh official image builds, writes to USB, installs to the intended
  disk, and boots to usable NVIDIA Desktop and Gaming Mode.
- [ ] The original image remains unchanged and all independent validations pass.
- [ ] Failure leaves a usable recovery route and bounded diagnostics.

### Beta

- [ ] Repeat build, already-current, upgrade, cancellation, and cleanup paths
  pass on real media.
- [ ] SteamOS A/B update and rollback are proven on hardware.
- [ ] At least one NVIDIA laptop and one desktop GPU configuration pass the
  published compatibility matrix.
- [ ] Packaged macOS installation works without developer tools.

### Stable

- [ ] Normal operation requires no shell knowledge or manual driver repair.
- [ ] Supported SteamOS/kernel/NVIDIA/GPU combinations are explicitly certified.
- [ ] Application, Core bundle, appliances, dependencies, and outputs have
  auditable provenance and authenticated update paths.
- [ ] Documentation matches the shipped behavior and known limitations.

## Deferred until after alpha

These are not current OPEMOS.EXE implementation work:

- Production Windows and Linux application ports, including a signed Windows USB
  writer. The explicitly authorized experimental Ubuntu/Debian host-testing
  path above is current work.
- Raspberry Pi Imager-style password and Wi-Fi provisioning.
- Automatic official-image download assistance.
- Multiple certified NVIDIA profiles and the optional no-CUDA profile beyond
  Core’s reviewed/hardware-tested contract.
- The persistent SteamOS storage manager, installed-system recovery UI, update
  guardian, backend hot-update system, and device-side Wi-Fi support. Those
  belong to Core and the SteamOS Desktop Companion.
- Support pipeline internals, sanitizers, build recipes, release publication,
  and device deployment. Core owns the entry points; a later OPEMOS.EXE
  maintainer UI/CLI may schedule them and present authenticated results.
- Automated pushing, publishing, rebooting, or destructive deployment. These
  always require separately implemented authorization and fresh confirmation.

Deferred items should return here only when an accepted milestone makes them
current and their repository ownership is unambiguous.
