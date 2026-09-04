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
  local Core commit `2ab12b29a5c7d7a2e18793e787e5c76c6febb1a5` through EXE
  acquisition, installed-trust authentication, pending activation, canonical
  appliance staging, Core guest consumption, handoff retirement, and healthy
  activation. The integration found and fixed the evidence filename and
  canonical handoff-JSON mismatches. The cross-repository test is explicitly
  opt-in until that Core commit is published, and does not activate production
  trust or the normal path.
- [x] Prefer the independently pinned 55-file canonical Core bundle for normal
  installer staging. A verified manifest is rechecked against its independent
  digest, bundle identity, commit, file set, hashes, sizes, roles, and modes;
  any authenticated integrity failure stops. The 50-file snapshot remains only
  as an explicit temporary fallback when the immutable release is unavailable,
  pending equivalent install-media and final-image tests before deletion.
- [ ] Wire staged generations into managed appliances only after Core publishes
  the guest-consumption contract and EXE passes a real subprocess/SIGKILL,
  restart, cancellation, cleanup, and ENOSPC handoff matrix. A routine compatible
  lock addition must require neither a new EXE binary nor a reimage; unknown
  schema or trust-policy versions must stop safely.
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
  16-case matrix at local commit
  `04561e16974748e8c2e7d60c6b48b01e9e51b311`. Bind every authorization to the
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
  bounded. ENOSPC/EDQUOT/fsync injection and production activation remain gated.
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

- Windows and Linux application ports, including a signed Windows USB writer.
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
