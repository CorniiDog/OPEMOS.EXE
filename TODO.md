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
- [x] Replace the experimental Linux launcher's synchronous child wait with
  an isolated process group, SIGINT/SIGTERM forwarding, a five-second forced
  shutdown bound, and cleanup of children left behind by an exited leader.
  Real disposable subprocess tests cover graceful and stubborn signal handlers,
  leader exit status, surviving child cleanup, spawn failure, invalid grace
  bounds, and signal-handler removal. SIGKILL of the launcher and descendants
  leaving the group remain outside this guarantee; no GUI or VM was launched.
  On Ubuntu 24.04.4 through the shared scheduler, formatting and Clippy pass,
  319 Rust tests pass (27 ignored), and all 105 frontend tests plus documentation,
  hygiene, and boundary integrity pass against the unchanged Core fixture pin.
- [x] Exercise the experimental development launcher in a real Ubuntu 24.04.4
  Wayland/GNOME user session. The binary started twice and bounded SIGINT closure
  left no launcher or EXE processes. The run exposed Tauri rewriting Cargo.toml
  formatting and leaving a generated Linux capability schema; the launcher now
  snapshots and restores exact preexisting bytes/modes and removes only a schema
  proven absent before launch, including child-failure paths. Two new tests cover
  absent/preexisting files, modes, parent cleanup, thrown actions, and symlink
  rejection; all nine focused launcher tests pass. The launcher now waits for
  process-group quiescence before restoration; a repeat package build leaves no
  schema, Cargo rewrite, or descendant. The validated package was extracted
  without installation, launched under Wayland, and closed by SIGTERM with no
  orphan. GNOME denied noninteractive screenshot access, so visual content,
  focus, companion windows, Debian, and SIGKILL-of-launcher restoration remain
  open. Formatting,
  Clippy, 330 Rust tests (27 ignored), and 107 frontend tests plus documentation,
  hygiene, and boundary integrity pass through the shared scheduler.
- [ ] Validate graphical development and packaged application launch/close on
  Ubuntu and Debian, including companion windows and orphan-process checks.
  Ubuntu 24.04.4 Wayland now covers the development main window and the extracted
  debug-package main window. A bounded opt-in AT-SPI smoke starts the exact
  regular executable, verifies the scheduler-capped package exposes the exact
  experimental frame/readiness/unavailable surface, its ordered KVM-unavailable
  explanation with explicit TCG opt-in and no automatic fallback, no ready
  heading, and exactly the Settings, image chooser, and Valve-page buttons with
  no build or USB-writing action exposed. It opens the native recovery-image
  chooser, requires the SteamOS recovery-image filter with no all-files option,
  proves Open remains disabled before selection while Cancel is enabled, cancels
  without selecting input, proves the chooser is gone, and restores focus to its
  opener, then
  verifies the unauthenticated Settings landmark's exact
  five-control focus order plus initial and restored focus, and proves CUDA
  omission, maintainer workspace, and automated-release controls remain disabled
  and unfocusable. It then opens the read-only
  compatibility dialog, opens its native resolver JSON chooser, requires the
  JSON-only filter with no all-files option, disabled empty-selection Open and
  enabled Cancel, cancels without reading a file, proves the chooser is gone,
  and restores focus to its opener. It verifies the exact accessible warnings that preview
  structure is unauthenticated and non-authorizing, fixtures are debug-only and
  non-production, and local inputs are cleared without credentials or guest work.
  The dynamic status now mirrors its bounded text into an accessibility label;
  the live fixture result exposes `Development fixture — non-production` as a
  status bar and `Unverified Core result` as a landmark,
  then verifies the dialog's exact native focusable order, initial Close focus,
  and initial empty status. Inspecting an empty document must expose the bounded
  `Choose or paste` error as
  exactly one status bar without a result landmark; Clear must restore the exact
  empty status before fixture use. It then verifies Core's exact compatible
  publication, artifact, pending-verification,
  and target fields plus all four development-fixture generation rows. Every
  compatible, no-artifact, and compatible-after-clear fixture result must expose
  exactly the non-production status and unverified-result landmark with no stale
  empty/error status. It switches to the no-artifact fixture and verifies Core's
  exact status/reason/message plus its
  bounded exact-target action fields in order. Clear then removes every result,
  action, generation, and fixture-origin sentinel from the accessibility tree,
  requires exactly one `No result loaded.` status, and retains Clear focus, then
  reloading Compatible must restore only its exact rows and
  focus its fixture control. Closing and reopening the populated dialog must
  remove every prior result and origin sentinel, restore exactly one empty
  status, and restore native Close-first focus. It
  closes only the dialog,
  restores focus to its Settings opener, preserves the main document, stops the
  complete process group, and proves no
  new `qemu-system-*` process remains. Unit tests
  reject missing opt-in/display, symlink and non-executable inputs, invalid
  deadlines, missing/duplicate controls, oversized trees, failed actions,
  malformed or symlinked process data, a stubborn process group, exact timeout,
  immediate failure when the packaged process exits before UI readiness, and
  executable pathname replacement after a no-follow descriptor is pinned, and
  stale, missing, invalid, or duplicate AT-SPI application process identities,
  reordered or extra Settings controls, missing or duplicate Settings/dialog
  restored focus, PID reuse, and malformed
  or mismatched bounded `/proc` stat identities. The QEMU snapshot keys PID plus
  kernel start time; the live tree reports the spawned package PID exactly. Package
  archive validation passes with SHA-256
  `28fd817d490c06b76d35190ac4bcf63816f8478d910d9e9620a345cde7213ad5`; no
  package was installed. Twenty-five focused harness tests reject false-ready or
  ambiguous unavailable surfaces, altered unavailable explanations or fallback
  policy, extra unavailable-mode actions, unexpected initial button focus,
  missing or broadened chooser filters, unsafe empty-selection Open/Cancel
  state, a stale native chooser, missing or duplicate chooser focus restoration,
  enabled, focusable, missing, or duplicate unavailable Settings controls,
  altered, missing, or extra compatibility safety warnings, inaccessible fixture
  origin or unverified-result landmark, reordered or extra
  or ambiguously bounded rows, stale cleared fields or result headings, wrong
  Clear focus, altered or duplicate empty-document errors, a result exposed for
  empty input, stale or duplicate empty-status labels, stale, missing, or
  duplicate fixture origins/result landmarks after transitions, stale next actions after
  recovery, and altered compatible trust text, stale close/reopen state, and wrong
  reopened focus; the live package
  smoke passes. Debian,
  companion windows, delivered key-event/editable-text traversal, and pixel
  rendering remain open; GNOME Wayland accepted an exploratory AT-SPI Escape
  synthesis request without delivering it to the WebKit dialog. WebKit exposes
  the resolver text field as an entry without an AT-SPI EditableText interface.
  The former HTML file control also accepted `press` without opening a chooser;
  replacing it with the native Tauri dialog closed that blocker in the packaged
  smoke while retaining local-only, unverified parsing. The renderer test proves the accessible status label
  follows loading, result, error, and clear without retaining stale text.
  Scheduler-limited
  formatting and
  Clippy pass, 331 Rust
  tests pass (27 ignored), and all 111 frontend tests plus documentation, hygiene,
  package, focused smoke, and boundary integrity checks pass against unchanged
  Core fixture commit `3e49323fce266af8686039fb6487918ef5a64fd9`.
  Managed-appliance lifecycle and image equivalence remain separately blocked by
  the unchanged resource minimum above. The Ubuntu
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
  selection, now through a native Tauri file dialog and bounded EXE-owned reader. Enforce nonempty files, the same
  1 MiB byte bound, strict UTF-8, and unchanged document IPC/Rust validation;
  label file and pasted results Unverified document. Four new frontend tests
  cover exact size, BOM preservation, bad sizes/encoding, read failure, changed
  length, cancelled picker, repeated selection, close, and stale read success
  or failure after clear or a newer request. A Rust regression additionally
  rejects relative paths, empty/oversized/nonregular files, and symlinks. Paths
  enter only the EXE-local preview command and never establish trust. The rebuilt
  Ubuntu package now passes the native chooser accessibility smoke; pixel
  rendering remains gated. No production activation is added. The earlier HTML
  input implementation passed 319 Rust tests (27 ignored) and 102 frontend tests.
  On 2026-09-04, the native chooser follow-up passes formatting and Clippy, 331
  Rust tests (27 ignored), all 111 frontend tests, 25 focused smoke-harness tests,
  live extracted-package AT-SPI smoke, package validation, documentation, hygiene,
  and boundary integrity against the unchanged Core fixture pin.

- [x] Reuse the read-only Core compatibility inspector in the maintainer
  workspace as well as normal Settings. Both windows accept the same bounded
  pasted/local resolver documents and debug-only non-production fixtures, show
  Core fields verbatim, and expose no source selection, generation mutation,
  network, cache, guest, build, or activation action. Cross-window concurrency
  tests prove independent revision state: a stale or closed maintainer request
  cannot replace the main result and vice versa. Static wiring tests require the
  shared controller, stylesheet, bounded inputs, and explicit no-authorization
  notice in the maintainer surface. The broader available/selected/active/LKG
  generation UI remains gated and open. On Ubuntu 24.04.4 through the shared
  scheduler, formatting and Clippy pass, 330 Rust tests pass (27 ignored), and
  all 109 frontend tests plus documentation, hygiene, and boundary integrity
  pass against the unchanged Core fixture pin. Native maintainer-dialog visual
  and focus validation remains blocked by GNOME screenshot policy.

- [x] Validate the normal Settings compatibility inspector through the live
  Ubuntu 24.04.4 Wayland accessibility tree. AT-SPI found the native frame,
  WebKit document, Settings panel, dialog, fixture controls, and all four debug
  generation rows; it invoked the fixture, verified selected/active identity
  values, closed the dialog without closing the main document, and launcher
  shutdown left no process. This exposed empty native names for generated
  description terms and values. The renderer now assigns exact text-only ARIA
  labels, with a hostile-looking value regression proving labels remain data,
  not markup. Formatting and Clippy pass, 330 Rust tests pass (27 ignored), and
  all 110 frontend tests plus documentation, hygiene, and boundary integrity
  pass through the shared scheduler. Pixel rendering, focus order, maintainer
  companion launch, packaged accessibility, and Debian remain open.

- [x] Split Tauri permissions into exact main, build-progress, and maintainer
  window capabilities. Main retains native dialog, URL opener, focus, and drag;
  maintainer retains native dialog, hide, and drag; build progress retains only
  hide and drag beyond core IPC. No window receives an unused show permission,
  build progress receives neither dialog nor opener, and maintainer receives no
  opener. An exact regression rejects changed window membership, permission
  order, permission additions, duplicate coverage, or scope collapse. On
  2026-09-04, Tauri/Cargo capability validation, all 111 frontend tests,
  documentation, hygiene, 25 Linux GUI harness tests, package validation, and
  live extracted-package AT-SPI smoke pass; main Settings, native image and JSON
  choosers, focus restoration, process cleanup, and the no-QEMU
  invariant remain functional. Package SHA-256 is
  `f7a43e115e234ed977ad91d7daa8a7660f0453cad3a6cf73bd692849048dfc76`.
  At this commit, the restrictive production CSP and further `core:default`
  review remained open; the follow-up below closes both.

- [x] Enable a restrictive packaged-webview CSP and replace every broad Tauri
  permission default with the exact frontend calls. The CSP admits only bundled
  scripts, images, fonts, and styles plus Tauri's documented IPC endpoints;
  runtime progress/log rendering retains the required inline-style allowance.
  Objects, forms, frames, base-URL changes, and every other source are denied.
  `core:default`, `dialog:default`, and `opener:default` are absent. Main receives
  only listen/unlisten/emit, window inventory/focus/drag, dialog open, and URL
  open; build progress and maintainer receive only listen/unlisten/emit-to,
  hide/drag, plus dialog open for maintainer. The exact regression rejects any
  directive, permission, order, or membership drift. On 2026-09-04, focused
  frontend and Cargo checks plus a rebuilt extracted-package AT-SPI smoke pass;
  Settings, both native choosers, compatibility IPC, focus restoration, clean
  process-group shutdown, and the no-QEMU invariant remain functional. Package
  SHA-256 is
  `2fa3e4036e793ecbaaf149979740f9c46aafb3ac0f291e83c0faf1243bb8f883`.
  This does not grant webview networking or alter production trust/activation.

- [x] Add shared reduced-motion and forced-color behavior to main, build-progress,
  maintainer, and compatibility controls. Reduced motion bounds every animation
  to one effectively instantaneous iteration, removes transition delay, and
  disables pressed-button displacement while retaining final progress/status
  state. Forced colors use system button, canvas, highlight, and disabled colors
  for borders, custom checkbox marks, focus outlines, and unavailable controls;
  disabled controls remain visibly distinct without opacity loss. An exact
  regression covers repetition, transition, focus, checkbox, status, and disabled
  boundaries across the shared stylesheet. On 2026-09-04, the focused five-case
  theme suite and all 112 frontend tests plus documentation, hygiene, and boundary
  integrity pass. Pixel-level forced-color/reduced-motion rendering, zoom, long
  localization, and display scaling remain in the broader graphical gate.

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
- [x] Exercise that generation-status presentation in both shared inspector
  surfaces using a closed debug-only host fixture. The fixture provides two
  synthetic identities and distinct selected, active, and last-known-good state;
  production and unverified-document responses cannot supply generation state.
  The frontend requires the exact four-field shape, one to four unique available
  identities, positive safe sequences, bounded IDs, lowercase SHA-256 values,
  no extra fields, and membership of every selected/active/LKG identity in the
  available set. It displays Core's exact-target support field verbatim and
  labels every generation row “development fixture.” Tests cover absent state,
  missing/extra fields, empty/oversized/duplicate inventories, malformed hashes,
  invalid sequences, unavailable selections, and origin substitution. This adds
  no cache reader, production discovery, source selection, or activation; the
  parent production UI item stays open. On Ubuntu 24.04.4 through the shared
  scheduler, formatting and Clippy pass, 330 Rust tests pass (27 ignored), and
  all 110 frontend tests plus documentation, hygiene, and boundary integrity
  pass against the unchanged Core fixture pin.
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
  Awaiting user ownership clarification: does “authenticated maintenance”
  require a Core-owned authorization contract, or an explicit EXE host-local
  maintenance approval? EXE owns transfer cleanup; Core owns signer/keyring
  policy and authorization contracts. The existing recovery path preserves a
  stage without a durable file receipt and supplies no deletion authority.
  Stop this action until the user identifies the intended authority; do not
  infer it from scheduler continuation, mutable lease records, or same-UID
  ownership. Review at `08d2e9a` found no implementation changes to validate;
  existing production gates and preserved stages remain unchanged.
  Decision recorded 2026-09-04: the user approved Core's canonical creator-owned
  cleanup boundary from commit `3a6f0652f4118936820871f8201f7c5e1250acbf`.
  Core owns cleanup of Core-created artifacts it can safely identify; EXE may
  consume a bounded provenance-preserving Core flag only after revalidating exact
  artifact identity and provenance. Missing, stale, malformed, mismatched,
  conflicting, or ambiguous evidence still preserves the artifact. This resolves
  the ownership question but does not implement or activate maintenance cleanup.
- [x] Mirror the explicitly authorized artifact-cleanup ownership boundary from
  canonical Core commit `3a6f0652f4118936820871f8201f7c5e1250acbf` without
  rewording. EXE integrity pins now require Git blob
  `68fd9553bb8fee79cee803a38f980a94b2d80e57` and SHA-256
  `136d3572effa90c1b84bcf51002d7f9641c367132de20d54dd7173f68f13c6a8`,
  verify the pinned Core counterpart bytes when the sibling checkout exists, and
  assert the creator-ownership, exact revalidation, fail-safe ambiguity, and
  no-blanket-deletion rules. The dated decision handoff is
  `docs/decisions/2026-09-04-artifact-cleanup-ownership.md`; prior TODO and Git
  history remain preserved. Core completed the reverse counterpart pin at
  `a7011dca932f5a89426a07005bc52418651b94b5`, targeting exact EXE mirror commit
  `064d1d54c7ef2eda3d56e80c67e9f8e78a554725`. Both repositories' default and
  local focused boundary validation passes.
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
- [x] Reject overlapping image/adjacent-manifest reservations before inactive
  staging. A regression reproduced two live reservations sharing one output
  path. Acquire both paths in image-then-manifest lexical order using the same
  output-lock namespace, including on reopen; verify both guards through
  record creation, staging, and recovery. Tests cover both acquisition orders,
  partial-acquisition lock release, reopen contention, cross-process overlap,
  manifest-lock replacement before staging, and restrictive umask. Source
  bytes and output paths remain unchanged after rejected reservations. The
  SIGKILL inventory allows four locks and ten total private entries, accounting
  for exactly one additional empty manifest lock. Production remains inactive.
  On Ubuntu 24.04.4 through the shared scheduler, formatting and Clippy pass,
  323 Rust tests pass (27 ignored), and all 105 frontend tests plus documentation,
  hygiene, and boundary integrity pass against the unchanged Core fixture pin.
- [ ] Test output-name and adjacent-manifest collisions, interrupted two-file
  finalization, stale manifests, and concurrent builds selecting the same
  source or destination.

### 4. Lifecycle and failure hardening

- [ ] Give every build, appliance, handoff, USB operation, and async worker a
  generation ID so stale completions cannot overwrite newer state.
  - [x] Gate overlapping GitHub maintainer-status refreshes and login-poll
    responses with one bounded latest-request generation. Older successes and
    errors cannot replace a newer authentication/authorization result; polling
    additionally retains its existing login-attempt identity. Independent gate,
    invalid-candidate, stale-success/error wiring, and mutable-counter exposure
    regressions cover the slice. On 2026-09-05, the focused 18-case async/layout
    suite and all 144 frontend tests plus documentation, hygiene, and boundary
    integrity pass. Other async workers remain under the parent lifecycle item.
  - [x] Bind the initial GitHub maintainer-connect response to the same
    latest-status generation and its existing login-attempt identity. A newer
    refresh can supersede a delayed connect success without preventing the
    current login poll from starting; a superseded connect error clears pending
    login state without replacing the newer status message. On 2026-09-05, the
    focused 18-case async/layout suite and all 144 frontend tests pass, along
    with documentation, repository hygiene, and boundary integrity checks.
    Other async workers remain under the parent lifecycle item.
  - [x] Reject stale GitHub login-poll errors using both the login-attempt
    identity and latest-status generation before changing the visible message.
    A refresh or reconnect that supersedes an in-flight rejected poll now keeps
    its newer state. On 2026-09-05, the focused 18-case async/layout suite and
    all 144 frontend tests pass, along with documentation, repository hygiene,
    and boundary integrity checks. Other async workers remain under the parent
    lifecycle item.
  - [x] Give the native image chooser its own latest-request generation and
    capture the active image-selection generation before opening the dialog.
    An older overlapping chooser and a chooser superseded by drag-and-drop can
    no longer start validation or replace the newer selection. On 2026-09-05,
    the focused 41-case workflow/layout suite and all 145 frontend tests pass,
    along with documentation, repository hygiene, and boundary integrity
    checks. Other async workers remain under the parent lifecycle item.
- [x] Add the inactive descriptor-bound source/output reservation foundation:
  pinned source and parent descriptors, exclusive immutable locks, strict
  basenames, and a closed durable record that preserves torn or stale state.
- [x] Close renamed-source contention in the inactive output reservation.
  A regression reproduced two reservations accepting the same inode after a
  rename. Retain the existing pathname lock and add a device/inode lock before
  hashing, acquired in pathname → inode → output order; verify both source
  locks throughout consumption. Same-parent and cross-parent rename tests
  preserve exclusivity, failed inode acquisition releases its pathname lock,
  lock replacement revokes the guard, and a real subprocess holds exclusivity
  across rename until exit. The source and foreign bytes remain unchanged.
  This is an inactive host reservation change, not production export wiring;
  working-image/USB locks and broader lifecycle lock-order proof remain open.
  The bounded SIGKILL inventory now permits exactly one additional empty lock
  (at most three locks and nine total private entries). On Ubuntu 24.04.4 under
  the shared scheduler, formatting and Clippy pass, 321 Rust tests pass
  (27 ignored), and all 105 frontend tests plus documentation, hygiene, and
  boundary integrity pass against the unchanged Core fixture pin.
- [x] Bind inactive publication to the exact source guard recorded by its
  reservation. A regression reached staging with a valid guard for a different
  source. Guard verification now rejects identity or hash mismatch before any
  publication step. Six reserved/staged/complete cases cover distinct sources
  with different or identical bytes, repeated rejection without file/receipt
  changes, and successful retry after reacquiring the original guard. A further
  case rejects substitution after the original source changes, including a new
  guard for that changed inode. Production wiring and cleanup gates stay open.
  On Ubuntu 24.04.4 through the shared scheduler, formatting and Clippy pass,
  325 Rust tests pass (27 ignored), and all 105 frontend tests plus documentation,
  hygiene, and boundary integrity pass against the unchanged Core fixture pin.
- [x] Require inactive source/output reservations to share the same pinned
  private lock-directory identity. A regression accepted an output reservation
  in a second root, creating an independent lock namespace for the same source.
  Reject this before output lock/record creation, recheck acquired lock roots,
  and reject equal-byte/equal-inode source guards from another root during
  publication and completion recovery. Tests cover empty-root preservation,
  repeated rejection, correct-root retry, and alternate spelling of the same
  directory. Choosing the fixed installed application root remains gated;
  this change does not configure production storage or trust. On Ubuntu
  24.04.4 through the shared scheduler, formatting and Clippy pass, 327 Rust
  tests pass (27 ignored), and all 105 frontend tests plus documentation, hygiene,
  and boundary integrity pass against the unchanged Core fixture pin.
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
- [x] Add cooperative cancellation to inactive source reservation acquisition
  and verification, checking before acquisition and around each 1 MiB hash
  read (including completion). Eight acquisition and six verification cases
  cover early, mid-read, and final-read cancellation. Cancelled acquisition
  releases both locks for retry without changing source bytes/metadata;
  cancelled verification retains ownership and never caches acceptance of
  later-mutated bytes. Pre-cancelled missing input performs no root mutation.
  Existing non-cancellable entry points retain their behavior. Runtime UI
  cancellation wiring and interruption of a blocked filesystem syscall remain
  separate gates; production output publication stays inactive. On Ubuntu
  24.04.4 through the shared scheduler, formatting and Clippy pass, 329 Rust
  tests pass (27 ignored), and all 105 frontend tests plus documentation, hygiene,
  and boundary integrity pass against the unchanged Core fixture pin.
- [x] Add cooperative cancellation to the inactive output publication
  transaction. Check before mutation and after each staged image/manifest chunk,
  file sync, durable receipt, rename, and publication sync boundary. Seven early,
  multi-chunk, receipted, and finalization cancellation cases retain both source
  and output reservations, preserve exact source bytes and metadata, never expose
  a manifest without its image, and resume through the same descriptor-bound
  transaction to an exact verified pair. This does not wire runtime UI
  cancellation, delete recovery evidence, or activate production publication.
  On Ubuntu 24.04.4 through the shared scheduler, formatting and Clippy pass,
  330 Rust tests pass (27 ignored), and all 105 frontend tests plus documentation
  and hygiene checks pass against the unchanged Core fixture pin.
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
- [x] Enable a restrictive production CSP and reduce Tauri dialog/opener/global
  capabilities to the minimum required per window. Completed above with exact
  per-window permissions and packaged Linux runtime evidence.
- [ ] Audit licenses and redistribution obligations for bundled QEMU, firmware,
  Fedora components, NVIDIA artifacts, and other third-party material.
- [ ] Sign and notarize the macOS application, publish checksums and release
  notes, and test clean install plus upgrade on a non-development Mac.

## Focused quality work

### Application and UI

- [ ] Model the main workflow as an explicit state machine rather than scattered
  DOM state; test every allowed transition and reject impossible ones.
  - [x] Centralize build admission as the first bounded state-machine slice.
    A pure snapshot reducer names empty, selected, building, complete, and
    USB-writing phases; derives every build blocker; accepts all three output
    modes and acknowledged upstream intent; and rejects malformed snapshots,
    concurrent build/write activity, and build-after-completion. The main
    renderer now consumes this single result instead of repeating admission
    predicates. On 2026-09-04, the focused 17-case workflow/layout suite and
    all 119 frontend tests plus documentation, hygiene, and boundary integrity
    pass.
  - [x] Route the build-click event boundary through that same admission
    snapshot, eliminating a second predicate list that could drift from the
    rendered disabled state. Programmatic starts now reject missing inputs,
    unavailable hosts, absent outputs, unacknowledged upstream intent, completed
    outputs, active USB writes, and impossible concurrent activity through the
    same fail-closed reducer. On 2026-09-04, the focused 18-case workflow/layout
    suite and all 120 frontend tests plus documentation, hygiene, and boundary
    integrity pass.
  - [x] Route image-selection admission through the same reducer. Empty,
    selected, and completed phases can select or replace an image; active build
    and USB-write phases return their exact blocker, and impossible concurrent
    mutation still throws before UI state is cleared. On 2026-09-05, the focused
    19-case workflow/layout suite and all 121 frontend tests plus documentation,
    hygiene, and boundary integrity pass.
  - [x] Centralize USB-write admission without changing its destructive
    confirmation or native revalidation. The event boundary now requires the
    completed-image phase and a live preflight capability; missing, malformed,
    stale-phase, build-active, and already-writing inputs fail closed before the
    confirmation dialog. On 2026-09-05, the focused 20-case workflow/layout
    suite and all 122 frontend tests plus documentation, hygiene, and boundary
    integrity pass.
  - [x] Route output-folder selection through the reducer. Only the selected,
    non-mutating phase may preview or adopt a destination; empty, completed,
    building, USB-writing, malformed, and impossible concurrent states return
    stable blockers before any native preview call. On 2026-09-05, the focused
    21-case workflow/layout suite and all 123 frontend tests plus documentation,
    hygiene, and boundary integrity pass.
  - [x] Centralize USB preflight admission and require the typed destructive
    confirmation at the event boundary as well as in native validation. Only a
    completed image with no pending arm, an exact target identity, and matching
    ERASE-device text can invoke preflight; malformed capability shapes and all
    partial combinations fail closed. Native revalidation remains unchanged.
    On 2026-09-05, the focused 22-case workflow/layout suite and all 124
    frontend tests plus documentation, hygiene, and boundary integrity pass.
    The broader workflow transition model remains open.
  - [x] Route USB preflight cancellation through the reducer. Cancellation now
    requires the completed-image phase, one live session, and no cancellation
    already pending; missing and malformed capabilities or stale workflow phases
    fail closed before native cancellation while existing operation-context race
    checks remain authoritative. On 2026-09-05, the focused 23-case
    workflow/layout suite and all 125 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Route USB target selection through the reducer. Target changes now
    require a stable selected-image or completed-image phase; empty, building,
    USB-writing, malformed, and impossible concurrent states fail closed before
    clearing a live preflight session or changing target context. Native target
    identity inspection and destructive confirmation remain unchanged. On
    2026-09-05, the focused 24-case workflow/layout suite and all 126 frontend
    tests plus documentation, hygiene, and boundary integrity pass. The broader
    workflow transition model remains open.
  - [x] Route USB target clearing through the reducer before DOM mutation. Clear
    requests now require a selected target and a stable selected-image or
    completed-image phase; missing targets, malformed capabilities, active
    builds, USB writes, and impossible concurrent states fail closed without
    discarding the visible selection or live preflight context. Native target
    inspection and destructive confirmation remain unchanged. On 2026-09-05,
    the focused 25-case workflow/layout suite and all 127 frontend tests plus
    documentation, hygiene, and boundary integrity pass. The broader workflow
    transition model remains open.
  - [x] Route USB review opening through the reducer. Review now requires the
    completed-image phase and a selected target; selected-only, empty, building,
    USB-writing, missing-target, malformed, and impossible concurrent states
    fail closed before the destructive-review dialog opens. Native preflight,
    identity revalidation, and final confirmation remain unchanged. On
    2026-09-05, the focused 26-case workflow/layout suite and all 128 frontend
    tests plus documentation, hygiene, and boundary integrity pass. The broader
    workflow transition model remains open.
  - [x] Route USB review dismissal through the reducer. Dismissal remains
    available through empty, selected, completed, and asynchronous build-refresh
    phases, but fails closed once destructive USB writing starts or workflow
    mutation becomes impossible. Session cancellation and generation invalidation
    behavior remain unchanged. On 2026-09-05, the focused 27-case
    workflow/layout suite and all 129 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Route image export-mode changes through the reducer. The checkbox stays
    editable in empty and selected phases; completed, building, USB-writing, and
    impossible concurrent states reject synthetic mutations and restore the
    authoritative completed or active-build destination before rerendering. USB
    target selection remains independently gated. On 2026-09-05, the focused
    28-case workflow/layout suite and all 130 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Route destructive USB confirmation editing through the reducer. Text
    entry now requires an idle completed-image phase, selected target, no pending
    preflight, and no live session; rejected synthetic edits are cleared and
    cannot enable preflight. Missing and malformed capabilities, active writes,
    and impossible concurrent states fail closed. On 2026-09-05, the focused
    29-case workflow/layout suite and all 131 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Apply image-selection admission before opening the native picker.
    Programmatic picker clicks now reject building, USB-writing, malformed, and
    impossible concurrent states before native UI appears; the existing inner
    reducer guard remains authoritative for drag/drop, delayed picker results,
    and selection replacement. On 2026-09-05, the focused 29-case
    workflow/layout suite and all 131 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Apply output-directory admission before opening the native folder
    picker. Programmatic clicks now reject empty, completed, building,
    USB-writing, malformed, and impossible concurrent states before native UI
    appears; the existing inner reducer guard remains authoritative for delayed
    picker results and explicit destination reset. On 2026-09-05, the focused
    29-case workflow/layout suite and all 131 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Route manual USB target refresh through the reducer. User-triggered
    refresh now requires a stable selected-image or completed-image phase; empty,
    building, USB-writing, malformed, and impossible concurrent states fail
    closed before session cancellation or native disk inspection. The internal
    build-completion refresh remains separately protected by exact operation and
    target identity checks. On 2026-09-05, the focused 30-case workflow/layout
    suite and all 132 frontend tests plus documentation, hygiene, and boundary
    integrity pass. The broader workflow transition model remains open.
  - [x] Apply output-directory admission before explicit destination reset.
    Rejected synthetic reset clicks now leave the output-selection revision and
    current destination untouched in empty, completed, building, USB-writing,
    malformed, and impossible concurrent states; the existing inner guard still
    protects delayed calls. On 2026-09-05, the focused 30-case workflow/layout
    suite and all 132 frontend tests plus documentation, hygiene, and boundary
    integrity pass. The broader workflow transition model remains open.
  - [x] Apply image-selection admission to drag-over and drop events. Invalid
    building, USB-writing, malformed, and impossible states no longer advertise
    an active drop target or enter selection; non-over events still clear stale
    highlighting, and the inner selection guard continues to protect delayed
    work. On 2026-09-05, the focused 30-case workflow/layout suite and all 132
    frontend tests plus documentation, hygiene, and boundary integrity pass. The
    broader workflow transition model remains open.
  - [x] Bind NVIDIA source selection and upstream approval into the accepted
    build context before asynchronous preview/window setup. Build requests now
    emit only those immutable values, source controls stay locked through the
    active build, and both failure and completion restore them. Late DOM changes
    can no longer alter an admitted request. On 2026-09-05, the focused 30-case
    workflow/layout suite and all 132 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Bind the selected input path/name, output mode, and output directory to
    the accepted build context before asynchronous preview and window setup.
    Preview and build dispatch now use only that immutable request snapshot, so
    delayed UI or internal state changes cannot redirect an admitted build to a
    different source or destination. On 2026-09-05, the focused 30-case
    workflow/layout suite and all 132 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Restore build controls from the actual asynchronous terminal phase.
    Failed build completions now re-enable source and output configuration,
    while verified completed outputs keep those immutable controls locked and
    still allow selecting a different image. On 2026-09-05, the focused 30-case
    workflow/layout suite and all 132 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Route NVIDIA source intent and explicit upstream approval changes
    through the reducer. Empty and selected-image phases accept changes;
    completed, building, USB-writing, malformed, and impossible states restore
    the last accepted source and approval instead of honoring synthetic events.
    Source controls also remain locked when a delayed branch refresh ends in a
    non-editable phase. On 2026-09-05, the focused 31-case workflow/layout suite
    and all 133 frontend tests plus documentation, hygiene, and boundary
    integrity pass. The broader workflow transition model remains open.
  - [x] Make NVIDIA branch-list refresh transactional. Results now replace the
    source options only when they belong to the latest positive-safe-integer
    request generation and the workflow is still empty or selected; stale,
    completed, building, USB-writing, malformed, and impossible states preserve
    the accepted options and source intent. On 2026-09-05, the focused 32-case
    workflow/layout suite and all 134 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Guard NVIDIA branch refresh before native IPC and gate late errors with
    the same transactional admission. Requests that begin in completed,
    building, USB-writing, malformed, or impossible states do no work, and a
    request that becomes stale or non-editable cannot overwrite the current
    workflow message with an obsolete fetch failure. On 2026-09-05, the focused
    32-case workflow/layout suite and all 134 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Reject impossible completed-output relationships in the reducer. A
    completed output now requires its selected source image, and USB-writing
    state requires that completed output; all ordinary USB-writing fixtures
    model the retained completed image explicitly. On 2026-09-05, the focused
    32-case workflow/layout suite passes after correcting the newly exposed
    invalid fixture, and all 134 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Reject detached upstream-approval state. The reducer now requires an
    upstream source whenever explicit upstream approval is set; switching back
    to a trusted source validates a normalized proposed snapshot before clearing
    approval, while synthetic approval events on trusted sources restore the
    safe unchecked state. On 2026-09-05, the focused 32-case workflow/layout
    suite and all 134 frontend tests plus documentation, hygiene, and boundary
    integrity pass. The broader workflow transition model remains open.
  - [x] Reject active-build state without its selected source image. Build
    admission binds the image before entering mutation and image replacement is
    already blocked throughout that phase, so a missing image now fails closed
    instead of being classified as an ordinary build. On 2026-09-05, the focused
    32-case workflow/layout suite and all 134 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Reject completed-output state without a retained output mode. Imported
    and newly built completions both select image retention before rendering the
    completed phase, so a null output mode now fails closed instead of presenting
    an internally contradictory completion. On 2026-09-05, the focused 32-case
    workflow/layout suite and all 134 frontend tests plus documentation, hygiene,
    and boundary integrity pass. The broader workflow transition model remains
    open.
  - [x] Reject USB-writing state without a USB-bearing output mode. Destructive
    writing now requires `usb` or `both`, and all ordinary writing fixtures model
    the retained completed image plus selected USB destination explicitly. On
    2026-09-05, the focused 32-case workflow/layout suite passes after correcting
    the newly exposed invalid fixtures; all 134 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Reject active-build state without its admitted output mode. Build
    admission requires a non-null output destination before mutation and output
    controls remain locked for that phase, so losing the mode now fails closed.
    On 2026-09-05, the focused 32-case workflow/layout suite and all 134 frontend
    tests plus documentation, hygiene, and boundary integrity pass. The broader
    workflow transition model remains open.
  - [x] Reject active upstream builds without retained explicit approval.
    Upstream admission requires consent before mutation and source controls stay
    locked throughout the build, so a missing approval now fails closed instead
    of becoming an ordinary active-build snapshot. On 2026-09-05, the focused
    32-case workflow/layout suite and all 134 frontend tests plus documentation,
    hygiene, and boundary integrity pass. The broader workflow transition model
    remains open.
  - [x] Reject empty workflows with a USB-bearing output mode. USB target
    selection requires a selected image, and image replacement clears the target
    before its temporary empty phase, so `usb` and `both` now fail closed without
    an image. On 2026-09-05, the focused 32-case workflow/layout suite and all 134
    frontend tests plus documentation, hygiene, and boundary integrity pass. The
    broader workflow transition model remains open.
  - [x] Route terminal build completion through reducer phase admission. A
    completion may now mutate workflow state only while the reducer still names
    an active build; empty, selected, completed, USB-writing, malformed, and
    impossible concurrent snapshots fail closed before completion rendering.
    Exact request identity, selected-image generation, output inspection, and
    later operation-context checks remain authoritative. On 2026-09-05, the
    focused 33-case workflow/layout suite and all 135 frontend tests plus
    documentation, hygiene, and boundary integrity pass. The broader workflow
    transition model remains open.
  - [x] Route USB write progress through reducer admission. Progress renders
    only during the destructive write phase and only for the bounded native
    phase vocabulary, positive safe total, in-range monotonic byte counts,
    stable total, forward phase movement, and a bounded nonempty message.
    Verification may reset its phase-local byte count, while stale, malformed,
    backward, and regressing events leave the visible status untouched. On
    2026-09-05, the focused 34-case workflow/layout suite and all 136 frontend
    tests plus documentation, hygiene, and boundary integrity pass. Physical
    removable-media validation remains a separate release gate, and the broader
    workflow transition model remains open.
  - [x] Validate USB write completion before rendering verified success. The
    admitted preflight session now binds the image, session, whole-device
    identifier, and raw device node before native IPC. A resolved result must
    retain that exact device identity, report a positive safe byte count,
    `verified` status, matching hexadecimal image/readback SHA-256 values, a
    boolean eject outcome, and a bounded nonempty message. Malformed, mismatched,
    stale-phase, or false-success results enter the existing safe error UI. On
    2026-09-05, the focused 35-case workflow/layout suite and all 137 frontend
    tests plus documentation, hygiene, and boundary integrity pass. Physical
    removable-media validation remains a separate release gate, and the broader
    workflow transition model remains open.
  - [x] Bind USB completion verification to the preflight image digest and
    distinguish automatic-eject failure. A terminal result whose internally
    matching hashes differ from the preflight-authenticated image now fails
    closed. A byte-verified result with `ejected: false` remains an accepted
    completed write, preserves the native manual-eject instruction, and uses
    error attention styling rather than presenting an entirely successful
    finish. On 2026-09-05, the focused 36-case workflow/layout suite and all 138
    frontend tests plus documentation, hygiene, and boundary integrity pass.
    Physical removable-media validation remains a separate release gate, and
    the broader workflow transition model remains open.
  - [x] Require the complete admitted USB write context at terminal result
    validation. Empty, oversized, missing, or malformed session tokens, image
    paths, whole-device identifiers, raw device nodes, and preflight image
    digests now fail closed even when a result otherwise appears verified. The
    renderer already dispatches and validates against the same immutable context.
    On 2026-09-05, all 36 focused workflow/layout tests, including the new context
    boundary cases, and all 138 frontend tests plus documentation, hygiene, and
    boundary integrity pass. Physical removable-media validation remains a
    separate release gate, and the broader workflow transition model remains
    open.
- [ ] Split oversized frontend workflow/log rendering code only where behavior
  can be covered by focused tests.
  - [x] Extract the pure USB write start, progress, and completion reducer
    slice from the general workflow module. The new module retains the same
    snapshot authority and keeps UI orchestration in the main window while
    isolating its bounded phase vocabulary, context/result validation, and
    monotonic progress rules. A new regression rejects malformed retained
    progress history as well as malformed incoming events. On 2026-09-05, the
    focused 37-case workflow/layout suite and all 139 frontend tests plus
    documentation, hygiene, and boundary integrity pass. Further splitting
    remains limited to behavior with equivalent focused coverage.
  - [x] Extract the pure USB target, review, confirmation, and preflight
    admission slice from the general workflow module. The dedicated module
    continues to consume the same authoritative phase reducer while keeping
    destructive-review capability checks separate from unrelated build/source
    transitions. A new combined-invalid-input regression proves blocker
    precedence remains preflight pending, target identity, identity token, then
    exact destructive confirmation. On 2026-09-05, the focused 38-case
    workflow/layout suite and all 140 frontend tests plus documentation, hygiene,
    and boundary integrity pass. Further splitting remains limited to behavior
    with equivalent focused coverage.
  - [x] Extract build-source selection and asynchronous branch-refresh admission
    from the general workflow reducer. The dedicated module still derives its phase
    from the authoritative workflow snapshot, accepts changes only in empty/selected
    phases, and rejects stale refresh generations before they can update the source
    menu. A new combined stale-and-building regression preserves the stronger active-
    mutation blocker, and static wiring requires the separate reducer import. On
    2026-09-05, the focused 38-case workflow/layout suite and all 140 frontend tests
    plus documentation, hygiene, and boundary integrity pass. Further splitting
    remains limited to behavior with equivalent focused coverage.
  - [x] Extract image export-mode and output-directory admission from the general
    workflow reducer. The dedicated output-state module still derives every phase
    from the authoritative workflow snapshot; directory changes remain limited to
    selected images, while export-mode changes remain limited to empty or selected
    phases. A combined completed-output and unavailable-host regression proves the
    completed phase remains authoritative and cannot reopen output controls. On
    2026-09-05, the focused 38-case workflow/layout suite and all 140 frontend tests
    plus documentation, hygiene, and boundary integrity pass. Further splitting
    remains limited to behavior with equivalent focused coverage.
  - [x] Extract build-start and terminal-completion admission from the general
    workflow reducer. The dedicated lifecycle module still derives its decision
    from the authoritative snapshot: starts require every readiness input, while
    completion remains admitted for an already-running build even if host readiness
    drops afterward, allowing bounded terminal cleanup and result handling. Static
    wiring requires the separate lifecycle import. On 2026-09-05, the focused
    38-case workflow/layout suite and all 140 frontend tests plus documentation,
    hygiene, and boundary integrity pass. Further splitting remains limited to
    behavior with equivalent focused coverage.
- [x] Add a user-selectable image output folder and safe non-overwriting name.
  The main workflow now uses a native directory chooser, supports an explicit
  return to the source folder, invalidates stale chooser results when image
  selection changes, and disables destination changes during builds or for
  completed images. Preview, host-space admission, appliance session state, and
  final export share the same canonical directory. Existing create-only image
  and adjacent-manifest collision scanning remains authoritative, including
  manifest-only reservations and versioned NVIDIA names. Missing paths and
  regular files are rejected as output directories. On 2026-09-04, the focused
  13-case layout suite and Rust collision/directory test pass; formatting and
  warnings-as-errors Clippy pass; all 113 frontend tests plus documentation,
  hygiene, and boundary integrity pass. The complete Rust suite reached 330
  passes with 27 ignored before one unrelated live sibling Core
  installer-result fixture conformance case failed while Core was busy changing
  its local fixtures; that unchanged external failure was not retried or treated
  as EXE feature validation.
- [x] Keep advanced diagnostics accessible without exposing them by default.
  Build logs now start behind an explicit keyboard-accessible disclosure with
  synchronized `aria-expanded`, panel visibility, and expanded layout state.
  Copy-diagnostic and live-follow controls remain inside the revealed panel;
  every new build collapses stale diagnostic output again. On 2026-09-04, the
  focused 11-case diagnostics suite and all 112 frontend tests plus
  documentation, hygiene, and boundary integrity pass.
- [x] Add a narrow-effective-width/high-zoom reflow contract for the main
  workflow. At 760 CSS pixels or below in either dimension, the shell becomes
  vertically scrollable, two-column readiness/build/download layouts collapse
  to one column, output actions wrap, and long source/output paths wrap at any
  character inside bounded scroll regions instead of forcing horizontal
  clipping. On 2026-09-04, the focused 14-case layout suite and all 114
  frontend tests plus documentation, hygiene, and boundary integrity pass.
  This is structural coverage; pixel rendering, translated-string fixtures, and
  real display scaling remain in the broader graphical gate.
- [x] Extend the narrow-effective-width/high-zoom reflow contract to the build
  progress and compatibility-management windows. At 760 CSS pixels or below in
  either dimension, fixed desktop minimums no longer force clipping; progress
  content can scroll, status/actions wrap, expanded diagnostics retain a usable
  viewport, compatibility grids collapse to one column, and long identities,
  paths, and patch previews wrap within their cards. On 2026-09-04, the focused
  build-diagnostics and maintainer-layout regressions pass; all 116 frontend
  tests plus documentation, hygiene, and boundary integrity pass. Real pixel
  rendering, translated-string fixtures, and display scaling remain in the
  broader gate.
- [ ] Test compact and expanded layouts, long localized text, zoom, reduced
  motion, high contrast, keyboard-only use, and display scaling.
- [x] Keep unknown Core phases indeterminate; never infer percentages from
  heartbeats or free-form log text. Unknown structured phases now retain only
  their bounded label and current validation/installation context: even a
  syntactically determinate future record exposes no inherited overall progress,
  completed/total values, unit, or step fraction. The focused progress parser
  regression covers unknown phases before and after known determinate progress;
  existing strict parsing continues to reject malformed, regressing, oversized,
  and contradictory records. On 2026-09-04, the focused 11-case diagnostics
  suite and all 112 frontend tests plus documentation, hygiene, and boundary
  integrity pass.

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
- [x] Keep a conspicuous “do not disconnect” warning visible throughout write,
  verification, flush, and eject. The alert is exposed before native destructive
  work begins, remains present across every admitted progress update, and clears
  only from the terminal cleanup path after the native operation resolves or
  fails. Its visible text explicitly covers writing, read-back verification,
  flushing, and safe ejection. On 2026-09-05, the focused 15-case main-layout
  suite and all 141 frontend tests plus documentation, hygiene, and boundary
  integrity pass. Linux physical-device writing remains unavailable.
- [x] Never expose internal/system disks or accept a partition when a whole
  removable device is required. macOS discovery requires an exact numeric whole-
  disk identifier and canonical `/dev/diskN` node, explicit external physical,
  writable, removable-or-ejectable metadata, a bounded capacity, supported block
  size and image alignment, plus nonempty device-tree provenance; final preflight
  reruns the same eligibility parser and binds its identity token. The expanded
  fail-closed matrix covers every required field missing or malformed, internal,
  partition, virtual, non-writable, non-removable, deceptive raw-node, oversized,
  unsupported-block, and unaligned cases. On 2026-09-05, formatting, warnings-as-
  errors Clippy, and the focused native safety test pass. The full Rust suite
  reached 330 passes with 27 ignored; its sole failure was the already-recorded
  mutable sibling-Core installer-result fixture mismatch while Core was busy,
  which was not retried or counted as USB validation. Linux physical-device
  discovery and writing remain unavailable.

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
  application and confirm no orphan QEMU processes remain. The experimental
  Ubuntu debug package now has the equivalent bounded AT-SPI launch/close and
  before/after QEMU inventory coverage; the signed release-package path remains
  gated and unclaimed.

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
