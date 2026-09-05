# OPEMOS ownership boundary

> **READ-ONLY GOVERNANCE CONTRACT**
>
> This file may change only when the project owner explicitly requests a
> boundary change. Feature work, refactoring, repinning, release work, and
> automated cleanup must not edit it. Summaries elsewhere are non-authoritative.

## Dependency direction

```text
OPEMOS Core contracts
├── CLI
├── SteamOS Desktop Companion
├── SteamOS DRM/KMS interstitial
└── OPEMOS.EXE
```

OPEMOS Core is the lower-level policy and contract provider. The CLI, SteamOS
Desktop Companion, fullscreen DRM/KMS interstitial, and OPEMOS.EXE are sibling
Core consumers. The OPEMOS repository owns the interstitial implementation,
packaging, and tests, but the interstitial is not part of the Core policy layer.

OPEMOS Core never imports, invokes, builds against, or requires OPEMOS.EXE.
Frontends do not import, link against, or execute one another. The sole UI
exception permits OPEMOS.EXE to deploy the interstitial as target payload; it
does not permit OPEMOS.EXE or another frontend to launch it.

## OPEMOS Core owns

- SteamOS/NVIDIA compatibility, release selection, and safe next actions.
- Exact Valve headers, NVIDIA source selection, exact-target builds, artifact
  validation, canonical bundle manifests, schemas, and publication contracts.
- Reviewed userspace locks, signer/keyring policy, payload profiles, package
  authentication, and dependency correctness.
- Mounted-target installation, internal rollback, modules, GRUB, `depmod`,
  initramfs, receipts, and structured post-install verification.
- Machine-readable progress/results and the contracts consumed by the
  target-side CLI, Desktop Companion, DRM/KMS interstitial, recovery guardian,
  and device updater.
- Core contract, archive, Fedora build/transaction, target mutation, and
  contract-conformance tests.

## OPEMOS.EXE host ownership

- Host application windows, menus, accessibility, labels, progress weighting,
  diagnostics, controls, and application updates.
- Host HTTP acquisition, physical cache location, retries, authenticated
  manifest pinning, host-to-appliance transport, and transfer cleanup.
- Recovery-image inspection, boot-slot/kernel discovery, A/B and partition
  layout, QEMU/appliance lifecycle, mount orchestration, and exclusive overlay
  ownership.
- Outer rollback by retaining or discarding disposable overlays, preservation
  of the source image, independent final-image/output-manifest validation,
  export, host-shell integration, and verified removable-media writing.
- The installation-media welcome application and its guarded target-disk
  selection bridge.
- Host UI, download/transfer, VM, overlay, export, removable-media, and
  independent image tests.

This ownership is cross-platform. The current implementation and validated
host path target macOS, especially Apple Silicon, but the same boundary applies
to future supported host operating systems. Platform-specific APIs and adapters
remain inside OPEMOS.EXE and do not move into Core policy.

## Networking boundary

Networking is divided into three independent scopes:

- **Host networking:** OPEMOS.EXE owns host downloads, proxy and retry UX,
  physical cache placement, and transfer into managed appliances. Core defines
  the permitted identities, hashes, signatures, provenance, and authentication
  rules.
- **Appliance networking:** OPEMOS.EXE owns VM network attachment, isolation,
  lifecycle, and host-to-guest transport. Core commands declare bounded network
  requirements. Installation defaults to no external appliance egress and uses
  authenticated staged inputs; an exact-target build may receive only the
  explicitly authorized egress its Core build contract requires. Core never
  configures the host network.
- **Installed-device networking:** SteamOS and the user own connectivity,
  credentials, and device network configuration. Core-owned update/recovery
  clients own only their authenticated, bounded requests after SteamOS boots.
  Credentials and device network state never appear in progress, result,
  receipt, or diagnostic contracts.

Success in one network scope neither establishes trust nor grants network
authority in another scope.

## Source intent and Core authorization

OPEMOS.EXE records the user's requested source intent, such as Automatic,
published artifact, exact-target local build, reviewed project source, or
explicit development control. User intent is an input, not authorization.
Automatic is itself explicit user intent: it asks Core to select only within
the current reviewed production policy. It never authorizes development
sources, approximation, or fallback outside that policy.

Core alone validates whether that intent is permitted for the exact target and
returns an authorized bounded action or a fail-closed result. OPEMOS.EXE never
translates rejected intent into another source mode, silently chooses another
branch or commit, or bypasses Core authorization. Core never invents user intent
or broadens the requested operation.

## A/B ownership

Recovery-image A/B orchestration belongs to OPEMOS.EXE. It inspects the image,
determines the relevant recovery rootfs/var/EFI pairing, mounts only the
selected disposable overlay, and preserves the original image.

SteamOS owns the base operating-system slot transition. Core-owned recovery and
guardian contracts own NVIDIA state, receipts, validation, repair, and payload
rollback in response to that transition. Image-time slot selection does not
define installed-system update policy, and Core policy never selects the base
OS slot, repartitions storage, or reinterprets the source recovery image.

## Sole UI exception

The OPEMOS repository—not OPEMOS.EXE—owns and implements the fullscreen
no-input DRM/KMS UI shown on SteamOS during boot, recovery, installation work,
and updates. It remains a sibling consumer of Core progress and state contracts.
This is the one explicit exception to OPEMOS.EXE's ownership of the graphical
image-builder experience.

OPEMOS.EXE consumes the fullscreen UI only as an authenticated OPEMOS-owned
interstitial target payload from the exact pinned bundle. It may deploy it and
stage bounded Core progress/state inputs, but it must not fork, rewrite, import,
link, or execute that Linux frontend as part of its host runtime.

After deployment, a Core-owned installed-device supervisor may launch and
monitor the interstitial through a bounded Core contract. That is Core-to-
consumer lifecycle orchestration, not frontend-to-frontend execution. The
OPEMOS repository owns the interstitial's source, renderer, behavior, tests,
packaging, release, and device lifecycle. The interactive installation-media
welcome application remains builder-owned and separate.

## Artifact cleanup ownership

Artifact cleanup follows creator ownership. OPEMOS.EXE owns and cleans artifacts
it creates. Core owns and cleans artifacts it creates when Core can safely identify
them. Neither component gains authority to remove artifacts created by the other.

For a concerning conflict involving a Core-created artifact, Core may expose a
bounded, provenance-preserving flag that OPEMOS.EXE can consume to drive the
defined resolution. Before acting, the consumer must revalidate the exact artifact
identity and applicable provenance. Missing, stale, malformed, mismatched,
conflicting, or ambiguous evidence fails safely without cleanup. The flag grants
no blanket deletion authority and does not transfer ownership to OPEMOS.EXE.

## Shared handoff

1. OPEMOS.EXE discovers the exact target from the recovery image.
2. The pinned Core resolver decides compatibility or authorizes its bounded
   exact-target build contract.
3. OPEMOS.EXE downloads and transfers only identities named by authenticated
   Core contracts.
4. Core validates and mutates the mounted disposable target transaction.
5. OPEMOS.EXE independently validates the resulting image and either exports
   it or discards the overlay.

Transport success never establishes trust. Core success never replaces the
builder's independent final-image check. Maintainers own real SteamOS/NVIDIA
hardware certification and cross-repository release approval.
