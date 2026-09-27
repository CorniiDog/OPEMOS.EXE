---
layout: page
title: Troubleshooting
description: Interpret failures, gather diagnostics, and identify user versus maintainer actions.
---

## Start with the diagnostic summary

Use **Copy Diagnostic Log** in the progress window. Preserve the first explicit
`[builder] ERROR`, the structured reason in parentheses, and the nearby OPEMOS
message. Routine Fedora boot, pacman warnings, and cleanup output may occur
after the authoritative failure.

## Who should act

| Situation | Owner | Response |
| --- | --- | --- |
| Unsupported or corrupt recovery image | User | Select another official Valve image |
| Insufficient host disk space | User | Free the exact reported amount |
| Temporary network failure | App/user | Retry; reuse only exact authenticated cache entries |
| Missing exact NVIDIA artifact | App | Offer an exact-kernel local build when supported |
| Missing Valve headers or NVIDIA branch | Maintainer | Add or restore trusted compatibility inputs |
| Signature, lock, or provenance mismatch | Maintainer | Audit the exact bytes; never bypass normal trust |
| Vermagic, userspace, module, or initramfs mismatch | App/maintainer | Reject the overlay and correct the contract |
| QEMU remains after close | App | Report diagnostics; lifecycle cleanup is an invariant |
| Unsupported USB target | User | Select a whole external physical removable drive |

## Windows reports a missing packaged prerequisite

If a portable Windows candidate reports `Windows host prerequisite is missing:
qemu-img` while `runtime/qemu/qemu-img.exe` exists, do not install QEMU globally
or add an arbitrary directory to `PATH`. The executable was built without the
runtime-manifest pin, or its portable bundle identity is inconsistent. Rebuild
with `bundle_windows.ps1`, verify the staged provenance and manifest hashes, and
launch from that complete directory. On first successful launch, the generated
`state/cache-v1/cache-manifest.json` must bind the exact executable hash and
runtime-manifest hash.

The packaged application deliberately resolves required commands only from its
verified runtime bundle. This failure is therefore a packaging error rather than
a missing end-user dependency.

## Windows refuses USB-writer elevation

The Windows security option **User Account Control: Only elevate executables
that are signed and validated** rejects an unsigned portable OPEMOS candidate
before the bounded USB writer can start. Windows reports native error 8235 as
`A referral was returned from the server`.

OPEMOS checks that policy and the current executable's Authenticode trust before
requesting elevation. When the policy is enabled and the candidate is unsigned
or untrusted, the app stops without opening the Windows referral dialog and
without changing the selected USB. Use a reviewed, trusted Authenticode-signed
OPEMOS build. Do not disable the policy or route the writer through a signed
system interpreter to bypass it.

## Apparently stalled stages

Source hashing, emulated x86_64 boot, package measurement, pacman hooks, and
`mkinitcpio` can take time. The lower progress channel may be indeterminate when
the support tool can provide only bounded heartbeats. An indeterminate bar
means alive without a trustworthy percentage; it does not imply a freeze.

## Black screen or missing Wi-Fi on target hardware

Keep the original recovery USB available and avoid wiping or reinstalling
until the active slot, running kernel, NVIDIA module, and graphical logs are
known. See [Hardware and update recovery](hardware-and-updates.md) for a
read-only black-screen collection, Wi-Fi controller/firmware diagnosis, and
the planned fail-safe A/B update behavior.

## Safe retry

After failure, confirm the app reports cleanup and QEMU shutdown. Retry from the
original Valve image, not a partially named output. Exact authenticated caches
may be reused, but disposable overlays and partial outputs must be recreated.

## Report a problem

Include the copied diagnostic summary, host macOS and architecture, input image
basename and detected target, selected NVIDIA source, first structured failure
reason, and whether cancellation or window close occurred.

Do not include credentials, private keys, GitHub tokens, Wi-Fi passwords, or a
Valve recovery image.
