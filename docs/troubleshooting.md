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
