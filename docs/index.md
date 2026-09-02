---
layout: default
title: OPEMOS.EXE
description: Build and export an exact-kernel NVIDIA SteamOS recovery image from a desktop application.
---

<section class="opemos-hero" aria-labelledby="opemos-exe-title">
  <div class="opemos-wordmark"><span aria-hidden="true"></span>OPEMOS.EXE</div>
  <p class="opemos-kicker">SteamOS NVIDIA Image Builder</p>
  <h1 id="opemos-exe-title">Official recovery image in.<br>Validated NVIDIA image out.</h1>
  <p class="opemos-summary">
    A local desktop workflow for exact-kernel NVIDIA resolution, isolated
    SteamOS image mutation, independent verification, and safe image or USB
    export.
  </p>
  <div class="opemos-actions">
    <a class="opemos-button opemos-button-primary" href="{{ '/getting-started.html' | relative_url }}">Get started</a>
    <a class="opemos-button opemos-button-secondary" href="{{ '/workflow.html' | relative_url }}">Understand the workflow</a>
  </div>
</section>

OPEMOS.EXE is the graphical companion to
[OPEMOS](https://github.com/CorniiDog/OPEMOS). The application owns the host,
image, appliance, and export boundaries; OPEMOS owns NVIDIA compatibility,
artifact, userspace, and offline-installation contracts.

> Active development: structural image mutation is not the same as a certified
> hardware boot. Preserve the original Valve image and read the trust label on
> every result.

## Application preview

<div class="screenshot-grid" aria-label="Application screenshots">
  <figure class="screenshot-slot" data-screenshot="main-window">
    <img src="{{ '/assets/screenshots/main-window.png' | relative_url }}" alt="OPEMOS.EXE main recovery-image workflow" loading="lazy">
    <figcaption>Main recovery-image workflow</figcaption>
  </figure>
  <figure class="screenshot-slot" data-screenshot="build-progress">
    <img src="{{ '/assets/screenshots/build-progress.png' | relative_url }}" alt="OPEMOS.EXE source verification and build progress window" loading="lazy">
    <figcaption>Live build progress and diagnostics</figcaption>
  </figure>
  <figure class="screenshot-slot" data-screenshot="maintainer-workspace">
    <img src="{{ '/assets/screenshots/maintainer-workspace.png' | relative_url }}" alt="OPEMOS.EXE permission-gated maintainer workspace" loading="lazy">
    <figcaption>Permission-gated maintainer workspace</figcaption>
  </figure>
</div>

## Choose your path

| Goal | Start here |
| --- | --- |
| Build from an official recovery image | [Getting started](getting-started.md) |
| Diagnose hardware or recover from an update | [Hardware and update recovery](hardware-and-updates.md) |
| Understand every stage and trust label | [Build workflow](workflow.md) |
| Prepare appliances and run tests | [Developer guide](developer-guide.md) |
| Review process and data boundaries | [Architecture](architecture.md) |
| Understand authentication and failure policy | [Security](security.md) |
| Diagnose a failed or apparently stalled build | [Troubleshooting](troubleshooting.md) |

## What the app owns

- Official-image selection and signature-based format detection
- Cancellable normalization, hashing, and host-space preflight
- Native and x86_64 Fedora appliance lifecycle
- Read-only source attachment and disposable overlay mutation
- Exact OPEMOS artifact and installer pinning
- Structured progress, diagnostics, cancellation, and cleanup
- Independent final-image inspection
- Image export and fail-closed removable-media writing

## What remains

Physical NVIDIA hardware boot, Valve installer propagation, SteamOS A/B update
behavior, Secure Boot policy, Windows USB authorization, and hardware-bound
certification attestations remain explicit roadmap gates.
