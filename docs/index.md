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

<div class="screenshot-grid" aria-label="Reserved application screenshots">
  <figure class="screenshot-slot" data-screenshot="main-window">
    <div role="img" aria-label="Reserved space for the OPEMOS.EXE main workflow screenshot">Main workflow screenshot</div>
    <figcaption><code>docs/assets/screenshots/main-window.png</code></figcaption>
  </figure>
  <figure class="screenshot-slot" data-screenshot="build-progress">
    <div role="img" aria-label="Reserved space for the build progress screenshot">Build progress screenshot</div>
    <figcaption><code>docs/assets/screenshots/build-progress.png</code></figcaption>
  </figure>
  <figure class="screenshot-slot" data-screenshot="maintainer-workspace">
    <div role="img" aria-label="Reserved space for the maintainer workspace screenshot">Maintainer workspace screenshot</div>
    <figcaption><code>docs/assets/screenshots/maintainer-workspace.png</code></figcaption>
  </figure>
</div>

The slots intentionally render without broken image icons. Replace each slot
with its named image after capturing the corresponding window.

## Choose your path

| Goal | Start here |
| --- | --- |
| Build from an official recovery image | [Getting started](getting-started.md) |
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
