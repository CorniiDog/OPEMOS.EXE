# Product-first review tiers synchronization

Date: 2026-09-11

The user explicitly authorized OPEMOS.EXE to mirror the exact `BOUNDARIES.md`
bytes from canonical OPEMOS Core squash commit
`e36e9052b982893b5fc89f6df0fa1c8671b7cad1` as the second step of the staged
product-first governance update. The canonical source PR was
https://github.com/CorniiDog/OPEMOS/pull/35, with preserved source head
`9fdcaf22d8be4d199807904f018f0f7c1b8a6bd9`.

Canonical identities:

- Core source commit: `e36e9052b982893b5fc89f6df0fa1c8671b7cad1`
- `BOUNDARIES.md` Git blob: `9b379788b1deadbb2088887eb10be325008254ac`
- `BOUNDARIES.md` SHA-256: `c44a987b4931f413ee72cc6d94ff3797f746bbdba4bcf51c7d7aed9406ffd9f2`

The synchronized authority allows routine documentation, isolated UI,
developer-tooling, test-harness-only, and similarly non-destructive pull
requests to merge after their required checks pass without counterpart-primary
approval only when their material behavior cannot reach disks, images, VM or
process lifecycle, production trust, release publication, physical hardware,
or cross-repository contracts.

Image construction or export, device selection or writing, VM or process
lifecycle, Core bundle consumption, compatibility decisions, and cross-
repository contracts retain exact counterpart-primary review. Release,
signing/trust, production, physical-media, and hardware-certification work also
retains every applicable explicit-user gate. Standalone evidence-only pull
requests are prohibited; implementation pull requests and authenticated
handoffs preserve evidence.

Preserved preceding synchronized identities:

- EXE mirror commit: `507e23cf848cde3c74390f7e6c41ba09f9084a15`
- Git blob: `2f8424a1df29fce2859126f7c42fd1885db8a425`
- SHA-256: `8c882b9a25e3d53fc200d82fff0807a8746dc826410271563d37342542c01df0`

The canonical bytes were obtained from authenticated GitHub at the immutable
Core squash above and independently matched both expected identities before
being copied. The sibling Core checkout was not used. Because this pull request
changes a cross-repository contract, Core must approve its exact unchanged
identity before merge. After EXE verifies its squash commit on protected
`main`, Core may perform its separate final counterpart repin.
