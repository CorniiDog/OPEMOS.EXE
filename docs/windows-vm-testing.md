---
layout: page
title: Contained Windows packaging VM
description: Local containment and resource limits for future Windows package testing.
---

# Contained Windows packaging VM

Windows packaging tests use the gitignored repository-local root
`local-inputs/windows-vm/`. Initialize or inspect the empty containment with:

```bash
node scripts/windows-vm.mjs init
node scripts/windows-vm.mjs status
```

The root and its `sources`, `generated`, `base`, `overlays`, `runtime`, `logs`,
and `manifests` directories must be real directories owned by the current user
with mode `0700`. A create-only mode-`0600` marker binds the root to
OPEMOS.EXE. Inspection rejects links, special files, unexpected top-level
entries, changed ownership or permissions, excessive depth, and excessive file
counts before later tooling may use the tree.

Storage accounting distinguishes sparse logical size from allocated disk use.
Sources are limited to 8 GiB logical size, overlays to 12 GiB allocated size,
the whole tree has a 40 GiB soft allocated target, and 55 GiB is the hard
allocated limit. A future base disk may be 64 GiB sparse while its sealed
allocated target remains at most 30 GiB.

This containment step does not download an ISO, create a disk, generate
credentials, start QEMU, access a network, or activate Core discovery or
production trust. Later VM operations remain serialized through the shared
`heavy.sh` wrapper and must retain loopback-only SSH, no host-disk passthrough,
and local closed compatibility inputs.
