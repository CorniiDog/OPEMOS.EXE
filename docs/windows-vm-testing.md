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


## Bind official evaluation media

Before an ISO may be used, create a local identity document with the exact
schema accepted by `scripts/windows-media.mjs`. It binds the canonical Microsoft
HTTPS source, Windows 11 Enterprise Evaluation product and edition, x86_64
architecture, release label, filename, byte size, and lowercase SHA-256. Then
make the downloaded ISO read-only and verify it locally:

```bash
chmod 0400 local-inputs/windows-vm/sources/windows-eval.iso
node scripts/windows-media.mjs verify local-inputs/windows-vm/manifests/windows-media.json
```

Verification refuses non-Microsoft or non-HTTPS origins, additional or missing
identity fields, unsupported products or architectures, files above 8 GiB,
links, mutable permissions, size mismatch, and byte-hash mismatch. The identity
document and ISO remain ignored local inputs. This verifier does not download
media, choose a mutable release, or authenticate an absent Microsoft signature;
the exact official release and digest must be recorded before acquisition.

## Generate reviewed unattended inputs

The committed `templates/windows/` files contain placeholders and no account
password or SSH key. Put a unique one-time account password and public key in a
mode-`0600` ignored runtime JSON file with exactly `account`, `password`, and
`sshPublicKey`, then generate the private installer inputs:

```bash
node scripts/windows-unattend.mjs generate \
  local-inputs/windows-vm/runtime/provision-input.json
```

Generation publishes `generated/autounattend.xml` and
`generated/provision.ps1` as create-only mode-`0600` files. It refuses unsafe
account names, short or control-bearing passwords, malformed public keys,
unknown fields, permissive input files, template drift, and existing outputs.
If the second output cannot be published, it removes only the answer file it
created and preserves the conflicting file.

The answer file limits autologon to one setup login. The reviewed provisioning
script installs the Microsoft OpenSSH Server capability, enables its existing
firewall rule, installs only the supplied public key with restricted ACLs,
disables SSH password authentication, restarts the service, and writes a bounded
completion marker. It does not disable Defender, Windows Update, firewall,
WebView2, accessibility, recovery, or device services. Derived files and the
runtime input remain ignored private state and must be removed after successful
provisioning before a base is sealed.

## Current verified evaluation source

On 2026-09-06, Microsoft Evaluation Center identified Windows 11 Enterprise
Evaluation version 25H2 for x64 and linked the EN-US ISO plus its verification
PDF. The resolved immutable local identity is:

- ISO: `windows-11-enterprise-evaluation-25h2-en-us-x64.iso`
- size: `7092807680` bytes
- SHA-256: `a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9`
- build: `26200.6584`
- Microsoft hash PDF SHA-256:
  `0d44bc561af90844c0a0da5ddc420f5fa84459872c02a1def6240fcfe1aac2c7`

The ISO was downloaded through `heavy.sh` into the ignored containment, checked
for exact size, matched to Microsoft's published EN-US digest, changed to mode
`0400`, and independently rehashed by `windows-media.mjs`. Total containment
allocation was `7092822016` bytes after verification. The official ISO remains
an immutable local input and is never committed or redistributed.

## Private answer media

The official Windows ISO stays unchanged. `windows-installer-media.mjs create`
builds a separate small answer ISO from only the generated private pair. It
checks their ownership, mode, size, reviewed markers, and resolved placeholders,
then invokes `genisoimage` with fixed Joliet and Rock Ridge graft names. Output
is create-only and removed if creation or post-validation fails.

The first local answer media is 374784 bytes with SHA-256
`7c4feeccb81b890fa50b999e2af60af63e37f5b43100d0fc5dd945ad103543ae`.
Both Joliet and Rock Ridge inventories contain exactly `autounattend.xml` and
`opemos-provision.ps1`. Its unique ED25519 public-key fingerprint is
`SHA256:yE5d5TQXr4G63Hd5dPlMs4HJiQ5kENP3j5BqRL29O1o`; private key and password
remain unprinted mode-`0600` runtime inputs. Total containment allocation is
`7093252096` bytes. These derived secrets must be removed after provisioning and
before sealing the base.
