# Screenshot assets

The documentation reserves three 16:9 slots:

| Filename | Capture |
| --- | --- |
| `main-window.png` | Main workflow after selecting an image, with both readiness cards and output controls visible |
| `build-progress.png` | Progress window showing status, split progress pill, colored logs, and diagnostic controls |
| `maintainer-workspace.png` | Permission-gated maintainer window with a validated plan and local editor target |

Capture at native scale, crop only the outer transparent margin, and redact host
usernames, paths, device serials, tokens, and credentials. Prefer PNG and keep
each image below 2 MiB.

Until an image is reviewed and committed, retain the accessible placeholder in
`docs/index.md`; do not add a broken `<img>` reference.
