# Artifact cleanup ownership boundary synchronization

Date: 2026-09-04

The user explicitly authorized OPEMOS.EXE to mirror the exact `BOUNDARIES.md`
bytes from canonical OPEMOS Core commit
`3a6f0652f4118936820871f8201f7c5e1250acbf`.

Canonical identities:

- Core source commit: `3a6f0652f4118936820871f8201f7c5e1250acbf`
- `BOUNDARIES.md` Git blob: `68fd9553bb8fee79cee803a38f980a94b2d80e57`
- `BOUNDARIES.md` SHA-256: `136d3572effa90c1b84bcf51002d7f9641c367132de20d54dd7173f68f13c6a8`

The synchronized authority states that cleanup follows creator ownership. EXE
cleans EXE-created artifacts. Core cleans Core-created artifacts it can safely
identify. A bounded, provenance-preserving Core flag may drive an EXE resolution
only after EXE revalidates the exact artifact identity and applicable provenance.
Missing, stale, malformed, mismatched, conflicting, or ambiguous evidence fails
safely without cleanup. The flag grants no blanket deletion authority and does
not transfer ownership.

This synchronization resolves the recorded ownership question. It does not
implement the maintenance action, delete or retire any artifact, change trust or
production activation, or authorize either repository to modify the other. The
EXE commit containing this record is the counterpart Core should pin in its final
synchronization step.
