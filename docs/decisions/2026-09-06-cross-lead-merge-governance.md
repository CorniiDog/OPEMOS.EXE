# Cross-repository pull-request governance synchronization

Date: 2026-09-06

The user explicitly authorized OPEMOS.EXE to mirror the exact `BOUNDARIES.md`
bytes from canonical OPEMOS Core squash commit
`73e8d15c07671f3174f1a948d525e18db1084e5a` as the second step of the staged
cross-repository governance migration.

Canonical identities:

- Core source commit: `73e8d15c07671f3174f1a948d525e18db1084e5a`
- `BOUNDARIES.md` Git blob: `2f8424a1df29fce2859126f7c42fd1885db8a425`
- `BOUNDARIES.md` SHA-256: `8c882b9a25e3d53fc200d82fff0807a8746dc826410271563d37342542c01df0`

The synchronized authority permits only the owning repository primary lead to
squash-merge a bounded pull request after the counterpart primary reviews and
approves its exact repository, pull-request number, base branch and commit,
unchanged head commit, material scope, and required-check set. Every required
check must pass. A changed identity invalidates approval. Helpers and Resolver
cannot approve or merge.

When GitHub refuses an approving review solely because both leads authenticate
as the pull-request author, only an exact authenticated counterpart-primary
scheduler/handoff record may substitute. After verifying the protected-main
squash commit, the owning primary may delete only that merged topic branch.
This grants no force-push, history rewrite, other-ref deletion, release, trust,
production, boundary, or hardware authority.

The canonical bytes were obtained from authenticated GitHub at the immutable
Core squash above and independently matched both expected identities before
being copied. The sibling Core checkout was not used. Core must approve this
EXE pull request's exact unchanged identity before merge. After EXE verifies its
squash commit on `main`, Core may perform the separate final counterpart repin.
