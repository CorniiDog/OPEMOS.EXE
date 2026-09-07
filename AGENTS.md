# Repository agent instructions

`BOUNDARIES.md` is the read-only ownership authority mirrored from OPEMOS Core.
Do not modify it or its integrity test during ordinary implementation, cleanup,
documentation, release, or repinning work. A change requires an explicit user
request to change project boundaries and a synchronized source-commit, blob,
and SHA-256 update. Do not infer that permission from a task that merely touches
both repositories.

Repository summaries may link to the authority but must not contradict it.
Never edit OPEMOS Core from this repository's task unless the user separately
and explicitly authorizes that cross-repository mutation.

## Cross-lead pull-request governance

Use a fresh short-lived EXE branch and pull request for each bounded work item.
The EXE primary may squash-merge only after the Core primary approves the exact
repository, pull request, base commit, unchanged head commit, material scope,
and required-check set under `BOUNDARIES.md`, with every required check passing.
Helpers and Resolver cannot approve or merge. If GitHub refuses the Core
primary's approving review solely because both leads authenticate as the pull-
request author, use only the exact authenticated scheduler/handoff fallback in
the authority. Any changed head, base, material scope, or required-check set
invalidates approval.

After verifying the protected-main squash commit, the EXE primary may delete
only that merged topic branch. Never force-push, rewrite published history,
delete another ref, use a non-squash merge, or bypass branch protection. This
governance grants no release, trust, production, boundary, or hardware authority.
