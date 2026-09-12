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
Every tier-appropriate required check must pass. Routine documentation, isolated
UI, developer-tooling, and test-harness-only changes may merge without Core
counterpart approval only when they cannot reach disks, images, VM or process
lifecycle, production trust, release publication, physical hardware, or cross-
repository contracts. Record that classification and the checks in the pull
request.

Imaging-sensitive, compatibility, Core-consumption, and cross-repository-contract
changes require Core primary approval of the exact repository, pull request,
base commit, unchanged head commit, material scope, and required-check set under
`BOUNDARIES.md`. Release, signing/trust, production, physical-media, and hardware
work retains that review plus every explicit user gate. Helpers and Resolver
cannot approve or merge. If GitHub refuses the Core primary's approving review
solely because both leads authenticate as the pull-request author, use only the
exact authenticated scheduler/handoff fallback in the authority. Any changed
head, base, material scope, or required-check set invalidates approval.

Do not open a standalone evidence-only pull request to restate a completed
merge. Preserve evidence in the implementation pull request and authenticated
handoff; defer a final squash identity to later material work when needed.

After verifying the protected-main squash commit, the EXE primary may delete
only that merged topic branch. Never force-push, rewrite published history,
delete another ref, use a non-squash merge, or bypass branch protection. This
governance grants no release, trust, production, boundary, or hardware authority.
