# OMEN Actions queue

Every native package push continues to invoke the normal SteamOS workflow.
All SteamOS invocations share the `opemos-omen-robot` workflow concurrency group
with `queue: max` and cancellation disabled. GitHub retains up to 100 pending
runs instead of replacing an older pending run when another push arrives.
Only one workflow can proceed through the OMEN transaction and result phase at
a time. The existing host resource/GPU queue remains the final admission owner.

An expired or explicitly unavailable runner heartbeat is a waiting condition,
not a reason to discard the push. The hosted reader validates repository,
protected controller workflow, installed-source identity and runner labels,
then emits `queueable=true`. It keeps `ready=false` and every VM result
unavailable while waiting. A malformed authoritative identity still fails. Missing or malformed optional
availability/clock telemetry remains a waiting state, never a readiness claim.
The normal self-hosted job stays in GitHub's queue until the registered runner
is online and idle; the offline queue itself needs no additional hosted polling job.

OMEN's existing recovery timer is separately configured to observe connectivity
and recover through the normal control path every 15 seconds after a check
finishes. GitHub's native dispatcher handles delivery when the runner is back;
its internal dispatch interval is not configured by this workflow. GitHub's
self-hosted queue timeout remains 24 hours. The existing producer-side result observer also polls its one dispatched run
every 15 seconds; it never dispatches another copy while that run is queued.
That existing hosted observer still occupies a hosted runner. Its four-hour
observer deadline remains distinct from the native
self-hosted queue's 24-hour limit; a timeout never means acceptance. No new
credential is required.

Queuing grants no VM or GPU permission. The installed job-start hook rechecks
the real source, lease, namespace and broker before checkout, and the normal
queue rechecks exclusive GPU/resource/data ownership before any VM operation.
If the installed controller changes while a run is queued, a stale pinned
source must be refused by that hook; it is never silently relabeled. Application
source transitions must account for pending work through their normal reviewed
handoff. This change does not deploy a new controller or prove a VM boot.

GitHub documents the built-in behavior in [workflow concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
and [self-hosted runner routing](https://docs.github.com/en/actions/reference/runners/self-hosted-runners).
