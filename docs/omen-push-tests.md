# Automatic native candidate tests on OMEN

Ubuntu and Windows native workflows run on every repository branch push. Their
successful native package **job**, exact attempt and uploaded descriptor select
one automatic `04 SteamOS` invocation. The parent waits for the resulting check;
the result therefore belongs to the candidate commit, including an open PR's
branch update. A downstream OMEN failure does not invalidate an otherwise
successful package job for selection. The macOS route remains explicitly
unavailable until its real native guest is supplied; Ubuntu or Windows evidence
cannot cover it.

There are three separate source identities:

* `workflow_source_commit`: the protected workflow that authenticated the job.
* `source_commit`: the installed, reviewed OMEN controller and its exact lease,
  pinned Engine, planner, queue and source graph.
* `candidate_source_commit`: the API-authenticated native build under test.

Candidate code is never checked out as the privileged controller. The Root broker
rechecks the repository, producer workflow, native job, candidate ref/SHA, run,
attempt and artifact hashes. It streams the artifact into a private create-only
file, verifies the archive hash and passes it as opaque data to the normal
planner. Package/executable identity is also required by the existing guest and
transaction consumers. A candidate that changes controller code tests its package
in the disposable guest; it does not deploy its controller changes.

## Installed operation data

`scripts/omen_control/` contains the existing controller roles and their source
predecessor identities. Deployment is an owning-EXE operation after exact Core
source/effects review and the current R118 owner's actual safe closure. It must
not overwrite an active release, clear an unknown recovery nonce or rearm a
consumed attempt.

The Root-owned profile pins the normal planner/registry and an `operation_root`
that is private to the admitted broker. It also specifies
`max_candidate_archive_bytes`, within the existing 60 GB whole-VM limit. Each
configured platform's registry row can pin `automatic_operation` as
`{"path": "/absolute/installed-operation.json", "sha256": "..."}`. This replaces
pre-registering a different response for every run nonce. It is a fixed reviewed
normal operation recipe, not a candidate-provided executable or approval.

The recipe has `schema: 1`, ordered `documents`, `prepare` and `collect`. Each
document has a unique JSON basename and a JSON `value`. The existing normal
prepared-operation ABI remains complete: config, operand, plan, staging path,
Robot job, expected executable, build/heal entry, additional operations and the
actual executable transaction path. It does not accept a partial success packet.

Only these typed data references are substituted:

| Reference | Value |
| --- | --- |
| `$run` | Repository, controller SHA, run, attempt, nonce or consumer start |
| `$request: prepare` | Original complete preparation request |
| `$candidate` | One descriptor field, or `*` for the whole descriptor |
| `$archive` | Opaque archive path, SHA-256 or byte count |
| `$path` | A fixed basename under this run's private directory |
| `$document` | Hash/path of an earlier ordinary JSON operand |
| `$job` | Fixed job prefix plus the fresh operation nonce |
| `$result` | Held hash/path of an actual same-operation output, collection only |

There is no evaluation, import, shell interpolation, generated executable or new
scheduler. Candidate fields belong only in guest-input data. Installed commands,
controller source pins, original base identities, Root policy and GPU/resource
admission remain the reviewed normal recipe's identities. A static recipe does
not stand in for current machine observations, an issued grant, a passed result
or normal closure. The normal consumers still perform those checks at use.

The existing recovery service may invoke the reviewed heartbeat producer after
its ordinary cycle. A heartbeat is a fresh observation of the installed source,
canonical control unit/lease and live listener/controller/worker. A busy runner,
active unrelated Actions job or occupied GPU is not a routing veto: the ordinary
queue supplies serialization and pool admission. Source/worker/unknown-reservation
and finite lease faults still refuse. Freshness remains 180 seconds. A later Main
merge does not silently relabel an older installed controller as new source.

## Evidence and current limits

Optional preflight catalogs, summary paths and diagnostic uploads cannot authorize
or veto routing. Result acceptance requires authenticated current producer data
again, the actual broker transaction, actual reports, guest evidence and closure.
A missing cached preflight report cannot turn a failure into a pass. A failed
broker's original typed cause is preserved if diagnostic reauthentication fails.

Admitted CI tests cover non-Main/PR metadata, run/attempt drift, opaque archive
custody, JSON-only per-run construction, same-head fresh identities, a Linux
connect-denied producer/consumer and busy-route versus actual source/worker
faults. Fixtures explicitly model GitHub/native facts and are not VM acceptance.

Live deployment still requires the actual installed normal registry/operation
data, current original-base/media identities and Root admission policy to be
reconciled at the safe machine checkpoint. Do not fabricate those inputs from
this document or a historical receipt. OMEN's R118 job/domain remains the first
owner until its actual current phase, lease and normal closure are known.

Feature acceptance is a harmless non-Main push followed automatically through
native package, normal OMEN job, actual domain/CPU/console/installer or truthful
failure, candidate/GPU coverage and normal closure on that commit. YAML, dispatch,
fixture, queue submission or a paused domain is not that acceptance.
