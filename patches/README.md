# SteamOS VM launch-check repair

`steamos-vm-launch-checks.patch` versions the reusable software definitions of
the existing queue and privileged VM adapters. It covers assignment archive
reads, readiness and worker identity, optional diagnostic boundaries, native
producer observations, immutable canonical closure checks, and metadata byte
accounting. `scripts/vm_runtime_diagnostics.py` provides the portable observation
and completion functions embedded by those adapters.

The patch deliberately omits module-level machine operands, compressed grants,
source/history receipts, credentials and five machine-bound placement adapters.
Those remain separate authenticated deployment inputs. This is neither a new
dispatcher nor an alternate execution route.

For staging, authenticate the immutable predecessor before applying this
zero-context patch to an owned disposable source copy with
`git apply --unidiff-zero`. Bind the applied definition hashes to the normal
producer/consumer qualification. Deployment must still authenticate the
complete emitted source manifest and current machine inputs, obtain the exact
independent source/caller review, and use normal queue/resource admission.
Applying or merging this patch grants no VM, device or cleanup authority.

A normally failed, never-prepared attempt may already have a canonical queue
assignment record. That record is retained as data; only a hardware grant or
runtime context denotes runtime authority. Historical source identity is bound
to the complete source graph in the actual normal closure observation, rather
than a stale literal identifying one earlier attempt. Complete canonical
closure, held inventory, file hashes and current ownership checks still apply.
The assignment remains bound to its original RUNNING row and export digest;
only the normal terminal fields may differ in the CLOSED row. Its explicit
non-authority flags and unchanged invocation binding are independently checked.

Repository-wide queued Actions counts are optional telemetry, not ownership of
the OMEN runner or a prerequisite for manual VM admission. The manual producer
retains unknown telemetry as unknown; its validator and window use actual
assigned Runner21 work, OS processes, kernel locks and canonical reservations.
Source, runner identity and assigned-work changes still refuse admission.

Window summaries and duplicate native JSON receipts are optional diagnostics.
Their absence or write failure cannot prevent startup, mask the original native
failure or skip timer restoration. Required authenticated inputs, one-use
attempt ownership, raw process transport, numeric exits, EOF/reap/FD closure and
verified cleanup remain authoritative. A genuine admission refusal retains its
failed predicates and complete observation.

Preflight grant binding compares the complete canonical bytes emitted by the
normal JSON publisher, then consumes that held wire value. Native Python tuple
containers and their JSON list representation do not carry different authority.
The full pin/hash/ownership, phase, source, worker, disk and finite-clock checks
remain mandatory; no proof field is omitted or synthesized.
