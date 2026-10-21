# Required OMEN producer acceptance (source proposal; unrun)

A successful native package job no longer makes the Ubuntu or Windows workflow
successful while its required OMEN transaction is missing. The new hosted
`omen-required` job runs even after package failure. It fails with diagnostic
artifacts when the package, trusted event, exact artifact, runner, normal plan,
real GUI execution or complete SteamOS/NVIDIA result is unavailable.

## Exact call graph and completion order

1. The existing native `appimage-package` / `build` job finishes and publishes its
   immutable executable-producer metadata and package artifact. Its separate
   hosted `omen-required` job starts while the **workflow** remains in progress.
2. `required_omen.py dispatch-and-wait` authenticates protected current Main and
   the exact current producer attempt, passed native package job, binding/upload
   steps, artifact creation interval, archive digest and descriptor. No package
   code executes in this hosted gate. Only the trusted-Main job can receive an
   Actions write token. A separate read-only non-Main job checks out the candidate
   on a hosted runner solely for failed diagnostics: it cannot dispatch04 or
   access OMEN. This also avoids bootstrapping a missing helper from old Main.
3. One builtin-token `workflow_dispatch` starts the existing trusted 04 workflow
   on Main with a fresh correlation nonce and exact source/run/attempt/artifact.
   The hosted producer waits for that exact nonce/run/attempt, not producer
   completion. Dispatch ambiguity, failed acknowledgement or expiry is terminal;
   no second dispatch. `GITHUB_TOKEN` dispatch is an official trigger exception.
4. The unchanged 04 trusted-event/heartbeat guard executes hosted first. The
   unchanged Root job-start hook authenticates the exact current protected Main
   04 workflow before self-hosted checkout. `scope-guard` independently repeats
   exact package/source/attempt checks. Offline preflight emits all20 FAIL /
   unavailable diagnostics, even when the self-hosted job cannot start.
5. Pinned RF 7.5 runs `required-platform.robot` -> OPEMOSRobot -> confined
   `robot_client.produced_platform`. Protocol2 carries only a finite descriptor
   selection. No caller argv, host pathname, admission or artifact proof is sent.
6. **Proposed concrete Root integration in sibling root-source/, NOT installed:** existing
   `control.py` authenticates its original protocol keys, peer, prior run guard,
   current Main, source and one-use nonce. Its exact additional action predicate
   accepts only `execute-produced-platform` with the five typed selection fields.
   The actual host-engine branch calls `required_omen.broker_execute_produced`
   with the actual private `omen_robot.Engine` and Root's authenticated GitHub
   adapters. It publishes returned `exports` with the unchanged `_publish`, then
   passes actual summary and actual published descriptors to
   `required_omen.required_broker_reply`. All existing action branches remain.
   The supplied reply helper retains the actual same-operation first/secondary
   outcome, does not promote all20/all-platform summaries and adds acceptance
   only from the verified normal transaction. Reply/item/operation limits remain
   1MiB/16MiB/256MiB. Current installed control rejects this new action; it must
   continue to do so until the whole matching graph is reviewed and installed.
7. The private Engine calls its existing pure `prepare` hook and requires exact
   `prepared.expected` equality **before** staging, expiry, submission or VM
   effects. The genuine existing planner must support the independently passed
   package JOB while the producer workflow is in progress, or explicitly return
   unavailable. This proposal does not fabricate planner operands/approvals or
   bypass an existing completed-workflow-only planner. Such an unavailable plan
   is a visible failed gate, not a deadlock or a claimed actual pass.
8. The unchanged normal transaction verifies actual source/package/archive and
   executable bytes, ordinary queue admission, 60GB/10CPU/32GiB/no-swap/resource
   boundaries, actual guest Robot pointer transitions, output image+manifest,
   complete virtualUSB readback, distinct installed x86 SteamOS target,
   same-target NVIDIA/render/kernel/recovery, restoration and terminal closure.
   The extra expected producer comparison is before all of those effects.
9. Actual public Robot XML/report/log/xUnit, screenshots, argv, pointer and GPU
   evidence are copied by the existing bounded full-SHA exchange. Failure uses
   the existing read-only same-operation failure collector; first error and
   independent persistence/capture failures remain typed, closure UNKNOWN stays
   UNKNOWN. No retry, cleanup or acceptance from current absence.
10. Hosted `required-platform-result` runs even after a failed/skipped unavailable
    runtime. It consumes exact Root reply, current typed acceptance, all actual
    report bytes against Root SHA/size descriptors, passed real Robot outputs,
    five pointer transitions, full image/readback equality and SteamOS identity.
    It creates a small same-run typed passed result only after all validations.
    Its always steps upload failed outcomes and hosted diagnostics as well.
11. The producer consumes only that exact current 04 attempt/result and its
    completed successful named runtime/result jobs, rereads both live attempts,
    then finishes its required check. A stale rerun, skipped step, failed upload,
    unavailable stage or diagnostic-only report fails the producer.

The legacy 04 `actual-robot-transactions` all20/all-platform suite remains a
separate path. A scoped platform run leaves that job skipped; the unchanged
full-stack acceptance checker therefore cannot accept a scoped platform pass as
all-platform/all-VM acceptance. Ubuntu/Windows ready roles remain independent;
missing Mac or independent inventory roles remain visible unavailable/failed.
The producer `workflow_run: completed` trigger remains a later full-suite event,
not a prerequisite of the producer's scoped check.

## Reports and exact scope

All failed paths preserve/create `output.xml`, `report.html`, `log.html`,
`xunit.xml`, diagnostics and explicit missing-screenshot metadata. Fallback output
is plainly marked **diagnostic only**, contains FAIL (never SKIP/PASS), and never
fabricates a PNG or replaces existing actual output. Actual screenshots/logs
remain in the same-run `robot-actual-*` artifact. Small typed results reference
that artifact; disks, credentials, private source/config and originals are not
uploaded. The existing source staging 14400s bound remains unchanged here; this is not a
new retention/deletion authority. The latest protected-active/unknown retention
policy must be reconciled by its owning Root source, with no active lease purge.

## Required qualification (all UNRUN for this proposal)

- In an admitted source-test lane: `python3 -m unittest discover -s tests -p
  test_omen_required.py -v` (29 authored metadata/decision cases). These synthetic
  decisions never constitute actual guest, Robot or SteamOS acceptance.
- Owning EXE review/integration against exact current Main; source/Root graph
  comparison and Core counterpart requirements remain. Root separately reviews
  the actual held control/host-engine routing/publisher, fixed planner/profile,
  action allowlist, normal operands, source pins and job-start hook. The held factual Root source was used for the separate concrete control.py /
  host_engine.py patch; neither that patch nor its 15-file graph is installed.
- Actual protected Main run with runner unavailable must make 01/02 required
  check and 04 failed with downloadable all20 unavailable diagnostics/reports.
  Confirm PR/fork has no OMEN dispatch and no write-token trust escalation.
- Actual package-passed/in-progress producer -> once-only 04 dispatch -> real
  admitted guest Robot chooser/Build -> current image+manifest/fullhash ->
  virtualUSB write/flush/fullreadback -> installed SteamOS/NVIDIA/render/recovery
  -> complete queue/GPU/FD/process closure -> typed result -> producer required
  check. Capture actual run/attempt/artifact IDs, all exact logs/screenshots and
  report artifacts. Stage unavailability must remain visibly red.
- Negative actual metadata tests: rerun during wait, Main moves, foreign/fork,
  archive mismatch/truncation, wrong descriptor, old receipt/nonce, missing report,
  failed/absent native/Robot/GPU or closure. Never substitute packaging, source
  tests or a manual GUI receipt for that automatic transaction.

No workflow dispatch, token installation, Root source deployment, runner change,
VM, queue, GUI, USB or GPU operation was performed to prepare this proposal.

Latest WORKFLOW requires macOS ARM on OMEN. This Ubuntu/Windows proposal does not
implement or admit that separate route or substitute hosted macOS/old receipts;
it preserves the current inventory and reports the missing role as unavailable.

The owning integration also makes the current Main03 job hosted metadata-only
on Ubuntu, with an explicit failed route diagnostic before native commands.
It does not run hosted macOS, admit an OMEN macOS guest, or modify held Mac app
implementation. Its reports are unavailable-route diagnostics, not guest Robot
execution. No Main merge can start the old hosted Mac path through this job.
