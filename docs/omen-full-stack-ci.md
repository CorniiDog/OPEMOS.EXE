# All required VMs in graphical full-stack CI

This is a disabled, isolated source candidate. It provides a complete normal
controller/queue/evidence path for **all20 exact VM/lane IDs** in
`ci/required-vms.json`. It has not been installed, activated or run. Missing and
broken cases remain visible failures. Inventory, format readability, source
readiness, CI packaging and a process starting are not full-stack acceptance.

## Every required VM stays visible

The fixed catalog includes eight transferred Hyper-V identities, eight distinct
Ubuntu counterparts, the admitted Apple Silicon macOS lane, the same-SteamOS-
guest NVIDIA/recovery lane, Windows `opemos-windows-debloat-20261019-r3b` and Ubuntu
`OPEMOS-Ubuntu-FullStack-PR189-20261019-r1`. Fresh instances do not replace old
required IDs. An owned disposable runtime copy records its original inventory
ID and its separate actual runtime instance ID. A different known required
VM cannot be substituted as that runtime instance.

The hosted workflow's `always()` report renders every row after tests, preflight,
SSH, configuration or dispatch failure. It retains `ci-summary.json` and
`ci-vms.md`; the preferred status-bridge route also keeps `ci-status-view.json`.
The reporter succeeding means that the table was rendered, never that a VM
passed. Each row names the exact ID, actual runtime instance and subject role when verified, state
and concrete missing condition. No absent/skipped row becomes green. Planned runtime IDs are recorded separately
until an actual validated receipt or bound status view confirms the instance.

The exact existing `github_context` for every VM is reused. The existing local
`gh` bridge publishes all20 contexts, the separate `opemos/vm/all-required`
aggregate and five role-case contexts. It does not invent differently named
substitute checks and leave old error contexts stale. Status descriptions bind
current run ID/attempt, nonce, actual runtime instance and role code; the commit
API path binds the full source SHA and target URL binds the workflow run. Old
runs/attempts, unavailable identity, mismatched nonce or incomplete coverage
cannot pass. The operative04 request retains its concurrency group and never cancels active work.

Root actually POSTed and read back these20 stable checks on main7aaadcf4:
18error,2pending,0pass. This verifies an existing authenticated status route.
It proves neither this workflow integration nor any runtime acceptance. The
candidate performs no GitHub writes in the source-preparation assignment.

The source catalog is embedded in a separately descriptor-bound small inventory
module so configuration/SSH failure cannot hide a row. Static review verifies
that its records equal `ci/required-vms.json`. A changed catalog requires exact
source review and new dependency pins. Final coverage also needs a fresh actual
canonical discovery receipt from an existing ordinary pinned producer job. New
canonical IDs fail aggregate coverage until independently added; genuine unchanged
individual passed results remain recorded. Discovery launches nothing.

## Existing credentials and outbound SSH

`04 SteamOS` (`steamos.yml`) is the sole operative acceptance request. It is
manual on protected main and requires exact successful same-source producer
`run:attempt` identities for Windows, Ubuntu and macOS. The current main-based
candidate does not add the held Mac workflow while its real producer is absent;
04 still requires it and reports macOS failed/unverified. It never skips that
platform or substitutes an old branch artifact.

The existing eligible local owner invokes the controller once for that exact
live04 request after its expectation envelope exists:

```text
OPEMOS_GITHUB_RUN_ID=<exact-live-04-workflow-dispatch-run>
OPEMOS_CONTROLLER_CONFIG_SHA256=<reviewed-installed-config-sha>
python3 scripts/omen_ci.py existing-gh
```

The existing local gh session checks the live canonical protected-main04 run,
source/attempt and all three producer expectations, then enters the existing
heavy/SSH route. No new runner, token, credential, daemon or endpoint is required.
The hosted status report is a bound status-bridge view, never local receipt or
VM execution proof. The two old `omen-full-stack*.yml` workflows are explicitly
unavailable diagnostics: they render all20 and three failed/unverified platform
rows then exit1. They do not advertise or dispatch an incomplete request route.
No private key was read or uploaded by source preparation.

## Only exact ordinary per-VM transactions may run

`ci/omen-run.example.json` declares all20 `vms` keys with null operands,
`admitted_vm_ids=[]`, and five role-case maps with empty lists. This is an
explicit failed/unavailable plan, not a green inventory test. Each nonnull entry
must name its exact inventory ID, actual runtime instance, explicit role case,
reviewed existing runtime admission, manifest, package/input, output evidence
root and ordinary runtime receipt producer. Every manifest job's approval must
match that runtime admission pin. The role map assigns an ID at most once.
The transferred family includes Ubuntu-server and appliance roles: it is not
silently assumed to be Windows. Each entry also declares its actual subject_role:
imaging_host, fedora_appliance or steamos_target. A transferred Fedora Agent-Boot
instance can be the inner appliance of a Windows-host transaction without
impersonating that outer host; its own inventory/original/runtime identity binds
to the appliance role. The same canonical ID cannot occupy two roles. Missing role/control/graph operands stay failed.

A host imaging operand has this shape (all pins must be real):

```json
{
  "inventory_vm_id": "exact required catalog ID",
  "runtime_instance_id": "exact separately admitted existing or disposable runtime ID",
  "case": "windows-full-stack",
  "subject_role": "imaging_host",
  "hardware_scope": "virtual-only",
  "runtime_admission": {"path": "/existing/owned/admission.json", "sha256": "64 lowercase hex"},
  "manifest": {"path": "/existing/owned/manifest.json", "sha256": "64 lowercase hex"},
  "job_ids": ["fresh-reviewed-normal-job"],
  "package_sha256": "64 lowercase hex",
  "input_sha256": "64 lowercase hex",
  "artifacts": [{"path": "/existing/current-source-package.zip", "size": 123, "sha256": "64 lowercase hex"}],
  "inputs": [{"path": "/existing/readonly/original.img", "size": 123, "sha256": "64 lowercase hex"}],
  "receipt_path": "/existing/owned/runtime/result.json",
  "evidence_root": "/existing/owned/runtime"
}
```

Only IDs in the explicit finite owner-reviewed admitted set may submit. The
configured maximum defaults to2 and remains bounded1..20; discovery never
populates admissions. Each transaction retains normal full60GB VM accounting
and the existing10CPU/32GiB shared pool; the pinned normal worker remains the
actual at-use owner/helper/pool/disk/GPU/lifecycle authority. No mass launch,
original replacement, resource-limit change or new worker is authorized.

The adapter only submits to and joins the existing admitted queue worker. It
never executes `run`, replaces a worker, initializes a queue or contacts a busy
owner. Current Windows/Ubuntu runtime instances and original/counterpart disks
remain untouched by this source candidate. Concrete queue and case operands
must be supplied through their owning normal transactions.

Final discovery uses `inventory_observation.path`, a measured dynamic receipt
from `producer_job_id` in the same admitted normal manifests. That exact job must
have passed; its source is subject to ordinary queue file/approval custody. Its
receipt binds producer ID, full source SHA, nonce, closure_verified=true,
observed_at within300s at final consumption and the complete canonical vm_ids
list. The ordinary producer must run after the case transactions. It is not a
new observer service or unreviewed JSON writer. Its descriptor-read hash is
retained. Missing, stale or extra-ID discovery keeps the aggregate failed.

## Correct host -> Fedora -> USB -> SteamOS graph

Host imaging receipts use four separate `roles`:

* `imaging_host`: actual Windows/x86_64, Ubuntu Linux/x86_64 or admitted Apple
  Darwin/arm64 VM. It binds inventory/original IDs, separate runtime instance,
  ownership/disposable relationship, disk identity, executable app PID+birth and
  actual app window ID. Screenshots and pointer actions concern the executable.
* `fedora_appliance`: actual owned Fedora/x86_64 inner instance, its outer host
  instance ID and exact outer-host QEMU PID+birth.
* `virtual_usb`: exact owned virtual medium ID, bytes, source output SHA and
  readback SHA. No physical USB operation is admitted.
* `steamos_target`: actual owned SteamOS/x86_64 VM, distinct from both host and
  Fedora, with disk identity, boot medium ID and imaged output SHA.

`output` binds full source/package/input/nonce to actual image and manifest
hashes present in typed retained files. USB readback must match the actual
output; the target must boot that exact owned medium/image. This is the normal
input->output->USB->target transaction, not four unrelated green screenshots.

Normal/abrupt recovery boot IDs and disk continuity belong to the actual
**SteamOS target**. `recovery_target_id` and `recovery_target_disk_identity` must
match it, with distinct baseline/normal/abrupt boot IDs. Darwin host identity is
never treated as an x86 SteamOS guest. The NVIDIA autoheal case also attaches its
old/new kernel and driver proof to that same target. Host imaging checks keep
virtual-only/gpu_claim=false; admitted full autoheal alone may claim a GPU.

The host cases still require actual pointer chooser/Build, cold readiness,
output image+manifest, contained virtualUSB write/flush/readback, SteamOS boot,
normal recovery and abrupt VM power-off/restart. Required typed hashed artifacts
and real PNGs accompany exact source/package/input/nonce/job identities and
complete process/pool/queue closure. Startup-only, Xvfb, keyboard-only,
process-crash or source/package tests are not substitutes.

Successful-but-wrong readiness rejection remains mandatory through the actual
same-package consumer on the imaging host. Its exact consumer PID+birth and
appliance instance, expected/distinct observed marker, transport_exit0,
consumer_outcome=rejected, continued_build=false, original unchanged and full
closure bind the same source/nonce/host/disk. Typed fault-log and queue-closure
files are mandatory; omission or transport failure cannot pass.

macOS requires real admitted Apple Silicon hardware/session and admission
identity for the outer host, plus separately admitted actual x86 target operands.
OMEN evidence staging does not fabricate macOS on non-Apple OMEN or fake a
SteamOS target inside an arm64 host identity.

## Full NVIDIA autoheal is an actual hardware-scoped acceptance gate

This case needs an existing independently reviewed shared-GPU normal job
approval/lease for `omen-iommu-group-1`. The runtime and GPU admission pins must
match the ordinary job approval; exactly one existing libvirt job carries the
lease nonce/resource. Source preparation grants no GPU transition or lease.
Missing admission/capacity remains an explicit unavailable failure.

Same actual SteamOS target/GPU UUID/driver and full old/new kernel releases must
show NVIDIA loaded, numeric query/render exits0, NVIDIA-vendor nonsoftware
rendering before update and after both normal and abrupt recovery. Three
separate query/render/display captures are mandatory. All four exact GPU
functions must return to their measured original host drivers, with verified
QMP/domain/lease closure. Unknown historical closure cannot pass. The current
busy/capacity-blocked GPU owner is not contacted or displaced.

## Exact bytes, dependencies and four-hour copies

The unchanged canonical reader is reused: bounded nofollow held FD, regular
single link/UID, overflow sentinel/EOF, exact length/SHA, full9 FD-before/after
and path-after, closed before returning bytes. Source/JSON consumes returned
bytes, not a checked path reopened later. Both scripts bind the exact reader
and inventory dependency. The remote verifier and installed expiry bootstrap
execute returned verified stage bytes. Code/JSON rejects duplicate/nonfinite
fields. Large artifacts stream one held source FD through SHA/copy/flush and
independent readback with full9/path checks and validated digest-only targets.

Existing effective SSH options must be independently reviewed against all
pinned config/Include/known-host sources. OpenSSH uses closed strict batch/host-
key/identity options with sealed local known-host and existing-key descriptors;
it cannot reopen a changed Include/config/key dependency. The key stays local.

The exact installed self-contained normal queue source is descriptor-bound and
executed through unchanged `verified_namespace`; current reviewed reference is
SHAba577d32,388189B. Any local dependencies must be separately bound and cannot
replace standard-library modules. Only unchanged `main(status|submit)` runs.
Normal submit's own cap/parser/normalize/enqueue consumes sealed immutable memfd
manifest bytes. Every cwd/file/approval/libvirt-observer base-relative field and
command executable must be absolute, preserving original-base semantics under
`/proc/self/fd`. Relative operands fail. No target method is overridden.

Only NEW private marked `/media/connor/Games/OPEMOS/CI-artifacts` copies may
expire. Each run uses exact run/attempt/one-use nonce, owner marker and held
nofollow lock. Existing packages/disks/originals/history stay intact. Reviewed
staging/input/free-space budgets remain mandatory; small receipts survive.
Expiry eligibility is exactly creation+14400s. The uninstalled minute timer
requires inactive result, fresh closed normal queue rows, owner/type/link/path
and unchanged-directory guards before symlink-safe deletion of that run alone.
Active, unknown, absent closure and terminal_cleanup retain all artifacts.

The private expiry unit contains literal exact canonical reader bytes; stage
and config are consumed using OPEMOS_OMEN_STAGE_SHA256 and
OPEMOS_OMEN_CONFIG_SHA256. It needs the reviewed exact queue WAL write allowlist.
No timer/installation is enabled here. Actual deletion occurs only at the next
admitted check after eligibility and closure, never by killing an active run.

## Completing activation

1. EXE integrates the coherent isolated patch on an owning fresh branch, runs
   authored tests/required checks in GitHub or admitted VM and obtains exact
   Core counterpart lifecycle/cleanup review. No support push/approval/merge.
2. Install/review exact controller, reader, inventory, stage, private config/unit
   pins, existing effective SSH trust route and current queue/module/pool pins.
   Create only the new marked artifact root; preserve all original data.
3. Supply exact individually admitted per-VM normal manifests/approvals/current
   packages/inputs/role graphs and fresh final discovery producer. Keep all20
   keys visible, including every broken/unavailable identity. Do not use active
   current Windows/Ubuntu instances as replacements for retained originals.
4. Verify actual normal/fault descriptor custody, all-VM omission/new-ID/stale
   binding failures, Darwin-to-x86 target graph, wrong-readiness rejection,
   NVIDIA/recovery/restoration and TTL/active protections in CI/admitted VM.
   Static checks and catalog publication are checkpoints, not that verification.
5. Prefer the existing-gh route and existing eligible scheduler's exact run-ID
   invocation. Enable only once actual operands and normal workflow guards exist.
   Keep the full aggregate red until all20 independently validated current-source
   VM results and every role case truly pass. A new attempt uses a reviewed fresh
   nonce/manifests, not an unchanged replay of a known failure.


## Complete retained queue metadata and truthful nested Ubuntu roles

R3's29 tests passed in an actual UID1000 OMEN guest, but the actual canonical
status subsequently contained73 historical rows/32,217,262 UTF8 bytes, exceeding
its4MiB string capture. That failed before dispatch and expiry. R4 replaces that
capture, not the queue database, worker, statuses, historical fields or source.
Every status/submit call derives a fresh finite envelope from actual current
DB+WAL+SHM logical bytes times8 plus8MiB JSON/escaping headroom, limited by an
explicit reviewed maximum(8..512MiB). The disabled example selects256MiB and64MiB
scratch-volume reserve. It requires a private canonical existing scratch dir and
actual free space for the complete envelope plus reserve before capture. Mutable DB measurement binds dev/inode/type/UID/GID/link core identity and uses
the maximum observed before/after/path size; legitimate timestamps/size growth is
recorded, not frozen. Immutable code/JSON still require strict full9 custody. Growth
is remeasured after normal main; future overflow fails all20 visibly and needs an
explicit reviewed metadata budget/space operand, not pruning rows or an unchanged
retry. It never hardcodes the observed32MB payload as the limit.

Text writes count strict UTF8 bytes, binary writes may split a character, and
only EOF permits strict decoding/duplicate-key-safe JSON parsing. A private
anonymous held temporary FD receives every byte through a complete-write loop;
size/full9/hash are rechecked from that same FD. Overflow, short/zero write,
incomplete UTF8, parse failure or normal-producer failure cannot produce a
truncated accepted snapshot. The capture FD closes in finally. The unchanged
normal canonical queue main is executed from verified descriptor bytes and its
unreachable sqlite connection is normally collected; self-descriptor observation
must show its queue descriptors closed on success. All original queue rows,
unknown result fields and top-level fields are consumed unchanged. This is an
operational metadata transaction, not graphical/VM acceptance. Other owners may
change the live queue normally; the status receipt is never a reservation/freeze.

`nested-ubuntu-linux` is a fifth typed case solely for OPEMOS-Ubuntu-KVM-A/B with
subject_role `nested_linux`. Existing four imaging/autoheal cases retain every
GUI/wrong-marker/USB/SteamOS/NVIDIA/render/recovery gate. Nested proof cannot be
labelled Fedora appliance, executable host, GPU or full-stack. The real retained
A-r6 and B-r1 result/queue/serial bytes are test fixtures, preserved in full. Their
normal parser checks exact actual Ubuntu source pins, readonly payload argv,
ordered outer/payload/inner boot+poweroff markers, serial size/SHA, numeric QEMU0,
source preservation and actual CLOSED canonical cgroup/pool descriptor proof.
Unknown old process-birth data stays explicitly UNKNOWN; no new value is invented.
Historical nested success remains historical. It cannot pass a current pipeline
by itself: the normal per-VM receipt still requires a newly admitted source/run/
nonce/inventory/runtime/input/job wrapper and exact four typed retained artifacts
(actual result, queue closure, serial, payload manifest). The dispatcher never
requeues/relabels an existing historical job as a new transaction. Existing
owners supply that current ordinary producer; missing operands stay failed.

Reports render distinct Windows, Ubuntu, macOS and SteamOS recovery sections and
a clearly labelled transferred-original-VM section; source disk origin does not
turn Fedora into Windows. Stable20 IDs and published contexts are unchanged.
The source also reconciles Root's three packaging workflow labels onto immutable
2b12fea6: macOS desktop .app, Windows desktop .exe, and a separate actual Ubuntu
AppImage/deb packaging workflow. Existing Debian-container qualification remains
unchanged and is not called Ubuntu full-stack. Packaging is not device/GUI/boot
acceptance. R3's original patch/29passes/cwd-correction remain preserved; R4 tests
must execute in the admitted guest/CI before current-source owner integration.

## 04 SteamOS: one accepted output per exact executable

The compact producer names are `01 Windows EXE`, `02 Ubuntu AppImage` and
`03 macOS Executable`. The separate `04 SteamOS` workflow is manual on protected
main. It accepts only three numeric `run:attempt` selections at its exact source
commit. It has no `workflow_run`, `pull_request_target`, arbitrary command, SSH
secret, new runner registration or new endpoint. Its ordinary GitHub token reads
metadata; the existing approved local gh session and outbound OMEN SSH route
remain the controller route. Zero registered runners does not prevent that route.

Each producer uploads its package, records the actual package and executable
bytes through held descriptors, then uploads a small producer descriptor. The
consumer independently reads the successful exact workflow attempt, canonical
repository/head repository, source commit, main ref, unexpired artifact ID/name,
archive digest and attempt timestamps. It verifies the metadata ZIP digest and
exact single member. A PR artifact or another attempt/source/platform cannot be
used, even when its filename or package bytes are the same. Only the three
primary executable artifacts are expected; bundled runtime helper executables
are package contents, not alternate platform acceptance results. The producer
archive is checked again on OMEN, including the exact package member, full package
SHA, and for macOS the actual app ZIP executable member and full executable SHA.

The workflow publishes `steamos-expectations-RUN-ATTEMPT` before its bounded
controller wait. The existing local controller independently revalidates that
small artifact against live producer metadata, then binds its complete canonical
SHA into the remote request and the pinned installed plan. An old plan cannot be
silently reused. The controller must be invoked with that exact live run ID and
a fresh checkout/work directory. The finite plan remains an explicitly admitted
ordinary-queue transaction, with all 20 original VM IDs and stable contexts.
Discovery never grants launch authority. A missing config, private fixture,
package, case, target or GPU admission remains a failure, not a skipped pass.

For every expected descriptor key `PLATFORM-ARTIFACT_ID`, the installed plan's
`executable_acceptance` supplies one independently reviewed entry:

- `operation_nonce`: a distinct one-use 32-hex operation identity.
- `receipt_path`: absolute current ordinary-owner transaction result path.
- `evidence_roots`: exact existing private operation directories whose real
  directory identity is checked; no path may escape those reviewed roots.
- `build_operand`: the existing platform case operand, including exact
  `package_sha256`, original `input_sha256`, inventory/runtime identities,
  `subject_role: imaging_host`, virtual-only hardware scope, normal manifest
  pin, runtime-admission pin and bounded exact ordinary `job_ids`.
- `heal_operand`: the actual separate x86 SteamOS target operand, including its
  exact image input SHA, `subject_role: steamos_target`, old/new kernels, driver,
  normal manifest/runtime-admission pins, independently admitted GPU lease pin
  and nonce, and distinct ordinary job IDs.

The current receipt includes the exact executable descriptor, acceptance
`source_commit/run_id/attempt/operation_nonce`, descriptor-pinned `archive_pin`,
`package_pin`, `executable_pin`, pinned `build_receipt`, `install_receipt`,
`heal_receipt` and `build_queue_proofs`/`heal_queue_proofs` maps. Each queue proof
is a full9-pinned ordinary result from after the consumer run started, with the
same actual current canonical queue ID/state/unit/InvocationID, numeric timing,
CLOSED lifecycle, complete UID0 cgroup traversal/emptiness and admitted pool/all
owned descriptors closed. These extra jobs are **joined only**: this addition
never submits, launches or replaces them. Their IDs are included in the CI
retention marker and active/unknown closure guard even when receipt validation
fails. They cannot alias an inventory launch or another executable's operation.

Each build receipt retains the existing graphical chooser/Build, cold readiness,
successful-but-wrong readiness rejection, original input integrity, genuine raw
image and manifest, full virtual USB, actual SteamOS boot and normal/abrupt
recovery evidence. The adjacent manifest must be the normal producer's completed
`nvidia-mutation-valid`/`nvidia-offline-installed` output with matching actual raw
image size/SHA and original source SHA. The unchanged app command
`inspect_completed_nvidia_image` must accept those exact bytes and the current
installation-media welcome revision, with a typed `completed-image-inspection`
log. This audit adds identity checks; it does not replace or relax that app
consumer. A marker-only image cannot pass. USB capacity must fit the full image;
written bytes and readback bytes must each equal the entire image, flush and full
readback must be explicit, and the readback SHA must equal the actual output SHA.

The separate install receipt is `OPEMOS_VIRTUAL_STEAMOS_INSTALL_V1`, binding
source/run/attempt/nonce/package/image/USB ID and full readback SHA to the actual
owned x86 SteamOS target ID and disk identity. It records numeric install exit0,
`installation-media-welcome`, installed root/EFI UUIDs, verified installed image,
original preservation, a distinct actual output identity and target generation,
plus retained install log, boot log and graphical screenshot. It does not claim
that the Darwin/Windows/Ubuntu host or the Fedora appliance became SteamOS.
Build/install and NVIDIA receipts must describe the same target/disk and exact
baseline, normal and abrupt boot IDs. NVIDIA autoheal still requires the existing
independently admitted shared-GPU scope: actual old/new kernel driver build,
loaded module, successful driver query, NVIDIA rendering/display on all three
boots, and four-function original-driver restoration, QMP/domain/lease closure.
No GPU authority is created by this workflow or receipt schema. Missing GPU or
recovery operands keep the full suite red while virtual-only evidence remains
available separately.

All expected artifacts have separate `opemos/steamos/PLATFORM-ARTIFACT_ID`
contexts and an `opemos/steamos/all-executables` aggregate. Descriptions bind the
current acceptance run/attempt, full descriptor digest and operation nonce.
The hosted waiter also requires all 20 existing VM contexts and role cases. It
reports a status-bridge view, never local receipt validation. The OMEN result is
green only when both the independent all-VM aggregate and every per-executable
output transaction pass. A reused receipt, job, output identity, target
generation or operation nonce cannot cover another artifact. Equal image hashes
alone are allowed only with distinct real operations and target generations.
The existing four-hour expiry remains limited to new marked CI copies, after
all ordinary jobs are terminal and closure is known. Originals, disks, previous
receipts and active/unknown runs are retained.

### Activation and evidence still required

The disabled examples are intentionally incomplete. The owning primaries must
integrate and test the exact source, produce successful same-source platform
artifacts, and review/install exact controller/module/config/plan pins through
the existing route. A normal current-source discovery must account for every
existing inventory VM; missing or broken VMs remain visible. Existing eligible
runtime owners must supply fresh individually admitted platform GUI/USB output
transactions and separately installed x86 target/NVIDIA/recovery jobs. macOS
requires an actual independently admitted Apple Silicon route, not a fabricated
macOS guest on non-Apple OMEN. The Linux/macOS virtual USB implementation is a
separately held owner-reviewed source dependency, not an acceptance claim here.
No such runtime operation was performed by this source candidate.

The public synthetic safety batch is explicitly separate from required actual
OMEN verification. Public workflows run `test_omen_ci*.py` without publishing or
expecting a private fixture in the checkout. This can establish unit safety only.
The relocated real-canonical test is never silently skipped: the exact explicit
`tests/verify_omen_ci_canonical.py` command requires the existing private fixture,
UID1000 and actual QEMU/KVM guest detection, and emits a create-only qualification
receipt. Without that independently admitted job's complete passed receipt and
normal queue closure, the installed controller refuses admission even if all
public tests passed. See the R6 contract below.

Only generated nested A/B unit-test copies are published. Their provenance file
records original and generated byte hashes, transformations and scope. Personal
mount/home labels are neutralized, generated serial metadata is recomputed, and
the complete original R4 fixtures are preserved outside this candidate. These
sanitized examples qualify parser faults only; they are not genuine current-run
nested acceptance. No private key, password, token or raw installed queue source
is included as a fixture. Real private runtime evidence must remain in its owned
receipt store; review public metadata before any publication.

GitHub's artifact identity/digest and attempt APIs and upload outputs are
documented by [REST artifacts](https://docs.github.com/en/rest/actions/artifacts?apiVersion=2022-11-28),
[workflow runs](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2022-11-28)
and [upload-artifact outputs](https://github.com/actions/upload-artifact#outputs).

Output identity is not an arbitrary label: `output_identity` is canonical compact
sorted-JSON SHA256 of `{imaging_host_id, descriptor_identity}`, where the latter
is the actual output-image full9 identity returned by its held hash/copy FD.
`target_generation` is canonical JSON SHA256 of `{target_id,
target_disk_identity, baseline_boot_id, installed_root_uuid, installed_efi_uuid,
image_sha256}` from the same installed-target receipt. The stage recomputes both
before accepting the transaction; retained copies or invented labels cannot
substitute for the original producer output and installed target generation.


## R6 actual metadata failure and required OMEN qualification

The preserved R4 actual UID1000 run completed 35 tests and errored in its one
canonical77-row metadata case. R4 sampled queue descriptors before allocating
its own anonymous spool, then compared them while that spool was still open.
When scratch was the queue directory (or nested below it), the correct broad
queue-path classifier counted the adapter's live spool. The original inner FD
was not exported and remains unknown. R3's 29 tests lacked this case; R4 static
checks did not establish a pass. Those original results and sources remain
immutable outside this new candidate.

R6 keeps the classifier broad and fixes transaction order: verified unchanged
producer, complete capture and strict parse, measured storage-envelope check,
exact ownership observation, close each owned capture/manifest descriptor, GC
normal unreachable SQLite cycles, then take the final queue descriptor snapshot.
It never excludes anonymous FDs or hides the issue by changing scratch placement.
Actual before/after queue FD sets and each owned allocation/before-close/after-
close observation include target and full9 descriptor identity. Existing queue
files may grow, so descriptor comparison uses core identity while preserving full9
size/time observations. A new or replaced queue FD still fails. Genuine named,
unlinked anonymous and simultaneous producer-failure leaks remain refused.

Primary producer/parser/overflow failures are retained alongside any closure
failures, with numeric producer exit when available, byte counts and prefix SHA.
Even a close fault after actual FD closure keeps the operation failed. Failure
exceptions carry the complete inner custody receipt through the remote result;
successful normal dispatch retains initial/final metadata custody. Source/parse/
close evidence is a checkpoint, never VM or full-stack acceptance. No cap, VM
readiness deadline, queue producer, worker, DB or history was changed.

The separately required admitted VM invocation is:

```bash
OPEMOS_CI_CANONICAL_QUEUE_FIXTURE_PATH=/ABSOLUTE/PRIVATE/verified-normal-queue.py \
OPEMOS_CI_SOURCE_COMMIT=EXACT_CURRENT_40_HEX_COMMIT \
OPEMOS_CI_VM_INSTANCE_ID=EXACT_ADMITTED_EXISTING_VM_INSTANCE \
OPEMOS_CI_CANONICAL_QUALIFICATION_RESULT=/ABSOLUTE/NEW/qualification.json \
python3 tests/verify_omen_ci_canonical.py
```

The private fixture is the existing 388189-byte source SHA
`ba577d32e0ad4d582a2908521695056256f0d81c71f715486b83ff2648c379de`,
transferred through the existing admitted owner/queue route, mode private and
owned UID1000, with before/after source checks. It is not fetched from an untrusted
PR or committed to the repository. The test invokes its exact main and SQLite
producer without method overrides in fresh private test DBs only. It retains
77 complete rows including unknown data, more than32MiB of actual canonical
metadata and actual owned/queue FD closure for same/nested/separate scratch.
The existing ordinary owner also runs the public synthetic suite in the same
admitted guest and retains both numeric exits, full stdout/stderr and guest/pool/
source closure. Missing fixture/environment/actual VM detection is a failure,
not skip/pass. `systemd-detect-virt --vm` must actually report QEMU/KVM, UID must
be1000 and the instance must match independently reviewed admission.

Installed `required_canonical_qualification` supplies the complete actual receipt,
its exact source pin map, actual runtime instance, existing normal manifest and
admission pins, producer job ID and full raw queue closure pin. The current
request now includes `stage_sha256` from the local controller's exact verified
remote-program pin. Qualification source pins must match that same executing
stage and reader/inventory/executable-contract/verifier graph at the current
source commit. The canonical fixture SHA/size, three complete scratch cases,
actual full9 owned-close observations, numeric0 and all unknown rows must pass.
The independent normal job must match current canonical unit/InvocationID and
CLOSED UID0 cgroup traversal, empty processes and admitted pool/all owned FD
closure. No qualification job is launched or admitted by this gate.

The source base is Root's exact canonical-main-derived PR192 commit
`21a33b1ec9ac723f2e7b9f8aaf8a104c6195184b`. Its current macOS producer preflight,
removed manual fullstack input and `OPEMOS_MACOS_FULLSTACK=1` are preserved.
Unmerged macOS implementation files from the earlier2b12 source are not carried.
Missing current Mac producer inputs remain failed/unverified; four labels and
per-executable artifact identity steps remain present. Root's independent repo
and all active primary trees were untouched.


## R7 complete six-finding transaction

This candidate is based on canonical main
`0371a6ae9c4dab1cfe6fe1957ab350cec44ac76a`. It preserves main's verified Windows
name and resolved concurrency plus approved Ubuntu workflow. The R6 Mac workflow
preflight/descriptor integration is preserved separately for the owning Mac
source PR; no absent producer workflow or unmerged Mac implementation is added.
04 continues to require genuine all-three current-main artifacts.

Deduplication saves storage only. Every declared original input/artifact/evidence
source is opened through held full9/size/SHA custody even if its digest object
already exists. Every cached digest object is independently verified, including
its full size and bytes. A failed partial is preserved as failed evidence and
never accepted, overwritten or counted as retained. Budget is charged only for
a new complete copy.

Each per-inventory subject binds `original_source` with actual retained original
`sha256`, `size` and complete full9 `identity`. That pin must equal an actually
verified readonly ordinary input; it is distinct from a generic recovery-image
or shared base template. The subject receipt carries the same pin. One actual
runtime or source backing cannot cover two original catalog IDs, at pre-effect
plan admission or final all20 aggregation. Same-original successive artifact
copies may exist, and genuine shared auxiliary roles are not counted as catalog
subjects. A hosted status bridge still enforces runtime uniqueness while reporting
that it did not locally validate retained source bytes. No transferred original
can be replaced by a fresh accepted Windows baseline.

The installed controller and stage use one identical reviewed `result_contract`:
`max_bytes`, `stderr_max_bytes`, and `free_reserve_bytes`. Disabled examples leave
the main result budget null. Before effects the stage composes a conservative
minimum from the existing complete canonical metadata maximum, each allowed
1MiB leaf receipt with at-most3x UTF8-to-ASCII JSON expansion, and256MiB for
bounded descriptor/custody/plan fields. At most20 inventory and16 executable
entries are admitted. The standalone adapter refuses inherited queue FDs before
capture, so successful observations have only its bounded own descriptors; an
actual4096-entry failure snapshot including path escaping fits the diagnostic
reserve. The finite full contract is capped at1GiB and must meet the composition
minimum, rather than blindly changing a reader limit. New-run disk admission
reserves both complete live and retained result copies in addition to artifacts,
and independently admits the actual full-result scratch volume for the complete
result contract plus reserve before effects.
All unknown rows/fields remain in compact lossless full receipts. A writer
records a failed `.partial` and never promotes it if a contract/write/close
fails. The full receipt, stdout serializer, local complete capture, summary
reader/writer and4h expiry/retained-receipt reader consume the same bound.
New owned markers pin that bound; old unmarked-size receipts retain the previous
1MiB contract. No old history or oversized unknown receipt is silently removed.

SSH uses its existing approved exact key/known-host route. Stdout and stderr
stream into new private owned files before parsing, with byte/SHA/full9/EOF,
actual numeric or timeout disposition and exact local reap/close evidence.
The source/run/attempt request identity and sequential sealed-FD outcomes are
stored separately; keys, route/config body and command arguments are not stored.
Malformed/numeric failure stderr and timeout partials remain available. Overflow
retains bounded partial/sentinel custody with explicit incomplete state and
never accepts a truncated reply. The exact local SSH child may be stopped after
its finite bound; remote job/VM closure remains UNKNOWN unless its own actual
receipt proves it. Early closed stdin still drains both output pipes. Nonsecret
queue code/dependency SourceReadFailure full evidence joins the remote failure;
private-key/config evidence is not serialized. Each successful sealed allocation
is registered immediately, so failure of the second closes the first and retains
primary plus close errors. The private `ci-transport-index.json` binds complete
local stream files to the request; public status text contains no private bytes.

The required real canonical verification now takes actual77-row >32MiB metadata
through complete full-receipt serialization, finite local process stdout capture,
lossless parse and actual guarded expiry/retained full-receipt consumer for each
same/nested/separate scratch case. It is explicitly a metadata/pipe/retention
probe, not an actual SSH, all20, GUI, USB, SteamOS or GPU pass. Existing normal
owner admission/closure remains required. R6's actual61 public plus required1/3
results are preserved unchanged and are not transferred to this changed source.
New/changed public faults and this complete actual canonical verification must
run only after independent review in the admitted guest/CI route.


## Bound control acceptance and first-failure custody

A retained passing remote summary is raw runtime evidence, not permission to
publish acceptance. The normal dispatch writes `ci-dispatch-verdict.json` only
after binding exact summary bytes/full9, current controller source, source
commit, run and attempt to the actual SSH numeric exit and complete local
stream/sealed-descriptor closure. The existing heavy parent records its actual
child PID/start where observable, numeric exit and reap outcome in
`ci-heavy-control.json`. Before either publisher runs, the parent creates
`ci-control-verdict.json` joining that actual parent outcome to the exact summary
and both child records. Every success in both `existing-gh` and standalone
`publish-existing` independently revalidates this chain against the verified
installed controller source/result contract. Missing, stale, replaced, nonzero
or unknown closure makes every VM/case/executable acceptance status fail before
any success write. All20 remain visible; raw per-VM facts and the original
summary stay unchanged. Hosted wait consumes those gated statuses and cannot
turn a failed aggregate into acceptance. Reusing `publish-existing` requires the
same retained ordinary control records; passing JSON alone cannot substitute.

The full `inventory-report` CLI loads its cap from the pinned installed config
using `OPEMOS_CONTROLLER_CONFIG_SHA256` before reading a local full summary.
An unconfigured/hosted small diagnostic keeps the1MiB fallback. Neither an
unverified summary field nor a larger global default can select its own cap.
All unknown fields are retained through its bounded create-only report writer.

Transport spool counters/digests advance for each actual successful short-write
prefix, before any subsequent zero/error. Received bytes and retained bytes
remain separate. On every success or failure, the still-open RDWR descriptor is
fsynced and fully read back under its finite envelope; full9 before/after/path,
actual size/SHA and FD closure are recorded. Fsync/observation/close failures
remain alongside the first write failure. Unobservable bytes get explicit
UNKNOWN custody, not an inaccurate shorter-prefix SHA.

Final receipt storage failures raise with the already collected original
transport receipt attached: true started/PID/streams/EOF/numeric/reap/first cause
remain available to the outer SSH handler. A separate persistence failure and
UNKNOWN durability are appended; existing partial files are preserved without
overwrite or automatic retry. This also applies to sealed-closure/index storage.
No second storage route or successful persistence is invented when unavailable.
Subprocess exceptions use a safe schema of type, phase, duration, timeout value,
owned PID/start and numeric/UNKNOWN state. No command, bootstrap/config body,
argv, token or private key bytes enter the receipt, including closed-stdio
wait-after-EOF TimeoutExpired. Local reap never proves remote VM closure.

CI8 adds composed positive and negative publication/hosted-wait tests using
actual finite local children and files, prefix/EIO/zero-write faults, complete
first failure plus secondary persistence, fresh-process full inventory report,
and safe closed-stdio wait timeout. These are synthetic source-safety probes,
not actual SSH/all20/GUI/SteamOS/NVIDIA acceptance. R7 results and all earlier
failures stay frozen. Only an independently admitted guest/CI run may execute
the new source batch and required exact canonical three-scratch verifier.


## Required real pointer action bytes

`ci/gui-pointer-contract.json` describes the disabled, field-only ordinary
producer contract. Imaging receipts now require actual typed action files for
chooser-open, chooser-confirm-exact-input, Build, virtualUSB-select-and-review
and virtualUSB-Write-confirmation. `gui_input_method: pointer` and a PNG alone
cannot pass. The same `validate_receipt` path covers inventory and every exact
executable transaction; its computed pointer proof is mandatory in the existing
per-executable report/status bridge. All CI8 parent/dispatch/transport verdict
checks still run before any acceptance status can become successful.

Each action file is parsed from the canonical bounded held-FD SHA/size/full9
reader. Its accepted sender code, native/console observer code, actual sender
PID/birth/exit/EOF/reap, source/run/attempt/operation nonce, genuine executable
producer descriptor, original input, instance/session/boot, app birth/executable,
root/current window, visible enabled control ID/role/rect and actual point must
agree. Source code files themselves are retained under existing roots/capacity/
128-file/4h safeguards. Per-phase actual QMP request bytes and matching numeric
responses must contain movement then exactly one left down/up, with no API
refusal. AX/DOM may inspect; keyboard may type a path. None may activate a
required control in place of the pointer. A failed sender or unknown closure
never becomes success.

Clock domain/ID is independently admitted, and comparisons are only within that
same declared monotonic-ns domain. Frames require distinct acquisition IDs,
source-ordered before/after captures and current session/geometry, not different
pixel hashes. Two fresh acquisitions can contain identical pixels. A generic
reused PNG cannot replace a measured target observation or an action-specific
transition. Actual physical pixel geometry and native coordinate space/scale
are separate: Windows/Linux QMP coordinates use measured physical pixels;
macOS CGEvent logical points and display origin/scale must map to actual capture
pixel dimensions. No host/guest/Apple monotonic offset is assumed.

Windows retains original QMP PPM and derived PNG plus conversion receipt/code.
The consumer checks actual raw pixels against the bounded RGB PNG conversion;
a PNG hash does not silently stand for the raw PPM. macOS records actual
CGEvent posts and observed pointer/native same-control hit; `CGEvent.post` has
no delivery acknowledgement and none is synthesized. Typed frames, source code,
action and transition bytes must all resolve through the ordinary files/checks
references. Exact input selection and planned output bind chooser/Build, while
actual output image and exclusively owned USB backing/device bind target review
and Write. A posted action or failure screenshot is not Build/Write/output
success: flush/full readback/install/boot/NVIDIA and recovery gates still apply.

Existing audited Ubuntu/Windows operational sender copies have a separately
sealed compatibility candidate. They preserve actual owned QMP/socket/peer/
process guards and add source-bound native/console context, actual phases,
acquisition metadata and caller-observed sender lifecycle. They do not invent
the missing native window/control/transition measurements; an existing owner
must supply them as fresh retained read-only observation bytes. Those private
operational copies are not repository workflow activation or new credentials.
Their historical fixed lane guards must never be blindly reused for a current
busy or different owner. Current safe admission/deployment is separate.

The historical PR188 Swift compatibility delta is held outside this main-based
candidate for EXE's current macOS producer integration. It records boot-clock,
actual CGWindow identity, frame hash/acquisition and honest per-post phases, but
is uncompiled/unintegrated here and has no real exact-input/Build/USB completion
records. Current Mac workflow and source producer remain absent; 04 still fails
without a genuine current-source Mac artifact. A consumer-only change is not a
promise of working Mac full-stack acceptance. Missing historical fields remain
UNKNOWN and old receipts are never backfilled.

All new action/chronology/foreign identity/keyboard/AX/DOM/failed-send/frame/raw
conversion/USB/source-custody cases are synthetic source-safety tests authored
for one later admitted changed-source guest/CI transaction. No controller tests,
imports, compile, native event or VM operation were run for this candidate.


## CI10 joined destination and failure custody

The QMP sender must compare the actual observed name, PID/start, host boot,
socket identity and peer, writable owned OS disk and argv digest to the exact
independently pinned `OPEMOS_ADMITTED_POINTER_DESTINATION` mapping **before any
mouse input**. The mapping binds the admitted graphical runtime and guest boot,
current executable/package, app birth/root window, original source and current
source/run/attempt/nonce. A coherent context from another VM cannot supply this
mapping. Retain the actual observed destination and mapping bytes; the normal
`validate_receipt` and per-executable path consume both. Ubuntu's numbered
operation frame must be the very context before-frame path/hash/acquisition,
not another image with matching geometry or pixels.

Existing caller copies now reserve all four distinct action, lifecycle,
stdout and stderr outputs before spawning an input sender. Destinations must be
canonical private current-principal paths inside that exact existing operation
root, absent and disjoint from every input and one another. Each create-only
no-follow descriptor reserves its bounded blocks before input. Pending/attempted
records use those same descriptors; storage failure never repeats the click or
retries an exclusive create to replace the first error. Required missing output
or admission operands fail explicitly; no new lease service is introduced.

Each actual request, numeric ID, phase and sender tick is checkpointed before
writing to QMP. A write/read failure or lost reply retains that exact attempted
prefix with UNKNOWN delivery/response. Only an actual matching response can
replace UNKNOWN, and incomplete phases remain failed in the ordinary consumer.
The one existing outer Ubuntu SSH process and inner sender have finite owned
PID/start/pidfd custody through errors, partial IO, exact stop/wait and independent
pipe closure. An identity-read failure does not abandon a spawned process.
Normal Windows callers retain the complete bounded raw stdout/stderr bytes and
actual numeric before return. Empty raw streams stay empty with size0 and the
empty digest; only these two typed kinds may be empty. EOF, confirmed byte count,
full9 identity and raw file refs must join the same sender lifecycle and reserved
inodes. Primary sender failure is separate from secondary persistence/closure
failure. Local SSH exit/closure does not establish remote guest/VM closure.

CI10 is reconciled from immutable actual Main00885837. The approved Main195
full-stack acceptance workflow, documentation, checker and tests are byte-equal
to that base. The separately held historical Mac compatibility is unchanged and
uncompiled; an absent current Mac producer still fails 04 SteamOS.

The preceding CI9 actual qualification refused **before** VM/test creation:
its whole13.49MB source archive was wrongly included in the canonical<=8MiB
queue metadata `files` set, and a caller attempted worker start before consuming
submit failure. No107-test pass exists. For the later changed-source qualification,
the existing runner must consume successful submit before any worker dispatch.
It must separately retain/held-FD verify the whole public/private source archives
as exact SHA/size large assets; do not put those large archives in queue metadata.
Keep the canonical cap unchanged. This candidate supplies the staging contract
only, and does not submit, start or modify any queue/worker.
