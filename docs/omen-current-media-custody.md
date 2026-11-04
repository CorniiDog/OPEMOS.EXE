# Fresh installer preparation after host reboot

An interrupted VM can leave its generated installer file owned by QEMU with
the previous preparation ACL. Closing that job on the next host boot does not
restore its old `/run` receipts or prove historical QMP, lease, ACL or waitpid
facts. The old prepared-continuation constructor is therefore unsuitable for
a fresh launch. Its historical evidence remains unchanged.

The current-generation path adopts the retained installer as **read-only
media**. It preserves the actual QEMU owner and ACL, rather than calling it a
fresh Root-owned file or replaying old ACL preparation. It adds no second raw
image: the existing 8.4 GB backing is still charged in the literal 60 GB whole
graph, alongside the original, R66, carrier, partial and metadata reserve.

The normal Root caller must first admit its source, queue, worker, resources
and current native machine state. It creates an owned read-only loop and an
ext4 mount with `ro,noload,nodev,nosuid,noexec`; it must not replay the retained
filesystem journal. `retained_media.capture_current` then measures the entire
raw file and backing through read-only descriptors and binds their full
identities, actual mount/loop relationship, numeric ACLs and current host boot.
Its copy-origin record remains historical data. No old grant is continued.

`current_media_preparation.prepare` calls the normal preflight, access-stage
and placement producers. Its two retained-media access rows make no ownership
or ACL changes. Four writable IO rows are newly created outside the readonly
filesystem. Their normal DAC probe still proves that QEMU can use the intended
IO and cannot read the golden original. The real queue consumer validates the
same custody operand. XML generation marks the installer readonly and disables
DAC relabel for that disk only, after validating current custody. The kernel
readonly mount and loop enforce immutability despite the retained file owner's
write bits. Other disks and native guards retain their existing checks.

`fresh_media_parent.produce` constructs a fresh candidate/job from the installed
operation profile and current qualification. It feeds its actual output to
both normal placement consumers and the ordinary queue manifest normalizer.
It returns an unsubmitted manifest; the existing queue submit/worker/issuer/
libvirt lifecycle owns execution, resource admission, exclusive GPU lease,
finite clocks and cleanup. The R119 first-initialization mitigation is unchanged.

`run_current_media.py` connects these functions to the actual queue submit and
worker entry, followed by the exact-job status API and normal terminal/native
closure. Its read-only loop is held through the operation and detached only
after canonical release and current no-holder/domain/host checks. It records a
failed VM result as a failure, even when normal cleanup succeeded. In-process
disk reads use a distinct capture type; they do not invent a transport child,
exit status or waitpid claim.

The installed `media_window.py` and `media_client.py` take ordinary request
identifiers as data. They retain the existing recovery mutex, current assigned
build/owner checks, single normal idle-control retirement, ordered closure,
45-minute restoration backstop and verified timer restoration. Exact code and
effects review precedes installation; no LLM receipt, agent or nonce-specific
executable is a runtime input. The normal drain preserves Root source/lease,
canonical binding, PID/start/UID/argv/cgroup and pidfd checks. Repository-wide
queued Actions and an unrelated old control row/tick-report format no longer
authorize or veto retirement. Actual assigned work still refuses it.

The historical installed-schema report also has no launch authority. The real
installed schema validator still checks the actual XML immediately before
`createXML`, using its bound executable/source identity. A missing old report
does not substitute for that check or prevent it from being reached.

The installed source contract binds immutable controller roles and the whole
queue deployment, including its two current custody consumers. Current job,
boot and candidate metadata are data, not generated executable bodies. The
runtime requires neither Codex nor an agent cohort or developer review folder.
The old fixed source-path/hash joins are replaced coherently with that installed
contract; historical source bodies and receipts remain history.

The materialized normal modules originate from the immutable R118 source graph;
the changed custody, staging, publisher, observer and queue functions are the
review scope. This does not authorize executing an unreviewed privileged
candidate. Installation and changed lifecycle effects require exact Core
source/effects approval and the owning EXE protected merge.

Source tests distinguish typed-contract and consumer coverage from kernel and
hardware acceptance. A complete new native qualification, actual submitted job,
domain creation, CPU resume, domain-bound console/installer screen, NVIDIA
operation and normal closure must be recorded separately. A source/CI pass or
paused domain proves none of the later milestones.

This firstboot operation tests the retained authenticated recovery media and
the reviewed controller. Candidate application/package execution is separate
coverage. The automatic-push routing merged in PR218 still needs its actual
installed recipe/heartbeat reconciliation and guest candidate delivery before
an automatic development check can truthfully claim that candidate was tested.
