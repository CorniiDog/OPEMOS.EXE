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
