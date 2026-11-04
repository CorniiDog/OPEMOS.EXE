# Interrupted host-boot reconciliation

`scripts/omen_control/reboot_recovery.py` adds a finite failed-only normal queue
API for the demonstrated case where a host reboot removes `/run`, the original
unit and domain, while its canonical reservation remains running. It does not
dispatch work, recreate the old scope, mount a backing file, restore ACLs, change
PCI power or signal a process. Historical QMP, child exit, lease and ACL closure
remain unknown. `CLOSED` describes the new-boot queue disposition explicitly.

The installed Root profile pins the actual queue code, existing read-only peer,
existing owned-command capture, immutable original image and complete original
four-function endpoint baseline. It also pins the recovery code's full file
identity and bytes. The profile and executable live under
`/var/lib/opemos-reboot-recovery`, are Root-owned and immutable to the runner.
No candidate checkout, AI connection, historical review directory or fresh
nonce-specific executable is consumed. This source change and its actual
installation/effects mapping require exact Core review before privileged use.

The normal owner enters through the existing `heavy.sh` admission and acquires
the existing worker and SQLite writer locks. Root observations use private
copies of the complete canonical database, never an original SQL connection.
Trusted journal boot/unit/invocation/start fields authenticate the original
boot. Current unit/domain/whole-pool absence, Intel scanout, complete IOMMU
membership, all original endpoint drivers/overrides, all-host VFIO FD absence,
immutable source pins and the whole original-image hash must pass.

The writer preserves the complete original row and first native proof before
committing `terminal_cleanup` with the reservation retained. A second independent
native observation and unchanged complete rows/bindings/configuration precede
the failed-only final disposition. A failure after preparation leaves that
durable reservation held for its owning disposition. There is no automatic
retry or rearm. Other pending jobs and historical rows are preserved; queue
length is not an eligibility gate. Duplicate diagnostic JSON is optional and
cannot veto or mask the actual Root capture.

The actual entry is the installed program's `reconcile PROFILE JOB` action,
running as the normal queue owner under its existing heavy entry. Its `observe`
action is Root-only and read-only. Installation data must come from actual
authenticated files and observations, not examples or guessed paths. No profile
or privileged execution is supplied by this documentation.

Tests exercise the real private SQLite producer/consumer, retained commit,
competing writer lock, same/wrong boot, journal/start, source/binding/epoch drift,
unit replacement, domain/holder/unknown, original-hash and deadline refusals,
file replacement/symlink refusal, primary-error preservation and no rearm.
External native facts are explicitly modeled. They do not prove Root, libvirt,
hardware restoration or a SteamOS boot. An actual reviewed observation and
normal transaction remain required after source/CI review and safe installation.

PR #218 was merged as `ce3cc45097f078ceb8417bfdfd6aa927c18be1d9`; this is the
next bounded recovery change on that source. R118's reservation remains held.
The separate ACPI/VFIO power-transition failure needs an evidence-backed repair
and review before another GPU activation. Nothing here changes PM, the physical
Intel host, exclusive group ownership, virtual-USB-only policy, CPU10/RAM32GiB,
no-swap or the whole-VM 60-GB limit.

Admission precedes the original queue connection and any schema/sidecar access.
The actual kernel heavy-lock holder must be the caller or its stable ancestor,
with the pinned existing wrapper body and Bash interpreter; an unrelated busy
lock and environment marker never grant admission. Log operands are confined
before any mkdir and canonical selection precedes owned history creation.
