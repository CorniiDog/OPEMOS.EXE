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

The same affected launcher now carries the previously reviewed normal native
adapter, parent and issuer bodies in repository source. Their narrow changed
join pins a stable Root-owned `managed_vfio.py` and actual `modprobe` tool as
separate protected native-tool operands. `create_paused` initializes the existing
VFIO driver with `disable_idle_d3=1` only while both driver and core are unloaded,
after normal grant/source/worker/resource/data/host admission. No IDs, overrides,
bind, reset, PM sysfs or persistent host configuration are written by this fix.
Libvirt remains the only all-four-function binder and performs the initial wake.

Exact Ubuntu 7.0.0-42 source copies the driver option into core at module init
and into each device at core initialization. A late visible sysfs `Y` alone is
insufficient; the recorded first initialization supplies the option. The inherited
bridge/all-four D3cold state can still fail at initial D0. Actual stable-host and
console evidence is required; the new setting is not a boot claim. After genuine
normal libvirt/FD/driver restoration, only the newly owned unused VFIO module
graph may be removed to restore its original unloaded setting. Foreign users or
unknown closure retain normal ownership and FIRST evidence. Optional cached-power
diagnostics cannot veto startup. No host reboot or global graphics/ASPM change
is introduced. Tests of the option decision are not module/hardware acceptance.

The imported launcher bodies retain their original internal dependencies. Safe
installation must bind all unchanged counterparts and the actual merged changed
bodies in one coherent current source graph; merely importing this helper is not
an installed or executed launcher. Deployment and real first-init/cleanup remain
unverified until exact Core source/caller/effects approval and native receipts.

Actual OMEN modprobe is a symlink to kmod; kmod does not accept a `modprobe`
subcommand. Installation therefore makes one stable Root-owned executable copy
of the measured existing `/usr/bin/kmod` at
`/var/lib/opemos-vfio-idle-d3/modprobe`, retaining its recognized multicall name.
The exact whole body and original system binary provenance are pinned before
use; no candidate executable or changed tool interpreter is substituted.

Core's R119 findings are retained: the kernel acquisition PID from external
`flock` can exit while Bash retains its inherited OFD; the fence now authenticates
the live pinned wrapper's actual fdinfo FLOCK record and named inode, without
pretending the dead acquisition PID is the owner. The original create clock is
rechecked immediately after module preparation and before createXML. Module
state is separately attempted/proven/restored. Only proven same-inode unused
modules use exact single-name `rmmod`; recursive modprobe removal is forbidden
and pre-existing vfio/irqbypass remain. Unknown partial state preserves FIRST
and the resource hold. A protected pre-effect ownership record is retained;
optional later duplicate publications cannot mask actual init/cleanup results.
