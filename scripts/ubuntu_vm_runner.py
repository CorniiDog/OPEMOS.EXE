"""Fixed, network-isolated Ubuntu migration QEMU launch slice.

Not yet a complete migration runner: aggregate allocation and post-run reference
switch acceptance remain gates. Never invoke on Windows originals.
"""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import fcntl
import json
import uuid
import hashlib
import selectors
import time
import signal
import threading
from vm_write_ceiling import compact_owned_image, bounded_file_ceiling, VM_BUDGET_BYTES, validate_chain


def pin_owned_qemu_network(launcher_pid, required_files, deadline):
    """Pin an owned descendant's private netns; never search global QEMU names.

    Caller keeps its launcher alive and lifecycle lock held. This gate opens no
    connection and grants no guest authentication or transition authority.
    """
    if type(launcher_pid) is not int or launcher_pid <= 0:
        raise ValueError('exact launcher PID required')
    if type(deadline) not in (int, float) or not time.monotonic() < deadline <= time.monotonic() + 900:
        raise ValueError('finite bounded admission deadline required')
    if not required_files or time.monotonic() >= deadline:
        raise ValueError('live files and deadline required')
    def identity(pid):
        if time.monotonic() >= deadline:
            raise TimeoutError('namespace admission deadline')
        root = Path('/proc') / str(pid)
        fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
        return (pid, int(fields[19]), root.stat().st_uid, int(fields[1]))
    launcher = identity(launcher_pid)
    if launcher[2] != os.getuid():
        raise ValueError('launcher owner mismatch')
    expected = set()
    for path in required_files:
        info = Path(path).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('unsafe required runtime file')
        expected.add((info.st_dev, info.st_ino))
    qemu = shutil.which('qemu-system-x86_64')
    if not qemu:
        raise ValueError('existing QEMU executable required')
    executable = os.stat(qemu)
    pending = [(launcher_pid, None)]; seen = set(); matches = []; observed = {}
    while pending:
        pid, parent = pending.pop()
        if pid in seen or len(seen) >= 64:
            raise ValueError('ambiguous or excessive owned process tree')
        seen.add(pid)
        before = identity(pid)
        observed[pid] = before
        if parent is not None and before[3] != parent:
            raise ValueError('descendant no longer owned by launcher tree')
        root = Path('/proc') / str(pid)
        if before[2] != launcher[2]:
            raise ValueError('descendant owner mismatch')
        pending.extend((int(child), pid) for child in
                       (root / 'task' / str(pid) / 'children').read_text().split())
        actual = (root / 'exe').stat()
        if (actual.st_dev, actual.st_ino) == (executable.st_dev, executable.st_ino):
            handles = set()
            for entry in (root / 'fd').iterdir():
                info = entry.stat()
                handles.add((info.st_dev, info.st_ino))
            pool = '/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice'
            if not any(line.split(':', 2)[-1] == pool or
                       line.split(':', 2)[-1].startswith(pool + '/')
                       for line in (root / 'cgroup').read_text().splitlines()):
                raise ValueError('QEMU outside admitted pool')
            if not expected.issubset(handles):
                raise ValueError('QEMU runtime file ownership mismatch')
            matches.append(before)
        if identity(pid) != before:
            raise ValueError('owned process changed during inspection')
    if any(identity(pid) != before for pid, before in observed.items()) or len(matches) != 1:
        raise ValueError('exactly one live owned QEMU required')
    selected = matches[0]
    fd = os.open(f'/proc/{selected[0]}/ns/net', os.O_RDONLY | os.O_CLOEXEC)
    try:
        pinned = os.fstat(fd)
        host = os.stat('/proc/self/ns/net')
        current = os.stat(f'/proc/{selected[0]}/ns/net')
        if ((pinned.st_dev, pinned.st_ino) == (host.st_dev, host.st_ino) or
                (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino) or
                any(identity(pid) != before for pid, before in observed.items())):
            raise ValueError('private owned network namespace required')
        chain = [selected]
        while chain[-1][0] != launcher_pid:
            ancestor = observed.get(chain[-1][3])
            if ancestor is None or ancestor in chain:
                raise ValueError('complete launcher ancestry required')
            chain.append(ancestor)
        return fd, selected, tuple(chain)
    except BaseException:
        os.close(fd)
        raise


def relay_owned_guest_stdio(namespace_fd, qemu_identity, deadline, ancestry, cancel=None):
    """Fixed AgentBoot ProxyCommand bytes, never a listening/host relay.

    Caller retains the lifecycle lock and the admitted namespace descriptor.
    This uses only the pre-existing private loopback endpoint; SSH authentication
    stays on the controller. No private key or credential enters this process.
    """
    if type(deadline) not in (int, float) or not time.monotonic() < deadline <= time.monotonic() + 900:
        raise ValueError('finite bounded relay deadline required')
    if cancel is not None and not isinstance(cancel, threading.Event):
        raise ValueError('owned relay cancellation event required')
    def check_cancelled():
        if cancel is not None and cancel.is_set():
            raise InterruptedError('owned relay cancelled')
    check_cancelled()
    if not isinstance(qemu_identity, tuple) or len(qemu_identity) != 4:
        raise ValueError('exact admitted QEMU identity required')
    pid, start, uid, parent = qemu_identity
    if type(pid) is not int or pid <= 0 or uid != os.getuid():
        raise ValueError('exact admitted QEMU owner required')
    if (not isinstance(ancestry, tuple) or not 1 <= len(ancestry) <= 64 or
            ancestry[0] != qemu_identity or
            any(not isinstance(item, tuple) or len(item) != 4 for item in ancestry) or
            len({item[0] for item in ancestry}) != len(ancestry) or
            any(child[3] != ancestor[0] for child, ancestor in zip(ancestry, ancestry[1:]))):
        raise ValueError('complete admitted launcher ancestry required')
    pinned = os.fstat(namespace_fd)
    def verify():
        root = Path('/proc') / str(pid)
        fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
        current = (pid, int(fields[19]), root.stat().st_uid, int(fields[1]))
        for expected in ancestry:
            ancestor = Path('/proc') / str(expected[0])
            values = (ancestor / 'stat').read_text().rsplit(')', 1)[1].split()
            actual = (expected[0], int(values[19]), ancestor.stat().st_uid, int(values[1]))
            if actual != expected:
                raise ValueError('admitted launcher ancestry changed')
        ns = (root / 'ns/net').stat()
        host = os.stat('/proc/self/ns/net')
        if (current != qemu_identity or
                (ns.st_dev, ns.st_ino) != (pinned.st_dev, pinned.st_ino) or
                (ns.st_dev, ns.st_ino) == (host.st_dev, host.st_ino)):
            raise ValueError('owned private QEMU namespace changed')
    nsenter, nc = shutil.which('nsenter'), shutil.which('nc')
    if not nsenter or not nc or not hasattr(os, 'pidfd_open'):
        raise ValueError('existing relay tools and kernel PID lifetime support required')
    verify()
    lifetime = os.pidfd_open(pid, 0)
    child = None
    try:
        verify()
        with selectors.DefaultSelector() as selector:
            selector.register(lifetime, selectors.EVENT_READ)
            if selector.select(0):
                raise ValueError('QEMU exited before relay')
            check_cancelled()
            child = subprocess.Popen([nsenter, f'--net=/proc/self/fd/{namespace_fd}',
                                      '--', nc, '-N', '-n', '-w', '3', '127.0.0.1', '2222'],
                                     pass_fds=(namespace_fd,), start_new_session=True,
                                     stderr=subprocess.DEVNULL)
            while child.poll() is None:
                check_cancelled()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('owned relay absolute deadline')
                if selector.select(min(remaining, 0.05)):
                    raise ValueError('QEMU exited during relay')
                verify()
            return child.returncode
    finally:
        if child is not None:
            # This process group was created here and its leader remains an
            # unreaped Popen child. Never kill a discovered/global process.
            if child.returncode is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            child.wait()
        os.close(lifetime)


def base_digest(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def qmp_stdio_status(reader, writer, timeout_seconds=3):
    """Exact no-network greeting/capabilities/status protocol, bounded once.

    Caller owns the child and must kill/reap on every protocol refusal. Only
    monitor status is evidence here, never Windows or application acceptance.
    """
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 3:
        raise ValueError('bounded QMP deadline required')
    deadline = time.monotonic() + timeout_seconds
    pending = bytearray()
    total = 0
    with selectors.DefaultSelector() as selector:
        selector.register(reader, selectors.EVENT_READ)
        def receive():
            nonlocal total
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError('QMP absolute deadline expired')
                if b'\n' in pending:
                    line, _, rest = pending.partition(b'\n')
                    pending[:] = rest
                    value = json.loads(line)
                    if not isinstance(value, dict) or 'error' in value:
                        raise ValueError('invalid QMP response')
                    return value
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError('QMP absolute deadline expired')
                chunk = os.read(reader.fileno(), 4096)
                if not chunk:
                    raise ValueError('QMP closed before response')
                total += len(chunk)
                if total > 65536:
                    raise ValueError('QMP output exceeds bound')
                pending.extend(chunk)
        if 'QMP' not in receive():
            raise ValueError('missing QMP greeting')
        for identifier, command in ((1, 'qmp_capabilities'), (2, 'query-status')):
            # This tiny bounded write cannot fill an empty owned QMP pipe.
            writer.write((json.dumps({'execute': command, 'id': identifier}) + '\n').encode())
            writer.flush()
            while True:
                value = receive()
                if 'event' in value:
                    continue
                if value.get('id') != identifier or 'return' not in value:
                    raise ValueError('QMP response identity mismatch')
                break
        status = value['return']
        if not isinstance(status, dict) or type(status.get('running')) is not bool or not isinstance(status.get('status'), str):
            raise ValueError('invalid QMP guest status')
        return status


def require_ntfs_envelope(root):
    """Kernel allocation boundary, not a claimed logical-length quota.

    Only an exact owned regular-file loop volume is accepted. Its fixed kernel
    capacity contains every runtime payload; QEMU's namespace exposes no other
    writable storage. No physical partition, remote parent, or FUSE fallback.
    """
    data = json.loads(subprocess.run(['findmnt', '-J', '-T', str(root), '-o',
                                     'SOURCE,FSTYPE,TARGET'], check=True,
                                    capture_output=True, text=True).stdout)['filesystems'][0]
    device = data['source']
    if data['fstype'] != 'ntfs3' or not device.startswith('/dev/loop') or not device[9:].isdigit():
        raise ValueError('fixed owned NTFS loop envelope required')
    loop = Path('/sys/class/block') / Path(device).name
    backing = Path((loop / 'loop/backing_file').read_text().strip())
    if not backing.is_absolute():
        backing = Path('/') / backing
    info = backing.lstat()
    if backing.resolve() != backing or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
        raise ValueError('unsafe envelope backing')
    if (backing.parent / '.opemos-migration-owned').read_text() != 'OPEMOS.EXE\n':
        raise ValueError('unowned envelope backing')
    capacity = int((loop / 'size').read_text()) * 512
    allocated = info.st_blocks * 512
    if not 0 < capacity <= info.st_size <= VM_BUDGET_BYTES - 1024 * 1024 or allocated > VM_BUDGET_BYTES - 1024 * 1024:
        raise ValueError('envelope exceeds aggregate budget')
    return {'kernelCapacityBytes': capacity, 'hostAllocatedBytes': allocated,
            'backingFile': str(backing), 'device': device}


def sync_directory(root):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def recover_retirement(root, manifest):
    """Caller holds lifecycle lock. Unknown transactions are retained/refused."""
    journal = root / '.retirement.json'
    if not journal.exists():
        return
    if journal.is_symlink():
        raise ValueError('linked retirement journal')
    transaction = json.loads(journal.read_text())
    if set(transaction) not in ({'old', 'identity', 'replacement', 'receipt'},
                                {'old', 'identity', 'replacement', 'receipt', 'replacementIdentity'}):
        raise ValueError('unknown retirement transaction')
    for key in ('old', 'replacement', 'receipt'):
        if Path(transaction[key]).name != transaction[key] or transaction[key] in ('.', '..'):
            raise ValueError('unsafe retirement path')
    if manifest['image'] not in (transaction['replacement'], transaction['old']):
        raise ValueError('retirement still referenced; preserve for investigation')
    receipt_path = root / transaction['receipt']
    if receipt_path.is_symlink():
        raise ValueError('linked receipt')
    receipt = json.loads(receipt_path.read_text())
    if receipt.get('retirementCandidate') != transaction['old']:
        raise ValueError('retirement receipt mismatch')
    old = root / transaction['old']
    replacement = root / transaction['replacement']
    if old.exists():
        info = old.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or [info.st_dev, info.st_ino] != transaction['identity']:
            raise ValueError('retirement identity mismatch')
        new_info = replacement.lstat()
        new_identity = transaction.get('replacementIdentity', manifest.get('generated', {}).get(replacement.name))
        if not stat.S_ISREG(new_info.st_mode) or new_info.st_uid != os.getuid() or new_info.st_nlink != 1 or [new_info.st_dev, new_info.st_ino] != new_identity:
            raise ValueError('replacement identity mismatch')
        for image in (old, replacement):
            validate_chain(root, image, manifest.get('base'))
            subprocess.run(['qemu-img', 'check', str(image)], check=True, capture_output=True)
        subprocess.run(['qemu-img', 'compare', str(old), str(replacement)], check=True, capture_output=True)
        if manifest['image'] == transaction['old']:
            if old.name in manifest['retained'] or manifest.get('generated', {}).get(old.name) != transaction['identity']:
                raise ValueError('pre-reference retirement ownership mismatch')
            manifest['image'] = replacement.name
            manifest['retained'].append(old.name)
            manifest['generated'][replacement.name] = new_identity
        if transaction['old'] in manifest['retained']:
            if manifest.get('generated', {}).get(transaction['old']) != transaction['identity']:
                raise ValueError('referenced retirement ownership mismatch')
            manifest['retained'].remove(transaction['old'])
            del manifest['generated'][transaction['old']]
            pending = root / ('manifest-' + uuid.uuid4().hex + '.pending')
            with open(pending, 'x') as output:
                json.dump(manifest, output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
            os.replace(pending, root / 'manifest.json')
            sync_directory(root)
        old.unlink()
        sync_directory(root)
    else:
        if transaction['old'] in manifest['retained'] or transaction['old'] in manifest.get('generated', {}):
            raise ValueError('missing old image still referenced; preserve journal')
        new_info = replacement.lstat()
        expected = transaction.get('replacementIdentity', manifest.get('generated', {}).get(replacement.name))
        if manifest['image'] != replacement.name or not stat.S_ISREG(new_info.st_mode) or new_info.st_uid != os.getuid() or new_info.st_nlink != 1 or [new_info.st_dev, new_info.st_ino] != expected:
            raise ValueError('missing old image without matching replacement identity')
        validate_chain(root, replacement, manifest.get('base'))
        subprocess.run(['qemu-img', 'check', str(replacement)], check=True, capture_output=True)
    journal.unlink()
    sync_directory(root)


def launch_command(image, memory_mib=2048, cpus=1, privileged_namespace=False):
    image = Path(image)
    if not image.is_absolute() or image.is_symlink() or ',' in str(image):
        raise ValueError('image must be an absolute non-link path')
    info = image.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        raise ValueError('image must be exclusively owned')
    if image.resolve() != image:
        raise ValueError('symlink ancestry refused')
    if type(memory_mib) is not int or not 512 <= memory_mib <= 30720:
        raise ValueError('bounded memory required')
    if type(cpus) is not int or not 1 <= cpus <= 12:
        raise ValueError('bounded CPU count required')
    bwrap = shutil.which('bwrap')
    qemu = shutil.which('qemu-system-x86_64')
    if not bwrap or not qemu:
        raise RuntimeError('existing bwrap and QEMU required; no unsandboxed fallback')
    prefix = []
    identity = []
    namespaces = ['--unshare-all']
    if privileged_namespace:
        sudo = shutil.which('sudo')
        if not sudo:
            raise RuntimeError('noninteractive namespace setup unavailable')
        prefix = [sudo, '-n']
        setpriv = shutil.which('setpriv')
        if not setpriv:
            raise RuntimeError('sandbox identity drop unavailable')
        namespaces = ['--unshare-pid', '--unshare-ipc', '--unshare-net', '--unshare-uts']
        identity = [setpriv, f'--reuid={os.getuid()}', f'--regid={os.getgid()}', '--clear-groups', '--no-new-privs']
    return prefix + [bwrap, '--die-with-parent'] + namespaces + ['--ro-bind', '/', '/',
            '--dev', '/dev', '--proc', '/proc', '--bind', str(image), str(image)] + identity + [
            qemu, '-machine', 'q35,accel=tcg', '-cpu', 'max',
            '-smp', str(cpus), '-m', str(memory_mib), '-display', 'none',
            '-monitor', 'none', '-serial', 'none', '-nic', 'none',
            '-no-reboot', '-drive', 'if=ide,format=qcow2,file=' + str(image)]


def launch_bounded(image, ceiling, timeout_seconds=300, firmware=None, isolated_ssh=False,
                   relay_stdio=False, relay_base=None):
    """Reap on every exit; caller must hold lifecycle lock and verify accounting."""
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 900:
        raise ValueError('bounded runtime required')
    if type(isolated_ssh) is not bool or (isolated_ssh and firmware is None):
        raise ValueError('isolated SSH requires explicit selection and Windows firmware')
    if type(relay_stdio) is not bool or (relay_stdio and not isolated_ssh):
        raise ValueError('stdio relay requires explicit isolated SSH selection')
    if relay_stdio and (relay_base is None or Path(relay_base).parent != image.parent or
                        Path(relay_base).resolve() != Path(relay_base) or
                        Path(relay_base) == image):
        raise ValueError('stdio relay requires admitted local immutable base')
    command = (windows_launch_command(image, image.parent / firmware['code'],
                                      image.parent / firmware['vars'], isolated_ssh=isolated_ssh) if firmware is not None
               else launch_command(image, privileged_namespace=True))
    if type(ceiling) is not int or not 0 < ceiling < 60_000_000_000:
        raise ValueError('invalid write ceiling')
    prlimit = shutil.which('prlimit')
    if not prlimit:
        raise RuntimeError('post-sudo kernel limit tool unavailable')
    qemu_index = command.index(shutil.which('qemu-system-x86_64'))
    command[qemu_index:qemu_index] = [prlimit, f'--fsize={ceiling}:{ceiling}', '--']
    if Path(image).stat().st_size > ceiling:
        raise ValueError('image already exceeds write ceiling')
    if firmware is not None:
        command.extend(['-qmp', 'stdio'])
    deadline = time.monotonic() + timeout_seconds
    with subprocess.Popen(command, stdin=subprocess.PIPE if firmware is not None else subprocess.DEVNULL,
                          stdout=subprocess.PIPE if firmware is not None else subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, bufsize=0) as process:
        cancel = threading.Event()
        worker = None
        namespace_fd = None
        outcome = []
        try:
            if firmware is not None:
                status = qmp_stdio_status(process.stdout, process.stdin,
                                          min(3, timeout_seconds))
                receipt = Path(image).parent / ('receipt-qmp-' + uuid.uuid4().hex + '.json')
                with receipt.open('x') as output:
                    json.dump({'monitorStatus': status, 'workflowAccepted': False}, output)
                    output.flush(); os.fsync(output.fileno())
                sync_directory(receipt.parent)
                if relay_stdio:
                    if not status['running']:
                        raise ValueError('stdio relay requires running QEMU')
                    namespace_fd, identity, ancestry = pin_owned_qemu_network(
                        process.pid, (image, relay_base, image.parent / firmware['code'],
                                      image.parent / firmware['vars']), deadline)
                    def transport():
                        try:
                            outcome.append(relay_owned_guest_stdio(
                                namespace_fd, identity, deadline, ancestry, cancel))
                        except BaseException as error:
                            outcome.append(error)
                    worker = threading.Thread(target=transport, name='opemos-owned-relay')
                    worker.start()
                # Drain asynchronous monitor output so a full pipe cannot
                # stall the guest. Cap it; output flooding is a refusal.
                total = 0
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while process.poll() is None:
                        if worker is not None and not worker.is_alive():
                            worker.join()
                            if len(outcome) != 1:
                                raise ValueError('missing owned relay result')
                            if isinstance(outcome[0], BaseException):
                                raise outcome[0]
                            process.stdin.write(b'{"execute":"quit","id":3}\n')
                            process.stdin.flush()
                            process.wait(timeout=min(3, max(0.001, deadline - time.monotonic())))
                            return outcome[0]
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(command, timeout_seconds)
                        if selector.select(min(remaining, 0.1)):
                            data = os.read(process.stdout.fileno(), 4096)
                            total += len(data)
                            if total > 65536:
                                raise ValueError('QMP runtime output exceeds bound')
                            if not data:
                                selector.unregister(process.stdout)
                                if worker is not None:
                                    raise ValueError('QMP closed during owned relay')
                                return process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if worker is not None:
                raise ValueError('QEMU exited during owned relay')
            return process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except BaseException:
            if firmware is not None and process.poll() is None:
                try:
                    process.stdin.write(b'{"execute":"quit","id":3}\n')
                    process.stdin.flush()
                    process.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            process.kill()
            process.wait()
            raise
        finally:
            # Never release the caller's image lock or reconcile disk state
            # while an owned transport still holds the namespace/guest alive.
            cancel.set()
            if worker is not None and worker.ident is not None:
                worker.join()
            if namespace_fd is not None:
                os.close(namespace_fd)


def require_windows_pool():
    """Require actual process ancestry, not merely a configured empty slice."""
    pool = '/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice'
    membership = Path('/proc/self/cgroup').read_text().splitlines()
    if len(membership) != 1 or not membership[0].startswith('0::' + pool + '/'):
        raise ValueError('Windows process must inherit the admitted VM pool')
    controls = Path('/sys/fs/cgroup' + pool)
    expected = {'memory.max': '34359738368', 'memory.swap.max': '0',
                'cpu.max': '1000000 100000', 'cpuset.cpus.effective': '0-9'}
    if any((controls / name).read_text().strip() != value for name, value in expected.items()):
        raise ValueError('Windows pool limits changed; refuse launch')


def validate_windows_firmware(root, firmware, image_names):
    """Exact staged CODE bytes and mutable VARS identity, never host paths."""
    if not isinstance(firmware, dict) or set(firmware) != {'code', 'codeSha256', 'vars', 'varsIdentity'}:
        raise ValueError('exact firmware record required')
    names = [firmware['code'], firmware['vars']]
    if len(set(names)) != 2 or any(not isinstance(name, str) or Path(name).name != name or name in ('.', '..') or ',' in name or name in image_names or not name.endswith('.fd') for name in names):
        raise ValueError('invalid firmware names')
    for name, length in zip(names, (3653632, 540672)):
        path = root / name
        info = path.lstat()
        if path.resolve() != path or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size != length:
            raise ValueError('unsafe staged firmware')
    if base_digest(root / firmware['code']) != firmware['codeSha256']:
        raise ValueError('firmware CODE hash mismatch')
    info = (root / firmware['vars']).lstat()
    if [info.st_dev, info.st_ino] != firmware['varsIdentity']:
        raise ValueError('firmware VARS identity mismatch')
    return set(names)


def windows_launch_command(image, firmware_code, firmware_vars, isolated_ssh=False):
    """First migrated Gen2 guest: no NIC unless exact isolated SSH is selected.

    Firmware must be staged as owned direct files inside the same allocation
    envelope. Caller holds the lifecycle lock and accounts both firmware files.
    This command preparation does not establish Windows workflow acceptance.
    """
    if type(isolated_ssh) is not bool:
        raise ValueError('explicit isolated SSH selection required')
    require_windows_pool()
    image = Path(image)
    require_ntfs_envelope(image.parent)
    code, variables = Path(firmware_code), Path(firmware_vars)
    for firmware, length in ((code, 3653632), (variables, 540672)):
        if firmware.parent != image.parent or firmware == image or ',' in str(firmware):
            raise ValueError('firmware must be a distinct contained direct file')
        info = firmware.lstat()
        if firmware.resolve() != firmware or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size != length:
            raise ValueError('unsafe or unmatched staged OVMF firmware')
    if code == variables:
        raise ValueError('firmware code and variables must differ')
    kvm = Path('/dev/kvm').stat()
    if not stat.S_ISCHR(kvm.st_mode) or not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise ValueError('KVM unavailable; no TCG fallback')
    command = launch_command(image, memory_mib=6152, cpus=2, privileged_namespace=True)
    # The generic sandbox drops supplementary groups. Preserve only the
    # already-authorized device group or QEMU cannot open mode-0660 KVM.
    if kvm.st_gid != os.getgid():
        if kvm.st_gid not in os.getgroups():
            raise ValueError('KVM device group is not already authorized')
        command[command.index('--clear-groups')] = '--groups=' + str(kvm.st_gid)
    # Only the exact KVM device and mutable VARS file extend the existing
    # namespace. CODE and immutable base remain covered by read-only root.
    bind_index = command.index('--proc')
    command[bind_index:bind_index] = ['--dev-bind', '/dev/kvm', '/dev/kvm',
                                     '--bind', str(variables), str(variables)]
    qemu_index = command.index(shutil.which('qemu-system-x86_64'))
    command[command.index('q35,accel=tcg')] = 'q35,accel=kvm'
    command[command.index('max', qemu_index)] = 'host'
    command.extend(['-drive', 'if=pflash,format=raw,readonly=on,file=' + str(code),
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)])
    if isolated_ssh:
        # Forward exists only in the existing unshared network namespace;
        # no bridge/tap, host wildcard listener, or unrestricted guest egress.
        nic_index = command.index('-nic')
        if command[nic_index + 1] != 'none' or '--unshare-net' not in command:
            raise ValueError('isolated network baseline changed')
        command[nic_index + 1] = ('user,model=e1000,mac=00:15:5d:10:0f:02,restrict=on,'
                                  'net=172.22.64.0/20,host=172.22.64.1,'
                                  'hostfwd=tcp:127.0.0.1:2222-172.22.79.248:22')
    return command


def run_owned_vm(directory, timeout_seconds=300, isolated_ssh=False, relay_stdio=False):
    """Locked standalone lifecycle; retains every prior image and output.

    This is not Windows migration acceptance or an NTFS aggregate quota.
    RLIMIT bounds file length; actual allocation is independently measured.
    """
    if type(isolated_ssh) is not bool:
        raise ValueError('explicit isolated SSH selection required')
    if type(relay_stdio) is not bool or (relay_stdio and not isolated_ssh):
        raise ValueError('stdio relay requires explicit isolated SSH selection')
    root = Path(directory)
    if not root.is_absolute() or root.resolve() != root or root.is_symlink():
        raise ValueError('unsafe lifecycle root')
    if (root / '.opemos-migration-owned').read_text() != 'OPEMOS.EXE\n':
        raise ValueError('unowned lifecycle root')
    lock_path = root / '.lifecycle-lock'
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        manifest_path = root / 'manifest.json'
        if manifest_path.is_symlink():
            raise ValueError('linked manifest refused')
        original = manifest_path.read_bytes()
        manifest = json.loads(original)
        keys = set(manifest) - {'base', 'baseSha256', 'writeCeilingBytes', 'windowsFirmware'}
        if keys not in ({'schemaVersion', 'image', 'retained'}, {'schemaVersion', 'image', 'retained', 'generated'}) or manifest['schemaVersion'] != 1:
            raise ValueError('unsupported lifecycle manifest')
        base = manifest.get('base')
        base_hash = None
        envelope = None
        if base is not None:
            declared_ceiling = manifest.get('writeCeilingBytes')
            if type(declared_ceiling) is not int or not 0 < declared_ceiling < VM_BUDGET_BYTES:
                raise ValueError('exact backed-runtime write ceiling required')
            if Path(base).name != base or base in ('.', '..') or base == manifest['image'] or base in manifest['retained']:
                raise ValueError('invalid immutable base reference')
            envelope = require_ntfs_envelope(root)
            validate_chain(root, root / manifest['image'], base)
            base_hash = base_digest(root / base)
            if base_hash != manifest.get('baseSha256'):
                raise ValueError('immutable base hash mismatch')
        elif 'baseSha256' in manifest or 'writeCeilingBytes' in manifest:
            raise ValueError('hash without base')
        if isolated_ssh and manifest.get('windowsFirmware') is None:
            raise ValueError('isolated SSH requires Windows firmware')
        # Refuse before retirement recovery can change any image references.
        # This endpoint is only for the verified first Agent-Boot lineage.
        if isolated_ssh and base_hash != '2a6fd3993ad38ca2d1d3b74dc8fd7d3ed51b0ad16297b85ab9981fa42ababa52':
            raise ValueError('isolated SSH requires the exact migrated Agent-Boot base')
        recover_retirement(root, manifest)
        original = manifest_path.read_bytes()
        manifest = json.loads(original)
        names = [manifest['image']] + manifest['retained']
        if len(names) != len(set(names)):
            raise ValueError('duplicate image accounting')
        allowed = set(names) | {'.opemos-migration-owned', '.lifecycle-lock', 'manifest.json'}
        if base is not None:
            allowed.add(base)
        firmware = manifest.get('windowsFirmware')
        if firmware is not None:
            if base is None:
                raise ValueError('Windows firmware requires immutable base')
            allowed.update(validate_windows_firmware(root, firmware, allowed))
        allocated = 0
        for entry in root.iterdir():
            info = entry.lstat()
            if (entry.name not in allowed and not (entry.name.startswith('receipt-') and entry.name.endswith('.json'))) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError('unaccounted or unsafe lifecycle file')
            allocated += info.st_blocks * 512
        if any(not isinstance(name, str) or Path(name).name != name or ',' in name for name in names):
            raise ValueError('invalid image identity')
        image = root / manifest['image']
        # The active image is one of the two capped writable files, not a
        # third fixed backing allocation. Count every OTHER retained/runtime
        # file in the fixed budget; never omit a retained historical image.
        # Length limits still need separate filesystem-allocation acceptance.
        fixed_allocation = allocated - image.stat().st_blocks * 512
        ceiling = bounded_file_ceiling(fixed_allocation, 2, 1024 * 1024)
        if base is not None:
            ceiling = min(ceiling, declared_ceiling)
        metadata = validate_chain(root, image, base)
        details = metadata.get('format-specific', {}).get('data', {})
        if metadata.get('format') != 'qcow2' or details.get('dirty-flag') or details.get('corrupt'):
            raise ValueError('dirty or dependent image refused')
        subprocess.run(['qemu-img', 'check', str(image)], check=True, capture_output=True)
        admitted_info = image.lstat()
        admitted_identity = [admitted_info.st_dev, admitted_info.st_ino]
        try:
            try:
                if isolated_ssh:
                    if relay_stdio:
                        exit_code = launch_bounded(image, ceiling, timeout_seconds, firmware=firmware,
                                                   isolated_ssh=True, relay_stdio=True,
                                                   relay_base=root / base)
                    else:
                        exit_code = launch_bounded(image, ceiling, timeout_seconds, firmware=firmware, isolated_ssh=True)
                elif firmware is not None:
                    exit_code = launch_bounded(image, ceiling, timeout_seconds, firmware=firmware)
                else:
                    exit_code = launch_bounded(image, ceiling, timeout_seconds)
            finally:
                # Reaped before reconciliation; failed current data is retained.
                recover_retirement(root, json.loads(manifest_path.read_text()))
                if base is not None and base_digest(root / base) != base_hash:
                    raise ValueError('base changed during guest operation')
                if firmware is not None:
                    validate_windows_firmware(root, firmware, names + [base])
            if exit_code != 0:
                raise RuntimeError('guest failed; image retained, no reference switch')
        except BaseException as failure:
            try:
                retained_info = image.lstat()
                retained_identity = [retained_info.st_dev, retained_info.st_ino]
            except FileNotFoundError:
                retained_identity = None
            failure_receipt = root / ('receipt-failure-' + uuid.uuid4().hex + '.json')
            evidence = {'status': 'FAILED', 'phase': 'guest-or-postcheck',
                        'errorType': type(failure).__name__, 'error': str(failure)[:4096],
                        'image': image.name,
                        'admittedImageIdentity': admitted_identity,
                        'retainedImageIdentity': retained_identity,
                        'currentImageRetained': retained_identity == admitted_identity,
                        'referenceSwitched': False, 'writeCeilingBytes': ceiling,
                        'totalBeforeAllocatedBytes': allocated,
                        'totalAfterAllocatedBytes': sum(entry.lstat().st_blocks * 512 for entry in root.iterdir())}
            # Evidence-only: never clean the failed image to make room. ENOSPC
            # may prevent the receipt; preserve and propagate that failure too.
            with open(failure_receipt, 'x') as output:
                json.dump(evidence, output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
            sync_directory(root)
            raise
        export = 'compact-' + uuid.uuid4().hex + '.qcow2'
        receipt = compact_owned_image(root, manifest['image'], export, lifecycle_lock=lock, export_ceiling=ceiling, backing_name=base)
        total = sum(entry.stat().st_blocks * 512 for entry in root.iterdir())
        if total > VM_BUDGET_BYTES or manifest_path.read_bytes() != original:
            raise ValueError('budget or manifest changed; export retained without switch')
        generated = manifest.get('generated', {})
        new_info = (root / export).stat()
        generated[export] = [new_info.st_dev, new_info.st_ino]
        updated = {'schemaVersion': 1, 'image': export, 'retained': names, 'generated': generated}
        if firmware is not None:
            updated['windowsFirmware'] = firmware
        if base is not None:
            if base_digest(root / base) != base_hash:
                raise ValueError('base changed during export')
            updated.update(base=base, baseSha256=base_hash, writeCeilingBytes=declared_ceiling)
            receipt['allocationEnvelope'] = envelope
            receipt['immutableBaseSha256'] = base_hash
        receipt['totalBeforeAllocatedBytes'] = allocated
        receipt['totalAllocatedBytes'] = total
        receipt['referenceSwitched'] = False
        # Only the immediately superseded generated image is a candidate.
        # Unclassified originals and retained distinct outputs are never removed.
        old_name = manifest['image']
        old_identity = manifest.get('generated', {}).get(old_name)
        if old_identity is not None:
            old = image.lstat()
            if [old.st_dev, old.st_ino] != old_identity or old.st_nlink != 1:
                raise ValueError('generated retirement identity mismatch; both images retained')
            subprocess.run(['qemu-img', 'check', str(image)], check=True, capture_output=True)
            receipt['retirementCandidate'] = old_name
            receipt_path = root / ('receipt-' + uuid.uuid4().hex + '.json')
            with open(receipt_path, 'x') as output:
                json.dump(receipt, output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
            # Journal intent BEFORE changing references; restart handles either
            # phase only after identity, check and compare verification.
            journal = root / '.retirement.json'
            with open(journal, 'x') as output:
                json.dump({'old': old_name, 'identity': old_identity,
                           'replacement': export, 'receipt': receipt_path.name,
                           'replacementIdentity': [new_info.st_dev, new_info.st_ino]}, output)
                output.flush()
                os.fsync(output.fileno())
            sync_directory(root)
        # Intent and verified replacement identity are durable BEFORE the first
        # reference change. Recovery can complete either side of this switch.
        pending = root / ('manifest-' + uuid.uuid4().hex + '.pending')
        with open(pending, 'xb') as output:
            output.write((json.dumps(updated, sort_keys=True) + '\n').encode())
            output.flush()
            os.fsync(output.fileno())
        os.replace(pending, manifest_path)
        sync_directory(root)
        receipt['referenceSwitched'] = True
        if old_identity is not None:
            # Do not unlink until a separate durable manifest removes the ref.
            updated['retained'].remove(old_name)
            del updated['generated'][old_name]
            pending = root / ('manifest-' + uuid.uuid4().hex + '.pending')
            with open(pending, 'x') as output:
                json.dump(updated, output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
            os.replace(pending, manifest_path)
            sync_directory(root)
            check_identity = image.lstat()
            if [check_identity.st_dev, check_identity.st_ino] != old_identity:
                raise ValueError('retirement path replaced')
            image.unlink()
            sync_directory(root)
            journal.unlink()
            sync_directory(root)
            receipt['retiredGeneratedImage'] = old_name
        receipt['totalAfterAllocatedBytes'] = sum(entry.stat().st_blocks * 512 for entry in root.iterdir())
        final_receipt = root / ('receipt-' + uuid.uuid4().hex + '.json')
        with open(final_receipt, 'x') as output:
            json.dump(receipt, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        sync_directory(root)
        return receipt
