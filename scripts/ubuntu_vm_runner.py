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
import struct
import base64
import sqlite3
import re
from vm_write_ceiling import compact_owned_image, bounded_file_ceiling, VM_BUDGET_BYTES, validate_chain


def pin_owned_qemu_network(launcher_pid, required_files, deadline, allow_setup_root=False):
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
    if launcher[2] != os.getuid() and not (allow_setup_root and launcher[2] == 0):
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
        if before[2] != os.getuid() and not (allow_setup_root and before[2] == 0):
            raise ValueError('descendant owner mismatch')
        pending.extend((int(child), pid) for child in
                       (root / 'task' / str(pid) / 'children').read_text().split())
        if before[2] == 0 and allow_setup_root:
            permitted = [shutil.which(name) for name in ('sudo', 'bwrap', 'setpriv', 'python3')]
            # /proc/<privileged-setup>/exe is not a same-UID-readable handle.
            # Bind only this owned ancestry's exact constructed tool argv;
            # QEMU itself still requires same UID and kernel executable inode.
            setup_argv = [value.decode() for value in (root / 'cmdline').read_bytes().split(b'\0') if value]
            if not setup_argv or setup_argv[0] not in permitted:
                raise ValueError('unknown privileged setup executable')
            actual = None
        else:
            actual = (root / 'exe').stat()
        if actual is not None and (actual.st_dev, actual.st_ino) == (executable.st_dev, executable.st_ino):
            if before[2] != os.getuid():
                raise ValueError('QEMU must run as the original user, never root')
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
            'backingFile': str(backing), 'device': device,
            'backingIdentity': [info.st_dev, info.st_ino],
            'backingBytes': info.st_size, 'backingUID': info.st_uid,
            'backingMode': stat.S_IMODE(info.st_mode),
            'loopDeviceIdentity': list((os.stat(device).st_dev, os.stat(device).st_rdev)),
            'loopOffset': int((loop / 'loop/offset').read_text()),
            'loopSizeLimit': int((loop / 'loop/sizelimit').read_text()),
            'mountTarget': data['target']}


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
    refuse_windows_lease(image.parent)
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
    refuse_windows_lease(Path(image).parent)
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
    image = Path(image)
    refuse_windows_lease(image.parent)
    require_windows_pool()
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
    if kvm.st_gid != os.getgid() and kvm.st_gid in os.getgroups():
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


AGENTBOOT_BASE = '2a6fd3993ad38ca2d1d3b74dc8fd7d3ed51b0ad16297b85ab9981fa42ababa52'
AGENTBOOT_CODE = 'ad23261d43116abc3747d59a7837fbf578c9586a8993f4eeba064cd07eccb083'
AGENTBOOT_VARS = '5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e'
AGENTBOOT_ENVELOPE = '/media/connor/Games/OPEMOS-migration-20261009-r1/agent-boot-runtime-r1/owned-runtime.ntfs'
WINDOWS_LEASE = '.graphical-lease.json'


def validate_agentboot_envelope(envelope, root):
    """Selected transferred file identity, not a generic marked NTFS volume.

    Device/inode are the retained host identity, not a portable fixture pin.
    A remount/migration that changes them needs fresh independent admission.
    """
    if (envelope['backingFile'] != AGENTBOOT_ENVELOPE or
            envelope['backingIdentity'] != [2051, 227] or
            envelope['backingBytes'] != 59_900_000_256 or
            envelope['kernelCapacityBytes'] != 59_900_000_256 or
            envelope['backingUID'] != 1000 or envelope['backingMode'] != 0o600 or
            envelope['loopOffset'] != 0 or envelope['loopSizeLimit'] != 0 or
            envelope['mountTarget'] != str(root)):
        raise ValueError('selected transferred AgentBoot envelope identity required')
    return envelope


def require_agentboot_envelope(root):
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root:
        raise ValueError('exact direct AgentBoot mount root required')
    observed = validate_agentboot_envelope(require_ntfs_envelope(root), root)
    # sysfs names alone do not prove that a loop still references the inode at
    # that name (the original can be unlinked/replaced). Read LOOP_GET_STATUS64
    # from the exact loop device, using the existing bounded sudo control route.
    probe = r'''
import os,sys,stat,fcntl,struct,json
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
try:
 s=os.fstat(fd)
 if not stat.S_ISBLK(s.st_mode):raise ValueError('not a loop block device')
 b=bytearray(232);fcntl.ioctl(fd,0x4c05,b,True)
 print(json.dumps({'loopRdev':s.st_rdev,'backing':list(struct.unpack_from('=5Q',b))}))
finally:os.close(fd)
'''
    kernel = json.loads(subprocess.run(
        ['sudo', '-n', '/usr/bin/python3', '-I', '-c', probe, observed['device']],
        check=True, capture_output=True, text=True, timeout=2).stdout)
    if (kernel['backing'][:2] != [2051, 227] or kernel['backing'][3:] != [0, 0] or
            kernel['loopRdev'] != observed['loopDeviceIdentity'][1] or
            root.stat().st_dev != kernel['loopRdev']):
        raise ValueError('kernel loop backing or exact mounted filesystem changed')
    observed['kernelLoopStatus'] = kernel
    return observed


def refuse_windows_lease(root):
    # Existence, including a malformed/linked/partial marker, is a durable
    # refusal. No consumer imports a claimed "closed" flag or deletes it.
    if os.path.lexists(Path(root) / WINDOWS_LEASE):
        raise ValueError('durable Windows lease held; separate exact Root finalization required')


def windows_process_identity(pid):
    root = Path('/proc') / str(pid)
    values = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'startTicks': int(values[19]), 'uid': root.stat().st_uid,
            'pgid': int(values[2])}


def persist_windows_record(path, record):
    # A partial write is intentionally not reusable. x/NOFOLLOW and directory
    # fsync make controller/CLI death a durable refusal, not a lease release.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(record, stream, sort_keys=True)
        stream.flush(); os.fsync(stream.fileno())
    sync_directory(Path(path).parent)


def windows_queue_binding(queue_directory):
    """Read the existing queue row and actual systemd identity; never mutate it.

    This is custody evidence, not runtime authority. Root still admits the exact
    row/source/inputs and owns pool release after full cgroup closure.
    """
    queue = Path(queue_directory)
    if not queue.is_absolute() or queue.resolve() != queue:
        raise ValueError('exact existing queue directory required')
    database_info = owned_regular(queue / 'queue.sqlite3', 16_777_216)
    membership = Path('/proc/self/cgroup').read_text().splitlines()
    pool = '/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice'
    prefix = 'opemos-testq-' + hashlib.sha256(str(queue).encode()).hexdigest()[:12] + '-'
    if len(membership) != 1 or not membership[0].startswith('0::' + pool + '/'):
        raise ValueError('exact queue cgroup required')
    cgroup = membership[0][3:]
    unit = cgroup.removeprefix(pool + '/')
    if re.fullmatch(re.escape(prefix) + r'[0-9a-f]{32}\.service', unit) is None:
        raise ValueError('controller must be in exact original queue unit')
    db = sqlite3.connect((queue / 'queue.sqlite3').as_uri() + '?mode=ro', uri=True, timeout=2)
    try:
        rows = db.execute('SELECT id,spec,state,unit,cpus FROM jobs WHERE unit=?', (unit,)).fetchall()
    finally:
        db.close()
    if len(rows) != 1 or rows[0][2:4] != ('running', unit):
        raise ValueError('one live exact queue lease required')
    spec = json.loads(rows[0][1])
    cpus = json.loads(rows[0][4])
    if (not isinstance(cpus, list) or len(cpus) != 2 or
            any(type(cpu) is not int or not 0 <= cpu <= 9 for cpu in cpus) or
            len(set(cpus)) != 2 or spec.get('memory') != 8 * 1024 ** 3):
        raise ValueError('exact two-CPU eight-GiB whole-job reservation required')
    props = dict(line.split('=', 1) for line in subprocess.run(
        ['systemctl', 'show', unit, '-p', 'InvocationID', '-p', 'ControlGroup',
         '-p', 'KillMode', '-p', 'ActiveState'], check=True, capture_output=True,
        text=True, timeout=2).stdout.splitlines() if '=' in line)
    if (props.get('ControlGroup') != cgroup or props.get('KillMode') != 'control-group' or
            props.get('ActiveState') != 'active' or
            re.fullmatch('[0-9a-f]{32}', props.get('InvocationID', '')) is None or
            props['InvocationID'] != os.environ.get('INVOCATION_ID')):
        raise ValueError('current system queue invocation required')
    cgpath = Path('/sys/fs/cgroup' + cgroup)
    cg = cgpath.stat()
    if (int((cgpath / 'memory.max').read_text()) != 8 * 1024 ** 3 or
            (cgpath / 'memory.swap.max').read_text().strip() != '0' or
            (cgpath / 'cpu.max').read_text().strip() != '200000 100000'):
        raise ValueError('actual queue unit resource limits changed')
    after = owned_regular(queue / 'queue.sqlite3', 16_777_216)
    if (after.st_dev, after.st_ino) != (database_info.st_dev, database_info.st_ino):
        raise ValueError('queue database replaced during binding')
    return {'queueDirectory': str(queue), 'jobID': rows[0][0], 'unit': unit,
            'databaseIdentity': [after.st_dev, after.st_ino],
            'specSha256': hashlib.sha256(rows[0][1].encode()).hexdigest(),
            'reservedCPUs': cpus, 'memoryBytes': spec['memory'], 'invocationID': props['InvocationID'],
            'cgroup': cgroup, 'cgroupIdentity': [cg.st_dev, cg.st_ino],
            'bootID': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def reserve_windows_lease(root, lock, envelope, command, queue):
    """Durable deny-reuse lease BEFORE Popen, retained even on clean CLI exit.

    Root finalization must match this file/queue/invocation/boot, inspect recorded
    launcher and QEMU births (or preserve an unknown birth), and prove full unit
    cgroup and owned group absence before any separate resource reuse. This
    consumer neither releases a queue row nor implements a finalizer bypass.
    """
    refuse_windows_lease(root)
    info = os.fstat(lock)
    record = {'schemaVersion': 1, 'state': 'HELD_UNTIL_SEPARATE_ROOT_FINALIZATION',
              'queue': queue, 'envelope': envelope,
              'controller': windows_process_identity(os.getpid()),
              'lockIdentity': [info.st_dev, info.st_ino],
              'argvSha256': hashlib.sha256(json.dumps(command).encode()).hexdigest(),
              'runnerSha256': base_digest(Path(__file__)),
              'baseSha256': AGENTBOOT_BASE, 'codeSha256': AGENTBOOT_CODE,
              'templateSha256': AGENTBOOT_VARS, 'resourceReleaseAuthorized': False}
    persist_windows_record(Path(root) / WINDOWS_LEASE, record)
    lease = owned_regular(Path(root) / WINDOWS_LEASE, 65536)
    return {'path': str(Path(root) / WINDOWS_LEASE), 'identity': [lease.st_dev, lease.st_ino],
            'sha256': base_digest(Path(root) / WINDOWS_LEASE), 'queue': queue}


def owned_regular(path, maximum):
    path = Path(path)
    info = path.lstat()
    if (path.resolve() != path or not stat.S_ISREG(info.st_mode) or
            info.st_uid != os.getuid() or info.st_nlink != 1 or not 0 <= info.st_size <= maximum):
        raise ValueError('unsafe owned regular file')
    return info


def windows_runtime_lock(root):
    refuse_windows_lease(root)
    path = Path(root) / '.lifecycle-lock'
    before = owned_regular(path, 0)
    if stat.S_IMODE(before.st_mode) != 0o600:
        raise ValueError('unsafe lifecycle lock mode')
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        os.close(fd)
        raise ValueError('lifecycle lock replaced')
    return fd


def create_windows_graphical_runtime(directory):
    """Create only this retained AgentBoot overlay/VARS transaction; never boot.

    Caller has separately admitted and mounted the exact envelope. Exclusive
    lifecycle ownership is held throughout. Any partials remain for review, not
    automatically replaced, retired or reused after a failed initialization.
    """
    if os.getuid() != 1000 or os.geteuid() != 1000:
        raise ValueError('retained AgentBoot controller must run as UID1000, not root')
    root = Path(directory)
    require_agentboot_envelope(root)
    if (root / '.opemos-migration-owned').read_text() != 'OPEMOS.EXE\n':
        raise ValueError('unowned Windows runtime')
    lock = windows_runtime_lock(root)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        expected = {'.opemos-migration-owned', '.lifecycle-lock', 'base.qcow2',
                    'OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd'}
        if {p.name for p in root.iterdir()} != expected:
            raise ValueError('initialized, partial or unknown Windows runtime; preserve it')
        pins = {'base.qcow2': AGENTBOOT_BASE, 'OVMF_CODE_4M.fd': AGENTBOOT_CODE,
                'OVMF_VARS_4M.fd': AGENTBOOT_VARS}
        for name, sha in pins.items():
            owned_regular(root / name, VM_BUDGET_BYTES)
            if base_digest(root / name) != sha:
                raise ValueError('retained AgentBoot input hash mismatch')
        validate_chain(root, root / 'base.qcow2')
        image = root / 'graphical.qcow2'
        variables = root / 'graphical-vars.fd'
        # A reservation prevents another cooperative initializer. qemu-img must
        # not reuse any preexisting output; all original paths stay untouched.
        reservation = root / 'graphical-initialization.json'
        with reservation.open('x') as stream:
            json.dump({'state': 'creating', 'base': AGENTBOOT_BASE}, stream)
            stream.flush(); os.fsync(stream.fileno())
        sync_directory(root)
        image_fd = os.open(image, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_RDWR, 0o600)
        try:
            subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2',
                            '-b', str(root / 'base.qcow2'), f'/proc/self/fd/{image_fd}'],
                           cwd=root, pass_fds=(image_fd,), check=True, capture_output=True, timeout=60)
            if (os.fstat(image_fd).st_dev, os.fstat(image_fd).st_ino) != (image.stat().st_dev, image.stat().st_ino):
                raise ValueError('created overlay path replaced; preserve partials')
            os.fsync(image_fd)
        finally:
            os.close(image_fd)
        owned_regular(image, 12_000_000_000)
        validate_chain(root, image, 'base.qcow2')
        with (root / 'OVMF_VARS_4M.fd').open('rb') as source, variables.open('xb') as target:
            os.fchmod(target.fileno(), 0o600)
            shutil.copyfileobj(source, target, 65536)
            target.flush(); os.fsync(target.fileno())
        if base_digest(variables) != AGENTBOOT_VARS:
            raise ValueError('working VARS copy mismatch; preserve partials')
        control = root / 'graphical-evidence'
        control.mkdir(mode=0o700)
        var_info = owned_regular(variables, 540672)
        result = {'schemaVersion': 1, 'image': image.name, 'base': 'base.qcow2',
                  'baseSha256': AGENTBOOT_BASE, 'writeCeilingBytes': 12_000_000_000,
                  'vars': variables.name, 'varsIdentity': [var_info.st_dev, var_info.st_ino],
                  'code': 'OVMF_CODE_4M.fd', 'codeSha256': AGENTBOOT_CODE,
                  'template': 'OVMF_VARS_4M.fd', 'templateSha256': AGENTBOOT_VARS,
                  'control': control.name, 'runtimeAuthorized': False}
        for name, sha in pins.items():
            if base_digest(root / name) != sha:
                raise ValueError('immutable input changed during initialization')
        with (root / 'graphical-manifest.json').open('x') as stream:
            json.dump(result, stream, sort_keys=True)
            stream.flush(); os.fsync(stream.fileno())
        sync_directory(root)
        return result
    finally:
        os.close(lock)


def windows_graphical_command(directory, package_iso, package_sha256):
    """Concrete AgentBoot argv, paused/no-NIC/private stdio; not admission."""
    if os.getuid() != 1000 or os.geteuid() != 1000:
        raise ValueError('retained AgentBoot controller must run as UID1000, not root')
    root = Path(directory)
    require_agentboot_envelope(root)
    manifest = json.loads((root / 'graphical-manifest.json').read_text())
    if (manifest.get('baseSha256') != AGENTBOOT_BASE or manifest.get('image') != 'graphical.qcow2'
            or manifest.get('vars') != 'graphical-vars.fd' or manifest.get('control') != 'graphical-evidence'
            or manifest.get('code') != 'OVMF_CODE_4M.fd' or manifest.get('codeSha256') != AGENTBOOT_CODE
            or manifest.get('template') != 'OVMF_VARS_4M.fd' or manifest.get('templateSha256') != AGENTBOOT_VARS):
        raise ValueError('unknown graphical runtime binding')
    for name, sha in [('base.qcow2', AGENTBOOT_BASE), ('OVMF_CODE_4M.fd', AGENTBOOT_CODE),
                      ('OVMF_VARS_4M.fd', AGENTBOOT_VARS)]:
        owned_regular(root / name, VM_BUDGET_BYTES)
        if base_digest(root / name) != sha:
            raise ValueError('retained input changed')
    variables = root / manifest['vars']
    info = owned_regular(variables, 540672)
    if [info.st_dev, info.st_ino] != manifest['varsIdentity']:
        raise ValueError('working VARS identity changed')
    package_iso = Path(package_iso)
    if package_iso.parent != root or ',' in str(package_iso):
        raise ValueError('package media must be inside exact envelope')
    owned_regular(package_iso, 8_000_000_000)
    if (len(package_sha256) != 64 or base_digest(package_iso) != package_sha256):
        raise ValueError('exact admitted package ISO hash required')
    control = root / manifest['control']
    info = control.lstat()
    if control.resolve() != control or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('unsafe private capture directory')
    image = root / manifest['image']
    owned_regular(image, 12_000_000_000)
    validate_chain(root, image, 'base.qcow2')
    command = windows_launch_command(image, root / manifest['code'], variables)
    at = command.index('--proc')
    command[at:at] = ['--bind', str(control), str(control)]
    qemu = command.index(shutil.which('qemu-system-x86_64'))
    # Runs AFTER sandbox setup and identity drop, before exec of QEMU. It uses
    # the same bound KVM device/UID; ACL access is actually tested, not assumed.
    device = Path('/dev/kvm').stat()
    probe = ('import os,stat,fcntl,sys,resource\n'
             f'if os.getuid()!={os.getuid()} or os.geteuid()!={os.getuid()}: raise RuntimeError("wrong sandbox UID")\n'
             's=os.stat("/dev/kvm")\n'
             f'if not stat.S_ISCHR(s.st_mode) or (s.st_dev,s.st_ino,s.st_rdev)!={(device.st_dev, device.st_ino, device.st_rdev)!r}: raise RuntimeError("KVM device changed")\n'
             'f=os.open("/dev/kvm",os.O_RDWR|os.O_CLOEXEC)\n'
             'try:\n'
             ' if fcntl.ioctl(f,0xae00,0)!=12: raise RuntimeError("unsupported KVM API")\n'
             'finally: os.close(f)\n'
             'resource.setrlimit(resource.RLIMIT_FSIZE,(12000000000,12000000000))\n'
             'os.execv(sys.argv[1],sys.argv[1:])\n')
    python = shutil.which('python3')
    if not python:
        raise ValueError('existing sandbox Python required')
    command[qemu:qemu] = [python, '-I', '-c', probe]
    command.extend(['-S', '-name', 'OPEMOS-Agent-Boot', '-vga', 'std',
                    '-device', 'qemu-xhci,id=opemos-xhci',
                    '-device', 'usb-tablet,bus=opemos-xhci.0',
                    '-drive', 'if=ide,media=cdrom,readonly=on,format=raw,file=' + str(package_iso),
                    '-qmp', 'stdio'])
    return command


class WindowsGraphicalQMP:
    """Only the owned AgentBoot stdio channel; no listener or guest execution."""
    def __init__(self, reader, writer, directory, deadline):
        self.reader, self.writer = reader, writer
        self.root = Path(directory)
        self.deadline = deadline
        self.buffer = bytearray()
        self.sequence = 0
        self.total = 0
        self.started = False
        self.handshaken = False
        self.frames = {}
        self.qemu_identity = None
        self.qemu_argv = None
        self.selector = selectors.DefaultSelector()
        self.selector.register(reader, selectors.EVENT_READ)

    def receive(self):
        while True:
            remaining = self.deadline - time.monotonic()
            if not 0 < remaining <= 900:
                raise TimeoutError('Windows QMP absolute deadline')
            if b'\n' in self.buffer:
                line, _, rest = self.buffer.partition(b'\n')
                self.buffer[:] = rest
                result = json.loads(line)
                if not isinstance(result, dict):
                    raise ValueError('QMP object required')
                return result
            if not self.selector.select(min(remaining, 5)):
                continue
            data = os.read(self.reader.fileno(), 4096)
            self.total += len(data)
            if not data or self.total > 1_048_576:
                raise ValueError('QMP closed or exceeded transcript bound')
            self.buffer.extend(data)

    def call(self, command, arguments=None):
        if self.qemu_identity is not None:
            pid, start, uid, _ = self.qemu_identity
            proc = Path(f'/proc/{pid}')
            fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
            if (int(fields[19]) != start or proc.stat().st_uid != uid or
                    (proc / 'cmdline').read_bytes() != self.qemu_argv):
                raise ValueError('owned QEMU PID/start/UID/argv changed')
        self.sequence += 1
        packet = {'execute': command, 'id': self.sequence}
        if arguments is not None:
            packet['arguments'] = arguments
        data = (json.dumps(packet) + '\n').encode()
        if len(data) > 4096 or time.monotonic() >= self.deadline:
            raise ValueError('bounded QMP command required')
        self.writer.write(data); self.writer.flush()
        for _ in range(128):
            reply = self.receive()
            if 'event' in reply:
                continue
            if reply.get('id') != self.sequence or 'error' in reply or 'return' not in reply:
                raise ValueError('QMP reply identity/error')
            return reply['return']
        raise ValueError('excessive asynchronous QMP events')

    def handshake(self):
        if self.handshaken:
            raise ValueError('duplicate graphical monitor handshake')
        if 'QMP' not in self.receive():
            raise ValueError('QMP greeting missing')
        self.call('qmp_capabilities')
        if self.call('query-name').get('name') != 'OPEMOS-Agent-Boot':
            raise ValueError('wrong guest monitor')
        state = self.call('query-status')
        if state.get('running') or state.get('status') not in ('paused', 'prelaunch'):
            raise ValueError('Windows must still be paused before device proof')
        self.handshaken = True
        return state

    def start(self, image, package, code, variables):
        state = self.call('query-status') if self.handshaken else self.handshake()
        if state.get('running') or state.get('status') not in ('paused', 'prelaunch'):
            raise ValueError('Windows left paused state before device proof')
        blocks = self.call('query-block')
        devices = self.call('human-monitor-command', {'command-line': 'info qtree'})
        actual = {row['inserted']['file']: row['inserted'] for row in blocks if 'inserted' in row}
        for path in (image, package, code, variables):
            if str(path) not in actual:
                raise ValueError('actual Windows disk/firmware binding differs')
        if not actual[str(package)].get('ro') or not actual[str(code)].get('ro'):
            raise ValueError('package/CODE must be read-only')
        if actual[str(image)].get('ro') or actual[str(variables)].get('ro'):
            raise ValueError('overlay/working VARS must be writable')
        if 'usb-tablet' not in devices or 'VGA' not in devices:
            raise ValueError('actual Windows display/tablet missing')
        proof = {'blocks': blocks, 'qtree': devices, 'paused': state, 'guestAccepted': False}
        with (self.root / 'device-proof.json').open('x') as stream:
            json.dump(proof, stream); stream.flush(); os.fsync(stream.fileno())
        sync_directory(self.root)
        self.call('cont')
        self.started = True
        return proof

    def capture(self, number):
        if not self.started or type(number) is not int or not 0 <= number < 16:
            raise ValueError('started guest and bounded frame number required')
        path = self.root / f'frame-{number:04d}.png'
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_RDWR, 0o600)
        try:
            original = os.fstat(fd)
            self.call('screendump', {'filename': str(path), 'format': 'png'})
            info = owned_regular(path, 16_777_216)
            if (info.st_dev, info.st_ino) != (original.st_dev, original.st_ino):
                raise ValueError('capture inode replaced')
            data = os.read(fd, 16_777_217)
            if len(data) != info.st_size or data[:8] != b'\x89PNG\r\n\x1a\n' or len(data) < 24:
                raise ValueError('invalid capture bytes')
            width, height = struct.unpack('>II', data[16:24])
            if not 1 < width <= 8192 or not 1 < height <= 8192:
                raise ValueError('unsupported actual framebuffer geometry')
            frame = {'number': number, 'width': width, 'height': height,
                     'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                     'device': info.st_dev, 'inode': info.st_ino}
            self.frames[number] = frame
            return {**frame, 'imageBase64': base64.b64encode(data).decode()}
        finally:
            os.close(fd)

    def click(self, frame_number, sha256, x, y, count=1):
        frame = self.frames.get(frame_number)
        if (not self.started or not frame or frame['sha256'] != sha256 or
                any(type(n) is not int for n in (x, y, count)) or count not in (1, 2) or
                not 0 <= x < frame['width'] or not 0 <= y < frame['height']):
            raise ValueError('click must reference an actual observed frame and integer coordinates')
        path = self.root / f'frame-{frame_number:04d}.png'
        info = owned_regular(path, 16_777_216)
        if (info.st_dev, info.st_ino, info.st_size) != (frame['device'], frame['inode'], frame['bytes']) or base_digest(path) != sha256:
            raise ValueError('referenced capture changed')
        if frame_number != max(self.frames):
            raise ValueError('stale screenshot; capture current visible enabled target first')
        self.call('input-send-event', {'events': [
            {'type': 'abs', 'data': {'axis': 'x', 'value': round(x * 32767 / (frame['width'] - 1))}},
            {'type': 'abs', 'data': {'axis': 'y', 'value': round(y * 32767 / (frame['height'] - 1))}}]})
        try:
            for _ in range(count):
                primary = None
                try:
                    self.call('input-send-event', {'events': [{'type': 'btn', 'data': {'down': True, 'button': 'left'}}]})
                except BaseException as error:
                    primary = error
                try:
                    self.call('input-send-event', {'events': [{'type': 'btn', 'data': {'down': False, 'button': 'left'}}]})
                except BaseException as cleanup:
                    if primary is not None:
                        raise RuntimeError(f'{primary}; pointer release also failed: {cleanup}') from primary
                    raise
                if primary is not None:
                    raise primary
        finally:
            # Any attempted action invalidates the observed UI state. A second
            # target requires another current screenshot, not a reused token.
            self.frames.clear()
        return {'frame': frame_number, 'sha256': sha256, 'x': x, 'y': y,
                'clickCount': count, 'actualPointerEvents': True}

    def close(self):
        self.selector.close()


def capture_windows_launcher(process, receipt, evidence):
    """An unobserved birth stays UNKNOWN, including a genuine /proc failure."""
    receipt['launcherPID'] = process.pid
    receipt['launcherBirth'] = 'UNKNOWN'
    birth = windows_process_identity(process.pid)
    if birth['pgid'] != process.pid:
        raise ValueError('launcher process group not isolated')
    receipt.update(launcherBirth=birth, launcherStartTicks=birth['startTicks'],
                   launcherPGID=birth['pgid'])
    persist_windows_record(evidence / 'lease-launcher.json', {
        'lease': receipt['durableLease'], 'launcher': birth})


def finalize_windows_graphical(root, lock, process, monitor, namespace_fd, envelope, receipt):
    """Independent cleanup/evidence stages; never replace first error.

    Only run_windows_graphical's own Popen handle can be cleaned. Unknown birth
    never authorizes group signalling or a closure claim. Durable lease custody
    is separate from every local close, reap, proof and receipt attempt.
    """
    errors = receipt.setdefault('secondaryErrors', [])
    receipt['closureVerified'] = False
    if process is not None:
        receipt.setdefault('launcherBirth', 'UNKNOWN')
        receipt.setdefault('qemuLauncherExit', 'UNKNOWN')

    def attempt(stage, action):
        try:
            action()
        except BaseException as error:
            errors.append({'stage': stage, 'type': type(error).__name__, 'error': str(error)})
            receipt['rootFinalizerRequired'] = True
            receipt['closureVerified'] = False

    def stop_monitor():
        if process is not None and process.poll() is None and monitor is not None:
            monitor.deadline = time.monotonic() + 2
            monitor.call('quit')
            process.wait(timeout=2)

    def stop_owned_child():
        if process is None or process.poll() is not None:
            return
        birth = receipt.get('launcherBirth', 'UNKNOWN')
        if not isinstance(birth, dict):
            receipt['launcherBirth'] = 'UNKNOWN'
            receipt['rootFinalizerRequired'] = True
            receipt['ownedCleanupScope'] = 'Popen handle only; no group birth proof'
            # Popen owns an unreaped direct child. Its kill implementation checks
            # child status before signalling; no discovered PID/name is used.
            # If sudo changed UID and denies this signal, record that refusal
            # and let the separately admitted Root unit finalizer handle it.
            process.kill()
        else:
            current = windows_process_identity(process.pid)
            if (current['startTicks'] != birth['startTicks'] or
                    current['pgid'] != process.pid or birth['pgid'] != process.pid):
                raise ValueError('launcher birth/group changed before cleanup')
            stopped = subprocess.run(['sudo', '-n', 'kill', '-KILL', '--',
                                      '-' + str(process.pid)], timeout=3, capture_output=True)
            receipt['ownedGroupCleanupExit'] = stopped.returncode
            if stopped.returncode != 0:
                raise RuntimeError('owned process group cleanup refused')

    def reap_child():
        if process is not None:
            receipt['qemuLauncherExit'] = process.wait(timeout=3)

    def prove_qemu_absence():
        identity = None if monitor is None else monitor.qemu_identity
        if identity is None:
            receipt['originalQemuIdentityAbsent'] = 'UNKNOWN'
            if process is not None:
                receipt['rootFinalizerRequired'] = True
            return
        qpid, qstart, _, _ = identity
        try:
            fields = Path(f'/proc/{qpid}/stat').read_text().rsplit(')', 1)[1].split()
            receipt['originalQemuIdentityAbsent'] = int(fields[19]) != qstart
        except FileNotFoundError:
            receipt['originalQemuIdentityAbsent'] = True
        if receipt['originalQemuIdentityAbsent'] is not True:
            receipt['rootFinalizerRequired'] = True

    def prove_group_absence():
        if process is None:
            return
        if not isinstance(receipt.get('launcherBirth'), dict):
            receipt['ownedProcessGroupAbsent'] = 'UNKNOWN'
            receipt['rootFinalizerRequired'] = True
            return
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            receipt['ownedProcessGroupAbsent'] = True
        else:
            receipt['ownedProcessGroupAbsent'] = False
            receipt['rootFinalizerRequired'] = True

    try:
        if receipt.get('primaryError') is not None:
            # Preserve the original failure before slow immutable rehashes or
            # other cleanup can itself hit the enclosing Root job deadline.
            attempt('first-error-persist', lambda: persist_windows_record(
                root / 'graphical-evidence' / 'first-error.json', {
                    'primaryError': receipt['primaryError'],
                    'launcherPID': None if process is None else process.pid,
                    'launcherBirth': receipt.get('launcherBirth', 'UNKNOWN'),
                    'durableLease': receipt.get('durableLease'),
                    'resourceReleaseAuthorized': False}))
        attempt('monitor-quit', stop_monitor)
        attempt('owned-child-stop', stop_owned_child)
        attempt('launcher-reap', reap_child)
        attempt('qemu-absence', prove_qemu_absence)
        attempt('group-absence', prove_group_absence)
        if namespace_fd is not None:
            attempt('namespace-close', lambda: os.close(namespace_fd))
        if monitor is not None:
            attempt('monitor-close', monitor.close)
        if process is not None:
            for name in ('stdin', 'stdout', 'stderr'):
                stream = getattr(process, name, None)
                if stream is not None:
                    attempt('launcher-' + name + '-close', stream.close)

        def check_envelope():
            receipt['envelopeAfter'] = require_agentboot_envelope(root)
            if any(receipt['envelopeAfter'][key] != envelope[key]
                   for key in envelope if key != 'hostAllocatedBytes'):
                raise ValueError('AgentBoot envelope identity changed')
        attempt('envelope-revalidation', check_envelope)
        receipt['immutableInputChecks'] = []
        for name, sha in [('base.qcow2', AGENTBOOT_BASE), ('OVMF_CODE_4M.fd', AGENTBOOT_CODE),
                          ('OVMF_VARS_4M.fd', AGENTBOOT_VARS)]:
            def check_input(name=name, sha=sha):
                actual = base_digest(root / name)
                receipt['immutableInputChecks'].append({'name': name, 'sha256': actual,
                                                       'matches': actual == sha})
                if actual != sha:
                    raise ValueError('immutable input hash mismatch: ' + name)
            attempt('input-rehash:' + name, check_input)
        receipt['closureVerified'] = (process is not None and process.returncode is not None and
                                      receipt.get('ownedProcessGroupAbsent') is True and
                                      receipt.get('originalQemuIdentityAbsent') is True and not errors and
                                      not receipt.get('rootFinalizerRequired'))
        receipt['explicitLockClose'] = 'PENDING'
        attempt('transaction-persist', lambda: persist_windows_record(
            root / 'graphical-evidence' / 'transaction.json', receipt))
    finally:
        # Even a schema/receipt/close error cannot skip the original lock close.
        def close_lock():
            os.close(lock)
            receipt['explicitLockClose'] = 'CLOSED'
        attempt('lock-close', close_lock)
        # transaction.json precedes lock release. This independent create-only
        # tail carries the actual close result and any persistence/close errors.
        attempt('finalization-tail-persist', lambda: persist_windows_record(
            root / 'graphical-evidence' / 'finalization.json', receipt))


def run_windows_graphical(directory, package_iso, package_sha256, control_in, control_out,
                          timeout_seconds=900, queue_directory=None):
    """Exact paused AgentBoot -> frames/pointer -> shutdown source transaction.

    Invoke only under separately reviewed Root queue/VM admission. Stream
    requests use the existing authenticated SSH/control session, never a new
    listener. This function cannot establish login or enable a disabled UI.
    Caller must inspect current frames and attest the visible enabled target.
    No initialization, retry, retirement or original mutation occurs here.
    """
    if os.getuid() != 1000 or os.geteuid() != 1000:
        raise ValueError('retained AgentBoot controller must run as UID1000, not root')
    if type(timeout_seconds) is not int or not 15 <= timeout_seconds <= 900:
        raise ValueError('bounded Windows transaction required')
    root = Path(directory)
    require_windows_pool()
    envelope = require_agentboot_envelope(root)
    lock = windows_runtime_lock(root)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        refuse_windows_lease(root)
    except BaseException:
        os.close(lock)
        raise
    process = monitor = None
    namespace_fd = None
    receipt = {'workflowAccepted': False, 'operations': [], 'envelope': envelope}
    primary = None
    deadline = time.monotonic() + timeout_seconds
    try:
        command = windows_graphical_command(root, package_iso, package_sha256)
        package_record = json.loads((root / 'graphical-package.json').read_text())
        package_keys = {'artifactId', 'archiveSha256', 'sourceCommit', 'coreCommit',
                        'isoSha256', 'portableInventoryVerified', 'executableSha256'}
        if (not isinstance(package_record, dict) or set(package_record) != package_keys or
                package_record.get('artifactId') != 11952692823 or
                package_record.get('archiveSha256') != '32d145dadca03547eb0f55fa8a188106de46604e5650ce8963bc32cb57c1a742' or
                package_record.get('sourceCommit') != '28c36055a51ae241b455757486bf838c5901e1d3' or
                package_record.get('coreCommit') != '01407aa6174b80e92cb7f3dcb534ade5cdd7bf00' or
                package_record.get('isoSha256') != package_sha256 or
                package_record.get('portableInventoryVerified') is not True or
                len(package_record.get('executableSha256', '')) != 64 or
                any(c not in '0123456789abcdef' for c in package_record.get('executableSha256', ''))):
            raise ValueError('exact full portable package/provenance verification missing')
        # This is the coordinator's staged, reviewed package evidence, not
        # authentication invented by a guest or a new trust input.
        receipt['packageEvidence'] = package_record
        allowed = {'.opemos-migration-owned', '.lifecycle-lock', 'base.qcow2',
                   'OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd', 'graphical.qcow2',
                   'graphical-vars.fd', 'graphical-manifest.json',
                   'graphical-initialization.json', 'graphical-package.json',
                   Path(package_iso).name, 'graphical-evidence'}
        if {p.name for p in root.iterdir()} != allowed:
            raise ValueError('unaccounted Windows runtime entries; preserve them')
        evidence = root / 'graphical-evidence'
        if list(evidence.iterdir()):
            raise ValueError('prior graphical evidence exists; do not silently retry/rearm')
        def account():
            total = 0
            for item in root.iterdir():
                if item == evidence:
                    entries = list(item.iterdir())
                    if len(entries) > 20:
                        raise ValueError('graphical evidence entry bound')
                    total += item.stat().st_blocks * 512
                    for child in entries:
                        info = owned_regular(child, 16_777_216)
                        total += info.st_blocks * 512
                else:
                    total += owned_regular(item, VM_BUDGET_BYTES).st_blocks * 512
            if total > 59_900_000_256:
                raise ValueError('Windows whole-envelope allocation exceeded')
            return total
        receipt['allocatedBefore'] = account()
        receipt['argv'] = command
        if queue_directory is None:
            raise ValueError('exact existing Root-admitted queue directory required')
        queue = windows_queue_binding(queue_directory)
        if require_agentboot_envelope(root) != envelope:
            raise ValueError('AgentBoot envelope changed before durable reservation')
        receipt['durableLease'] = reserve_windows_lease(root, lock, envelope, command, queue)
        receipt['durableLeaseRetained'] = True
        receipt['poolLeaseReleased'] = False
        with (evidence / 'stderr.log').open('xb') as log:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=log, start_new_session=True, bufsize=0)
            capture_windows_launcher(process, receipt, evidence)
            monitor = WindowsGraphicalQMP(process.stdout, process.stdin, evidence, deadline - 12)
            # Wait for the actual paused QEMU producer before inspecting its
            # host ancestry. No cont/device/input effect occurs during this.
            monitor.handshake()
            manifest = json.loads((root / 'graphical-manifest.json').read_text())
            namespace_fd, qemu_identity, ancestry = pin_owned_qemu_network(
                process.pid, (root / manifest['image'], root / manifest['base'], Path(package_iso),
                              root / manifest['code'], root / manifest['vars']), deadline - 12,
                allow_setup_root=True)
            monitor.qemu_identity = qemu_identity
            monitor.qemu_argv = Path(f'/proc/{qemu_identity[0]}/cmdline').read_bytes()
            receipt['qemuIdentity'] = qemu_identity
            receipt['ancestry'] = ancestry
            persist_windows_record(evidence / 'lease-qemu.json', {
                'lease': receipt['durableLease'], 'qemuIdentity': qemu_identity, 'ancestry': ancestry})
            namespace_info = os.fstat(namespace_fd)
            receipt['networkNamespaceIdentity'] = [namespace_info.st_dev, namespace_info.st_ino]
            receipt['bootID'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            receipt['cgroup'] = Path(f'/proc/{qemu_identity[0]}/cgroup').read_text().strip()
            if receipt['cgroup'] != '0::' + queue['cgroup']:
                raise ValueError('QEMU escaped exact leased queue unit')
            if any(os.getpgid(row[0]) != process.pid for row in ancestry):
                raise ValueError('owned setup/QEMU escaped exact launcher process group')
            receipt['deviceProof'] = monitor.start(root / manifest['image'], Path(package_iso),
                                                  root / manifest['code'], root / manifest['vars'])
            pending = bytearray()
            with selectors.DefaultSelector() as io:
                io.register(control_in, selectors.EVENT_READ)
                for _ in range(64):
                    while b'\n' not in pending:
                        if process.poll() is not None:
                            receipt['guestShutdownObserved'] = True
                            break
                        remaining = deadline - 12 - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError('Windows control absolute deadline')
                        if not io.select(min(remaining, 0.25)):
                            continue
                        chunk = os.read(control_in.fileno(), 4096)
                        if not chunk:
                            raise ValueError('control session closed; not app acceptance')
                        pending.extend(chunk)
                        if len(pending) > 4096:
                            raise ValueError('bounded control request required')
                    if process.poll() is not None:
                        break
                    line, _, rest = pending.partition(b'\n'); pending[:] = rest
                    op = json.loads(line)
                    if not isinstance(op, dict):
                        raise ValueError('control object required')
                    kind = op.get('kind')
                    if kind == 'capture':
                        result = monitor.capture(op['number'])
                    elif kind == 'click':
                        if op.get('visibleEnabledTarget') is not True or not isinstance(op.get('target'), str) or not 1 <= len(op['target']) <= 80:
                            raise ValueError('current visible enabled target observation required')
                        result = monitor.click(op['frame'], op['sha256'], op['x'], op['y'], op.get('clickCount', 1))
                    elif kind == 'powerdown':
                        result = monitor.call('system_powerdown')
                    elif kind == 'quit':
                        monitor.call('quit')
                        break
                    else:
                        raise ValueError('unapproved Windows control operation')
                    receipt['operations'].append({'request': op, 'result': {
                        k: v for k, v in result.items() if k != 'imageBase64'}})
                    packet = (json.dumps(result) + '\n').encode()
                    # The controlled stream is private; output must be drained
                    # by the same admitted controller or the operation refuses.
                    offset = 0
                    with selectors.DefaultSelector() as writable:
                        writable.register(control_out, selectors.EVENT_WRITE)
                        os.set_blocking(control_out.fileno(), False)
                        try:
                            while offset < len(packet):
                                remaining = deadline - 12 - time.monotonic()
                                if remaining <= 0 or not writable.select(remaining):
                                    raise TimeoutError('control output deadline')
                                try:
                                    offset += os.write(control_out.fileno(), packet[offset:offset + 65536])
                                except BlockingIOError:
                                    continue
                        finally:
                            os.set_blocking(control_out.fileno(), True)
                    account()
                else:
                    raise ValueError('Windows operation count exhausted')
            receipt['qemuLauncherExit'] = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if receipt['qemuLauncherExit'] != 0:
                raise RuntimeError(f"Windows launcher exited {receipt['qemuLauncherExit']}; not success")
            receipt['allocatedAfter'] = account()
            # Human-observed app/guest acceptance is separate. No settable
            # accepted flag can promote a stream of pointer operations to it.
    except BaseException as error:
        primary = error
        receipt['error'] = str(error)
        receipt['primaryError'] = {'type': type(error).__name__, 'error': str(error)}
    finally:
        finalize_windows_graphical(root, lock, process, monitor, namespace_fd, envelope, receipt)
    if primary is not None:
        primary.add_note('Windows finalization evidence: ' + json.dumps({
            'secondaryErrors': receipt.get('secondaryErrors', []),
            'rootFinalizerRequired': receipt.get('rootFinalizerRequired', False),
            'explicitLockClose': receipt.get('explicitLockClose', 'UNKNOWN')}))
        raise primary
    if receipt.get('rootFinalizerRequired') or receipt.get('secondaryErrors'):
        raise RuntimeError('Windows lifecycle/integrity failure; preserve exact job and inputs: ' +
                           json.dumps(receipt.get('secondaryErrors', [])))
    return receipt


def windows_graphical_main(arguments):
    """Narrow entry point; these commands require separate Root admission."""
    import argparse
    import sys
    parser = argparse.ArgumentParser(description='Retained AgentBoot graphical transaction; not runtime admission')
    parser.add_argument('operation', choices=['windows-graphical-initialize', 'windows-graphical-argv',
                                             'windows-graphical-run'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--package', type=Path)
    parser.add_argument('--package-sha256')
    parser.add_argument('--queue-directory', type=Path)
    selected = parser.parse_args(arguments)
    refuse_windows_lease(selected.directory)
    if selected.operation == 'windows-graphical-initialize':
        if selected.package is not None or selected.package_sha256 is not None or selected.queue_directory is not None:
            parser.error('initialization does not acquire or stage a package')
        result = create_windows_graphical_runtime(selected.directory)
    else:
        if selected.package is None or selected.package_sha256 is None:
            parser.error('exact verified package ISO and hash required')
        if selected.operation == 'windows-graphical-argv':
            if selected.queue_directory is not None:
                parser.error('argv rendering does not reserve a queue job')
            result = windows_graphical_command(selected.directory, selected.package, selected.package_sha256)
        else:
            if selected.queue_directory is None:
                parser.error('run requires the exact existing admitted --queue-directory')
            result = run_windows_graphical(selected.directory, selected.package, selected.package_sha256,
                                           sys.stdin.buffer, sys.stdout.buffer,
                                           queue_directory=selected.queue_directory)
    print(json.dumps(result, sort_keys=True))
    return 0


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
        refuse_windows_lease(root)
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


if __name__ == '__main__':
    import sys
    raise SystemExit(windows_graphical_main(sys.argv[1:]))
