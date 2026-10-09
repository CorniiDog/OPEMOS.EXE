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
from vm_write_ceiling import compact_owned_image, bounded_file_ceiling, VM_BUDGET_BYTES, validate_chain


def base_digest(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


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


def launch_bounded(image, ceiling, timeout_seconds=300, firmware=None):
    """Reap on every exit; caller must hold lifecycle lock and verify accounting."""
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 900:
        raise ValueError('bounded runtime required')
    command = (windows_launch_command(image, image.parent / firmware['code'],
                                      image.parent / firmware['vars']) if firmware is not None
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
    with subprocess.Popen(command, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as process:
        try:
            return process.wait(timeout=timeout_seconds)
        except BaseException:
            process.kill()
            process.wait()
            raise


def require_windows_pool():
    """Require actual process ancestry, not merely a configured empty slice."""
    pool = '/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice'
    membership = Path('/proc/self/cgroup').read_text().splitlines()
    if len(membership) != 1 or not membership[0].startswith('0::' + pool + '/'):
        raise ValueError('Windows process must inherit the admitted VM pool')
    controls = Path('/sys/fs/cgroup' + pool)
    expected = {'memory.max': '34359738368', 'memory.swap.max': '0',
                'cpu.max': '1200000 100000', 'cpuset.cpus.effective': '0-11'}
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


def windows_launch_command(image, firmware_code, firmware_vars):
    """First migrated Gen2 guest only: original 6152 MiB/two CPUs, no NIC.

    Firmware must be staged as owned direct files inside the same allocation
    envelope. Caller holds the lifecycle lock and accounts both firmware files.
    This command preparation does not establish Windows workflow acceptance.
    """
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
    return command


def run_owned_vm(directory, timeout_seconds=300):
    """Locked standalone lifecycle; retains every prior image and output.

    This is not Windows migration acceptance or an NTFS aggregate quota.
    RLIMIT bounds file length; actual allocation is independently measured.
    """
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
                exit_code = (launch_bounded(image, ceiling, timeout_seconds, firmware=firmware)
                             if firmware is not None else launch_bounded(image, ceiling, timeout_seconds))
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
