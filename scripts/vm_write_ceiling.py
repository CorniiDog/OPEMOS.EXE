"""Kernel write ceiling for the Ubuntu migration runner (not an aggregate quota).

The caller must separately account every backing, writable image and output.
This helper deliberately does not accept a caller-supplied remaining budget as
proof of the 60 GB aggregate cap.
"""
import resource
import json
import os
import stat
import subprocess
import fcntl
from contextlib import nullcontext
from pathlib import Path

VM_BUDGET_BYTES = 60_000_000_000


def validate_chain(root, image, backing_name=None):
    """Accept standalone, or exactly one explicit local immutable base."""
    root = Path(root)
    chain = json.loads(subprocess.run(
        ['qemu-img', 'info', '--backing-chain', '--output=json', str(image)],
        check=True, capture_output=True, text=True, timeout=60).stdout)
    expected = 1 if backing_name is None else 2
    if len(chain) != expected:
        raise ValueError('hidden or missing backing dependency')
    for entry in chain:
        details = entry.get('format-specific', {}).get('data', {})
        if entry.get('format') != 'qcow2' or details.get('dirty-flag') or details.get('corrupt'):
            raise ValueError('dirty or unapproved image')
    if backing_name is not None:
        if Path(backing_name).name != backing_name or backing_name in ('.', '..'):
            raise ValueError('unsafe backing name')
        base = root / backing_name
        info = base.lstat()
        if base.resolve() != base or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError('unsafe backing identity')
        if Path(chain[1]['filename']).resolve() != base or chain[1].get('backing-filename'):
            raise ValueError('unexpected external parent')
    return chain[0]


def bounded_file_ceiling(backing_bytes, writable_count, reserved_bytes):
    """Divide known headroom; reject unknown or exhausted accounting."""
    values = (backing_bytes, writable_count, reserved_bytes)
    if any(type(value) is not int for value in values):
        raise ValueError("exact integer accounting required")
    if backing_bytes < 0 or reserved_bytes <= 0 or writable_count <= 0:
        raise ValueError("invalid accounting")
    remaining = VM_BUDGET_BYTES - backing_bytes - reserved_bytes
    if remaining < writable_count:
        raise ValueError("VM budget exhausted")
    return remaining // writable_count


def install_file_ceiling(ceiling):
    """Call in the child before exec; limits writes and truncate in the kernel."""
    if type(ceiling) is not int or not 0 < ceiling < VM_BUDGET_BYTES:
        raise ValueError("invalid write ceiling")
    resource.setrlimit(resource.RLIMIT_FSIZE, (ceiling, ceiling))


def compact_owned_image(directory, image_name, export_name, lifecycle_lock=None, export_ceiling=None, backing_name=None):
    """Offline create-only export. Caller keeps both images and switches later.

    The directory's lifecycle lock must also be held by every runner. QEMU's
    image locks remain enabled in every command (never -U). No shared parents
    are accepted by this deliberately bounded migration operation.
    """
    root = Path(directory)
    for name in (image_name, export_name):
        if not name or Path(name).name != name or name in ('.', '..'):
            raise ValueError('image must be a direct owned child')
    if root.is_symlink() or not root.is_dir():
        raise ValueError('unsafe image directory')
    source = root / image_name
    target = root / export_name
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        raise ValueError('image is not an exclusively owned regular file')
    # This helper never invents an ownership marker for an existing directory.
    if (root / '.opemos-migration-owned').read_text() != 'OPEMOS.EXE\n':
        raise ValueError('missing migration ownership')
    with (open(root / '.lifecycle-lock', 'a+b') if lifecycle_lock is None else nullcontext(lifecycle_lock)) as lock:
        expected = (root / '.lifecycle-lock').stat()
        actual = os.fstat(lock.fileno())
        if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
            raise ValueError('wrong lifecycle lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        def command(*args):
            if export_ceiling is not None and args[:2] in (('qemu-img', 'create'), ('qemu-img', 'convert')):
                if type(export_ceiling) is not int or not 0 < export_ceiling < VM_BUDGET_BYTES:
                    raise ValueError('invalid export write ceiling')
                args = ('prlimit', f'--fsize={export_ceiling}:{export_ceiling}', '--') + args
            return subprocess.run(args, check=True, capture_output=True,
                                  text=True, timeout=300).stdout
        metadata = validate_chain(root, source, backing_name)
        base_identity = None
        if backing_name is not None:
            base_info = (root / backing_name).stat()
            base_identity = (base_info.st_dev, base_info.st_ino, base_info.st_size, base_info.st_mtime_ns)
        details = metadata.get('format-specific', {}).get('data', {})
        if details.get('dirty-flag') or details.get('corrupt'):
            raise ValueError('dirty or corrupt image')
        command('qemu-img', 'check', '-f', 'qcow2', str(source))
        # O_EXCL reserves the destination; qemu-img -n writes only this file.
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        # qemu-img create initializes the reserved file; the lifecycle lock
        # excludes cooperating runners. Failure retains the partial for audit.
        backing = () if backing_name is None else ('-F', 'qcow2', '-b', str(root / backing_name))
        command('qemu-img', 'create', '-f', 'qcow2', *backing, str(target), str(metadata['virtual-size']))
        # -n preserves the target's explicit backing; never rebase or commit.
        command('qemu-img', 'convert', '-n', '-m', '1', '-c', '-f', 'qcow2', '-O', 'qcow2', str(source), str(target))
        validate_chain(root, target, backing_name)
        command('qemu-img', 'check', '-f', 'qcow2', str(target))
        command('qemu-img', 'compare', '-f', 'qcow2', '-F', 'qcow2', str(source), str(target))
        current = source.lstat()
        if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise ValueError('source identity changed during export')
        if backing_name is not None:
            base_after = (root / backing_name).stat()
            if (base_after.st_dev, base_after.st_ino, base_after.st_size, base_after.st_mtime_ns) != base_identity:
                raise ValueError('immutable backing changed')
        return {'source': str(source), 'export': str(target),
                'beforeAllocatedBytes': current.st_blocks * 512,
                'afterAllocatedBytes': target.stat().st_blocks * 512,
                'originalRetained': True}
