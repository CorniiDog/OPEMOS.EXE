"""Owned regular-file USB for the existing normal Ubuntu VM lifecycle."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from vm_write_ceiling import VM_BUDGET_BYTES

@contextlib.contextmanager
def virtual_usb_backing(directory, capacity, charged_bytes, metadata_reserve=500_000_000):
    """One new regular-file USB for the existing admitted graphical VM.

    The ordinary VM job still owns queue admission, source and total storage
    observation. Keep this descriptor through QEMU and its normal finalizer;
    retain the file on success or failure. This creates no physical device.
    """
    root = Path(directory)
    if (not root.is_absolute() or root.resolve() != root or
            type(capacity) is not int or capacity <= 0 or capacity % 512 or
            type(charged_bytes) is not int or charged_bytes < 0 or
            type(metadata_reserve) is not int or metadata_reserve < 500_000_000 or
            charged_bytes + capacity + metadata_reserve > VM_BUDGET_BYTES):
        raise ValueError('exact finite virtual USB and whole-VM storage charge required')
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    fd = None
    core = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)
    try:
        before = os.fstat(directory_fd)
        if (core(before) != core(root.lstat()) or (before.st_uid, before.st_gid) != (os.getuid(), os.getgid()) or
                stat.S_IMODE(before.st_mode) != 0o700):
            raise ValueError('private owned graphical VM directory required')
        fd = os.open('virtual-usb.raw', os.O_RDWR | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
        os.fchmod(fd, 0o600)
        os.posix_fallocate(fd, 0, capacity)
        os.fsync(fd)
        os.fsync(directory_fd)
        path = root / 'virtual-usb.raw'
        value = os.fstat(fd)
        if (core(os.fstat(directory_fd)) != core(before) or
                core(root.lstat()) != core(before) or not stat.S_ISREG(value.st_mode) or
                (value.st_uid, value.st_gid) != (os.getuid(), os.getgid()) or value.st_nlink != 1 or
                value.st_size != capacity or value.st_blocks * 512 < capacity or
                stat.S_IMODE(value.st_mode) != 0o600 or
                (value.st_dev, value.st_ino) != (path.lstat().st_dev, path.lstat().st_ino)):
            raise ValueError('allocated owned regular-file virtual USB identity changed')
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        yield {'path': str(path), 'capacityBytes': capacity,
               'device': value.st_dev, 'inode': value.st_ino,
                'uid': value.st_uid, 'gid': value.st_gid,
                'identity': {key:getattr(value,key)for key in fields}}, fd
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory_fd)


def virtual_usb_identity(backing, fd):
    actual = os.fstat(fd)
    named = os.lstat(backing['path'])
    if (not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1 or
            stat.S_IMODE(actual.st_mode) != 0o600 or
            (actual.st_dev, actual.st_ino, actual.st_uid, actual.st_gid, actual.st_size) !=
            (backing['device'], backing['inode'], backing['uid'], backing['gid'], backing['capacityBytes']) or
            (named.st_dev, named.st_ino) != (actual.st_dev, actual.st_ino) or
            fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDWR):
        raise ValueError('held regular-file virtual USB differs')
    return actual


def virtual_usb_qemu_arguments(backing, fd, nonce):
    """Emulated USB storage backed only by the held file, never host /dev."""
    if type(nonce) is not str or re.fullmatch('[0-9a-f]{32}', nonce) is None:
        raise ValueError('same normal operation nonce required')
    virtual_usb_identity(backing, fd)
    # QEMU inherits this exact fd using the existing owned-Popen pass_fds path.
    # The existing xhci bus remains virtual inside the Ubuntu graphical guest.
    return ['-drive', f'if=none,id=virtualusb,format=raw,file=/proc/self/fd/{fd},cache=none',
            '-device', f'usb-storage,bus=xhci.0,drive=virtualusb,removable=on,serial=opemos-{nonce}']


def virtual_usb_readback(backing, fd, image):
    """After normal guest closure, flush/hash the same file and image extent.

    This is byte evidence only. The owning job must separately prove its actual
    GUI write/flush and QEMU closure before publication or a SteamOS handoff.
    """
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    identity = lambda s: {name: getattr(s, name) for name in fields}
    virtual_usb_identity(backing, fd)
    if (set(image) != {'path', 'bytes', 'sha256', 'identity'} or
            type(image['bytes']) is not int or not 0 < image['bytes'] <= backing['capacityBytes'] or
            image['bytes'] % 512 or re.fullmatch('[0-9a-f]{64}', image['sha256']) is None):
        raise ValueError('exact completed image extent/hash required')
    source = os.open(image['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                before.st_nlink != 1 or before.st_mode & 0o022 or
                identity(before) != image['identity'] or before.st_size != image['bytes'] or
                (before.st_dev, before.st_ino) == (backing['device'], backing['inode'])):
            raise ValueError('completed image custody or USB/source alias refused')
        os.fsync(fd)
        target_before = identity(os.fstat(fd))
        source_hash = hashlib.sha256(); prefix_hash = hashlib.sha256(); whole_hash = hashlib.sha256()
        offset = 0
        while offset < backing['capacityBytes']:
            size = min(1048576, backing['capacityBytes'] - offset)
            block = os.pread(fd, size, offset)
            if len(block) != size:
                raise ValueError('short complete virtual USB readback')
            whole_hash.update(block)
            count = min(size, max(0, image['bytes'] - offset))
            if count:
                original = os.pread(source, count, offset)
                if len(original) != count or original != block[:count]:
                    raise ValueError('virtual USB differs from actual completed image')
                source_hash.update(original); prefix_hash.update(block[:count])
            if any(block[count:]):
                raise ValueError('fresh virtual USB tail is not zero')
            offset += size
        if (source_hash.hexdigest() != image['sha256'] or prefix_hash.hexdigest() != image['sha256'] or
                identity(before) != identity(os.fstat(source)) or
                identity(before) != identity(os.lstat(image['path'])) or
                target_before != identity(os.fstat(fd)) or target_before != identity(os.lstat(backing['path']))):
            raise ValueError('whole image/hash or held source/USB epoch drift')
        return {'kind': 'OWNED_REGULAR_FILE_VIRTUAL_USB_READBACK', 'path': backing['path'],
                'bytesRead': offset, 'imageBytes': image['bytes'], 'readbackSHA256': prefix_hash.hexdigest(),
                'backingSHA256': whole_hash.hexdigest(), 'identity': target_before,
                'hostFlushCompleted': True, 'guestGUIOrBootAcceptanceClaimed': False}
    finally:
        os.close(source)


def virtual_usb_readback_observed(backing, fd, observation, app_birth, nonce, output_path):
    """Compare every USB byte with the same guest's completed-image witness.

    The owning normal job authenticates the observer channel and QEMU closure.
    The image remains inside its bounded guest COW; no second host image copy
    is needed. This function grants no boot, GUI-write or guest-source trust.
    """
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    identity = lambda s: {name: getattr(s, name) for name in fields}
    if (re.fullmatch('[0-9a-f]{32}', nonce or '') is None or
            observation.get('kind') != 'NATIVE_OBSERVATION' or
            observation.get('request_kind') != 'FILE' or observation.get('nonce') != nonce or
            observation.get('process') != app_birth or app_birth.get('inherited_nonce') != nonce or
            type(observation.get('sequence')) is not int or observation['sequence'] < 1 or
            type(observation.get('clock_ns')) is not int or observation['clock_ns'] <= 0):
        raise ValueError('same actual guest app/observer completed-image witness required')
    image = observation['value']
    path = Path(image['path'])
    info = image['identity']
    if (set(image) != {'path', 'bytes', 'sha256', 'identity'} or set(info) != set(fields) or
            not path.is_absolute() or '..' in path.parts or
            path != Path(output_path) or
            not any(parent.name == 'opemos-robot-' + nonce for parent in path.parents) or
            not stat.S_ISREG(info['st_mode']) or info['st_uid'] != 1000 or info['st_nlink'] != 1 or
            info['st_mode'] & 0o022 or info['st_size'] != image['bytes'] or
            type(image['bytes']) is not int or not 0 < image['bytes'] <= backing['capacityBytes'] or
            image['bytes'] % 512 or re.fullmatch('[0-9a-f]{64}', image['sha256']) is None):
        raise ValueError('actual owned guest output extent/hash/custody required')
    virtual_usb_identity(backing, fd)
    os.fsync(fd)
    before = identity(os.fstat(fd));prefix = hashlib.sha256();whole = hashlib.sha256();offset = 0
    while offset < backing['capacityBytes']:
        count = min(1048576, backing['capacityBytes'] - offset)
        block = os.pread(fd, count, offset)
        if len(block) != count:
            raise ValueError('short whole virtual USB readback')
        whole.update(block)
        extent = min(count, max(0, image['bytes'] - offset))
        prefix.update(block[:extent])
        if any(block[extent:]):
            raise ValueError('fresh virtual USB tail differs')
        offset += count
    virtual_usb_identity(backing, fd)
    if (prefix.hexdigest() != image['sha256'] or
            before != identity(os.fstat(fd)) or before != identity(os.lstat(backing['path']))):
        raise ValueError('USB bytes differ from actual guest image or backing epoch changed')
    return {'kind': 'OWNED_REGULAR_FILE_VIRTUAL_USB_READBACK', 'path': backing['path'],
            'bytesRead': offset, 'imageBytes': image['bytes'], 'readbackSHA256': prefix.hexdigest(),
            'backingSHA256': whole.hexdigest(), 'identity': before, 'hostFlushCompleted': True,
            'guestImageObservationSHA256': hashlib.sha256(json.dumps(observation, sort_keys=True,
                separators=(',', ':'), allow_nan=False).encode()).hexdigest(),
            'guestGUIOrBootAcceptanceClaimed': False}

