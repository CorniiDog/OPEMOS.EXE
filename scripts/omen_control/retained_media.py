"""Current custody of retained, read-only installer media.

A copy's origin boot is history.  The host which uses it must independently
measure its current bytes, loop/mount relationship and DAC state.  This module
does not mount, chown, set an ACL, bind a device, issue a grant or start a VM.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import stat

KIND = 'AUTHENTICATED_RETAINED_F9AA_READONLY_USB'
PROOF = 'ROOT_CURRENT_RETAINED_MEDIA_CUSTODY_V1'
RAW_BYTES = 8120172544
RAW_SHA = 'f9aa0fa2dd618febf28a5e2a583d1e2b5a8ca3f1205be965da584602ac962f40'
MEDIA_ACL = 'user::rw-\nuser:64055:r--\ngroup::---\nmask::r--\nother::---\n'
PARENT_ACL = 'user::rwx\nuser:64055:--x\ngroup::---\nmask::--x\nother::---\n'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def identity(s):
    return {k: getattr(s, k) for k in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def full_identity(value):
    keys = {'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
            'st_size', 'st_mtime_ns', 'st_ctime_ns'}
    need(type(value) is dict and set(value) == keys
         and all(type(x) is int and x >= 0 for x in value.values()),
         'complete typed full9 identity')


def is_adopted(c):
    return isinstance(c, dict) and isinstance(c.get('installer'), dict) and c['installer'].get('kind') == KIND


def origin_data(ref, nonce):
    """Read retained origin bytes from installed data, never a developer report directory."""
    from libvirt_native import held
    s = ref['identity']
    need(s['st_uid'] == s['st_gid'] == 0 and stat.S_ISREG(s['st_mode'])
         and stat.S_IMODE(s['st_mode']) in (0o400, 0o444) and s['st_nlink'] == 1,
         'protected immutable origin data')
    origin = json.loads(held(ref, 1048576))
    need(origin['kind'] == 'ROOT_AUTHENTICATED_CARRIER_TO_RAW_BOOT_COPY'
         and origin['runtimeAuthorized'] is False and origin['nonce'] == nonce
         and type(origin['bootID']) is str and bool(origin['bootID'])
         and (origin['rawBytes'], origin['rawSHA256']) == (RAW_BYTES, RAW_SHA),
         'actual raw-copy origin; its old boot remains historical')
    return {'kind': 'HISTORICAL_RAW_COPY_ORIGIN_DATA', 'bootID': origin['bootID'],
            'rawBytes': RAW_BYTES, 'rawSHA256': RAW_SHA, 'recordSHA256': ref['sha256']}


def _read(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        out = b''
        while chunk := os.read(fd, 65536):
            out += chunk
            need(len(out) <= cap, 'bounded kernel custody record')
        return out.decode()
    finally:
        os.close(fd)


def _mount(fd):
    rows = [x.split()[1] for x in _read('/proc/self/fdinfo/' + str(fd), 65536).splitlines()
            if x.startswith('mnt_id:')]
    need(len(rows) == 1 and rows[0].isdigit(), 'one held mount ID')
    rows = [x.split() for x in _read('/proc/self/mountinfo', 1048576).splitlines()
            if x.split()[0] == rows[0]]
    need(len(rows) == 1, 'one current held mount')
    a = rows[0]
    cut = a.index('-')
    return {'id': int(a[0]), 'parent': int(a[1]), 'device': a[2], 'root': a[3],
            'target': a[4], 'options': a[5].split(','), 'optional': a[6:cut],
            'type': a[cut + 1], 'source': a[cut + 2],
            'superOptions': a[cut + 3].split(',')}


@contextlib.contextmanager
def held_path(path, leaf=None):
    """Nofollow Root ancestry; only the exact declared media leaf may be QEMU-owned."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute media path')
    fds, names, before = [], [], []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        fds.append(fd); names.append(Path('/')); before.append(identity(os.fstat(fd)))
        for part in path.parts[1:]:
            fd = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            fds.append(fd); names.append(names[-1] / part); before.append(identity(os.fstat(fd)))
        for n, f, old in zip(names, fds, before):
            need(old == identity(os.lstat(n)), 'held/named media ancestry')
            if n == path and leaf is not None:
                need(old == leaf['identity'] and str(n) == leaf['path'], 'exact adopted leaf')
            else:
                need(old['st_uid'] == old['st_gid'] == 0, 'Root media ancestry')
                need(not old['st_mode'] & 0o022, 'no writable foreign media ancestor')
        yield fd
        for n, f, old in zip(names, fds, before):
            need(identity(os.fstat(f)) == identity(os.lstat(n)) == old,
                 'media full9/name stable throughout use')
    finally:
        for fd in reversed(fds):
            os.close(fd)


def _hash(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    h, n = hashlib.sha256(), 0
    while chunk := os.read(fd, 1048576):
        n += len(chunk); h.update(chunk)
    return n, h.hexdigest()


def validate_record(c, value):
    """Validate typed data; live kernel validation is a separate mandatory step."""
    v = c['installer']
    need(v['kind'] == KIND, 'retained installer kind')
    keys = {'kind', 'nonce', 'bootID', 'working', 'parent', 'backing', 'mount', 'loop',
            'workingACL', 'parentACL', 'origin', 'allOwnedFDsClosed'}
    need(type(value) is dict and set(value) == keys and value['kind'] == PROOF,
         'closed current custody schema')
    need(value['nonce'] == c['nonce'] and value['bootID'] == c['hostBoot'],
         'current candidate/host custody scope')
    need(value['working'] == c['working'] == v['bootCopy'] and value['backing'] == v['backing'],
         'exact current media/backing pins')
    w = value['working']; s = w['identity']
    for ref in (w, value['backing']):
        need(type(ref) is dict and set(ref) == {'path', 'bytes', 'sha256', 'identity'}
             and type(ref['path']) is str and Path(ref['path']).is_absolute()
             and '..' not in Path(ref['path']).parts
             and type(ref['bytes']) is int and ref['bytes'] > 0
             and re.fullmatch('[0-9a-f]{64}', ref['sha256']), 'full media role pin')
        full_identity(ref['identity'])
    need(set(value['parent']) == {'path', 'identity'}, 'parent metadata pin')
    full_identity(value['parent']['identity'])
    need(value['parent']['path'] == str(Path(w['path']).parent), 'exact retained parent')
    need((w['bytes'], w['sha256']) == (RAW_BYTES, RAW_SHA)
         and stat.S_ISREG(s['st_mode']) and s['st_nlink'] == 1
         and s['st_size'] == RAW_BYTES and (s['st_uid'], s['st_gid']) == (64055, 993)
         and stat.S_IMODE(s['st_mode']) == 0o640, 'actual retained QEMU-owned raw media')
    origin = value['origin']
    need(type(origin) is dict and set(origin) == {'kind', 'bootID', 'rawBytes', 'rawSHA256', 'recordSHA256'}
         and origin['kind'] == 'HISTORICAL_RAW_COPY_ORIGIN_DATA'
         and type(origin['bootID']) is str and bool(origin['bootID'])
         and (origin['rawBytes'], origin['rawSHA256']) == (RAW_BYTES, RAW_SHA)
         and type(origin['recordSHA256']) is str and re.fullmatch('[0-9a-f]{64}', origin['recordSHA256']),
         'preserved origin data; never current runtime authority')
    need(value['workingACL'] == MEDIA_ACL and value['parentACL'] == PARENT_ACL,
         'exact retained numeric DAC baseline; no new ACL authority')
    parent = value['parent']['identity']
    need(stat.S_ISDIR(parent['st_mode']) and parent['st_uid'] == parent['st_gid'] == 0
         and stat.S_IMODE(parent['st_mode']) == 0o710,
         'Root retained parent with traversal-only QEMU ACL')
    m = value['mount']
    need(m['target'] == str(Path(w['path']).parent) and m['root'] == '/'
         and m['type'] == 'ext4' and m['source'] == value['loop']['path']
         and 'ro' in m['options'] and 'rw' not in m['options']
         and {'nodev', 'nosuid', 'noexec'} <= set(m['options'])
         and 'ro' in m['superOptions'] and {'noload','norecovery'} & set(m['superOptions']),
         'read-only non-replaying retained filesystem')
    need(value['loop']['readOnly'] is True and value['loop']['backing'] == v['backing']['path']
         and value['loop']['offset'] == 0 and value['loop']['sizeLimit'] in (0, v['backing']['bytes']),
         'whole exact regular backing through read-only loop')
    need(value['allOwnedFDsClosed'] is True, 'custody producer descriptor closure')
    return value


def read_record(ref):
    from libvirt_native import held
    s = ref['identity']
    need(stat.S_ISREG(s['st_mode']) and stat.S_IMODE(s['st_mode']) == 0o400
         and s['st_uid'] == s['st_gid'] == 0 and s['st_nlink'] == 1,
         'protected current custody receipt')
    raw = held(ref, 1048576)
    return raw, json.loads(raw)


def contract(c):
    v = c['installer']
    raw, value = read_record(v['currentCustodyPin'])
    need(raw == json.dumps(v['currentCustody'], sort_keys=True, separators=(',', ':')).encode(),
         'actual whole current custody bytes, not historical receipt relabel')
    return validate_record(c, value)


def observe(c, *, hash_content=False):
    """Production consumer revalidates current kernel facts under held descriptors."""
    value = contract(c)
    return observe_record(value, hash_content=hash_content)


def observe_record(value, *, hash_content=False):
    from libvirt_access import ACL
    need(_read('/proc/sys/kernel/random/boot_id', 128).strip() == value['bootID'], 'live current boot')
    w, backing = value['working'], value['backing']
    with held_path(Path(w['path']).parent) as parent, held_path(w['path'], w) as fd:
        need(identity(os.fstat(parent)) == value['parent']['identity'], 'exact retained parent full9')
        need(_mount(parent) == value['mount'] == _mount(fd), 'same live read-only mount/leaf')
        need(os.fstatvfs(fd).f_flag & os.ST_RDONLY, 'kernel enforces read-only media')
        need(ACL().get(fd) == value['workingACL'] and ACL().get(parent) == value['parentACL'],
             'actual retained ACL baseline remains unchanged')
        loop = value['loop']; name = Path(loop['path']).name
        need(name.startswith('loop') and name[4:].isdigit(), 'actual generated loop identity')
        root = Path('/sys/class/block') / name
        live = {'path': loop['path'], 'backing': _read(root / 'loop/backing_file', 4096).strip(),
                'offset': int(_read(root / 'loop/offset', 128)),
                'sizeLimit': int(_read(root / 'loop/sizelimit', 128)),
                'readOnly': _read(root / 'ro', 128).strip() == '1'}
        need(live == loop and _read(root / 'dev', 128).strip() == value['mount']['device'],
             'current kernel loop/full backing relation')
        # The outer Games volume has its own authenticated shared-mount custody
        # in the normal storage guard. Do not generalize Root-only ancestry here.
        bf = os.open(backing['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            need(identity(os.fstat(bf)) == identity(os.lstat(backing['path'])) == backing['identity'],
                 'exact current outer backing full9')
            if hash_content:
                need(_hash(fd) == (w['bytes'], w['sha256']) and _hash(bf) == (backing['bytes'], backing['sha256']),
                     'whole retained raw and outer backing hashes')
            need(identity(os.fstat(bf)) == identity(os.lstat(backing['path'])) == backing['identity'],
                 'outer backing epoch unchanged')
        finally:
            os.close(bf)
        need(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
             'owned raw descriptor stays read-only')
    return value


def access_row(c, path, ref, role):
    """Only retained working/parent roles use a no-mutation access journal."""
    value = observe(c)
    need(role in ('working', 'working-parent'), 'finite immutable retained roles')
    want = c['working'] if role == 'working' else {
        'path': str(Path(c['working']['path']).parent), 'identity': value['parent']['identity']}
    need(path == want['path'] and ref == want, 'same exact retained access role')
    acl = value['workingACL'] if role == 'working' else value['parentACL']
    return {'path': path, 'role': role, 'before': ref, 'priorACL': acl, 'targetACL': acl,
            'uid': 64055, 'rights': 'r--' if role == 'working' else '--x',
            'immutableMediaCustodyPin': c['installer']['currentCustodyPin']}


def validate_stage_row(c, row, after, fullpin):
    """Queue-side validation of the exact operand already checked by its Root observer."""
    if not is_adopted(c) or row['role'] not in ('working', 'working-parent'):
        return False
    value = validate_record(c, c['installer']['currentCustody'])
    ref = c['installer']['currentCustodyPin']
    fullpin(ref, 0o400, 1048576)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    need(ref['bytes'] == len(raw) and ref['sha256'] == hashlib.sha256(raw).hexdigest(),
         'whole current custody record length/hash')
    role = row['role']; before = value['working'] if role == 'working' else value['parent']
    acl = value['workingACL'] if role == 'working' else value['parentACL']
    need(set(row) == {'path', 'role', 'before', 'priorACL', 'targetACL', 'uid', 'rights',
                      'immutableMediaCustodyPin'} and row['before'] == before
         and row['immutableMediaCustodyPin'] == ref and row['uid'] == 64055
         and row['path'] == before['path'] and row['priorACL'] == row['targetACL'] == acl
         and row['rights'] == ('r--' if role == 'working' else '--x')
         and after == {'path': before['path'], 'identity': before['identity'], 'ACL': acl},
         'immutable media preserved through the real stage/queue consumer')
    return True


def capture_current(c, origin, persist):
    """Normal Root preparation producer for an already owned read-only mount.

    Mount creation and current queue/source/native admission belong to the
    normal caller.  This operation only reads and publishes one create-only
    custody receipt; it cannot normalize ownership or repair old preparation.
    """
    from libvirt_access import ACL
    need(os.getuid() == 0 and is_adopted(c), 'Root retained-media preparation only')
    initial = set(os.listdir('/proc/self/fd'))
    w = c['working']; backing = c['installer']['backing']
    with held_path(Path(w['path']).parent) as parent, held_path(w['path'], w) as fd:
        mount = _mount(parent); loop = Path(mount['source']).name
        need(re.fullmatch('loop[0-9]+', loop), 'actual generated readonly loop')
        root = Path('/sys/class/block') / loop
        value = {'kind': PROOF, 'nonce': c['nonce'], 'bootID': c['hostBoot'],
                 'working': w, 'parent': {'path': str(Path(w['path']).parent),
                                        'identity': identity(os.fstat(parent))},
                 'backing': backing, 'mount': mount,
                 'loop': {'path': mount['source'],
                          'backing': _read(root / 'loop/backing_file', 4096).strip(),
                          'offset': int(_read(root / 'loop/offset', 128)),
                          'sizeLimit': int(_read(root / 'loop/sizelimit', 128)),
                          'readOnly': _read(root / 'ro', 128).strip() == '1'},
                 'workingACL': ACL().get(fd), 'parentACL': ACL().get(parent),
                 'origin': origin, 'allOwnedFDsClosed': True}
        validate_record(c, value)
    observe_record(value, hash_content=True)
    need(initial == set(os.listdir('/proc/self/fd')), 'custody producer FD set restored')
    ref = persist('retained-media-current-custody', value)
    need(ref is not None, 'durable current custody receipt')
    return {'currentCustody': value, 'currentCustodyPin': ref}


@contextlib.contextmanager
def held_row(row):
    """Verify a no-mutation row against its held protected custody, not a flag."""
    raw, value = read_record(row['immutableMediaCustodyPin'])
    need(value['kind'] == PROOF, 'current media custody kind')
    observe_record(value)
    role = row['role']
    need(role in ('working', 'working-parent'), 'immutable row role')
    ref = value['working'] if role == 'working' else value['parent']
    acl = value['workingACL'] if role == 'working' else value['parentACL']
    need(row['before'] == ref and row['path'] == ref['path']
         and row['priorACL'] == row['targetACL'] == acl and row['uid'] == 64055
         and row['rights'] == ('r--' if role == 'working' else '--x'),
         'current immutable role/ACL/source relation')
    with held_path(row['path'], ref if role == 'working' else None) as fd:
        class Held:
            def __init__(self): self.fd = fd
            def check(self, allow_leaf_epoch=False):
                now = identity(os.fstat(fd))
                need(now == identity(os.lstat(row['path'])) == ref['identity'],
                     'immutable held row full9')
                return now
        yield Held()
