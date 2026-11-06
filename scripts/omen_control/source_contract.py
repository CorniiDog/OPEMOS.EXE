"""Installed controller identity, separate from current job and candidate data."""
import json
import hashlib
import os
import re
from pathlib import Path
import stat

RUNTIME_ROLES = frozenset({
    'libvirt_peer', 'libvirt_access', 'libvirt_native', 'libvirt_preflight',
    'libvirt_producer', 'queue_assignment', 'runtime_entry', 'guest_delta',
    'guest_firmware_probe', 'held_history_reader', 'two_boot_contract',
    'postqueue_issuer', 'libvirt_storage', 'retained_media', 'source_contract',
})
PREPARATION_ROLES = frozenset({'current_media_preparation', 'fresh_placement_producer',
                               'fresh_media_parent', 'run_current_media'})


def validate(roles, queue, ref):
    # This consumer also runs in the ordinary queue, whose installed directory
    # contains only the two contract helpers, not the privileged runtime graph.
    need = _need
    held = _held_source
    i = ref['identity']
    need(stat.S_ISREG(i['st_mode']) and i['st_uid'] == i['st_gid'] == 0
         and stat.S_IMODE(i['st_mode']) == 0o444 and i['st_nlink'] == 1,
         'immutable installed controller contract')
    value = read_definition(ref)
    need(value['kind'] == 'OPEMOS_INSTALLED_MEDIA_SOURCE_CONTRACT_V2'
         and value['sourceRoles'] == roles and value['queuePrograms'] == queue
         and set(roles) == RUNTIME_ROLES, 'complete installed controller/queue identity')
    names = [Path(x['path']).name for x in queue]
    need(len(queue) == 7 and len(set(names)) == 7
         and names[:5] == ['test_queue.py', 'queue_job.py', 'heavy.sh', 'queue.sh', 'queue-files.sh']
         and names[-2:] == ['retained_media.py', 'source_contract.py'],
         'whole queue deployment includes its two immutable consumers')
    for name, pin in zip(('retained_media', 'source_contract'), queue[-2:]):
        need(pin['bytes'] == roles[name]['bytes'] and pin['sha256'] == roles[name]['sha256']
             and pin['identity']['st_uid'] == pin['identity']['st_gid'] == 0
             and stat.S_IMODE(pin['identity']['st_mode']) == 0o444,
             'same exact controller/queue helper bytes')
        held(pin, 1048576)
    root = Path(ref['path']).parent
    need(str(root) == value['deployment']['paths']['sourceRoot'] and str(Path(queue[0]['path']).parent) == value['deployment']['paths']['queueRoot'], 'same authenticated source/queue layout')
    preparation = value['preparationRoles']
    need(set(preparation) == PREPARATION_ROLES and not set(preparation) & set(roles),
         'complete static preparation entry and runtime consumer')
    for name, pin in {**roles, **preparation}.items():
        need(Path(pin['path']) == root / (name + '.py'), 'confined installed role')
        s = pin['identity']
        need(s['st_uid'] == s['st_gid'] == 0 and stat.S_ISREG(s['st_mode'])
             and stat.S_IMODE(s['st_mode']) == 0o444 and s['st_nlink'] == 1,
             'Root immutable executable source')
        held(pin, 1048576)
    return value


def deployment_paths(deployment_id):
    """One code definition, immutable deployment identity supplied as authenticated DATA."""
    if type(deployment_id) is not str or not re.fullmatch('[0-9a-f]{32}', deployment_id):
        raise ValueError('typed immutable deployment identity')
    return {'sourceRoot': '/run/opemos-media-source-' + deployment_id,
            'queueRoot': '/var/lib/opemos-media-queue-' + deployment_id,
            'drainRoot': '/var/lib/opemos-media-drain-' + deployment_id,
            'windowRoot': '/var/lib/opemos-media-window-' + deployment_id}


def operation_paths(deployment_id, attempt):
    deployment_paths(deployment_id)
    if type(attempt) is not str or not re.fullmatch('[0-9a-f]{32}', attempt):
        raise ValueError('typed immutable operation attempt')
    suffix = deployment_id + '-' + attempt
    return {'operationRoot': '/run/opemos-media-operation-' + suffix,
            'mountRoot': '/run/opemos-media-mount-' + suffix,
            'ioRoot': '/run/opemos-media-io-' + suffix,
            'placementRoot': '/run/opemos-media-placement-' + suffix,
            'runtimeRoot': '/run/opemos-media-runtime-' + suffix,
            'parentPath': '/run/opemos-media-parent-' + suffix + '.json',
            'jobPath': '/run/opemos-media-job-' + suffix + '.json'}


def candidate_paths(c):
    """Protected parent carries the generated context once; every reader verifies it."""
    context = c['operationContext']
    if type(context) is not dict or set(context) != {'deploymentId', 'attempt', 'paths'}:
        raise ValueError('complete operation context')
    expected = operation_paths(context['deploymentId'], context['attempt'])
    if c['nonce'] != context['attempt']:
        raise ValueError('current lease nonce is the fresh operation identity')
    if context['paths'] != expected or c['run'] != expected['ioRoot'] + '/run' or c['output'] != expected['ioRoot'] + '/output':
        raise ValueError('same confined operation paths/IO')
    if type(c.get('jobId')) is not str or not c['jobId'].endswith('-e' + context['attempt'][:16]):
        raise ValueError('same operation job identity')
    return expected


def _need(ok, reason):
    if not ok:
        raise ValueError(reason)


def _held_source(ref, cap):
    """Read immutable Root source DATA without importing or executing its graph."""
    if set(ref) != {'path', 'bytes', 'sha256', 'identity'}:
        raise ValueError('whole installed definition pin')
    fields = {'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'}
    if type(ref['identity']) is not dict or set(ref['identity']) != fields or not all(type(x) is int and x >= 0 for x in ref['identity'].values()):
        raise ValueError('complete typed definition full9')
    path = Path(ref['path']); descriptors = []; ancestors = []
    _need(path.is_absolute() and '..' not in path.parts and str(path) == ref['path'], 'absolute confined immutable source')
    _need(type(ref['bytes']) is int and 0 < ref['bytes'] <= cap and type(ref['sha256']) is str
          and re.fullmatch('[0-9a-f]{64}', ref['sha256']), 'bounded immutable source bytes/hash')
    identity = lambda st: {k: getattr(st, k) for k in fields}
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC); descriptors.append(fd)
        ancestors.append(('/', identity(os.fstat(fd))))
        current = Path('/')
        for part in path.parent.parts[1:]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd); descriptors.append(fd)
            st = os.fstat(fd)
            if st.st_uid != 0 or st.st_gid != 0 or st.st_mode & 0o022:
                raise ValueError('Root nofollow definition ancestry')
            current /= part; ancestors.append((str(current), identity(st)))
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd); descriptors.append(fd)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != before.st_gid or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o444 or before.st_nlink != 1 or not 0 < before.st_size <= cap:
            raise ValueError('immutable Root definition file')
        raw = b''
        while block := os.read(fd, 65536):
            raw += block
            if len(raw) > cap: raise ValueError('definition cap')
        if identity(before) != ref['identity'] or identity(before) != identity(os.fstat(fd)) or identity(before) != identity(os.lstat(path)) or len(raw) != ref['bytes'] or hashlib.sha256(raw).hexdigest() != ref['sha256']:
            raise ValueError('held/named definition full9/bytes/hash')
        for directory_fd, (name, old) in zip(descriptors, ancestors):
            now = identity(os.fstat(directory_fd))
            _need(now == identity(os.lstat(name)) and all(now[k] == old[k] for k in
                  ('st_dev','st_ino','st_mode','st_uid','st_gid')) and now['st_uid'] == now['st_gid'] == 0
                  and not now['st_mode'] & 0o022, 'held/named unchanged Root source ancestry')
        return raw
    finally:
        for fd in reversed(descriptors): os.close(fd)


def read_definition(ref):
    """Held immutable existing contract; no developer directory or live AI dependency."""
    value = json.loads(_held_source(ref, 1048576))
    if value.get('kind') != 'OPEMOS_INSTALLED_MEDIA_SOURCE_CONTRACT_V2' or type(value.get('guestNonce')) is not str or not re.fullmatch('[0-9a-f]{32}', value['guestNonce']):
        raise ValueError('current installed definition ABI/guest data')
    if value['deployment'] != dict(id=value['deployment']['id'], paths=deployment_paths(value['deployment']['id'])) or Path(ref['path']) != Path(value['deployment']['paths']['sourceRoot']) / 'installed-controller.json':
        raise ValueError('one shared authenticated deployment layout')
    return value


def current_from_queue(queue_path):
    """The executing immutable queue selects its paired existing definition."""
    path = Path(queue_path).absolute(); prefix = 'opemos-media-queue-'
    if path.parent.parent != Path('/var/lib') or not path.parent.name.startswith(prefix):
        return None  # historical source/test fixture, never current deployment authority
    identifier = path.parent.name[len(prefix):]; layout = deployment_paths(identifier)
    target = Path(layout['sourceRoot']) / 'installed-controller.json'
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd); raw = b''
        while block := os.read(fd, 65536):
            raw += block
            if len(raw) > 1048576: raise ValueError('definition cap')
        ref = {'path': str(target), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
               'identity': {k: getattr(st, k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}}
    finally: os.close(fd)
    value = read_definition(ref)
    if value['queuePrograms'][0]['path'] != str(path): raise ValueError('executing queue/definition join')
    return ref, value


def bind_scope(peer, parent):
    value = validate(parent['sourceRoles'], parent['queuePrograms'], parent['installedSourceContractPin'])
    c = parent['candidate']; paths = candidate_paths(c)
    if c['operationContext']['deploymentId'] != value['deployment']['id'] or parent['nonce'] != c['nonce'] or c['lineageNonce'] != value['guestNonce']:
        raise ValueError('same protected deployment/guest/scope')
    peer.SOURCE_PLACEMENT_NONCE = c['nonce']
    return value, paths


def parent_paths(parent):
    c = parent['candidate']
    if 'operationContext' in c:
        return candidate_paths(c)
    nonce = c['nonce']  # immutable historical input, never current selection
    return {'runtimeRoot': '/run/opemos-libvirt-runtime-' + nonce,
            'parentPath': '/run/opemos-libvirt-parent-' + nonce + '.json',
            'jobPath': '/run/opemos-libvirt-job-' + nonce + '.json',
            'placementRoot': '/run/opemos-steamos-placement-' + nonce}


def bind_request(peer, request):
    control = request.get('currentControl')
    if control is None:
        if Path(peer.__file__).parent.name.startswith('opemos-media-source-'):
            raise ValueError('current request must bind installed definition and parent')
        return None
    if type(control) is not dict or set(control) != {'definitionPin', 'parentPin'}:
        raise ValueError('closed current request control data')
    from libvirt_native import held
    ref = control['parentPin']; i = ref['identity']
    if i['st_uid'] != 0 or i['st_gid'] != 0 or not stat.S_ISREG(i['st_mode']) or stat.S_IMODE(i['st_mode']) != 0o444 or i['st_nlink'] != 1:
        raise ValueError('protected current parent')
    parent = json.loads(held(ref, 1048576))
    if parent['installedSourceContractPin'] != control['definitionPin'] or parent['jobId'] != request['jobId'] or parent['candidate']['jobId'] != request['jobId']:
        raise ValueError('exact current definition/parent/job')
    value, paths = bind_scope(peer, parent)
    if ref['path'] != paths['parentPath'] or parent['contextPath'] != paths['runtimeRoot'] + '/context.json' or parent['candidate']['nonce'] != request['leaseNonce'] or parent['sourceRoles']['libvirt_peer']['path'] != peer.__file__:
        raise ValueError('same protected request paths/source/scope')
    return parent
