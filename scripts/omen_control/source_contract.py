"""Installed controller identity, separate from current job and candidate data."""
import json
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
    from libvirt_native import held
    from libvirt_peer import need
    i = ref['identity']
    need(stat.S_ISREG(i['st_mode']) and i['st_uid'] == i['st_gid'] == 0
         and stat.S_IMODE(i['st_mode']) == 0o444 and i['st_nlink'] == 1,
         'immutable installed controller contract')
    from libvirt_access import Held
    with Held(ref['path']) as current:
        need(current.check() == ref['identity'], 'protected installed contract ancestry')
        value = json.loads(held(ref, 1048576))
        need(current.check() == ref['identity'], 'installed contract full9 remains exact')
    need(value['kind'] == 'OPEMOS_INSTALLED_MEDIA_SOURCE_CONTRACT_V1'
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
