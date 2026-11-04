"""Fresh normal preparation for retained installer media after a host reboot.

The normal Root caller owns readonly loop/mount creation and current source,
queue, worker and machine admission. This entry uses that mounted derivative,
creates fresh writable IO only, and calls the ordinary stage and placement
producers. It never continues an old grant, prepares GPU state or starts a VM.
"""
import copy
import json
import os
from pathlib import Path
import stat
import time


def prepare(expectation_pin, seed, origin_pin, persist):
    import libvirt_peer as p
    import libvirt_access as access
    import libvirt_preflight as pre
    from libvirt_native import held
    import fresh_placement_producer as placement
    import retained_media as media
    import source_contract

    p.need(os.getuid() == 0, 'Root current media preparation')
    i = expectation_pin['identity']
    p.need(i['st_uid'] == i['st_gid'] == 0 and stat.S_ISREG(i['st_mode'])
           and stat.S_IMODE(i['st_mode']) == 0o400 and i['st_nlink'] == 1,
           'actual protected Root expectation')
    e = json.loads(held(expectation_pin, 1048576))
    p.need(e['kind'] == 'ROOT_LIBVIRT_R4_PREFLIGHT_EXPECTATION' and e['RootAdopted'] is True
           and e['purpose'] == 'INSTALLER_ACCESS_STAGE' and e['preparedAccessPin'] is None,
           'new finite stage expectation; no old prepared continuation')
    started = time.time()
    p.need(e['issuedUnix'] <= started < e['startBeforeUnix'] <= e['issuedUnix'] + 300,
           'original finite preparation window')
    c = copy.deepcopy(e['candidate'])
    p.need(c['hostBoot'] == e['bootID'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
           'new current-boot generation')
    contract = source_contract.validate(e['sourceRoles'], e['queuePrograms'], e['installedSourceContractPin'])
    p.need(contract['originCopyReceiptPin'] == origin_pin, 'installed immutable origin identity')
    origin = media.origin_data(origin_pin, c['nonce'])
    p.need(media.is_adopted(c) and 'currentCustody' not in c['installer']
           and 'currentCustodyPin' not in c['installer'], 'new measured custody, not old receipt adoption')
    p.need(Path(c['run']).parent == Path(c['output']).parent
           and Path(c['run']).name == 'run' and Path(c['output']).name == 'output'
           and Path(c['run']).parent.parent == Path('/run')
           and Path(c['run']).parent.name.startswith('opemos-libvirt-io-' + c['nonce'] + '-'),
           'fresh confined writable IO outside readonly retained media')
    p.need(not os.path.lexists(c['run']) and not os.path.lexists(c['output']), 'fresh owned writable IO')
    c['installer'].update(media.capture_current(c, origin, persist))
    seed = copy.deepcopy(seed)
    p.need(seed['original'] == c['original'] and seed['working'] == c['working']
           and seed['boot'] == c['hostBoot'] and seed['nonce'] == c['nonce']
           and 'preparationBinding' not in seed, 'new placement seed/current measured media')
    seed['installer'] = c['installer']
    seed['ioScope'] = {'run': c['run'], 'output': c['output']}
    seed['mount'] = c['installer']['currentCustody']['parent']
    seed['loop'] = c['installer']['currentCustody']['loop']['path']
    seed_pin = persist('placement-seed', seed)
    e.update(candidate=c, placementSeedPin=seed_pin, installerContract=c['installer'])
    records = []
    def save(label, value):
        ref = persist(label, value); records.append((label, ref)); return ref
    first = pre.produce(c, e, save)
    prepin = [ref for name, ref in records if name == 'current-preflight']
    p.need(len(prepin) == 1 and first['preparedAccessPin'] is None, 'one actual ordinary stage preflight')
    grant = {'kind': 'ROOT_LIBVIRT_PREGRANT_ACCESS_STAGE_R7', 'RootIssued': True,
             'runtimeAuthorized': False, 'stageOnly': True,
             'issuedUnix': e['issuedUnix'], 'startBeforeUnix': e['startBeforeUnix'],
             'bootID': e['bootID'], 'nonce': c['nonce'], 'candidate': c,
             'currentPreflightPin': prepin[0]}
    gp = persist('current-access-stage-grant', grant)
    stage = access.stage_io(c, gp, save)
    pending = [ref for name, ref in records if name == 'access-stage-pending']
    p.need(len(pending) == 1 and stage['candidate'] == c, 'actual ordinary stage output')
    # Media and its parent are readonly: full9 and hashes have not changed.
    # Writable vars/serial and their four ACL journals are newly created scopes.
    e.update(purpose='INSTALLER_BOOT_READY', preparedAccessPin=pending[0],
             preparedDiskPins={'original': c['original'], 'working': c['working']})
    e['unusedPaths'] = [x for x in e['unusedPaths'] if x not in (c['run'], c['output'])]
    access.verify_prepared(c, pending[0], e['preparedDiskPins'])
    p.need(time.time() < e['startBeforeUnix'], 'no refreshed preparation clock')
    final = persist('current-final-expectation', e)
    result = placement.produce(final, seed_pin, save)
    return {'candidate': c, 'seedPin': seed_pin, 'expectationPin': final,
            'preparedAccessPin': pending[0], 'preparedDiskPins': e['preparedDiskPins'],
            'qualification': result, 'runtimeAuthorized': False}
