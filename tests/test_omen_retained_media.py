"""Typed producer/queue joins. Kernel mount and hardware are explicitly not modeled as passes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'scripts' / 'omen_control'
sys.path.insert(0, str(SOURCE))
import retained_media as media
import source_contract


def pin(path, mode, uid, gid, size, ino, sha='a' * 64):
    return {'path': path, 'bytes': size, 'sha256': sha,
            'identity': {'st_dev': 7, 'st_ino': ino, 'st_mode': mode,
                         'st_uid': uid, 'st_gid': gid, 'st_nlink': 1,
                         'st_size': size, 'st_mtime_ns': 1, 'st_ctime_ns': 1}}


def operand():
    work = pin('/run/owned-ro/working.raw', 0o100640, 64055, 993,
               media.RAW_BYTES, 12, media.RAW_SHA)
    backing = pin('/owned/backing.raw', 0o100600, 0, 0, 8400000000, 30)
    parent = {'path': '/run/owned-ro', 'identity': pin('/run/owned-ro', 0o40710, 0, 0, 4096, 2)['identity']}
    value = {'kind': media.PROOF, 'nonce': 'c' * 32, 'bootID': 'current-boot',
             'working': work, 'parent': parent, 'backing': backing,
             'mount': {'id': 123, 'parent': 22, 'device': '7:4', 'root': '/',
                       'target': '/run/owned-ro', 'options': ['ro', 'nodev', 'nosuid', 'noexec'],
                       'optional': [], 'type': 'ext4', 'source': '/dev/loop4',
                       'superOptions': ['ro', 'norecovery']},
             'loop': {'path': '/dev/loop4', 'backing': backing['path'], 'offset': 0,
                      'sizeLimit': 0, 'readOnly': True},
             'workingACL': media.MEDIA_ACL, 'parentACL': media.PARENT_ACL,
             'origin': {'kind': 'HISTORICAL_RAW_COPY_ORIGIN_DATA', 'bootID': 'old-boot',
                        'rawBytes': media.RAW_BYTES, 'rawSHA256': media.RAW_SHA,
                        'recordSHA256': 'b' * 64}, 'allOwnedFDsClosed': True}
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    ref = pin('/run/new/custody.json', 0o100400, 0, 0, len(raw), 40,
              hashlib.sha256(raw).hexdigest())
    c = {'nonce': 'c' * 32, 'hostBoot': 'current-boot', 'working': work,
         'installer': {'kind': media.KIND, 'bootCopy': work, 'backing': backing,
                       'currentCustody': value, 'currentCustodyPin': ref}}
    return c, value


class RetainedMediaContract(unittest.TestCase):
    def test_historical_origin_is_data_current_custody_is_current(self):
        c, v = operand()
        self.assertIs(media.validate_record(c, v), v)
        self.assertNotEqual(v['origin']['bootID'], v['bootID'])

    def test_wrong_current_scope_or_boot_refused(self):
        for key in ('nonce', 'bootID'):
            c, v = operand(); v[key] = 'wrong'
            with self.subTest(key=key), self.assertRaises(ValueError):
                media.validate_record(c, v)

    def test_raw_hash_owner_and_geometry_are_not_relabeled(self):
        for key, value in [('st_uid', 0), ('st_gid', 0), ('st_ino', 99), ('st_size', 1)]:
            c, v = operand(); v['working'] = copy.deepcopy(v['working'])
            v['working']['identity'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                media.validate_record(c, v)
        c, v = operand(); v['working'] = copy.deepcopy(v['working']); v['working']['sha256'] = '0' * 64
        with self.assertRaises(ValueError): media.validate_record(c, v)

    def test_writable_or_replaying_mount_and_loop_refused(self):
        for field in ('rw-mount', 'loop-rw', 'journal', 'alias'):
            c, v = operand()
            if field == 'rw-mount': v['mount']['options'].append('rw')
            if field == 'loop-rw': v['loop']['readOnly'] = False
            if field == 'journal': v['mount']['superOptions'] = ['ro']
            if field == 'alias': v['loop']['backing'] = '/foreign.raw'
            with self.subTest(field=field), self.assertRaises(ValueError): media.validate_record(c, v)

    def test_schema_acl_or_unknown_closure_refused(self):
        for field in ('extra', 'ACL', 'closure'):
            c, v = operand()
            if field == 'extra': v['approval'] = True
            if field == 'ACL': v['workingACL'] += 'other::rwx\n'
            if field == 'closure': v['allOwnedFDsClosed'] = False
            with self.subTest(field=field), self.assertRaises(ValueError): media.validate_record(c, v)

    def test_both_normal_queue_stage_roles_preserve_exact_baseline(self):
        c, v = operand()
        calls = []
        def fullpin(ref, mode, cap):
            calls.append((ref, mode, cap))
            self.assertEqual(ref, c['installer']['currentCustodyPin'])
        for role in ('working', 'working-parent'):
            ref = v['working'] if role == 'working' else v['parent']
            acl = v['workingACL'] if role == 'working' else v['parentACL']
            row = {'path': ref['path'], 'role': role, 'before': ref, 'priorACL': acl,
                   'targetACL': acl, 'uid': 64055,
                   'rights': 'r--' if role == 'working' else '--x',
                   'immutableMediaCustodyPin': c['installer']['currentCustodyPin']}
            after = {'path': ref['path'], 'identity': ref['identity'], 'ACL': acl}
            self.assertTrue(media.validate_stage_row(c, row, after, fullpin))
            changed = copy.deepcopy(after); changed['identity']['st_ctime_ns'] += 1
            with self.assertRaises(ValueError): media.validate_stage_row(c, row, changed, fullpin)
        self.assertEqual(len(calls), 4)

    def test_legacy_or_new_writable_roles_cannot_claim_immutable_exception(self):
        self.assertFalse(media.is_adopted({'installer': None}))
        self.assertFalse(media.is_adopted({}))
        c, v = operand()
        self.assertFalse(media.validate_stage_row(c, {'role': 'vars'}, {}, None))

    def test_normal_queue_calls_the_same_typed_consumer(self):
        # Import the actual queue module, not a duplicate validator or source assertion.
        spec = importlib.util.spec_from_file_location('retained_test_actual_queue', SOURCE / 'test_queue.py')
        queue = importlib.util.module_from_spec(spec); sys.modules[spec.name] = queue
        try:
            spec.loader.exec_module(queue)
            c, v = operand()
            self.assertEqual(queue.R109_PEER_SHA,
                             hashlib.sha256((SOURCE / 'libvirt_peer.py').read_bytes()).hexdigest())
            self.assertEqual(queue.R109_ACCESS_SHA,
                             hashlib.sha256((SOURCE / 'libvirt_access.py').read_bytes()).hexdigest())
            self.assertEqual(queue.R109_CURRENT_ADAPTER,
                             (SOURCE / 'standalone_peer_access_adapter.py').read_text())
        finally: sys.modules.pop(spec.name, None)


if __name__ == '__main__': unittest.main()
