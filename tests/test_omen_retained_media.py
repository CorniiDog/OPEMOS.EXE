"""Typed producer/queue joins. Kernel mount and hardware are explicitly not modeled as passes."""
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import subprocess
import uuid
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'scripts' / 'omen_control'
sys.path.insert(0, str(SOURCE))
import retained_media as media
import source_contract
import media_window
import idle_signal_owner
import media_probe
import normal_probe
import types


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
    @unittest.skipUnless(os.geteuid() == 0 and sys.platform == 'linux', 'admitted Linux Root only')
    def test_whole_history_normal_record_to_real_issuer_beyond_metadata_leaf(self):
        import libvirt_producer as producer
        import libvirt_peer as peer
        import postqueue_issuer as issuer
        import run_current_media as entry
        root = Path('/run/opemos-history-chunks-' + uuid.uuid4().hex)
        producer.create_root(str(root))
        try:
            run = object.__new__(entry.Run)
            run.root = root; run.placement_root = root; run.sequence = 0
            value = {'rows': [{'result': os.urandom(1500000).hex()}], 'bindings': [], 'config': []}
            raw = peer.canon(value)
            expected = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                        'counts': {k: len(v) for k, v in value.items()}}
            ref = producer.record_prior_history(value, run.record)
            parent = {'priorHistoryCodecPin': ref, 'priorHistory': expected}
            self.assertEqual(issuer.adopted_history(parent), value)
            codec = issuer.protected(ref)['value']
            self.assertGreater(codec['bytes'], 1048576)
            self.assertGreater(len(codec['chunks']), 1)
            self.assertTrue(all(x['bytes'] <= 1048576 for x in codec['chunks']))
            bad = copy.deepcopy(codec); bad['chunks'].reverse()
            badref = run.record('wrong-order', {'value': bad})
            with self.assertRaisesRegex(RuntimeError, 'ordered complete history spans'):
                issuer.adopted_history(dict(parent, priorHistoryCodecPin=badref))
            bad = copy.deepcopy(codec); bad['chunks'].pop()
            badref = run.record('missing-part', {'value': bad})
            with self.assertRaisesRegex(RuntimeError, 'complete finite compressed history'):
                issuer.adopted_history(dict(parent, priorHistoryCodecPin=badref))
            wrong = dict(expected, sha256='0' * 64)
            with self.assertRaisesRegex(RuntimeError, 'exact full adopted prior history bytes'):
                issuer.adopted_history(dict(parent, priorHistory=wrong))
            leaf = Path(codec['chunks'][0]['path']); leaf.chmod(0o600)
            leaf.write_bytes(b'{}'); leaf.chmod(0o400)
            with self.assertRaisesRegex(RuntimeError, 'protected ancestry/initial full9|held full9/name/EOF/SHA'): issuer.adopted_history(parent)
        finally:
            shutil.rmtree(root)

    def test_attempt_bound_placement_preserves_failed_namespace(self):
        c = {'nonce': 'a' * 32, 'jobId': 'fixture-e' + 'b' * 16, 'run': '/run/opemos-libvirt-io-' + 'a' * 32 + '-' + 'b' * 32 + '/run',
             'output': '/run/opemos-libvirt-io-' + 'a' * 32 + '-' + 'b' * 32 + '/output'}
        self.assertEqual(str(media.placement_root(c)), '/run/opemos-steamos-placement-' + 'a' * 32 + '-' + 'b' * 32)
        for bad in ('/run/foreign/run', c['run'] + '/../run'):
            with self.assertRaises(ValueError): media.placement_root(dict(c, run=bad))

    @unittest.skipUnless(os.geteuid() == 0 and sys.platform == 'linux', 'admitted Linux Root only')
    def test_real_readonly_loop_mount_metadata_and_normal_cleanup(self):
        """Real loop/mount/helper path. No native operation or validator is replaced."""
        import time
        import libvirt_native as native
        import install_media_controller as installer
        caps = int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines()
                        if x.startswith('CapEff:')), 16)
        if not caps & (1 << 21):
            self.skipTest('kernel CAP_SYS_ADMIN unavailable; real mount coverage NOT established')
        tools = {name: shutil.which(name) for name in ('losetup', 'mkfs.ext4', 'mount', 'umount')}
        if not all(tools.values()): self.skipTest('real loop/ext4 tools unavailable')
        with tempfile.TemporaryDirectory(prefix='opemos-loop-ci-') as directory:
            root = Path(directory); backing = root / 'filesystem.raw'; mount = root / 'mount'
            with backing.open('wb') as out: out.truncate(16777216)
            mount.mkdir()
            subprocess.run([tools['mkfs.ext4'], '-q', '-F', str(backing)], check=True)
            device = subprocess.check_output([tools['losetup'], '--find', '--show', '--read-only',
                                               '--nooverlap', str(backing)], text=True).strip()
            fd = os.open(device, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            role = {'fd': fd, 'path': device, 'backing': str(backing)}
            try:
                media.loop_guard(role)
                before = os.fstat(fd)
                # Exercise actual device metadata plus the real helper/mount consumer.
                os.utime(device, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
                command = [tools['mount'], '-t', 'ext4', '-o', 'ro,noload,nodev,nosuid,noexec', device, str(mount)]
                result = native.native_child(command, time.time() + 10, installer.pin(command[0]), loop=role)
                self.assertEqual((result['numeric'], result['closure']), (0, 'KNOWN'))
                self.assertTrue(media.owned_mount(mount, device))
                result = native.native_child([tools['umount'], str(mount)], time.time() + 10,
                                             installer.pin(tools['umount']), loop=role)
                self.assertEqual(result['numeric'], 0)
                # A real parent-FD leak after a successful mount is still a refusal.
                # Cleanup must discover that mount from the kernel, not a success flag.
                import threading
                leaked = []; stop = threading.Event()
                def hold_after_mount():
                    while not stop.wait(.005):
                        if media.owned_mount(mount, device):
                            leaked.extend(os.pipe()); return
                watcher = threading.Thread(target=hold_after_mount); watcher.start()
                executable = str(Path(sys.executable).resolve())
                child = [executable, '-B', '-c',
                         'import subprocess,time,sys;subprocess.run(sys.argv[1:],check=True);time.sleep(.3)', *command]
                try:
                    with self.assertRaises(Exception) as raised:
                        native.native_child(child, time.time() + 10, installer.pin(executable), loop=role)
                    evidence = raised.exception.nativeChildEvidence
                    self.assertEqual(evidence['numeric'], 0)
                    self.assertEqual(evidence['closure'], 'UNKNOWN')
                    self.assertTrue(any(x.get('changes', {}).get('added') for x in evidence['secondary']))
                    self.assertTrue(media.owned_mount(mount, device))
                finally:
                    stop.set(); watcher.join()
                    for held_fd in leaked: os.close(held_fd)
                # An unrelated/incorrect backing role is refused by the actual kernel reader.
                with self.assertRaises(ValueError): media.loop_guard(dict(role, backing=str(root / 'foreign')))
                bad = dict(role, fd=os.open(str(backing), os.O_RDONLY))
                try:
                    with self.assertRaises(ValueError): media.loop_guard(bad)
                finally: os.close(bad['fd'])
            finally:
                # Kernel state, not the caller's post-command flag, determines unmount necessity.
                if media.owned_mount(mount, device):
                    result = native.native_child([tools['umount'], str(mount)], time.time() + 10,
                                                 installer.pin(tools['umount']), loop=role)
                    self.assertEqual(result['numeric'], 0)
                os.close(fd)
                subprocess.run([tools['losetup'], '--detach', device], check=True)
            self.assertFalse(media.owned_mount(mount, device))

    @unittest.skipUnless(os.geteuid() == 0 and sys.platform == 'linux', 'admitted Linux Root only')
    def test_normal_io_namespace_to_real_uid_stage_and_consumer(self):
        import run_current_media as entry
        import libvirt_access as access
        import libvirt_producer as producer
        import libvirt_peer as peer
        import stat
        before = set(os.listdir('/proc/self/fd'))
        # TWO arbitrary future deployments/attempts, through the same production
        # namespace producer, six ACL producer, actual UID child and stage reader.
        for _ in range(2):
            deployment, attempt = uuid.uuid4().hex, uuid.uuid4().hex
            paths = source_contract.operation_paths(deployment, attempt)
            root, mount, io_root = map(Path,(paths['operationRoot'],paths['mountRoot'],paths['ioRoot']))
            c = {'operationContext':{'deploymentId':deployment,'attempt':attempt,'paths':paths},
                 'nonce':attempt,'jobId':'fixture-e'+attempt[:16],
                 'run':str(io_root/'run'),'output':str(io_root/'output')}
            made = []
            try:
                for path in (root,mount):producer.create_root(str(path));made.append(path)
                original = root/'original.raw'; original.write_bytes(b'original'); original.chmod(0o400)
                working = mount/'working.raw'; working.write_bytes(b'derivative'); working.chmod(0o600)
                c.update(original=entry.pin(original),working=entry.pin(working))
                ancestor = entry.create_io_namespace(c);made.append(io_root)
                self.assertEqual(stat.S_IMODE(ancestor['identity']['st_mode']),0o711)
                with self.assertRaises(FileExistsError):entry.create_io_namespace(c)
                for path in (Path(c['run']),Path(c['output'])):path.mkdir(mode=0o700)
                for path,data in ((Path(c['run'])/'OVMF_VARS_4M.fd',b'vars'),(Path(c['output'])/'serial.raw',b'')):
                    path.write_bytes(data);path.chmod(0o600)
                run=object.__new__(entry.Run);run.root=root;run.placement_root=root;run.sequence=0
                leaves=[(mount,'working-parent'),(working,'working'),(Path(c['run']),'runtime-parent'),
                        (Path(c['run'])/'OVMF_VARS_4M.fd','vars'),(Path(c['output']),'output-parent'),(Path(c['output'])/'serial.raw','serial')]
                rows=[];after=[]
                for path,role in leaves:
                    ref=access.metadata_pin(path)if role.endswith('parent')else entry.pin(path)
                    row=access.plan(str(path),ref,role,readonly_media=role=='working')
                    rows.append(row);after.append(access.apply(row,run.record))
                result=access.probe(rows,str(original),run.record)
                self.assertTrue(all(x['allowed']for x in result['rows']))
                self.assertFalse(result['originalAllowed'])
                pending={'kind':'LIBVIRT_R7_ACCESS_STAGE_PENDING_FULL_HASH','nonce':attempt,
                         'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                         'candidate':c,'runtimeAuthorized':False,'rows':rows,'after':after,
                         'ioAncestor':access.io_ancestor(c)}
                ref=run.record('access-stage-pending',pending)
                disks={'original':c['original'],'working':entry.pin(working)}
                access.verify_prepared(c,ref,disks)
                import test_queue as queue_consumer
                queue_consumer.validate_current_io_ancestor(c,pending['ioAncestor'])
                bad=copy.deepcopy(pending['ioAncestor']);bad['identity']['st_uid']=1000
                with self.assertRaisesRegex(ValueError,'Root traverse-only'):
                    queue_consumer.validate_current_io_ancestor(c,bad)
                io_root.chmod(0o700)
                with self.assertRaisesRegex(ValueError,'same current IO ancestor'):
                    queue_consumer.validate_current_io_ancestor(c,pending['ioAncestor'])
                with self.assertRaisesRegex(RuntimeError,'traverse-only IO ancestor'):
                    access.verify_prepared(c,ref,disks)
                with self.assertRaisesRegex(RuntimeError,'effective UID working IO access')as caught:
                    access.probe(rows,str(original),run.record)
                self.assertEqual(caught.exception.evidence['kind'],'EFFECTIVE_UID_ACCESS_REFUSAL')
                failed=caught.exception.evidence['value']
                self.assertFalse(failed['originalAllowed'])
                self.assertTrue(any(not x['allowed']for x in failed['rows']if x['role']=='vars'))
                io_root.chmod(0o711)
                escaped=copy.deepcopy(c);escaped['run']='/tmp/foreign/run'
                with self.assertRaisesRegex(ValueError,'confined operation paths'):
                    access.io_ancestor(escaped)
            finally:
                for path in reversed(made):shutil.rmtree(path)
        self.assertEqual(before,set(os.listdir('/proc/self/fd')))

    @unittest.skipUnless(os.geteuid() == 0 and sys.platform == 'linux', 'admitted Linux Root only')
    def test_external_allocation_padding_consumes_existing_metadata_reserve(self):
        import libvirt_storage as storage
        import install_media_controller as installer
        root = Path('/run/opemos-allocation-' + uuid.uuid4().hex); root.mkdir(mode=0o700)
        before = set(os.listdir('/proc/self/fd'))
        try:
            path = root/'backing.raw'; path.write_bytes(os.urandom(65537)); path.chmod(0o600)
            ref = installer.pin(path); allocated = path.stat().st_blocks * 512
            self.assertGreater(allocated, ref['bytes'])
            roles = [{'role':'container','pin':ref,'upperBytes':ref['bytes']},
                     {'role':'metadata','pin':None,'upperBytes':500000000}]
            padding, rows = storage.allocation_padding(roles)
            self.assertEqual(padding, allocated-ref['bytes'])
            self.assertEqual(rows[0]['allocatedBytes'], allocated)
            self.assertEqual(storage.reserve_usage(500000000-padding,padding,500000000),500000000)
            with self.assertRaisesRegex(RuntimeError, 'within existing reserve'):
                storage.reserve_usage(500000001-padding,padding,500000000)
            with self.assertRaisesRegex(RuntimeError, 'distinct charged external inodes'):
                storage.allocation_padding([roles[0], roles[0]])
            os.chown(path, 1000, 1000)
            with self.assertRaisesRegex(RuntimeError, 'exact charged external file'):
                storage.allocation_padding(roles)
            os.chown(path, 0, 0); ref = installer.pin(path)
            path.rename(root/'saved'); path.symlink_to('saved')
            with self.assertRaises(OSError):
                storage.allocation_padding([dict(roles[0],pin=ref)])
            path.unlink(); (root/'saved').rename(path)
            self.assertEqual(before,set(os.listdir('/proc/self/fd')))
        finally: shutil.rmtree(root)

    @unittest.skipUnless(os.geteuid() == 0 and sys.platform == 'linux', 'admitted Linux Root only')
    def test_media_ancestor_churn_keeps_endpoint_and_mount_custody(self):
        """Real files/mount IDs; no media hash, device or VM acceptance modeled as pass."""
        import install_media_controller as installer
        root = Path('/run/opemos-media-path-' + uuid.uuid4().hex)
        peer = Path('/run/opemos-media-peer-' + uuid.uuid4().hex)
        root.mkdir(mode=0o700); parent = root/'parent'; parent.mkdir(mode=0o710)
        leaf = parent/'working.raw'; leaf.write_bytes(b'owned readonly-media fixture')
        leaf.chmod(0o640); os.chown(leaf, 64055, 993)
        initial = set(os.listdir('/proc/self/fd'))
        try:
            ref = installer.pin(leaf)
            for path, declared in ((leaf, ref), (parent, None)):
                with media.held_path(path, declared):
                    peer.mkdir(mode=0o700); peer.rmdir()
                    sibling = root/'unrelated'; sibling.mkdir(); sibling.rmdir()
            with self.assertRaisesRegex(ValueError, 'media endpoint full9') as changed:
                with media.held_path(leaf, ref): leaf.write_bytes(b'changed media fixture')
            self.assertEqual(changed.exception.evidence['path'], str(leaf))
            self.assertTrue(changed.exception.evidence['checks'])
            with self.assertRaisesRegex(ValueError, 'media endpoint full9'):
                with media.held_path(parent): (parent/'unexpected').write_bytes(b'x')
            (parent/'unexpected').unlink()
            ref = installer.pin(leaf)
            with self.assertRaises(OSError):
                with media.held_path(leaf, ref):
                    leaf.rename(parent/'saved'); leaf.symlink_to('saved')
            leaf.unlink(); (parent/'saved').rename(leaf)
            ref = installer.pin(leaf)
            os.link(leaf, parent/'alias')
            with self.assertRaisesRegex(ValueError, 'exact adopted leaf'):
                with media.held_path(leaf, ref): pass
            (parent/'alias').unlink()
            os.chown(parent, 1000, 1000)
            with self.assertRaisesRegex(ValueError, 'Root media ancestry'):
                with media.held_path(leaf, installer.pin(leaf)): pass
            os.chown(parent, 0, 0)
            with self.assertRaisesRegex(ValueError, 'absolute media path'):
                with media.held_path(parent/'..'/'parent'): pass
            caps = int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines()
                            if x.startswith('CapEff:')), 16)
            if caps & (1 << 21) and shutil.which('mount') and shutil.which('umount'):
                mounted = False
                try:
                    with self.assertRaisesRegex(ValueError, 'same held/named media mount'):
                        with media.held_path(parent):
                            subprocess.run(['mount','--bind',str(parent),str(parent)],check=True,timeout=10)
                            mounted = True
                finally:
                    if mounted: subprocess.run(['umount',str(parent)],check=True,timeout=10)
            self.assertEqual(initial, set(os.listdir('/proc/self/fd')))
        finally:
            if peer.exists(): peer.rmdir()
            shutil.rmtree(root)

    def test_normal_worker_transport_outlives_short_helper_without_resetting_deadline(self):
        """Real owned child transport; child models the normal worker boundary only."""
        import libvirt_native as native
        import install_media_controller as installer
        import time
        executable=str(Path(sys.executable).resolve());ref=installer.pin(executable)
        command=[executable,'-B','-c','import time;time.sleep(11);print("worker-complete")']
        result=native.native_queue_worker(command,time.time()+15,ref)
        self.assertEqual(result['numeric'],0)
        self.assertTrue(result['EOF']and result['reaped']and result['pipesClosed'])
        self.assertEqual(result['groupRemaining'],[])
        self.assertEqual(result['closure'],'KNOWN')
        with self.assertRaises(subprocess.TimeoutExpired)as short:
            native.native_child(command,time.time()+15,ref)
        self.assertTrue(short.exception.nativeChildEvidence['reaped'])
        self.assertTrue(short.exception.nativeChildEvidence['EOF'])
        with self.assertRaises(Exception)as expired:
            native.native_queue_worker(command,time.time()-1,ref)
        self.assertIn('deadline',str(expired.exception))
        bad=copy.deepcopy(ref);bad['sha256']='0'*64
        with self.assertRaises(Exception):native.native_queue_worker(command,time.time()+15,bad)

    @unittest.skipUnless(os.geteuid()==0 and sys.platform=='linux','disposable Linux CI Root only')
    def test_real_geometry_not_optional_sink_is_authority(self):
        """Sparse geometry fixture only, not F9AA content/native-media acceptance."""
        import libvirt_peer as peer
        import libvirt_storage as storage
        with tempfile.TemporaryDirectory(dir='/run',prefix='opemos-geometry-')as directory:
            path=Path(directory)/'working.raw';path.touch(mode=0o600)
            with path.open('r+b')as file:file.truncate(media.RAW_BYTES)
            expected=pin(str(path),0o100600,0,0,media.RAW_BYTES,1,media.RAW_SHA)
            expected['identity']=peer.ident(path.stat())
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            def failed_sink(label,value):raise OSError('optional diagnostic is unwritable')
            try:
                actual=peer.working_metadata(fd,parent,str(path),expected,{},'fixture-geometry')
                value,errors=storage.working_geometry(actual,expected,True,False,failed_sink)
                self.assertEqual(value,expected['identity']);self.assertEqual(len(errors),1)
                with path.open('r+b')as file:file.truncate(4096)
                actual=peer.working_metadata(fd,parent,str(path),expected,{},'fixture-wrong-geometry')
                with self.assertRaises(peer.Refused)as caught:
                    storage.working_geometry(actual,expected,True,False,failed_sink)
                self.assertIn('inode/geometry',str(caught.exception))
                self.assertEqual(len(caught.exception.optionalDiagnosticErrors),1)
            finally:os.close(fd);os.close(parent)

    @unittest.skipUnless(os.geteuid()==0 and sys.platform=='linux','disposable Linux CI Root only')
    def test_actual_bash_ancestor_ofd_fence_without_forwarding_fd(self):
        """Real kernel ancestry/OFD; fixture UID0/path are not normal UID1000 admission."""
        import install_media_controller as installer
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);wrapper=root/'heavy.sh';lock=root/'heavy.lock'
            wrapper.write_text('#!/bin/bash\nset -euo pipefail\nexec 9>"$1"\nflock -n 9\nshift\n"$@"\n')
            wrapper.chmod(0o555);ref=installer.pin(wrapper)
            code=('import sys,json,os;sys.path.insert(0,sys.argv[1]);'
                  'from run_current_media import heavy_custody;'
                  'p=json.loads(sys.argv[2]);v=heavy_custody(p,sys.argv[3],0);'
                  'print(json.dumps(v));'
                  'p["sha256"]="0"*64;'
                  '\ntry:heavy_custody(p,sys.argv[3],0)'
                  '\nexcept Exception:pass'
                  '\nelse:raise AssertionError("wrong source hash passed")')
            command=['/usr/bin/bash',str(wrapper),str(lock),sys.executable,'-B','-c',code,
                     str(SOURCE),json.dumps(ref),str(lock)]
            result=subprocess.run(command,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            value=json.loads(result.stdout)
            self.assertEqual(value['owner']['exe'],'/usr/bin/bash')
            self.assertEqual(value['owner']['argv'][1],str(wrapper))
            self.assertEqual(value['sourcePin'],ref)
            self.assertEqual(value['OFD']['fd'],9)

    def test_real_runner_assignment_survives_missing_optional_telemetry(self):
        """Production routing reader with explicit API data, not a method override."""
        busy = False
        assigned = 0
        def api(endpoint):
            if '/actions/runners?' in endpoint:
                return {'runners':[{'id':21,'name':'opemos-omen-robot',
                                    'labels':[{'name':'opemos-omen-robot'}],
                                    'busy':busy,'status':'online'}]}
            if '/actions/runs?status=in_progress' in endpoint:
                return {'total_count':1,'workflow_runs':[{'id':7,'status':'in_progress',
                         'path':'.github/workflows/omen-robot.yml'}]}
            if '/actions/runs/7/jobs?' in endpoint:
                return {'total_count':assigned,'jobs':[
                    {'id':9,'run_id':7,'status':'in_progress','labels':['opemos-omen-robot'],
                     'runner_id':21}] if assigned else []}
            raise RuntimeError('optional endpoint unavailable')
        client=types.SimpleNamespace(gh_json=api,runner21_assigned_jobs=normal_probe.runner21_assigned_jobs)
        policy={'mainCommit':'a'*40,'queueSourceSHA256':'b'*64}
        value=media_probe.github(policy,client)
        self.assertIsNone(value['protectedMain'])
        self.assertIsNone(value['actionsQueued'])
        self.assertFalse(value['heartbeatCurrent'])
        self.assertEqual(value['actionsInProgress'],0)
        self.assertFalse(value['runnerBusy'])
        assigned=1; busy=True
        value=media_probe.github(policy,client)
        self.assertEqual(value['actionsInProgress'],1)
        self.assertTrue(value['runnerBusy'])

    @unittest.skipUnless(os.geteuid() == 0 and sys.platform == 'linux', 'disposable Linux CI Root only')
    def test_installed_normal_entry_without_connect_syscall(self):
        for _ in range(2):
            with self.subTest(deployment='arbitrary future identity'):
                self._installed_normal_entry_without_connect_syscall(uuid.uuid4().hex, uuid.uuid4().hex)

    def _installed_normal_entry_without_connect_syscall(self, deployment_id, attempt):
        """Actual installer/isolated entry; external queue helpers and media are MODELED, never executed."""
        import install_media_controller as installer
        import run_current_media as normal_entry
        import ctypes
        layout = source_contract.deployment_paths(deployment_id)
        paths = source_contract.operation_paths(deployment_id, attempt)
        source_root = Path(layout['sourceRoot'])
        if os.path.lexists(source_root): self.skipTest('existing source owner preserved')
        token = attempt
        guest_nonce = uuid.uuid4().hex
        queue_root = Path(layout['queueRoot'])
        drain_root = Path(layout['drainRoot'])
        public_parent=Path(paths['parentPath'])
        if os.path.lexists(public_parent): self.skipTest('existing public owner preserved')
        parent_identity=None
        fixture=Path(paths['ioRoot'])
        placement=Path(paths['placementRoot'])
        runtime=Path(paths['runtimeRoot'])
        for path in (fixture,placement,runtime):
            if os.path.lexists(path):self.skipTest('existing connected fixture owner preserved')
        created=[]
        def member(raw):
            return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                    'base64':__import__('base64').b64encode(raw).decode()}
        names = installer.RUNTIME | installer.PREPARE | {'standalone_peer_access_adapter'}
        sources = {n:member((SOURCE/(n+'.py')).read_bytes()) for n in names}
        queue_sources = {n:member((SOURCE/n).read_bytes() if (SOURCE/n).exists()
                                  else b'# MODELED existing external queue helper; not executed by this test\n')
                         for n in installer.QUEUE_NAMES}
        model = member(b'# MODELED existing normal helper; not executed by this test\n')
        drains = {'media_drain':member((SOURCE/'media_drain.py').read_bytes()),
                  'idle_signal_owner':member((SOURCE/'idle_signal_owner.py').read_bytes()),
                  'media_probe_remote':member((SOURCE/'media_probe_remote.py').read_bytes()),
                  'normal_probe':model,'normal_cycle':model}
        payload = {'kind':'ROOT_REVIEWED_CURRENT_MEDIA_INSTALL_V1','repository':'CorniiDog/OPEMOS.EXE',
                   'protectedMain':'a'*40,'reviewedHead':'b'*40,'deploymentId':deployment_id,  # modeled identity DATA, no review fabricated
                   'sources':sources,'queueSources':queue_sources,'queueRoot':str(queue_root),
                   'originCopyData':member(b'{}'), 'drainRoot':str(drain_root),'drainSources':drains,
                   'normalControlPolicy':{'normalProbeSHA256':model['sha256'],'normalCycleSHA256':model['sha256']},
                   'parentTemplate':{'noNIC':True,'noInstall':True,'maxBoots':1},
                   'operationProfile':{'kind':'OPEMOS_INSTALLED_CURRENT_MEDIA_OPERATION_V1','candidateTemplate':{'nonce':guest_nonce}}}
        def deny_connect():
            class Filter(ctypes.Structure):
                _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
            class Program(ctypes.Structure):
                _fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
            filters=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,42),
                               Filter(0x06,0,0,0x00050001),Filter(0x06,0,0,0x7fff0000))
            libc=ctypes.CDLL(None,use_errno=True);program=Program(4,filters)
            if libc.prctl(38,1,0,0,0)!=0 or libc.prctl(22,2,ctypes.byref(program),0,0)!=0:os._exit(125)
        try:
            installed = installer.install(payload)
            self.assertEqual(installed['hardwareEffects'], [])
            ref = installed['operationProfilePin']
            result = subprocess.run(['/usr/bin/python3','-I','-B',str(source_root/'run_current_media.py'),
                                     '--profile-pin-json',json.dumps(ref),'--observe-boot'],
                                    capture_output=True,timeout=15,preexec_fn=deny_connect)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            value=json.loads(result.stdout)
            self.assertEqual(value['kind'],'CURRENT_MEDIA_NATIVE_BOOT_OBSERVATION')
            self.assertEqual(value['bootID'],Path('/proc/sys/kernel/random/boot_id').read_text().strip())
            self.assertEqual(value['effects'],[])
            # Real protected-input adapter reader consumes actual installed
            # sources, including exact byte counts. Native facts are not used
            # by verify_inputs, and are not claimed by this test.
            import standalone_peer_access_adapter as adapter
            roles={n:installed['sourceRoles'][n]for n in installer.RUNTIME}
            nonce=attempt;boot=value['bootID']
            observer={k:roles['libvirt_peer'][k]for k in ('path','bytes','sha256')}
            domain={'leaseNonce':nonce,'name':'opemos-libvirt-'+nonce,
                    'uuid':'64f43b0c-9a98-494d-adc1-0782aea1d32e','observer':observer}
            spec={'id':'fixture-fresh-job-e'+token[:16],'platform':'steamos','owner':'root','cwd':'/run',
                  'files':[{k:roles[n][k]for k in ('path','bytes','sha256')}for n in sorted(roles)],
                  'cores':4,'memory':10737418240,'timeout_seconds':900,'depends_on':[],'requires_success':True,
                  'resources':['omen-iommu-group-1'],'libvirt_domain':domain,
                  'approval':'EXACT_PARENT_MINIMAL_PIN',
                  'command':['sudo','-n','/usr/bin/python3','-B',roles['runtime_entry']['path'],
                             '--parent-pin-json','EXACT_PARENT_FULL_PIN_JSON']}
            # Byte-sized media is an explicit content/storage MODEL. This case
            # cannot satisfy the real fixed-F9AA preflight or issue a VM grant.
            # Source files, ACLs, protected metadata, /run FDs, readonly system
            # libvirt connection, adapter process and final queue consumer are real.
            import libvirt_producer as producer
            import libvirt_access as acl
            import libvirt_peer as peer
            import time
            for path in (placement,runtime):producer.create_root(str(path));created.append(path)
            normal_entry.create_io_namespace({'nonce':nonce,'jobId':spec['id'],
                'operationContext':{'deploymentId':deployment_id,'attempt':attempt,'paths':paths},
                'run':str(fixture/'run'),'output':str(fixture/'output')})
            created.append(fixture)
            for name in ('media','run','output'):(fixture/name).mkdir(mode=0o700)
            original=installer.put(fixture/'original.raw',b'fixture original',0o400)
            working=installer.put(fixture/'media/working.raw',b'fixture media',0o600)
            installer.put(fixture/'run/OVMF_VARS_4M.fd',b'fixture vars',0o600)
            installer.put(fixture/'output/serial.raw',b'',0o600)
            c={'nonce':nonce,'hostBoot':boot,'jobId':spec['id'],'guestUUID':domain['uuid'],'name':domain['name'],
               'original':original,'working':working,'run':str(fixture/'run'),'output':str(fixture/'output'),
               'installer':{'kind':'AUTHENTICATED_F9AA_RAW_RECOVERY_USB_FIRSTBOOT','noInstallTarget':True},
               'operationContext':{'deploymentId':deployment_id,'attempt':attempt,'paths':paths},'lineageNonce':guest_nonce}
            profile=normal_entry.protected(installed['operationProfilePin'],0o444)
            loaded=normal_entry.load_current_queue(c,profile)
            self.assertEqual(loaded.__file__,installed['queuePrograms'][0]['path'])
            for key in ('queue','source'):
                wrong=copy.deepcopy(profile)
                if key=='queue':wrong['queuePrograms'][0]['sha256']='0'*64
                else:wrong['sourceRoles']['libvirt_access']['sha256']='0'*64
                with self.assertRaises(RuntimeError):normal_entry.load_current_queue(c,wrong)
            def save(label,value):return installer.put(fixture/(label+'.json'),installer.canon(value),0o400)
            rows=[];after=[]
            leaves=[(fixture/'media','working-parent'),(fixture/'media/working.raw','working'),
                    (fixture/'run','runtime-parent'),(fixture/'run/OVMF_VARS_4M.fd','vars'),
                    (fixture/'output','output-parent'),(fixture/'output/serial.raw','serial')]
            for path,role in leaves:
                ref=working if role=='working'else acl.metadata_pin(str(path))
                if not role.endswith('parent')and role!='working':ref=installer.pin(path)
                row=acl.plan(str(path),ref,role,verified_content=working if role=='working'else None,
                             readonly_media=role=='working')
                rows.append(row);after.append(acl.apply(row,save,defer_working_hash=True))
            acl.probe(rows,original['path'],save)
            disks={'original':original,'working':installer.pin(fixture/'media/working.raw')}
            stage={'kind':'LIBVIRT_R7_ACCESS_STAGE_PENDING_FULL_HASH','nonce':nonce,'bootID':boot,'candidate':c,
                   'grantPin':save('fixture-stage-data',{'fixtureOnly':True}),'rows':rows,'after':after,
                   'original':original,'workingBefore':working,'pendingFullContentProof':True,'runtimeAuthorized':False,
                   'ioAncestor':acl.io_ancestor(c)}
            stagepin=save('access-stage',stage)
            captures={n:save('capture-'+n,{'explicitNativeMediaModel':True})for n in('original','working')}
            binding={'sourceRoles':roles,'queuePrograms':installed['queuePrograms'],
                     'sourceGraphSHA256':hashlib.sha256(installer.canon(roles)).hexdigest(),
                     'preparedAccessPin':stagepin,'preparedDiskPins':disks,'splitDiskCapturePins':captures}
            storage={'kind':'ROOT_EXACT_STEAMOS_INSTALLER_GAMES_PLACEMENT','nonce':nonce,'boot':boot,
                     'original':original,'working':working,'installer':c['installer'],'preparationBinding':binding}
            storagepin=installer.put(placement/'storage-contract.json',installer.canon(storage),0o400)
            now=time.time()
            pre={'bootID':boot,'kind':'ACTUAL_LIBVIRT_R4_CURRENT_PREFLIGHT','observedUnix':now,
                 'original':original,'working':disks['working'],'preparedAccessPin':stagepin,
                 'splitDiskCapturePins':captures,'queuePrograms':installed['queuePrograms'],
                 'storagePlacement':{'receiptPin':storagepin},'explicitNativeMediaModel':True}
            prepin=save('preflight-data',pre)
            qualification={'kind':'ROOT_VERIFIED_FRESH_STEAMOS_PLACEMENT','qualifiedPlacementPin':storagepin,
                           'nonce':nonce,'bootID':boot,'sourceRoles':roles,'queuePrograms':installed['queuePrograms'],
                           'runtimeAuthorized':False,'RootIssuedRuntimeAuthority':False,
                           'currentPreflightPin':prepin,'currentPreflight':pre}
            qualifiedpin=installer.put(placement/'placement-qualified.json',installer.canon(qualification),0o400)
            parent={'kind':'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT','RootIssued':True,
                    'runtimeAuthorized':True,'MODEL_ONLY':False,'bootID':boot,'nonce':nonce,
                    'contextPath':paths['runtimeRoot']+'/context.json',
                    'candidate':c,'issuedUnix':now,'startBeforeUnix':now+299,'wholeDeadlineUnix':now+900,
                    'sourceRoles':roles,'jobId':spec['id'],'normalizedSpecTemplate':spec,
                    'installedSourceContractPin':installed['sourceContractPin'],'queuePrograms':installed['queuePrograms'],
                    'preparedAccessPin':stagepin,'preparedDiskPins':disks,'splitDiskCapturePins':captures,
                    'sourcePlacementPin':storagepin,'placementQualificationPin':qualifiedpin,'prequeuePreflightPin':prepin,
                    'TEST_SCOPE':'Structural/source/ACL/readonly observer only; no real media qualification or grant'}
            parent_ref=installer.put(public_parent,installer.canon(parent),0o444)
            parent_identity=parent_ref['identity']
            actual_spec=adapter.parent_spec(parent,parent_ref)
            request={'leaseNonce':nonce,'domainName':domain['name'],'domainUUID':domain['uuid'],
                     'observer':observer,'jobId':spec['id'],
                     'specSHA256':hashlib.sha256(installer.canon(actual_spec)).hexdigest(),
                     'currentControl':{'definitionPin':installed['sourceContractPin'],'parentPin':parent_ref}}
            jobtoken=uuid.uuid4().hex
            request.update(jobToken=jobtoken,unit='opemos-testq-abcdefabcdef-'+jobtoken+'.service',invocation='a'*32,
                           cpus=[0,1,2,3],controllerMemory=2147483648,domainMemory=8589934592,
                           reservationMemory=10737418240,vmSlice='opemos-vm-pool-libvirt'+jobtoken+'.slice',
                           partition='/opemos/vm/pool/libvirt'+jobtoken,gpuGroup='omen-iommu-group-1')
            with adapter.RootInputs(request.get('currentControl'))as inputs:
                accepted=adapter.verify_inputs(request,inputs,boot,include_context=False)
                self.assertEqual(accepted['implementationAccessPin'],roles['libvirt_access'])
                self.assertFalse(accepted['originalInputOnly'])
                for fault in ('source-hash','source-owner','escape'):
                    control=copy.deepcopy(request['currentControl'])
                    if fault=='source-hash':control['definitionPin']['sha256']='0'*64
                    elif fault=='source-owner':control['definitionPin']['identity']['st_uid']=1000
                    else:control['definitionPin']['path']='/run/../tmp/installed-controller.json'
                    with self.assertRaises(Exception):
                        with adapter.RootInputs(control) as wrong_inputs:
                            adapter.verify_inputs(dict(request,currentControl=control),wrong_inputs,boot,include_context=False)
                with adapter.load_pair(accepted)as(current_peer,current_access):
                    import postqueue_issuer as issuer
                    current_peer.SOURCE_PLACEMENT_PIN=None
                    issuer.bind_placement(current_peer,parent,parent_ref)
                    entry=types.ModuleType('actual_installed_entry');entry.__file__=roles['runtime_entry']['path']
                    exec(compile(Path(entry.__file__).read_bytes(),entry.__file__,'exec'),entry.__dict__)
                    self.assertEqual(entry.validate_context_sources({'sourceRoles':roles}),roles)
                    entry.bind_placement(current_peer,parent,parent_ref)
                    issuer.submission_manifest(parent,parent_ref,'/run')
                    for key in ('queue','source'):
                        wrong=copy.deepcopy(parent)
                        if key=='queue':wrong['queuePrograms'][0]['sha256']='0'*64
                        else:wrong['sourceRoles']['libvirt_access']['sha256']='0'*64
                        with self.assertRaises(Exception):issuer.submission_manifest(wrong,parent_ref,'/run')
                    # SAME real storage declaration boundary -> strict production walker.
                    # Device/media geometry is still an explicit model in this connected case.
                    storage_module=sys.modules['libvirt_storage']
                    walker=sys.modules['guest_firmware_probe'].metadata_cohort
                    declared_config=copy.deepcopy(c)
                    declared_config['installer']['kind']=media.KIND
                    storage_value={'ioScope':{'run':c['run'],'output':c['output']},
                                   'operationRoot':paths['operationRoot'],'currentQueueRoot':str(queue_root)}
                    roots,socket=storage_module.declared_metadata_roots(storagepin,nonce,declared_config,
                                                                       storage_value,True,request)
                    self.assertEqual(roots.count(str(placement)),1)
                    self.assertEqual(roots.count(str(source_root)),1)
                    self.assertEqual(len(roots),len(set(roots)))
                    baseline=set(os.listdir('/proc/self/fd'))
                    charged,entries,closure=walker(roots,allowed_socket=socket)
                    expected=0;seen=set()
                    for declared in roots:
                        if not os.path.lexists(declared):continue
                        node=Path(declared)
                        objects=[node]
                        if node.is_dir():objects+=list(node.rglob('*'))
                        for obj in objects:
                            st=os.lstat(obj);key=(st.st_dev,st.st_ino)
                            self.assertNotIn(key,seen);seen.add(key)
                            expected+=max(st.st_size,st.st_blocks*512)
                    self.assertEqual(charged,expected)
                    self.assertGreater(entries,0)
                    self.assertTrue(closure['allClosed'] and closure['FDSetRestored'])
                    self.assertEqual(set(os.listdir('/proc/self/fd')),baseline)
                    # The walker itself remains strict, including distinct operands for one inode.
                    with self.assertRaises(Exception):walker(roots+[str(source_root)],allowed_socket=socket)
                    self.assertEqual(set(os.listdir('/proc/self/fd')),baseline)
                    alias=fixture/'metadata-alias';alias.mkdir(mode=0o700)
                    import libvirt_native as native
                    import time
                    mount=native.native_child(['/usr/bin/mount','--bind',str(source_root),str(alias)],
                                               time.time()+10,installer.pin('/usr/bin/mount'))
                    self.assertEqual(mount['numeric'],0)
                    try:
                        with self.assertRaises(Exception):walker(roots+[str(alias)],allowed_socket=socket)
                        self.assertEqual(set(os.listdir('/proc/self/fd')),baseline)
                    finally:
                        unmount=native.native_child(['/usr/bin/umount',str(alias)],time.time()+10,
                                                   installer.pin('/usr/bin/umount'))
                        self.assertEqual(unmount['numeric'],0)
                    alias.rmdir()
                    for fault in ('missing','foreign','original-current','wrong-attempt','wrong-job','old-path'):
                        bad=copy.deepcopy(parent)
                        if fault=='missing':bad['sourceRoles'].pop('libvirt_storage')
                        elif fault=='foreign':bad['sourceRoles']['foreign']=bad['sourceRoles']['libvirt_storage']
                        elif fault=='original-current':bad['sourceRoles']['libvirt_peer']['sha256']=adapter.ORIGINAL_PEER_SHA
                        elif fault=='wrong-attempt':
                            bad['candidate']['operationContext']['attempt']='f'*32
                        elif fault=='wrong-job':bad['candidate']['jobId']='foreign-job'
                        else:
                            bad['sourcePlacementPin']['path']='/run/opemos-steamos-placement-'+nonce+'/storage-contract.json'
                            bad['placementQualificationPin']['path']='/run/opemos-steamos-placement-'+nonce+'/placement-qualified.json'
                        with self.assertRaises(Exception):issuer.bind_placement(current_peer,bad,parent_ref)
                        with self.assertRaises(Exception):entry.bind_placement(current_peer,bad,parent_ref)
                queue_spec=importlib.util.spec_from_file_location('actual_connected_queue',installed['queuePrograms'][0]['path'])
                queue=importlib.util.module_from_spec(queue_spec);sys.modules[queue_spec.name]=queue
                try:
                    queue_spec.loader.exec_module(queue)
                    captures=[]
                    actual=queue.observe_queue_libvirt(request,captures=captures)
                    self.assertEqual(actual['phase'],'NOT_PREPARED')
                    self.assertTrue(captures)
                    self.assertTrue(captures[-1]['proof']['allOwnedDescriptorsClosed'])
                finally:sys.modules.pop(queue_spec.name,None)
                for wrong in (dict(request,specSHA256='0'*64),dict(request,jobId='foreign-job'),
                              dict(request,observer=dict(observer,sha256=adapter.ORIGINAL_PEER_SHA))):
                    with self.assertRaises(RuntimeError):adapter.verify_inputs(wrong,inputs,boot,include_context=False)
        finally:
            if parent_identity is not None:
                self.assertEqual(media.identity(os.lstat(public_parent)),parent_identity)
                public_parent.unlink()
            for path in (source_root,queue_root,drain_root,*reversed(created)):
                if path.exists(): shutil.rmtree(path)

    def test_idle_offline_transition_requires_fresh_post_drain_cut(self):
        """Actual producer predicate and consumer; API/peer facts are explicit modeled inputs."""
        import time
        online = {'runnerOnline':True, 'runnerBusy':False, 'actionsInProgress':0}
        offline = dict(online, runnerOnline=False)
        calls = []
        final = dict(offline, networkReachable=True, sourceOwnerBusy=False, queueKnown=True,
                     otherActiveJobs=[], unknownReservations=[], guestActive=False,
                     gpuLeaseActive=False, hostGraphics='INTEL_HOST_NVIDIA_GUEST_ONLY',
                     workerLockFree=True, control={'state':'passed', 'terminalLifecycle':'CLOSED',
                                                   'reservationRetained':False})
        def modeled_external_observation(inputs):
            calls.append(inputs)
            if len(calls) == 1: media_probe.require_stable_assignment(online, offline)
            media_probe.require_stable_assignment(offline, offline)
            return final
        probe = types.SimpleNamespace(observe=modeled_external_observation,
                                      RunnerStatusTransition=media_probe.RunnerStatusTransition)
        cuts = []
        result = media_window.observe_after_drain(probe, {'modeledAPI':True}, time.monotonic()+3, cuts)
        self.assertIs(result, final)
        self.assertEqual(len(calls),2)
        self.assertEqual(cuts,[{'runnerStatusTransition':{'before':online,'after':offline}}])
        media_window.admitted_media(result)
        with self.assertRaises(media_probe.RunnerStatusTransition):
            media_probe.require_stable_assignment(online, offline)  # no pre-drain retry/acceptance
        with self.assertRaisesRegex(RuntimeError,'bounded runner status'):
            media_window.observe_after_drain(types.SimpleNamespace(
                observe=lambda inputs:media_probe.require_stable_assignment(online,offline),
                RunnerStatusTransition=media_probe.RunnerStatusTransition), {}, time.monotonic()-1, [])

    def test_post_drain_cut_keeps_original_deadline_before_and_after_observation(self):
        import time
        idle={'runnerOnline':True,'runnerBusy':False,'actionsInProgress':0}
        offline=dict(idle,runnerOnline=False)
        calls=[]
        def fresh(inputs):calls.append(inputs);return offline
        probe=types.SimpleNamespace(observe=fresh,RunnerStatusTransition=media_probe.RunnerStatusTransition)
        with self.assertRaisesRegex(RuntimeError,'before fresh cut'):
            media_window.observe_after_drain(probe,{},time.monotonic()-1,[])
        self.assertEqual(calls,[])
        def late(inputs):calls.append(inputs);time.sleep(.03);return offline
        probe.observe=late
        with self.assertRaisesRegex(RuntimeError,'after fresh cut'):
            media_window.observe_after_drain(probe,{},time.monotonic()+.015,[])
        self.assertEqual(len(calls),1)
        calls=[]
        def transition(inputs):
            calls.append(inputs);media_probe.require_stable_assignment(idle,offline)
        probe.observe=transition
        with self.assertRaisesRegex(RuntimeError,'before fresh cut'):
            media_window.observe_after_drain(probe,{},time.monotonic()+.03,[])
        self.assertEqual(len(calls),1)  # remaining sleep never starts a late second observation

    def test_assigned_busy_and_unknown_probe_failures_remain_final(self):
        import time
        idle={'runnerOnline':True,'runnerBusy':False,'actionsInProgress':0}
        for after in (dict(idle,runnerBusy=True),dict(idle,actionsInProgress=1),
                      dict(idle,runnerOnline=False,actionsInProgress=1)):
            calls=[]
            def external(inputs):
                calls.append(inputs);media_probe.require_stable_assignment(idle,after)
            probe=types.SimpleNamespace(observe=external,RunnerStatusTransition=media_probe.RunnerStatusTransition)
            with self.assertRaises(RuntimeError) as caught:
                media_window.observe_after_drain(probe,{},time.monotonic()+3,[])
            self.assertNotIsInstance(caught.exception,media_probe.RunnerStatusTransition)
            self.assertEqual(len(calls),1)
        def unknown(inputs):raise RuntimeError('actual source drift')
        with self.assertRaisesRegex(RuntimeError,'actual source drift'):
            media_window.observe_after_drain(types.SimpleNamespace(
                observe=unknown,RunnerStatusTransition=media_probe.RunnerStatusTransition),{},time.monotonic()+3,[])

    def test_repository_queue_and_heartbeat_are_not_media_permission(self):
        for queued in (None, 0, 100):
            value = {'networkReachable':True,'runnerBusy':False,'actionsInProgress':0,
                     'actionsQueued':queued,'heartbeatCurrent':False,'sourceOwnerBusy':False,
                     'queueKnown':True,'otherActiveJobs':[],'unknownReservations':[],
                     'guestActive':False,'gpuLeaseActive':False,
                     'hostGraphics':'INTEL_HOST_NVIDIA_GUEST_ONLY','workerLockFree':True,
                     'runnerOnline':False,'control':{'state':'absent'}}
            media_window.admitted_media(value)
            bad = dict(value, actionsInProgress=1)
            with self.assertRaises(RuntimeError): media_window.admitted_media(bad)
            bad = dict(value, sourceOwnerBusy=True)
            with self.assertRaises(RuntimeError): media_window.admitted_media(bad)

    def test_pidfd_selection_keeps_actual_worker_and_owner_guards(self):
        expected = {'job':'control-one','unit':'fixture.service','invocation':'a'*32,
                    'boot':'actual-boot','listenerPID':11,'listenerStart':101,
                    'loggerPID':10,'loggerStart':100}
        group = '/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/fixture.service'
        row = {'id':'control-one','unit':'fixture.service','state':'running'}
        probe = {'control':{'jobId':'control-one'},'runnerBusy':False,
                 'actionsInProgress':0,'actionsQueued':200,'guestActive':False}
        manager = {'ActiveState':'active','InvocationID':'a'*32,'MainPID':'10','ControlGroup':group}
        live = [{'pid':10,'start':100,'uids':[1000]*4,'cgroup':'0::'+group,'argv':[b'logger']},
                {'pid':11,'start':101,'uids':[1000]*4,'cgroup':'0::'+group,
                 'argv':[idle_signal_owner.LISTENER,b'run',b'--startuptype',b'service']}]
        self.assertEqual(idle_signal_owner.selected(row,probe,expected,manager,live,'actual-boot')['pid'],11)
        foreign = copy.deepcopy(live); foreign[1]['start'] += 1
        with self.assertRaises(RuntimeError): idle_signal_owner.selected(row,probe,expected,manager,foreign,'actual-boot')
        foreign = live + [{'pid':12,'start':102,'uids':[1000]*4,'cgroup':'0::'+group,'argv':[b'Runner.Worker']}]
        with self.assertRaises(RuntimeError): idle_signal_owner.selected(row,probe,expected,manager,foreign,'actual-boot')

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
            # The original D24 source schema remains twelve-role DATA. A real
            # wrong-scope refusal must not become a NameError from current-only
            # variables accidentally inserted in this legacy consumer.
            legacy=set(source_contract.RUNTIME_ROLES)-{'libvirt_storage','retained_media','source_contract'}
            roles={n:pin('/run/legacy/'+n+'.py',0o100444,0,0,1,500+i)for i,n in enumerate(sorted(legacy))}
            roles['libvirt_peer']=pin('/run/legacy/libvirt_peer.py',0o100444,0,0,queue.D24_PEER_BYTES,600,queue.D24_PEER_SHA)
            roles['libvirt_access']=pin('/run/legacy/libvirt_access.py',0o100444,0,0,15340,601,queue.D24_ACCESS_SHA)
            observer={k:roles['libvirt_peer'][k]for k in ('path','bytes','sha256')}
            envelope={'kind':'ROOT_REVIEWED_LIBVIRT_PEER_INPUT_AND_IMPLEMENTATION','effects':[],
                      'upstreamObserver':roles['libvirt_peer'],'proof':{},
                      'implementation':{'contract':queue.D24_ADAPTER_CONTRACT,'peer':roles['libvirt_peer'],
                        'access':roles['libvirt_access'],'sourceRoles':roles,'parent':None,'context':None,
                        'assignment':None,'grant':None,'placementBinding':None}}
            with self.assertRaisesRegex(ValueError,'only fresh D23 scope'):
                queue.validate_d24_peer_envelope(envelope,{'observer':observer,'leaseNonce':'c'*32},roles['libvirt_peer'])
            c, v = operand()
            self.assertEqual(queue.R109_PEER_SHA,
                             hashlib.sha256((SOURCE / 'libvirt_peer.py').read_bytes()).hexdigest())
            self.assertEqual(queue.R109_ACCESS_SHA,
                             hashlib.sha256((SOURCE / 'libvirt_access.py').read_bytes()).hexdigest())
            self.assertEqual(queue.R109_CURRENT_ADAPTER,
                             (SOURCE / 'standalone_peer_access_adapter.py').read_text())
            import libvirt_preflight as preflight
            import queue_assignment as assignment
            self.assertEqual(preflight.CONTROL_QUEUE_SHA,'16177e18b25de4b5b4a45849f5eddb7f7b58527f7d3425d48849927d5843103e')
            self.assertEqual(assignment.QUEUE_SHA,preflight.QUEUE_SHA)
        finally: sys.modules.pop(spec.name, None)

    @unittest.skipIf(os.geteuid() == 0, 'normal queue CLI runs as the unprivileged queue owner')
    def test_normal_exact_job_status_preserves_complete_row(self):
        spec = importlib.util.spec_from_file_location('retained_status_actual_queue', SOURCE / 'test_queue.py')
        queue = importlib.util.module_from_spec(spec); sys.modules[spec.name] = queue
        spec.loader.exec_module(queue)
        try:
            with tempfile.TemporaryDirectory(prefix='opemos-job-status-') as directory:
                state = Path(directory) / 'state'
                with contextlib.redirect_stdout(io.StringIO()): queue.main(['--queue', str(state), 'init'])
                root, db = queue.connect(state)
                value = {'terminalLifecycle': {'phase': 'CLOSED', 'reservationRetained': False},
                         'first': {'reason': 'actual test failure retained'}, 'unknown': None}
                row = {'id': 'fixture-one', 'spec': '{"platform":"steamos"}', 'state': 'failed',
                       'cpus': '[0,1,2,3]', 'unit': 'fixture.service', 'started': 10.0,
                       'finished': 11.0, 'result': json.dumps(value)}
                db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?)', tuple(row.values()))
                db.commit(); db.close()
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(queue.main(['--queue', str(state), 'status', '--job-id', row['id']]), 0)
                got = json.loads(output.getvalue())
                self.assertEqual(got, {'kind': 'NORMAL_QUEUE_EXACT_JOB_STATUS_V1', 'job': row, 'binding': None})
        finally: sys.modules.pop(spec.name, None)

    @unittest.skipUnless(os.geteuid() == 0, 'real protected-parent transport requires disposable CI Root')
    def test_complete_actual_queue_phase_consumer_with_protected_parent(self):
        """Real Root metadata transport and entire stage consumer; native/media facts are MODELED.

        No VM, mount or disk bytes are simulated as successful hardware. The
        separate Root observer must supply those actual facts before execution.
        """
        spec = importlib.util.spec_from_file_location('retained_phase_actual_queue', SOURCE / 'test_queue.py')
        queue = importlib.util.module_from_spec(spec); sys.modules[spec.name] = queue
        spec.loader.exec_module(queue)
        root = Path(tempfile.mkdtemp(prefix='opemos-retained-ci-', dir='/run'))
        parent_path = Path('/run/opemos-libvirt-parent-' + 'c' * 32 + '.json')
        if os.path.lexists(parent_path):
            root.rmdir(); sys.modules.pop(spec.name, None)
            self.skipTest('existing owner of exact fixture parent is preserved')
        parent_identity = None
        before_fd = set(os.listdir('/proc/self/fd'))
        def canonical(v): return json.dumps(v, sort_keys=True, separators=(',', ':')).encode()
        def put(path, v, mode):
            raw = canonical(v)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            try:
                os.fchmod(fd, mode); os.write(fd, raw); os.fsync(fd)
                ident = media.identity(os.fstat(fd))
            finally: os.close(fd)
            return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'identity': ident}
        try:
            c, value = operand()
            c.update(jobId='retained-fixture-job', guestUUID='64f43b0c-9a98-494d-adc1-0782aea1d32e',
                     name='opemos-libvirt-' + c['nonce'], run=str(root / 'run'), output=str(root / 'output'),
                     original=pin('/MODELED/golden.raw', 0o100400, 0, 0, 21474836480, 66))
            c['installer']['noInstallTarget'] = True
            c['installer']['currentCustodyPin'] = put(root / 'custody.json', value, 0o400)
            roles = {name: pin('/MODELED/source/' + name + '.py', 0o100444, 0, 0, 1, 100 + n)
                     for n, name in enumerate(sorted(source_contract.RUNTIME_ROLES))}
            observer = {k: roles['libvirt_peer'][k] for k in ('path', 'bytes', 'sha256')}
            domain = {'uuid': c['guestUUID'], 'name': c['name'], 'leaseNonce': c['nonce'], 'observer': observer}
            template = {'id': c['jobId'], 'approval': 'EXACT_PARENT_MINIMAL_PIN',
                        'command': ['entry', 'EXACT_PARENT_FULL_PIN_JSON'], 'libvirt_domain': domain}
            rows, after = [], []
            for role in ('working-parent', 'working', 'runtime-parent', 'vars', 'output-parent', 'serial'):
                directory = role.endswith('parent')
                if role in ('working', 'working-parent'):
                    ref = value['working'] if role == 'working' else value['parent']
                    acl = value['workingACL'] if role == 'working' else value['parentACL']
                    row = {'path': ref['path'], 'role': role, 'before': ref, 'priorACL': acl, 'targetACL': acl,
                           'uid': 64055, 'rights': 'r--' if role == 'working' else '--x',
                           'immutableMediaCustodyPin': c['installer']['currentCustodyPin']}
                    a = {'path': ref['path'], 'identity': ref['identity'], 'ACL': acl}
                else:
                    path = c['run'] if role == 'runtime-parent' else c['output'] if role == 'output-parent' else c['run'] + '/OVMF_VARS_4M.fd' if role == 'vars' else c['output'] + '/serial.raw'
                    rights = 'rwx' if directory else 'rw-'; base = 'rwx' if directory else 'rw-'
                    prior = 'user::' + base + '\ngroup::---\nother::---\n'
                    target = 'user::' + base + '\nuser:64055:' + rights + '\ngroup::---\nmask::' + rights + '\nother::---\n'
                    ref = pin(path, 0o40700 if directory else 0o100600, 0, 0, 4096 if directory else 1, 200 + len(rows))
                    if directory: ref = {k: ref[k] for k in ('path', 'identity')}
                    row = {'path': path, 'role': role, 'before': ref, 'priorACL': prior, 'targetACL': target, 'uid': 64055, 'rights': rights}
                    i = dict(ref['identity'], st_mode=0o40770 if directory else 0o100660)
                    a = {'path': path, 'identity': i, 'ACL': target}
                    if not directory: a.update(bytes=ref['bytes'], sha256=ref['sha256'])
                rows.append(row); after.append(a)
            disks = {'original': c['original'], 'working': c['working']}
            stage = {'kind': 'LIBVIRT_R7_ACCESS_STAGE_PENDING_FULL_HASH', 'nonce': c['nonce'],
                     'bootID': c['hostBoot'], 'candidate': c, 'grantPin': put(root / 'grant.json', {}, 0o400),
                     'rows': rows, 'after': after, 'original': c['original'], 'workingBefore': c['working'],
                     'pendingFullContentProof': True, 'runtimeAuthorized': False}
            stage_pin = put(root / 'stage.json', stage, 0o400)
            placement = put(root / 'placement.json', {}, 0o400); qualification = put(root / 'qualification.json', {}, 0o400)
            parent = {'kind': 'ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT', 'RootIssued': True, 'runtimeAuthorized': True,
                      'MODEL_ONLY': False, 'jobId': c['jobId'], 'nonce': c['nonce'], 'bootID': c['hostBoot'],
                      'candidate': c, 'sourceRoles': roles, 'normalizedSpecTemplate': template,
                      'preparedAccessPin': stage_pin, 'preparedDiskPins': disks,
                      'sourcePlacementPin': placement, 'placementQualificationPin': qualification}
            parent_pin = put(parent_path, parent, 0o444); parent_identity = parent_pin['identity']
            normalized = copy.deepcopy(template); normalized['approval'] = {k: parent_pin[k] for k in ('path', 'bytes', 'sha256')}
            normalized['command'][-1] = canonical(parent_pin).decode()
            request = {'jobId': c['jobId'], 'jobToken': 'd' * 32, 'leaseNonce': c['nonce'],
                       'domainUUID': c['guestUUID'], 'domainName': c['name'], 'observer': observer,
                       'specSHA256': hashlib.sha256(canonical(normalized)).hexdigest()}
            proof = {'phase': 'NOT_PREPARED', 'bootID': c['hostBoot'], 'intentPin': None, 'scope': None,
                     'leader': None, 'lease': None}
            custody = {'kind': 'ROOT_PHASE_PREPARED_ACCESS_CUSTODY_R1', 'phase': proof['phase'],
                       'nonce': c['nonce'], 'bootID': c['hostBoot'], 'requestSHA256': hashlib.sha256(canonical(request)).hexdigest(),
                       'parentPin': parent_pin, 'preparedAccessPin': stage_pin, 'preparedDiskPins': disks,
                       'sourceGraphSHA256': hashlib.sha256(canonical(roles)).hexdigest(),
                       'placementPin': placement, 'qualificationPin': qualification, 'stage': stage,
                       'stageRawBase64': __import__('base64').b64encode(canonical(stage)).decode(),
                       'data': {'phase': proof['phase'], 'stage': stage, 'mutable': [], 'phasePins': None}}
            queue.validate_installer_access_custody(custody, proof, request)
            for mutation in ('stage-raw', 'current-hash', 'media-owner'):
                bad = copy.deepcopy(custody)
                if mutation == 'stage-raw': bad['stageRawBase64'] = 'e30='
                if mutation == 'current-hash': bad['stage']['candidate']['installer']['currentCustodyPin']['sha256'] = '0' * 64
                if mutation == 'media-owner': bad['stage']['rows'][1]['before']['identity']['st_uid'] = 0
                with self.subTest(mutation=mutation), self.assertRaises((ValueError, RuntimeError)):
                    queue.validate_installer_access_custody(bad, proof, request)
        finally:
            if parent_identity is not None:
                self.assertEqual(media.identity(os.lstat(parent_path)), parent_identity)
                parent_path.unlink()
            shutil.rmtree(root)
            sys.modules.pop(spec.name, None)
            self.assertEqual(set(os.listdir('/proc/self/fd')), before_fd)


if __name__ == '__main__': unittest.main()
