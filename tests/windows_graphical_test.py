"""Process/pipe/file protocol regressions. Run only inside an admitted OMEN VM.

The producer below is explicitly NOT QEMU or a guest/permission/GPU proof.
No method under test is replaced to make its caller succeed.
"""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import ubuntu_vm_runner as runner
from ubuntu_vm_runner_test import fixture_spawn_receipt, fixture_reap_receipt


PRODUCER = r'''
import json,sys,struct,zlib
from pathlib import Path
root=Path(sys.argv[1]);mode=sys.argv[2]
def chunk(kind, data):
 return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',2,2,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(b'\0'+b'\0'*6+b'\0'+b'\0'*6))+chunk(b'IEND',b'')
print(json.dumps({'QMP':{}}),flush=True)
with (root/'commands.jsonl').open('x') as log:
 for line in sys.stdin:
  p=json.loads(line);log.write(json.dumps(p)+'\n');log.flush();c=p['execute'];r={}
  if c=='query-name':r={'name':'wrong' if mode=='wrong-name' else 'OPEMOS-Agent-Boot'}
  if c=='query-status':r={'running':False,'status':'prelaunch'}
  if c=='query-block':r=[{'inserted':{'file':str(root/n),'ro':n in ['package.iso','code.fd']}} for n in ['os.qcow2','package.iso','code.fd','vars.fd']]
  if c=='human-monitor-command':r='VGA usb-tablet'
  if c=='screendump':Path(p['arguments']['filename']).write_bytes(png)
  if mode=='press-failure' and c=='input-send-event' and p['arguments']['events'][0]['data'].get('down') is True:
   reply={'id':p['id'],'error':{'class':'GenericError','desc':'retained press failure'}}
  else:reply={'id':p['id']+(1 if mode=='wrong-id' else 0),'return':r}
  print(json.dumps(reply),flush=True)
  if c=='quit':break
'''


class WindowsGraphicalProtocolTest(unittest.TestCase):
    def transaction(self, mode, action):
        with tempfile.TemporaryDirectory(prefix='opemos-windows-protocol-') as directory:
            root = Path(directory)
            child = subprocess.Popen([sys.executable, '-c', PRODUCER, directory, mode],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, bufsize=0)
            identity = fixture_spawn_receipt(child, 'windows-protocol-not-guest')
            monitor = runner.WindowsGraphicalQMP(child.stdout, child.stdin, root, time.monotonic() + 10)
            try:
                action(root, monitor)
                monitor.call('quit')
                self.assertEqual(child.wait(timeout=3), 0)
            finally:
                monitor.close()
                if child.poll() is None:
                    child.kill(); child.wait(timeout=3)
                child.stdin.close(); child.stdout.close()
                error = child.stderr.read().decode(); child.stderr.close()
                fixture_reap_receipt(child, identity)
                self.assertEqual(error, '')

    def start(self, root, monitor):
        monitor.start(*(root / name for name in ['os.qcow2', 'package.iso', 'code.fd', 'vars.fd']))

    def test_complete_paused_producer_capture_click_release_and_close(self):
        def action(root, monitor):
            self.start(root, monitor)
            self.assertTrue((root / 'device-proof.json').exists())
            frame = monitor.capture(0)
            self.assertEqual((frame['width'], frame['height']), (2, 2))
            self.assertEqual(frame['sha256'], hashlib.sha256((root / 'frame-0000.png').read_bytes()).hexdigest())
            self.assertTrue(monitor.click(0, frame['sha256'], 1, 1, 2)['actualPointerEvents'])
            packets = [json.loads(line) for line in (root / 'commands.jsonl').read_text().splitlines()]
            buttons = [p['arguments']['events'][0]['data']['down'] for p in packets
                       if p['execute'] == 'input-send-event' and p['arguments']['events'][0]['type'] == 'btn']
            self.assertEqual(buttons, [True, False, True, False])
            with self.assertRaises(ValueError):
                monitor.click(0, frame['sha256'], 1, 1)
        self.transaction('normal', action)

    def test_changed_frame_and_invalid_coordinates_refuse_before_pointer(self):
        def action(root, monitor):
            self.start(root, monitor)
            frame = monitor.capture(0)
            for x, y in [(True, 0), (-1, 0), (2, 0), (0, 2)]:
                with self.assertRaises(ValueError):
                    monitor.click(0, frame['sha256'], x, y)
            (root / 'frame-0000.png').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'changed'):
                monitor.click(0, frame['sha256'], 1, 1)
        self.transaction('normal', action)

    def test_press_failure_still_sends_release_and_invalidates_frame(self):
        def action(root, monitor):
            self.start(root, monitor)
            frame = monitor.capture(0)
            with self.assertRaisesRegex(ValueError, 'reply'):
                monitor.click(0, frame['sha256'], 1, 1)
            packets = [json.loads(line) for line in (root / 'commands.jsonl').read_text().splitlines()]
            self.assertFalse(packets[-1]['arguments']['events'][0]['data']['down'])
            self.assertFalse(monitor.frames)
        self.transaction('press-failure', action)

    def test_wrong_guest_never_continues(self):
        def action(root, monitor):
            with self.assertRaisesRegex(ValueError, 'wrong guest'):
                self.start(root, monitor)
            self.assertNotIn('cont', (root / 'commands.jsonl').read_text())
        self.transaction('wrong-name', action)

    def test_existing_or_linked_capture_is_not_overwritten(self):
        def action(root, monitor):
            self.start(root, monitor)
            target = root / 'sentinel'; target.write_bytes(b'preserve')
            (root / 'frame-0000.png').symlink_to(target)
            with self.assertRaises(FileExistsError):
                monitor.capture(0)
            self.assertEqual(target.read_bytes(), b'preserve')
        self.transaction('normal', action)

    def test_reply_identity_mismatch_refuses(self):
        with self.assertRaisesRegex(ValueError, 'reply identity'):
            self.transaction('wrong-id', lambda root, monitor: self.start(root, monitor))

    def test_real_lock_exclusion_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory(prefix='opemos-graphical-lock-') as directory:
            root = Path(directory)
            lock_path = root / '.lifecycle-lock'
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(fd)
            first = runner.windows_runtime_lock(root)
            second = runner.windows_runtime_lock(root)
            try:
                fcntl.flock(first, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(first); os.close(second)
            lock_path.rename(root / 'retained-lock')
            lock_path.symlink_to(root / 'retained-lock')
            with self.assertRaises(ValueError):
                runner.windows_runtime_lock(root)

    def test_normal_protocol_transaction_retains_durable_lease_after_close(self):
        def action(root, monitor):
            (root / '.lifecycle-lock').touch(mode=0o600)
            lock = runner.windows_runtime_lock(root)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                binding = runner.reserve_windows_lease(root, lock, {'fixtureOnly': True},
                                                      ['protocol-not-qemu'], {'fixtureOnly': True})
                self.start(root, monitor)
                frame = monitor.capture(0)
                monitor.click(0, frame['sha256'], 1, 1)
                self.assertEqual(binding['sha256'], runner.base_digest(root / runner.WINDOWS_LEASE))
            finally:
                os.close(lock)
            # Closing the ordinary lock is not resource release, even after a
            # clean protocol close. The separate Root cgroup finalizer is not
            # simulated by setting a caller-controlled closed flag.
            with self.assertRaisesRegex(ValueError, 'durable Windows lease'):
                runner.windows_runtime_lock(root)
        self.transaction('normal', action)

    def test_real_cli_exit_releases_flock_but_not_lease_with_live_child(self):
        # Run the entire experiment in its own subreaper process. It adopts and
        # reaps only its generated child; no host or existing job is touched.
        supervisor = r'''
import ctypes,fcntl,json,os,signal,subprocess,sys
from pathlib import Path
import ubuntu_vm_runner as r
root=Path(sys.argv[1]);root.joinpath('.lifecycle-lock').touch(mode=0o600)
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(36,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'subreaper')
def expired(*unused):raise TimeoutError('bounded CLI boundary experiment')
signal.signal(signal.SIGALRM,expired);signal.alarm(8)
worker=r"""
import fcntl,json,os,subprocess,sys
from pathlib import Path
import ubuntu_vm_runner as r
root=Path(sys.argv[1]);fd=r.windows_runtime_lock(root);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
r.reserve_windows_lease(root,fd,{'fixtureOnly':True},['owned-child-not-qemu'],{'fixtureOnly':True})
c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
r.persist_windows_record(root/'child.json',r.windows_process_identity(c.pid))
print(json.dumps(r.windows_process_identity(c.pid)),flush=True)
sys.stdin.readline();os._exit(23)
"""
p=subprocess.Popen([sys.executable,'-c',worker,str(root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
row=None;pidfd=None
try:
 row=json.loads(p.stdout.readline());pidfd=os.pidfd_open(row['pid'])
 if r.windows_process_identity(row['pid'])!=row:raise ValueError('child birth changed')
 p.stdin.write('exit\n');p.stdin.flush()
 if p.wait(timeout=3)!=23:raise ValueError('initial worker failure not retained')
 if r.windows_process_identity(row['pid'])['startTicks']!=row['startTicks']:raise ValueError('child not live after CLI exit')
 fd=os.open(root/'.lifecycle-lock',os.O_RDWR)
 try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 finally:os.close(fd)
 try:r.windows_runtime_lock(root)
 except ValueError as e:
  if 'durable Windows lease' not in str(e):raise
 else:raise ValueError('lease did not prevent reuse after actual CLI exit')
 print(json.dumps({'workerExit':23,'childLiveAfterCLI':True,'flockReleased':True,'durableRefusal':True}),flush=True)
finally:
 signal.alarm(0)
 if p.poll() is None:p.kill();p.wait(timeout=3)
 p.stdin.close();p.stdout.close();error=p.stderr.read();p.stderr.close()
 if row is None and (root/'child.json').exists():row=json.loads((root/'child.json').read_text())
 if row is not None:
  if pidfd is None:pidfd=os.pidfd_open(row['pid'])
  if r.windows_process_identity(row['pid'])['startTicks']!=row['startTicks']:raise ValueError('cleanup birth changed')
  signal.pidfd_send_signal(pidfd,signal.SIGKILL)
  pid,status=os.waitpid(row['pid'],0)
  if pid!=row['pid'] or not os.WIFSIGNALED(status):raise ValueError('generated child not reaped')
  if Path('/proc',str(pid)).exists():raise ValueError('generated child still present')
  os.close(pidfd)
 if error:raise ValueError(error)
'''
        with tempfile.TemporaryDirectory(prefix='opemos-lease-cli-') as directory:
            child = subprocess.Popen([sys.executable, '-c', supervisor, directory],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True,
                                     env={**os.environ, 'PYTHONPATH': str(Path(runner.__file__).parent)})
            identity = fixture_spawn_receipt(child, 'lease-cli-boundary-not-guest')
            try:
                output, error = child.communicate(timeout=12)
                self.assertEqual(child.returncode, 0, error.decode())
                self.assertTrue(json.loads(output)['durableRefusal'])
                with self.assertRaisesRegex(ValueError, 'durable Windows lease'):
                    runner.windows_runtime_lock(Path(directory))
                # Actual documented runner CLI, not just an in-process caller:
                # durable refusal must precede mount/KVM/queue or image work.
                lease = (Path(directory) / runner.WINDOWS_LEASE).read_bytes()
                refused = subprocess.run([sys.executable, runner.__file__,
                                          'windows-graphical-initialize', directory],
                                         capture_output=True, timeout=3)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn(b'durable Windows lease', refused.stderr)
                self.assertEqual((Path(directory) / runner.WINDOWS_LEASE).read_bytes(), lease)
            finally:
                if child.poll() is None:
                    # Exact generated supervisor session only, not a process
                    # name or a discovered existing queue job.
                    os.killpg(child.pid, 9); child.wait(timeout=3)
                fixture_reap_receipt(child, identity)

    def test_partial_linked_and_claimed_closed_lease_never_rearm(self):
        for contents in ('', '{', '{"closed":true,"poolEmpty":true}'):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / runner.WINDOWS_LEASE).write_text(contents)
                (root / '.opemos-migration-owned').write_text('OPEMOS.EXE\n')
                with self.assertRaisesRegex(ValueError, 'durable Windows lease'):
                    runner.windows_runtime_lock(root)
                with self.assertRaisesRegex(ValueError, 'durable Windows lease'):
                    runner.run_owned_vm(root)
                with self.assertRaisesRegex(ValueError, 'durable Windows lease'):
                    runner.launch_bounded(root / 'unused.qcow2', 1024)
                with self.assertRaisesRegex(ValueError, 'durable Windows lease'):
                    runner.launch_command(root / 'unused.qcow2')
                with self.assertRaisesRegex(ValueError, 'durable Windows lease'):
                    runner.windows_launch_command(root / 'unused.qcow2', root / 'code', root / 'vars')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / runner.WINDOWS_LEASE).symlink_to(root / 'missing')
            with self.assertRaisesRegex(ValueError, 'durable Windows lease'):
                runner.windows_runtime_lock(root)

    def test_exact_agentboot_envelope_contract_refuses_generic_or_changed_volume(self):
        root = Path('/run/user/1000/fixture-only-not-an-admitted-mount')
        observed = {'backingFile': runner.AGENTBOOT_ENVELOPE,
                    'backingIdentity': [2051, 227], 'backingBytes': 59_900_000_256,
                    'kernelCapacityBytes': 59_900_000_256, 'backingUID': 1000,
                    'backingMode': 0o600, 'loopOffset': 0, 'loopSizeLimit': 0,
                    'mountTarget': str(root)}
        self.assertEqual(runner.validate_agentboot_envelope(observed, root), observed)
        changes = {'backingFile': '/another/marked/owned-runtime.ntfs',
                   'backingIdentity': [2051, 228], 'backingBytes': 59_899_999_744,
                   'kernelCapacityBytes': 59_899_999_744, 'backingUID': 0,
                   'backingMode': 0o666, 'loopOffset': 512, 'loopSizeLimit': 512,
                   'mountTarget': str(root.parent)}
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.validate_agentboot_envelope({**observed, key: value}, root)
        with self.assertRaises(ValueError):
            runner.validate_agentboot_envelope({**observed, 'backingIdentity': [2052, 227]}, root)

    def test_real_disappeared_proc_birth_keeps_primary_and_completes_finalization(self):
        with tempfile.TemporaryDirectory(prefix='opemos-birth-missing-') as directory:
            root = Path(directory)
            evidence = root / 'graphical-evidence'; evidence.mkdir()
            (root / '.lifecycle-lock').touch(mode=0o600)
            lock = runner.windows_runtime_lock(root)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            receipt = {'durableLease': runner.reserve_windows_lease(
                root, lock, {'fixtureOnly': True}, ['exited-child-not-qemu'], {'fixtureOnly': True})}
            child = subprocess.Popen([sys.executable, '-c', 'pass'], start_new_session=True,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            identity = fixture_spawn_receipt(child, 'actual-missing-proc-birth-not-guest')
            try:
                self.assertEqual(child.wait(timeout=3), 0)
                # A genuine absent /proc record, not an overridden stat reader.
                try:
                    runner.capture_windows_launcher(child, receipt, evidence)
                except FileNotFoundError as error:
                    receipt['primaryError'] = {'type': type(error).__name__, 'error': str(error)}
                else:
                    self.fail('reaped child unexpectedly supplied an original birth')
                self.assertEqual(receipt['launcherBirth'], 'UNKNOWN')
                original = dict(receipt['primaryError'])
                runner.finalize_windows_graphical(root, lock, child, None, None, {}, receipt)
                tail = json.loads((evidence / 'finalization.json').read_text())
                self.assertEqual(tail['primaryError'], original)
                self.assertEqual(json.loads((evidence / 'first-error.json').read_text())['primaryError'], original)
                self.assertEqual(tail['launcherBirth'], 'UNKNOWN')
                self.assertEqual(tail['qemuLauncherExit'], 0)
                self.assertEqual(tail['explicitLockClose'], 'CLOSED')
                self.assertTrue(tail['rootFinalizerRequired'])
                self.assertFalse(tail['closureVerified'])
                stages = {row['stage'] for row in tail['secondaryErrors']}
                self.assertIn('envelope-revalidation', stages)
                for name in ['base.qcow2', 'OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd']:
                    self.assertIn('input-rehash:' + name, stages)
                self.assertTrue((evidence / 'transaction.json').exists())
                with self.assertRaises(OSError):
                    os.fstat(lock)
                with self.assertRaisesRegex(ValueError, 'durable Windows lease'):
                    runner.windows_runtime_lock(root)
            finally:
                if child.poll() is None:
                    child.kill(); child.wait(timeout=3)
                for stream in (child.stdin, child.stdout, child.stderr):
                    stream.close()
                fixture_reap_receipt(child, identity)
                if receipt.get('explicitLockClose') != 'CLOSED':
                    os.close(lock)

    def test_live_unknown_birth_independent_close_and_persistence_errors_keep_evidence(self):
        with tempfile.TemporaryDirectory(prefix='opemos-birth-live-') as directory:
            root = Path(directory)
            evidence = root / 'graphical-evidence'; evidence.mkdir()
            (root / '.lifecycle-lock').touch(mode=0o600)
            lock = runner.windows_runtime_lock(root)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            receipt = {'durableLease': runner.reserve_windows_lease(
                root, lock, {'fixtureOnly': True}, ['live-child-not-qemu'], {'fixtureOnly': True}),
                       'primaryError': {'type': 'OSError', 'error': 'retained unobserved birth state'}}
            # This is the interrupted record shape, not a simulated successful
            # /proc observation. The target may not turn it into group proof.
            (evidence / 'transaction.json').write_bytes(b'preserve original transaction')
            child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                                     start_new_session=True, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            identity = fixture_spawn_receipt(child, 'live-unknown-birth-cleanup-not-guest')
            try:
                # Real EBADF and O_EXCL failures, no method under test replaced.
                runner.finalize_windows_graphical(root, lock, child, None, -1, {}, receipt)
                tail = json.loads((evidence / 'finalization.json').read_text())
                self.assertEqual(child.returncode, -9)
                self.assertEqual(tail['launcherBirth'], 'UNKNOWN')
                self.assertEqual(tail['ownedProcessGroupAbsent'], 'UNKNOWN')
                self.assertNotIn('ownedGroupCleanupExit', tail)
                self.assertEqual(tail['explicitLockClose'], 'CLOSED')
                self.assertEqual(tail['primaryError'], receipt['primaryError'])
                self.assertEqual(json.loads((evidence / 'first-error.json').read_text())['primaryError'], receipt['primaryError'])
                self.assertFalse(tail['closureVerified'])
                self.assertTrue(tail['rootFinalizerRequired'])
                stages = {row['stage'] for row in tail['secondaryErrors']}
                self.assertIn('namespace-close', stages)
                self.assertIn('transaction-persist', stages)
                self.assertEqual((evidence / 'transaction.json').read_bytes(), b'preserve original transaction')
                self.assertEqual(len([s for s in stages if s.startswith('input-rehash:')]), 3)
                with self.assertRaises(OSError):
                    os.fstat(lock)
                with self.assertRaisesRegex(ValueError, 'durable Windows lease'):
                    runner.windows_runtime_lock(root)
            finally:
                if child.poll() is None:
                    child.kill(); child.wait(timeout=3)
                for stream in (child.stdin, child.stdout, child.stderr):
                    stream.close()
                fixture_reap_receipt(child, identity)
                if receipt.get('explicitLockClose') != 'CLOSED':
                    os.close(lock)

    def test_new_normal_protocol_through_birth_and_finalizer_does_not_fake_os_proof(self):
        with tempfile.TemporaryDirectory(prefix='opemos-birth-protocol-') as directory:
            root = Path(directory)
            (root / '.lifecycle-lock').touch(mode=0o600)
            lock = runner.windows_runtime_lock(root)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            receipt = {'durableLease': runner.reserve_windows_lease(
                root, lock, {'fixtureOnly': True}, ['protocol-not-qemu'], {'fixtureOnly': True})}
            evidence = root / 'graphical-evidence'; evidence.mkdir()
            # Real fixture bytes must be rehashed and rejected, not installed as
            # new expected AgentBoot pins to make this caller pass.
            for name in ['base.qcow2', 'OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd']:
                (root / name).write_bytes(b'NOT AUTHENTICATED AGENTBOOT INPUT')
            child = subprocess.Popen([sys.executable, '-c', PRODUCER, str(evidence), 'normal'],
                                     start_new_session=True, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            identity = fixture_spawn_receipt(child, 'normal-birth-protocol-finalizer-not-guest')
            monitor = runner.WindowsGraphicalQMP(child.stdout, child.stdin, evidence, time.monotonic() + 10)
            try:
                runner.capture_windows_launcher(child, receipt, evidence)
                self.start(evidence, monitor)
                frame = monitor.capture(0)
                self.assertTrue(monitor.click(0, frame['sha256'], 1, 1)['actualPointerEvents'])
                monitor.call('quit'); self.assertEqual(child.wait(timeout=3), 0)
                runner.finalize_windows_graphical(root, lock, child, monitor, None, {}, receipt)
                tail = json.loads((evidence / 'finalization.json').read_text())
                self.assertEqual(tail['launcherBirth']['startTicks'], identity['startTicks'])
                self.assertEqual(tail['qemuLauncherExit'], 0)
                self.assertEqual(len(tail['immutableInputChecks']), 3)
                self.assertTrue(all(row['matches'] is False for row in tail['immutableInputChecks']))
                self.assertEqual(tail['originalQemuIdentityAbsent'], 'UNKNOWN')
                self.assertFalse(tail['closureVerified'])
                self.assertEqual(tail['explicitLockClose'], 'CLOSED')
                self.assertTrue((root / runner.WINDOWS_LEASE).exists())
            finally:
                monitor.close()
                if child.poll() is None:
                    child.kill(); child.wait(timeout=3)
                for stream in (child.stdin, child.stdout, child.stderr):
                    stream.close()
                fixture_reap_receipt(child, identity)
                if receipt.get('explicitLockClose') != 'CLOSED':
                    os.close(lock)


if __name__ == '__main__':
    unittest.main()
