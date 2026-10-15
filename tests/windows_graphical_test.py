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


if __name__ == '__main__':
    unittest.main()
