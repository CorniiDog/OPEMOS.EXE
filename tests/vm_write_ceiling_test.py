import importlib.util
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'scripts/vm_write_ceiling.py'
spec = importlib.util.spec_from_file_location('ceiling', MODULE)
ceiling = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ceiling)


class WriteCeilingTest(unittest.TestCase):
    def test_existing_qemu_delta_export_preserves_changed_and_zeroed_sectors(self):
        # Reproduced admission blocker: the 34.48-GB compressed Windows base
        # cannot coexist with another standalone copy below the 60-GB cap.
        # Prove the existing delta-export route without accepting an uncounted
        # backing file or mutating it. This is a tiny synthetic fixture only.
        with tempfile.TemporaryDirectory(prefix='opemos-delta-export-') as directory:
            root = Path(directory)
            base, active, exported = [root / name for name in
                                      ('base.qcow2', 'active.qcow2', 'export.qcow2')]
            def run(*args):
                return subprocess.run(args, check=True, capture_output=True,
                                      text=True, timeout=30).stdout
            run('qemu-img', 'create', '-f', 'qcow2', str(base), '16M')
            run('qemu-io', '-f', 'qcow2', '-c', 'write -P 0x5a 0 2M', str(base))
            original = hashlib.sha256(base.read_bytes()).hexdigest()
            run('qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2',
                '-b', str(base), str(active))
            run('qemu-io', '-f', 'qcow2', '-c', 'write -z 0 1M',
                '-c', 'write -P 0xa5 2M 1M', str(active))
            (root / '.opemos-migration-owned').write_text('OPEMOS.EXE\n')
            ceiling.compact_owned_image(root, active.name, exported.name,
                                        export_ceiling=8 * 1024 * 1024,
                                        backing_name=base.name)
            run('qemu-img', 'check', '-f', 'qcow2', str(exported))
            run('qemu-img', 'compare', '-f', 'qcow2', '-F', 'qcow2',
                str(active), str(exported))
            run('qemu-io', '-f', 'qcow2', '-c', 'read -P 0 0 1M',
                '-c', 'read -P 0x5a 1M 1M', '-c', 'read -P 0xa5 2M 1M',
                str(exported))
            chain = json.loads(run('qemu-img', 'info', '--backing-chain',
                                   '--output=json', str(exported)))
            self.assertEqual(len(chain), 2)
            self.assertEqual(Path(chain[1]['filename']), base)
            self.assertEqual(hashlib.sha256(base.read_bytes()).hexdigest(), original)
            # Count the fixed base AND both writable files, not only the delta.
            self.assertLess(sum(path.stat().st_blocks * 512 for path in
                                (base, active, exported)), 16 * 1024 * 1024)

    def test_reclaim_refuses_unowned_and_wrong_paths_before_tools(self):
        with tempfile.TemporaryDirectory(prefix='opemos-reclaim-refusal-') as directory:
            source = Path(directory) / 'source.qcow2'
            source.write_bytes(b'original')
            for name in ('../source.qcow2', '/source.qcow2', 'source.qcow2'):
                with self.assertRaises((ValueError, FileNotFoundError)):
                    ceiling.compact_owned_image(directory, name, 'export.qcow2')
            self.assertEqual(source.read_bytes(), b'original')
            self.assertFalse((Path(directory) / 'export.qcow2').exists())

    def test_accounting(self):
        self.assertEqual(ceiling.bounded_file_ceiling(40_000_000_000, 2, 2_000_000_000), 9_000_000_000)
        for args in [(60_000_000_000, 1, 1), (0, 0, 1), (0, 1, 0), (True, 1, 1)]:
            with self.assertRaises(ValueError):
                ceiling.bounded_file_ceiling(*args)

    def test_hidden_external_backing_refused_without_retiring_source(self):
        with tempfile.TemporaryDirectory(prefix='opemos-parent-refusal-') as directory:
            root=Path(directory)
            (root/'.opemos-migration-owned').write_text('OPEMOS.EXE\n')
            base=root/'base.qcow2'; other=root/'other.qcow2'; active=root/'active.qcow2'
            for path in (base,other):
                subprocess.run(['qemu-img','create','-f','qcow2',str(path),'16M'],
                               check=True,capture_output=True)
            subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(other),str(active)],
                           check=True,capture_output=True)
            before=active.read_bytes()
            with self.assertRaisesRegex(ValueError,'unexpected external parent'):
                ceiling.compact_owned_image(root,active.name,'export.qcow2',backing_name=base.name)
            self.assertEqual(active.read_bytes(),before)
            self.assertFalse((root/'export.qcow2').exists())

    def test_kernel_refuses_growth_without_polling(self):
        with tempfile.TemporaryDirectory(prefix='opemos-ceiling-test-') as directory:
            target = Path(directory) / 'owned-fixture'
            program = '''import os, resource, signal, sys
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (4096,4096))
fd=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
os.write(fd,b'x'*4096)
for operation in (lambda: os.write(fd,b'y'), lambda: os.ftruncate(fd,8192)):
 try: operation()
 except OSError as error:
  assert error.errno==27
 else: raise AssertionError('growth was not refused')
os.fsync(fd)
assert os.fstat(fd).st_size==4096
os.close(fd)
'''
            subprocess.run([sys.executable, '-c', program, str(target)], check=True, timeout=10)
            self.assertEqual(target.stat().st_size, 4096)
            self.assertEqual(target.read_bytes(), b'x' * 4096)


if __name__ == '__main__':
    unittest.main()
