"""Run in existing source CI/admitted OMEN VM, never on the controller.

These exercise real files and fdinfo, not a fake libvirt/runtime acceptance.
The 12GiB creation case deliberately uses the actual production minimum and
full allocation, so it is reserved for a separately admitted OMEN transaction.
"""
import importlib.util
import os
import selectors
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('output_disk_runner', SCRIPTS / 'ubuntu_vm_runner.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class OutputDisks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.media = self.root / 'media.raw'
        self.target = self.root / 'target.raw'
        self.media.write_bytes(b'media')
        # A sparse file is sufficient for constructor tests, NOT an allocation
        # or admission proof. Creation itself requires full posix_fallocate.
        with self.target.open('xb') as stream:
            stream.truncate(runner.OUTPUT_INSTALL_MINIMUM_BYTES)
        self.mp = {'path': str(self.media), 'identity': runner.output_disk_identity(self.media.stat())}
        self.tp = {'path': str(self.target), 'identity': runner.output_disk_identity(self.target.stat()),
                   'format': 'raw', 'backingChain': [], 'capacityBytes': runner.OUTPUT_INSTALL_MINIMUM_BYTES}
        self.xml = '<domain type="kvm"><os><type>hvm</type><boot dev="hd"/></os><metadata><binding>preserved</binding></metadata><devices><controller type="usb" model="qemu-xhci"/><disk type="file" device="disk"><driver type="raw"/><source file="historical.raw"/></disk></devices></domain>'

    def test_two_devices_then_media_detached(self):
        install = ET.fromstring(runner.output_install_disks_xml(self.xml, self.mp, self.tp, True))
        disks = install.findall('./devices/disk')
        self.assertEqual(len(disks), 2)
        self.assertEqual(disks[0].find('source').get('file'), str(self.media))
        self.assertIsNotNone(disks[0].find('readonly'))
        self.assertEqual(disks[0].find('target').get('bus'), 'usb')
        self.assertIsNone(disks[1].find('readonly'))
        installed = ET.fromstring(runner.output_install_disks_xml(self.xml, self.mp, self.tp, False))
        self.assertEqual(len(installed.findall('./devices/disk')), 1)
        self.assertEqual(installed.find('./devices/disk/source').get('file'), str(self.target))
        self.assertEqual(installed.find('./metadata/binding').text, 'preserved')
        self.assertEqual(installed.find('./devices/serial').get('type'), 'pty')
        self.assertEqual(installed.find('./devices/console').get('type'), 'pty')
        self.assertFalse(installed.findall('./devices/serial/source'))

    def test_media_never_target_and_capacity_not_label(self):
        for changes in ({'path': str(self.media), 'identity': self.mp['identity']},
                        {'capacityBytes': 6 * 1024**3}, {'capacityBytes': 13 * 1024**3},
                        {'format': 'qcow2'}, {'backingChain': ['hidden-parent']}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.output_install_disks_xml(self.xml, self.mp, {**self.tp, **changes}, True)
        self.media.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            runner.output_install_disks_xml(self.xml, self.mp, self.tp, True)

    def test_full_logical_target_is_charged_and_duplicate_path_is_not_double_counted(self):
        ledger = runner.output_storage_ledger([self.media, self.media, self.target], 1024)
        self.assertEqual(ledger['uniqueInodes'], 2)
        self.assertGreaterEqual(ledger['chargedBytes'], runner.OUTPUT_INSTALL_MINIMUM_BYTES + 1029)
        self.assertFalse(ledger['admissionClaimed'])
        with self.assertRaises(ValueError):
            runner.output_storage_ledger([self.target], runner.VM_BUDGET_BYTES)
        link = self.root / 'alias'
        link.symlink_to(self.media)
        with self.assertRaises(ValueError): runner.output_storage_ledger([link])

    @unittest.skipUnless(sys.platform == 'linux', 'actual Linux procfs properties')
    def test_actual_readonly_media_and_writable_target_fd_flags(self):
        code = ('import os,sys; a=os.open(sys.argv[1],int(sys.argv[3])); '
                'b=os.open(sys.argv[2],os.O_RDWR); print("READY",flush=True); '
                'sys.stdin.read(); os.close(a); os.close(b)')
        for access, accepted in ((os.O_RDONLY, True), (os.O_RDWR, False)):
            child = subprocess.Popen([sys.executable, '-c', code, str(self.media), str(self.target), str(access)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(5), 'actual child readiness deadline')
                    self.assertEqual(child.stdout.readline(), b'READY\n')
                root = Path('/proc') / str(child.pid)
                fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
                start = int(fields[19]); cgroup = (root / 'cgroup').read_text().strip()[3:]
                if accepted:
                    proof = runner.observe_output_disk_fds(child.pid, start, os.getuid(), cgroup,
                                                          self.mp, self.tp, True)
                    self.assertTrue(proof['diskFDs']['media'])
                    self.assertTrue(proof['diskFDs']['target'])
                else:
                    with self.assertRaises(ValueError):
                        runner.observe_output_disk_fds(child.pid, start, os.getuid(), cgroup,
                                                      self.mp, self.tp, True)
                child.communicate(timeout=5)
                self.assertEqual(child.returncode, 0)
            finally:
                if child.poll() is None:
                    child.kill(); child.communicate(timeout=5)
                child.stdin.close(); child.stdout.close(); child.stderr.close()


if __name__ == '__main__':
    unittest.main()
