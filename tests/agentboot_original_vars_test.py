"""Run only in an admitted OMEN VM. No mock grants firmware/OS acceptance."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'scripts' / 'agentboot_original_vars.py'
spec = importlib.util.spec_from_file_location('original_vars', MODULE)
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class OriginalVarsTest(unittest.TestCase):
    def test_unrelated_vmgs_and_ms_template_refuse(self):
        with self.assertRaisesRegex(ValueError, 'exact retained'):
            subject.original_variables(bytes(4194816))
        with self.assertRaisesRegex(ValueError, 'exact blank'):
            subject.build_derivative(bytes(540672), {})

    def test_truncated_or_unknown_firmware_never_parses(self):
        for image in (b'', bytes(72), bytes(540672), b'\xff' * 540672):
            with self.subTest(length=len(image)), self.assertRaises(ValueError):
                subject.inspect_store(image)

    def test_actual_cli_wrong_input_refuses_before_any_output(self):
        with tempfile.TemporaryDirectory(prefix='opemos-original-vars-refuse-') as directory:
            root = Path(directory)
            root.chmod(0o700)
            bad = root / 'not-original.vmgs'; bad.write_bytes(b'preserve')
            output = root / 'new-only'
            child = subprocess.run([sys.executable, str(MODULE), '--vmgs', str(bad),
                                    '--code', str(root / 'absent'), '--template', str(root / 'absent'),
                                    '--destination', str(output)], capture_output=True, timeout=3)
            self.assertNotEqual(child.returncode, 0)
            self.assertFalse(output.exists())
            self.assertEqual(bad.read_bytes(), b'preserve')

    def test_real_pinned_transaction_requires_private_admitted_inputs(self):
        # No synthetic success fixture, replacement pins or target-method patch.
        # Exact source inputs must be staged in the test VM under separate
        # admission; CI without them records SKIP, never a preserving import pass.
        names = ('OPEMOS_AGENTBOOT_VMGS', 'OPEMOS_AGENTBOOT_CODE', 'OPEMOS_AGENTBOOT_TEMPLATE')
        if not all(os.environ.get(name) for name in names):
            self.skipTest('exact private original VMGS and pinned OVMF inputs not admitted/staged')
        vmgs, code, template = [Path(os.environ[name]) for name in names]
        originals = [p.read_bytes() for p in (vmgs, code, template)]
        with tempfile.TemporaryDirectory(prefix='opemos-original-vars-transaction-') as directory:
            root = Path(directory); root.chmod(0o700)
            target = root / 'fresh'
            child = subprocess.run([sys.executable, str(MODULE), '--vmgs', str(vmgs),
                                    '--code', str(code), '--template', str(template),
                                    '--destination', str(target)], capture_output=True, timeout=10)
            self.assertEqual(child.returncode, 0, child.stderr.decode())
            import json
            receipt = json.loads(child.stdout)
            image = (target / 'agentboot-original-vars.fd').read_bytes()
            hashes = subject.verify_derivative(image)
            self.assertEqual(hashes, {name: pin[2] for name, pin in subject.PINS.items()})
            self.assertEqual(receipt['originalVariableSha256'], hashes)
            self.assertEqual(receipt['runtimeSecureBoot'], 'UNPROVEN')
            self.assertFalse(receipt['bootAuthorized'])
            retry = subprocess.run(child.args, capture_output=True, timeout=10)
            self.assertNotEqual(retry.returncode, 0)
            self.assertEqual((target / 'agentboot-original-vars.fd').read_bytes(), image)
            # Change each original trust data value in the derivative, then
            # independently parse/re-hash it: every change must be a refusal.
            for name in subject.PINS:
                value = subject.inspect_store(image)[name][2]
                offset = image.index(value)
                corrupted = bytearray(image); corrupted[offset] ^= 1
                with self.subTest(name=name), self.assertRaises(ValueError):
                    subject.verify_derivative(bytes(corrupted))
            # A changed policy byte must not be promoted to Secure Boot On.
            marker = 'SecureBootEnable'.encode('utf-16-le') + b'\0\0'
            offset = image.index(marker) + len(marker)
            corrupted = bytearray(image); corrupted[offset] = 0
            with self.assertRaisesRegex(ValueError, 'must be On'):
                subject.verify_derivative(bytes(corrupted))
        self.assertEqual([p.read_bytes() for p in (vmgs, code, template)], originals)


if __name__ == '__main__':
    unittest.main()
