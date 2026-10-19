"""Actual native producer path/descriptor transaction; no stat-method override.

Run in admitted native CI/VM only. A collection failure retains exact metadata
differences; it is not evidence of a particular Windows mechanism by itself.
"""
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('native_producer', ROOT / 'scripts/record_executable_artifact.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class NativeProducerCustody(unittest.TestCase):
    def test_actual_exe_path_descriptor_hash_and_readback(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve() / 'producer.exe'
            data = b'bounded native producer fixture, not an executable'
            path.write_bytes(data)
            value, raw = M.held(path, len(data), keep=True)
            self.assertEqual(raw, data)
            self.assertEqual(value, {'name': path.name, 'bytes': len(data),
                                    'sha256': hashlib.sha256(data).hexdigest()})
            self.assertEqual(path.read_bytes(), data)

    def test_actual_size_limit_remains_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve() / 'producer.exe'
            path.write_bytes(b'over cap')
            with self.assertRaisesRegex(ValueError, 'Actual non-reparse'):
                M.held(path, 1)


if __name__ == '__main__':
    unittest.main()
