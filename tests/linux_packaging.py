"""Corner cases for the local test-package binary comparison."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    'linux_packaging', Path(__file__).resolve().parent.parent / 'scripts/check_linux_packaging.py')
packaging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaging)


class BundleMarkerTests(unittest.TestCase):
    def compare(self, original, bundled, accepted=False):
        with tempfile.TemporaryDirectory(prefix='opemos-bundle-marker-') as directory:
            first, second = Path(directory) / 'original', Path(directory) / 'bundled'
            first.write_bytes(original)
            second.write_bytes(bundled)
            if accepted:
                packaging.verify_bundle_marker(first, second)
            else:
                with self.assertRaises(ValueError):
                    packaging.verify_bundle_marker(first, second)

    def test_exact_marker_across_chunk_boundary(self):
        # Differences cross the reader boundary, including their prefix context.
        prefix = b'x' * (1024 * 1024 - 1 - len(b'__TAURI_BUNDLE_TYPE_VAR_'))
        self.compare(prefix + b'__TAURI_BUNDLE_TYPE_VAR_UNK-tail',
                     prefix + b'__TAURI_BUNDLE_TYPE_VAR_DEB-tail', accepted=True)

    def test_absent_unchanged_or_wrong_marker(self):
        for original, bundled in [(b'', b''), (b'plain', b'plain'),
                                  (b'UNK', b'DEB'),
                                  (b'__TAURI_BUNDLE_TYPE_VAR_UNK', b'__TAURI_BUNDLE_TYPE_VAR_RPM')]:
            self.compare(original, bundled)

    def test_extra_changes_and_multiple_markers(self):
        original = b'__TAURI_BUNDLE_TYPE_VAR_UNK'
        bundled = b'__TAURI_BUNDLE_TYPE_VAR_DEB'
        self.compare(original + b'first', bundled + b'other')
        self.compare(original * 2, bundled * 2)
        self.compare(original + b'a', bundled + b'')

    def test_malformed_three_byte_change(self):
        self.compare(b'0123456789', b'012x4y6z89')


if __name__ == '__main__':
    unittest.main()
