"""Real filesystem guards; run in the admitted Mac job, never as UI acceptance."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import stage_macos_app


class CompanionFilesystemGuards(unittest.TestCase):
    def test_write_safe_closed_companion_and_tamper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = b"retained immutable fixture\n"
            source = root / "base.qcow2"
            source.write_bytes(data)
            source.chmod(0o444)
            (root / "appliance-manifest.json").write_text("{}")
            expected = [(source.name, len(data), hashlib.sha256(data).hexdigest())]
            stage_macos_app.verify_files(root, expected)
            self.assertEqual(source.read_bytes(), data)
            (root / "extra").write_bytes(b"undeclared")
            with self.assertRaises(ValueError):
                stage_macos_app.verify_files(root, expected)
            (root / "extra").unlink()
            source.chmod(0o644)
            source.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                stage_macos_app.verify_files(root, expected)

    def test_symlink_and_wrong_architecture_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "outside").write_bytes(b"x")
            (root / "base").symlink_to(root / "outside")
            (root / "appliance-manifest.json").write_text("{}")
            with self.assertRaises(ValueError):
                stage_macos_app.verify_files(root, [("base", 1, hashlib.sha256(b"x").hexdigest())])
            with self.assertRaises(ValueError):
                stage_macos_app.verify_companion(root)


if __name__ == "__main__":
    unittest.main()
