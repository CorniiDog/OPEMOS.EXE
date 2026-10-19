"""Actual filesystem/archive and native loader boundary tests, on hosted M1."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from acquire_runtime_macos import extract, load_lock, relocate


class DarwinProducer(unittest.TestCase):
    def test_locked_provider_graph_and_missing_dependency(self):
        lock = load_lock(ROOT / "runtime/macos-arm64.sources.json")
        self.assertIn("qemu", lock["formulae"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            del lock["formulae"]["qemu"]
            path.write_text(json.dumps(lock))
            with self.assertRaises(KeyError):
                load_lock(path)

    def archive(self, path, name, kind=tarfile.REGTYPE, link=""):
        with tarfile.open(path, "w:gz") as archive:
            item = tarfile.TarInfo(name)
            item.type, item.linkname = kind, link
            data = b"immutable license fixture\n"
            item.size = len(data) if kind == tarfile.REGTYPE else 0
            archive.addfile(item, io.BytesIO(data) if item.size else None)

    def test_real_archive_regular_and_escape_device_faults(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "bottle.tar.gz"
            output = root / "output"
            output.mkdir()
            self.archive(archive, "formula/1/LICENSE")
            extract(archive, output)
            self.assertEqual((output / "formula/1/LICENSE").read_bytes(), b"immutable license fixture\n")
            for name, kind, link in [("../escape", tarfile.REGTYPE, ""),
                                     ("device", tarfile.CHRTYPE, ""),
                                     ("link", tarfile.SYMTYPE, "/etc/passwd")]:
                self.archive(archive, name, kind, link)
                with self.assertRaises(ValueError):
                    extract(archive, output)
            self.assertFalse((root / "escape").exists())

    @unittest.skipUnless(sys.platform == "darwin", "actual Darwin compiler/loader required")
    def test_real_native_library_relocation_signing_and_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keg = root / "kegs/fixture/1"
            (keg / "lib").mkdir(parents=True)
            library = keg / "lib/libfixture.dylib"
            source = root / "fixture.c"
            source.write_text("int answer(void) { return 42; }\n")
            subprocess.run(["xcrun", "clang", "-dynamiclib", str(source), "-o", str(library),
                            "-Wl,-install_name,/opt/homebrew/opt/fixture/lib/libfixture.dylib"], check=True)
            rows = relocate(root, {"fixture": keg})
            self.assertEqual(len(rows), 1)
            self.assertNotEqual(rows[0]["before"], rows[0]["after"])
            # A separate actual process loads the transformed library.
            subprocess.run([sys.executable, "-c", "import ctypes,sys; assert ctypes.CDLL(sys.argv[1]).answer()==42", str(library)], check=True)


if __name__ == "__main__":
    unittest.main()
