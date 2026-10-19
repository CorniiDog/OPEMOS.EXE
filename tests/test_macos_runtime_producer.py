"""Actual filesystem/archive and native loader boundary tests, on hosted M1."""
import importlib.util
import http.server
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from acquire_runtime_macos import extract, load_lock, relocate, relocated_relative, close_curated_links
from prepare_macos_fullstack import ArtifactRanges


class DarwinProducer(unittest.TestCase):
    def test_actual_http_range_consumer_and_ignored_range_fault(self):
        payload = b"bounded exact immutable artifact bytes"
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == "/ignores-range":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                start, end = map(int, self.headers["Range"].removeprefix("bytes=").split("-"))
                self.send_response(206)
                self.send_header("Content-Range", f"bytes {start}-{end}/{len(payload)}")
                self.end_headers()
                self.wfile.write(payload[start:end + 1])
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            reader = ArtifactRanges(origin + "/exact", len(payload))
            self.assertEqual(reader.read(7), payload[:7])
            reader.seek(-5, 2)
            self.assertEqual(reader.read(), payload[-5:])
            self.assertEqual(reader.bytes_read, 12)
            with self.assertRaises(ValueError):
                reader.seek(len(payload) + 1)
            with self.assertRaisesRegex(ValueError, "exact byte range"):
                ArtifactRanges(origin + "/ignores-range", len(payload)).read(7)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

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

    def test_real_provider_sdk_curation_does_not_follow_prefix_certificate_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "python.tar.gz"
            prefix = "python@3.14/1/"
            with tarfile.open(archive, "w:gz") as source:
                for name in ["LICENSE", "Frameworks/Python.framework/Versions/3.14/lib/python3.14/json/__init__.py"]:
                    item = tarfile.TarInfo(prefix + name)
                    item.size = 7
                    source.addfile(item, io.BytesIO(b"fixture"))
                item = tarfile.TarInfo(prefix + "lib/python3.14/site-packages/pip/_vendor/certifi/cacert.pem")
                item.type, item.linkname = tarfile.SYMTYPE, "../../../../../../../../../etc/ca-certificates/cert.pem"
                source.addfile(item)
            output = root / "unpacked"
            output.mkdir()
            extract(archive, output, "python@3.14")
            self.assertFalse((output / prefix / "lib/python3.14/site-packages/pip").exists())
            self.assertEqual((output / prefix / "Frameworks/Python.framework/Versions/3.14/lib/python3.14/json/__init__.py").read_bytes(), b"fixture")
            self.assertEqual(len(list((output / "licenses/python@3.14").iterdir())), 1)
            self.assertEqual(relocated_relative("Frameworks/Python.framework/Versions/3.14/Python"),
                             Path("Frameworks/Python.framework-payload/Versions/3.14/Python"))

    def test_real_curated_directory_alias_closure_and_unknown_dangling_fault(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "bottle.tar.gz"
            with tarfile.open(archive, "w:gz") as source:
                item = tarfile.TarInfo("fixture/1/share/man")
                item.type = tarfile.DIRTYPE
                source.addfile(item)
                item = tarfile.TarInfo("fixture/1/lib/documentation-alias")
                item.type, item.linkname = tarfile.SYMTYPE, "../share/man"
                source.addfile(item)
            output = root / "output"
            output.mkdir()
            omitted = extract(archive, output, "fixture")
            removed = close_curated_links(output, omitted)
            self.assertEqual(len(removed), 1)
            self.assertFalse((output / "fixture/1/lib/documentation-alias").is_symlink())
            (output / "unknown").symlink_to(output / "never-declared")
            with self.assertRaisesRegex(ValueError, "Unknown dangling"):
                close_curated_links(output, omitted)

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
            main = root / "main.c"
            main.write_text("extern int answer(void); int main(void) { return answer() == 42 ? 0 : 1; }\n")
            executable = keg / "consumer"
            subprocess.run(["xcrun", "clang", str(main), "-L" + str(library.parent), "-lfixture",
                            "-o", str(executable)], check=True)
            before = subprocess.check_output(["/usr/bin/otool", "-L", str(executable)], text=True)
            self.assertIn("/opt/homebrew/opt/fixture/lib/libfixture.dylib", before)
            rows = relocate(root, {"fixture": keg})
            self.assertEqual(len(rows), 2)
            self.assertNotEqual(rows[0]["before"], rows[0]["after"])
            subprocess.run([str(executable)], check=True)
            # A separate actual process loads the transformed library.
            subprocess.run([sys.executable, "-c", "import ctypes,sys; assert ctypes.CDLL(sys.argv[1]).answer()==42", str(library)], check=True)


if __name__ == "__main__":
    unittest.main()
