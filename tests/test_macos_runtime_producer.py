"""Actual filesystem/archive and native loader boundary tests, on hosted M1."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from acquire_runtime_macos import extract, load_lock, relocate, relocated_relative, close_curated_links, is_macho_code, verify_firmware_pair
from stage_macos_app import FIRMWARE, FEDORA
from prepare_macos_fullstack import consume_input_receipt, RECOVERY_URL, RECOVERY_BYTES, RECOVERY_SHA256, reuse_retained, RETAINED_ARCHIVE_BYTES


class DarwinProducer(unittest.TestCase):
    def test_actual_workflow_readiness_leaves_normal_evidence_create_only(self):
        import textwrap
        workflow = (ROOT / '.github/workflows/macos-arm64.yml').read_text()
        code = textwrap.dedent(workflow.split("python3 - <<'PYMAC'\n", 1)[1]
                               .split('\n          PYMAC', 1)[0])
        code = code.replace('${{ env.OPEMOS_EXE_COMMIT }}', '1' * 40)
        for present in (False, True):
            with self.subTest(present=present), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                if present:
                    for name in ('scripts/check_macos_arm64_ci.py', 'tests/macos-ui-smoke.swift'):
                        path = root / name
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text('source operand\n')
                result = subprocess.run([sys.executable, '-c', code], cwd=root,
                                        capture_output=True, text=True, timeout=10)
                out = root / 'build/macos-arm64-evidence'
                if present:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(out.exists())
                    # The actual next consumer's create-only filesystem
                    # operation must remain possible, without deleting evidence.
                    out.mkdir(parents=True, exist_ok=False)
                    with self.assertRaises(FileExistsError):
                        out.mkdir(parents=True, exist_ok=False)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    evidence = json.loads((out / 'producer-readiness.json').read_bytes())
                    self.assertFalse(evidence['producer_ready'])
                    self.assertFalse(evidence['full_stack_passed'])
                    self.assertEqual(len(evidence['missing_files']), 2)

    def test_retained_derivative_refuses_size_hash_directory_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "archive.zip"
            output, evidence = root / "output", root / "evidence"
            archive.write_bytes(b"not the accepted archive")
            with self.assertRaisesRegex(ValueError, "archive identity mismatch"):
                reuse_retained(ROOT, output, evidence, archive)
            # Same logical size, sparse wrong bytes: exercise the hash branch
            # without allocating another full archive or overriding the producer.
            with archive.open("wb") as stream:
                stream.truncate(RETAINED_ARCHIVE_BYTES)
            with self.assertRaisesRegex(ValueError, "archive identity mismatch"):
                reuse_retained(ROOT, output, evidence, archive)
            link = root / "link.zip"
            link.symlink_to(archive)
            with self.assertRaisesRegex(ValueError, "archive identity mismatch"):
                reuse_retained(ROOT, output, evidence, link)
            directory = root / "directory.zip"
            directory.mkdir()
            with self.assertRaisesRegex(ValueError, "archive identity mismatch"):
                reuse_retained(ROOT, output, evidence, directory)
            self.assertFalse(output.exists())
            self.assertFalse(evidence.exists())

    def test_actual_private_directory_custody_and_receipt_faults(self):
        # Metadata custody only; production subsequently verifies all real
        # runtime/companion/recovery bytes. No fake payload acceptance.
        with tempfile.TemporaryDirectory(prefix="opemos-macos-inputs-") as generated, tempfile.TemporaryDirectory() as evidence:
            root = Path(generated).resolve(strict=True)
            receipt = Path(evidence) / "inputs.json"
            recovery = Path.home() / "Documents/opemos-pinned-recovery.img"
            metadata = root.stat()
            data = {"inputRoot": str(root), "identity": {"device": metadata.st_dev,
                    "inode": metadata.st_ino, "uid": os.getuid(), "mode": 0o700},
                    "complete": True, "firmwareSource": "locked-qemu-bottle-exact-existing-pair",
                    "recovery": {"url": RECOVERY_URL, "path": str(recovery),
                                 "bytes": RECOVERY_BYTES, "sha256": RECOVERY_SHA256},
                    "applianceSHA256": FEDORA[2]}
            receipt.write_text(json.dumps(data))
            self.assertEqual(consume_input_receipt(receipt, ROOT, recovery)[1], root)
            root.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "UID/directory identity"):
                consume_input_receipt(receipt, ROOT, recovery)
            root.chmod(0o700)
            for field in ("uid", "inode"):
                changed = json.loads(json.dumps(data))
                changed["identity"][field] += 1
                receipt.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    consume_input_receipt(receipt, ROOT, recovery)
            for changed in (dict(data, unexpected=True), dict(data, complete="true"),
                            dict(data, applianceSHA256="0" * 64), []):
                receipt.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    consume_input_receipt(receipt, ROOT, recovery)
            receipt.write_bytes(b"x" * 65537)
            with self.assertRaisesRegex(ValueError, "bounded regular"):
                consume_input_receipt(receipt, ROOT, recovery)
            alias = root.with_name(root.name + "-link")
            alias.symlink_to(root, target_is_directory=True)
            try:
                receipt.write_text(json.dumps(dict(data, inputRoot=str(alias))))
                with self.assertRaisesRegex(ValueError, "custody"):
                    consume_input_receipt(receipt, ROOT, recovery)
            finally:
                alias.unlink()
            receipt.write_text(json.dumps(data))
            linked = receipt.with_name("linked.json")
            linked.symlink_to(receipt)
            with self.assertRaisesRegex(ValueError, "bounded regular"):
                consume_input_receipt(linked, ROOT, recovery)

    def test_firmware_missing_same_size_corruption_directory_and_link_faults(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "firmware pin mismatch"):
                verify_firmware_pair(root)
            name = Path(next(iter(FIRMWARE))).name
            path = root / name
            path.write_bytes(b"\0" * FIRMWARE[next(iter(FIRMWARE))][0])
            with self.assertRaisesRegex(ValueError, "firmware pin mismatch"):
                verify_firmware_pair(root)
            path.unlink()
            path.mkdir()
            with self.assertRaisesRegex(ValueError, "firmware pin mismatch"):
                verify_firmware_pair(root)
            path.rmdir()
            path.symlink_to(ROOT / "LICENSE")
            with self.assertRaisesRegex(ValueError, "firmware pin mismatch"):
                verify_firmware_pair(root)

    def test_java_magic_is_not_a_macho_architecture_table(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "javaversion.class"
            path.write_bytes(bytes.fromhex("cafebabe0000003d") + b"class-data" * 300)
            self.assertFalse(is_macho_code(path))
            path.write_bytes(bytes.fromhex("cafebabe00000001") + b"\0" * 20)
            self.assertFalse(is_macho_code(path))
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

    def test_real_provider_installation_state_is_not_client_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "openssh.tar.gz"
            with tarfile.open(archive, "w:gz") as source:
                for name in ["openssh/1/LICENSE", "openssh/1/bin/ssh", "openssh/1/.bottle/etc/ssh/ssh_host_rsa_key"]:
                    item = tarfile.TarInfo(name)
                    item.size = 7
                    source.addfile(item, io.BytesIO(b"fixture"))
            original = archive.read_bytes()
            output = root / "output"
            output.mkdir()
            omitted = extract(archive, output, "openssh")
            self.assertTrue(omitted)
            self.assertFalse((output / "openssh/1/.bottle").exists())
            self.assertEqual((output / "openssh/1/bin/ssh").read_bytes(), b"fixture")
            self.assertEqual(archive.read_bytes(), original)

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
            self.assertTrue(is_macho_code(library))
            # One real ARM64 slice, accepted by lipo/codesign/dyld. No x86 lane.
            data = library.read_bytes()
            cpu, subtype = struct.unpack_from("<II", data, 4)
            fat_library = keg / "lib/libfatfixture.dylib"
            fat_header = struct.pack(">IIIIIII", 0xcafebabe, 1, cpu, subtype, 16384, len(data), 14)
            fat_library.write_bytes(fat_header + b"\0" * (16384 - len(fat_header)) + data)
            fat_library.chmod(0o755)
            self.assertTrue(is_macho_code(fat_library))
            main = root / "main.c"
            main.write_text("extern int answer(void); int main(void) { return answer() == 42 ? 0 : 1; }\n")
            executable = keg / "consumer"
            subprocess.run(["xcrun", "clang", str(main), "-L" + str(library.parent), "-lfixture",
                            "-o", str(executable)], check=True)
            before = subprocess.check_output(["/usr/bin/otool", "-L", str(executable)], text=True)
            self.assertIn("/opt/homebrew/opt/fixture/lib/libfixture.dylib", before)
            rows = relocate(root, {"fixture": keg})
            self.assertEqual(len(rows), 3)
            self.assertNotEqual(rows[0]["before"], rows[0]["after"])
            subprocess.run([str(executable)], check=True)
            # A separate actual process loads the transformed library.
            subprocess.run([sys.executable, "-c", "import ctypes,sys; assert ctypes.CDLL(sys.argv[1]).answer()==42", str(library)], check=True)
            subprocess.run([sys.executable, "-c", "import ctypes,sys; assert ctypes.CDLL(sys.argv[1]).answer()==42", str(fat_library)], check=True)


if __name__ == "__main__":
    unittest.main()
