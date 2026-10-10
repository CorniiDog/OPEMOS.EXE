import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error

from scripts.acquire_runtime_windows import MIN_RANGE_BYTES, RANGE_BYTES, acquire_source, current_lock_matches, download_locked_ranges, load_lock, move_tree, remove_empty_files, verify_authenticode


class WindowsRuntimeAcquisitionTests(unittest.TestCase):
    def test_repository_lock_is_the_exact_proven_runtime_closure(self):
        root = Path(__file__).resolve().parents[1]
        lock = load_lock(root / "runtime/windows-x86_64.sources.json")
        self.assertEqual(
            [item["component"] for item in lock["sources"]],
            ["git-for-windows", "github-cli", "python", "qemu", "cdrtools-binary", "cdrtools-source"],
        )
        entry = (root / "bundle_windows.ps1").read_text()
        self.assertIn("scripts/acquire_runtime_windows.py", entry)
        self.assertIn("build/runtime/windows", entry)
        qemu = next(item for item in lock["sources"] if item["component"] == "qemu")
        self.assertEqual(qemu["version"], "8.1.0")
        self.assertEqual(qemu["sha256"], "92fa6d148ec3fc25f875cbcbde2a5edc1fc5413ac44a9c77344ce7cbea0764d7")
        self.assertEqual(qemu["authenticode_thumbprint"], "2F92CB990D57719BDCCA2D72134378614A040D9B")

    def test_qemu_authenticode_requires_valid_exact_publisher(self):
        valid = mock.Mock(return_value=mock.Mock(returncode=0, stdout='{"Status":"Valid","Thumbprint":"ABCDEF"}'))
        verify_authenticode(Path("qemu.exe"), "ABCDEF", valid)
        command = valid.call_args.args[0]
        self.assertEqual(command[:4], ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand"])
        decoded = base64.b64decode(command[4]).decode("utf-16le")
        self.assertIn(r"Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1", decoded)
        self.assertIn(base64.b64encode(b"qemu.exe").decode("ascii"), decoded)
        self.assertNotIn("qemu.exe", decoded)
        with self.assertRaisesRegex(SystemExit, "publisher identity is not valid"):
            verify_authenticode(Path("qemu.exe"), "DIFFERENT", valid)
        expired = mock.Mock(return_value=mock.Mock(returncode=0, stdout='{"Status":"UnknownError","Thumbprint":"ABCDEF"}'))
        with self.assertRaisesRegex(SystemExit, "publisher identity is not valid"):
            verify_authenticode(Path("qemu.exe"), "ABCDEF", expired)
        failed = mock.Mock(return_value=mock.Mock(returncode=7, stderr="signature command failed\nwith detail"))
        with self.assertRaisesRegex(SystemExit, r"inspection failed \(7\): signature command failed with detail"):
            verify_authenticode(Path("qemu.exe"), "ABCDEF", failed)

    def test_cache_reuses_exact_and_replaces_tamper_without_partial_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            payload = b"pinned Windows archive"
            item = {"component":"fixture","version":"1","url":"https://example.invalid/a.zip","file":"a.zip","size":len(payload),"sha256":hashlib.sha256(payload).hexdigest()}
            target = cache / item["file"]
            target.write_bytes(payload)
            downloader = mock.Mock()
            self.assertEqual(acquire_source(item, cache, downloader), target)
            downloader.assert_not_called()
            target.write_bytes(b"tampered")
            acquire_source(item, cache, lambda _url, partial: Path(partial).write_bytes(payload))
            self.assertEqual(target.read_bytes(), payload)
            target.write_bytes(b"tampered again")
            with self.assertRaisesRegex(SystemExit, "identity mismatch"):
                acquire_source(item, cache, lambda _url, partial: Path(partial).write_bytes(b"wrong"))
            self.assertFalse(target.exists())
            self.assertEqual(list(cache.glob(".*.part")), [])

    def test_existing_runtime_reuse_is_bound_to_exact_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = {"schema_version":1,"platform":"windows","architecture":"x86_64","sources":[]}
            (root / "source-provenance.json").write_text(json.dumps(lock, sort_keys=True, separators=(",", ":")) + "\n")
            self.assertTrue(current_lock_matches(root, lock))
            self.assertFalse(current_lock_matches(root, dict(lock, architecture="arm64")))

    def test_same_endpoint_ranges_resume_522_and_require_exact_response_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            partial = Path(temporary) / "archive.part"
            payload = b"a" * RANGE_BYTES + b"final"
            requests = []
            sleeps = []
            class Response:
                def __init__(self, body, content_range): self.body=body; self.offset=0; self.status=206; self.headers={"Content-Range":content_range}
                def __enter__(self): return self
                def __exit__(self,*_args): return False
                def read(self,amount):
                    amount=min(amount,777_777); block=self.body[self.offset:self.offset+amount]; self.offset+=len(block); return block
            def opener(request,timeout):
                requests.append((request.full_url,request.headers["Range"],timeout,request.get_header("Accept-encoding"),request.get_header("User-agent")))
                if len(requests)==1: raise urllib.error.HTTPError(request.full_url,522,"transient",{},None)
                start,end=map(int,request.headers["Range"].removeprefix("bytes=").split("-"))
                return Response(payload[start:end+1],f"bytes {start}-{end}/{len(payload)}")
            download_locked_ranges("https://example.invalid/a.zip",partial,len(payload),opener,sleeps.append)
            self.assertEqual(partial.read_bytes(),payload)
            self.assertEqual([request[1] for request in requests],[f"bytes=0-{RANGE_BYTES-1}",f"bytes=0-{RANGE_BYTES//2-1}",f"bytes={RANGE_BYTES//2}-{RANGE_BYTES-1}",f"bytes={RANGE_BYTES}-{len(payload)-1}"])
            self.assertTrue(all(request[3:]==("identity","OPEMOS.EXE-runtime-acquisition/1") for request in requests))
            self.assertEqual(sleeps,[10])

            def invalid_response(request,timeout): return Response(b"wrong","bytes 0-4/5")
            with self.assertRaisesRegex(SystemExit,"range response is invalid"):
                download_locked_ranges("https://example.invalid/a.zip",partial,6,invalid_response,sleeps.append)

            sleeps.clear()
            def unavailable(request,timeout): raise urllib.error.HTTPError(request.full_url,522,"transient",{},None)
            with self.assertRaises(urllib.error.HTTPError):
                download_locked_ranges("https://example.invalid/a.zip",partial,6,unavailable,sleeps.append)
            self.assertEqual(sleeps,[10,30,60,120,180,300,300])

            attempted=[]
            def shrinking_ranges(request,timeout):
                attempted.append(request.headers["Range"])
                if len(attempted)<5: raise urllib.error.HTTPError(request.full_url,522,"transient",{},None)
                start,end=map(int,request.headers["Range"].removeprefix("bytes=").split("-"))
                return Response(b"x"*(end-start+1),f"bytes {start}-{end}/{RANGE_BYTES}")
            download_locked_ranges("https://example.invalid/a.zip",partial,RANGE_BYTES,shrinking_ranges,lambda _delay: None)
            self.assertEqual(attempted[:5],[f"bytes=0-{RANGE_BYTES-1}",f"bytes=0-{RANGE_BYTES//2-1}",f"bytes=0-{RANGE_BYTES//4-1}",f"bytes=0-{RANGE_BYTES//8-1}",f"bytes=0-{MIN_RANGE_BYTES-1}"])

    def test_archive_root_move_does_not_delete_an_already_moved_temporary_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extracted = root / ".gh"
            extracted.mkdir()
            (extracted / "LICENSE").write_text("license")
            destination = root / "gh"
            move_tree(extracted, destination, extracted)
            self.assertEqual((destination / "LICENSE").read_text(), "license")
            self.assertFalse(extracted.exists())

    def test_zero_byte_archive_placeholders_are_removed_before_manifesting(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "empty.pem").write_bytes(b"")
            (root / "command.exe").write_bytes(b"command")
            remove_empty_files(root)
            self.assertFalse((root / "empty.pem").exists())
            self.assertEqual((root / "command.exe").read_bytes(), b"command")


if __name__ == "__main__":
    unittest.main()
