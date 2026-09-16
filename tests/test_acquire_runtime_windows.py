import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.acquire_runtime_windows import acquire_source, current_lock_matches, load_lock, move_tree


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


if __name__ == "__main__":
    unittest.main()
