import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.acquire_appliance_windows import acquire, load_lock, stage


class WindowsApplianceAcquisitionTests(unittest.TestCase):
    def test_reuses_exact_cache_and_replaces_tamper_transactionally(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        payload = b"exact appliance"
        lock = {
            "schema_version": 1,
            "filename": "fedora-builder.qcow2",
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "url": "https://download.fedoraproject.org/fixture",
            "fedora_release": "44",
            "fedora_compose": "1.7",
            "architecture": "x86_64",
        }
        cache = root / "cache"
        cache.mkdir()
        target = cache / lock["filename"]
        target.write_bytes(payload)
        calls = []
        self.assertEqual(acquire(lock, cache, lambda *_: calls.append("download")), target)
        self.assertEqual(calls, [])
        target.write_bytes(b"tampered")

        def download(_url, destination):
            calls.append("replacement")
            Path(destination).write_bytes(payload)

        self.assertEqual(acquire(lock, cache, download).read_bytes(), payload)
        self.assertEqual(calls, ["replacement"])
        target.write_bytes(b"tampered again")
        with self.assertRaisesRegex(SystemExit, "exact locked identity"):
            acquire(lock, cache, lambda _url, destination: Path(destination).write_bytes(b"wrong"))
        self.assertFalse(target.exists())
        self.assertEqual(list(cache.glob("*.partial")), [])

    def test_real_lock_and_cloud_init_stage_a_closed_bundle(self):
        repository = Path(__file__).resolve().parent.parent
        lock = load_lock(repository / "runtime/windows-fedora-appliance.json")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        image = root / lock["filename"]
        # Stage uses the supplied lock identity, so use the authenticated local
        # fixture only for the small closed-tree behavior and restore its identity.
        fixture_lock = dict(lock, size=7, sha256=hashlib.sha256(b"qcow2\n").hexdigest())
        image.write_bytes(b"qcow2\n")
        output = root / "output"
        stage(fixture_lock, image, repository / "builder/appliance/cloud-init", output)
        manifest = json.loads((output / "appliance-manifest.json").read_text())
        self.assertEqual(manifest["files"][0]["sha256"], fixture_lock["sha256"])
        self.assertEqual(
            sorted(path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()),
            ["appliance-manifest.json", "cloud-init/meta-data", "cloud-init/user-data", "fedora-builder.qcow2"],
        )

    def test_lock_rejects_unpinned_origin_and_extra_fields(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "lock.json"
        document = json.loads((Path(__file__).resolve().parent.parent / "runtime/windows-fedora-appliance.json").read_text())
        document["url"] = "https://example.invalid/appliance"
        document["unexpected"] = True
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(SystemExit, "lock is invalid"):
            load_lock(path)


if __name__ == "__main__":
    unittest.main()
