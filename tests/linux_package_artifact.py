import json
from pathlib import Path
import tempfile
import unittest
import shutil

from scripts.stage_linux_packages import stage


COMMIT = "a" * 40


class LinuxPackageArtifactTests(unittest.TestCase):
    def test_bad_pinned_appliance_refuses_before_creating_artifact(self):
        temporary, root, _, _ = self.fixture()
        self.addCleanup(temporary.cleanup)
        (root / 'runtime').mkdir()
        shutil.copyfile(Path(__file__).resolve().parents[1] / 'runtime/windows-fedora-appliance.json',
                        root / 'runtime/windows-fedora-appliance.json')
        bad = root / 'wrong.qcow2'
        bad.write_bytes(b'not the pinned Fedora image')
        with self.assertRaisesRegex(SystemExit, 'existing authenticated Fedora pin'):
            stage(root, root / 'artifact', COMMIT, bad)
        self.assertFalse((root / 'artifact').exists())

    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        deb = root / "src-tauri/target/debug/bundle/deb/test.deb"
        app = root / "src-tauri/target/debug/bundle/appimage/test.AppImage"
        deb.parent.mkdir(parents=True)
        app.parent.mkdir(parents=True)
        deb.write_bytes(b"!<arch>\npackage")
        header = bytearray(20)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = (62).to_bytes(2, "little")
        app.write_bytes(header + b"application")
        app.chmod(0o755)
        return temporary, root, deb, app

    def test_stages_exact_packages_with_checksums_and_provenance(self):
        temporary, root, _, _ = self.fixture()
        self.addCleanup(temporary.cleanup)
        output = root / "artifact"
        result = stage(root, output, COMMIT)
        self.assertEqual(result["sourceCommit"], COMMIT)
        self.assertEqual([item["filename"] for item in result["packages"]], ["test.deb", "test.AppImage"])
        self.assertEqual(len((output / "SHA256SUMS.txt").read_text().splitlines()), 2)
        self.assertEqual(json.loads((output / "provenance.json").read_text()), result)

    def test_rejects_duplicate_package_and_existing_output(self):
        temporary, root, deb, _ = self.fixture()
        self.addCleanup(temporary.cleanup)
        (deb.parent / "other.deb").write_bytes(deb.read_bytes())
        with self.assertRaisesRegex(SystemExit, "exactly one Debian"):
            stage(root, root / "artifact", COMMIT)
        (deb.parent / "other.deb").unlink()
        (root / "artifact").mkdir()
        with self.assertRaisesRegex(SystemExit, "must not already exist"):
            stage(root, root / "artifact", COMMIT)

    def test_rejects_non_executable_wrong_arch_and_bad_commit(self):
        temporary, root, _, app = self.fixture()
        self.addCleanup(temporary.cleanup)
        app.chmod(0o644)
        with self.assertRaisesRegex(SystemExit, "must be executable"):
            stage(root, root / "artifact-a", COMMIT)
        app.chmod(0o755)
        data = bytearray(app.read_bytes())
        data[18:20] = (183).to_bytes(2, "little")
        app.write_bytes(data)
        with self.assertRaisesRegex(SystemExit, "x86_64"):
            stage(root, root / "artifact-b", COMMIT)
        with self.assertRaisesRegex(SystemExit, "40-character"):
            stage(root, root / "artifact-c", "not-a-commit")


if __name__ == "__main__":
    unittest.main()
