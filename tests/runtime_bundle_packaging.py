import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.stage_runtime_bundle import REQUIRED, stage


class RuntimeBundlePackagingTests(unittest.TestCase):
    COMMIT = "a" * 40
    def fixture(self, platform="linux"):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        runtime = root / "runtime"
        (runtime / "bin").mkdir(parents=True)
        (runtime / "licenses").mkdir()
        files = []
        commands = {}
        for name in sorted(REQUIRED[platform]):
            path = runtime / "bin" / name
            path.write_bytes((name + "\n").encode())
            relative = path.relative_to(runtime).as_posix()
            commands[name] = relative
            files.append({"path": relative, "size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        license_path = runtime / "licenses" / "fixture.txt"
        license_path.write_text("fixture license\n")
        files.append({"path": "licenses/fixture.txt", "size": license_path.stat().st_size, "sha256": hashlib.sha256(license_path.read_bytes()).hexdigest()})
        manifest = {"schema_version": 1, "platform": platform, "commands": commands, "files": files, "components": [{"name": "fixture", "version": "1", "license_files": ["licenses/fixture.txt"]}]}
        (runtime / "runtime-manifest.json").write_text(json.dumps(manifest, separators=(",", ":")))
        application = root / "application"
        application.write_bytes(b"application")
        return temporary, root, runtime, application

    def test_stages_hash_bound_closed_runtime_and_application(self):
        temporary, root, runtime, application = self.fixture()
        self.addCleanup(temporary.cleanup)
        manifest_hash = stage(runtime, root / "output", "linux", self.COMMIT, [application])
        provenance = json.loads((root / "output/bundle-provenance.json").read_text())
        self.assertEqual(provenance["runtime_manifest_sha256"], manifest_hash)
        self.assertEqual(provenance["source_commit"], self.COMMIT)
        self.assertEqual(provenance["applications"][0]["filename"], "application")

    def test_refuses_missing_commands_tampering_and_undeclared_files(self):
        temporary, root, runtime, application = self.fixture()
        self.addCleanup(temporary.cleanup)
        manifest_path = runtime / "runtime-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["commands"].pop("git")
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(SystemExit, "command inventory"):
            stage(runtime, root / "missing", "linux", self.COMMIT, [application])
        manifest["commands"]["git"] = "bin/git"
        manifest_path.write_text(json.dumps(manifest))
        (runtime / "bin/git").write_bytes(b"tampered")
        with self.assertRaisesRegex(SystemExit, "changed"):
            stage(runtime, root / "tampered", "linux", self.COMMIT, [application])

    def test_refuses_bad_application_without_partial_output(self):
        temporary, root, runtime, _ = self.fixture()
        self.addCleanup(temporary.cleanup)
        output = root / "output"
        with self.assertRaises(FileNotFoundError):
            stage(runtime, output, "linux", self.COMMIT, [root / "missing-application"])
        self.assertFalse(output.exists())
        self.assertEqual(list(root.glob(".output.staging-*")), [])

    def test_refuses_duplicate_component_and_undeclared_license(self):
        temporary, root, runtime, application = self.fixture()
        self.addCleanup(temporary.cleanup)
        manifest_path = runtime / "runtime-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["components"].append(dict(manifest["components"][0]))
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(SystemExit, "component identity"):
            stage(runtime, root / "duplicate", "linux", self.COMMIT, [application])
        manifest["components"] = [{"name": "fixture", "version": "1", "license_files": ["licenses/missing.txt"]}]
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(SystemExit, "declared license"):
            stage(runtime, root / "missing-license", "linux", self.COMMIT, [application])

    def test_platform_entry_points_share_runtime_input_and_output_contract(self):
        repository = Path(__file__).resolve().parent.parent
        linux = (repository / "bundle_linux.sh").read_text()
        macos = (repository / "bundle_macos.sh").read_text()
        windows = (repository / "bundle_windows.ps1").read_text()
        self.assertIn("--runtime-root", linux)
        self.assertIn("--runtime-root", macos)
        self.assertIn("RuntimeRoot", windows)
        self.assertIn("dist/linux", linux)
        self.assertIn("dist/macos", macos)
        self.assertIn("dist/windows", windows)
        for text, platform in ((linux, "linux"), (macos, "macos"), (windows, "windows")):
            self.assertIn(f"--platform {platform}", text)
            self.assertIn("OPEMOS_RUNTIME_MANIFEST_SHA256", text)


if __name__ == "__main__":
    unittest.main()
