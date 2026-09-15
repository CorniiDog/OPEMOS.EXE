import hashlib
import os
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts.acquire_runtime_linux import PAYLOAD_MERGES, acquire_archive, construct, copy_payload_tree, current_lock_matches, extracted_file, load_lock, write_ca_bundle, write_wrapper
from scripts.stage_runtime_bundle import REQUIRED, stage
from scripts.prepare_windows_runtime import prepare


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
        self.assertIn("CoreRoot", windows)
        self.assertIn("prepare_windows_runtime.py", windows)
        self.assertIn("dist/linux", linux)
        self.assertIn("dist/macos", macos)
        self.assertIn("dist/windows", windows)
        for text, platform in ((linux, "linux"), (macos, "macos"), (windows, "windows")):
            self.assertIn(f"--platform {platform}", text)
            self.assertIn("OPEMOS_RUNTIME_MANIFEST_SHA256", text)

    def test_linux_entry_acquires_pinned_runtime_by_default(self):
        repository = Path(__file__).resolve().parent.parent
        linux = (repository / "bundle_linux.sh").read_text()
        self.assertIn("scripts/acquire_runtime_linux.py", linux)
        self.assertIn("build/runtime/linux", linux)
        lock = load_lock(repository / "runtime/linux-ubuntu-24.04-amd64.sources.json")
        self.assertEqual(len(lock["archives"]), 78)
        self.assertIn(("usr/share/seabios", "usr/share/qemu"), PAYLOAD_MERGES)
        self.assertIn(("usr/lib/ipxe/qemu", "usr/share/qemu"), PAYLOAD_MERGES)

    def test_linux_archive_cache_reuses_exact_and_replaces_tamper_without_partial_file(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        cache = Path(temporary.name)
        payload = b"pinned archive"
        item = {"package": "fixture", "version": "1", "file": "fixture_1_amd64.deb", "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        target = cache / item["file"]
        target.write_bytes(payload)
        runner = mock.Mock()
        self.assertEqual(acquire_archive(item, cache, runner), target)
        runner.assert_not_called()
        target.write_bytes(b"tampered")

        def download(_args, cwd, check):
            self.assertTrue(check)
            self.assertFalse(target.exists())
            Path(cwd, item["file"]).write_bytes(payload)

        acquire_archive(item, cache, mock.Mock(side_effect=download))
        self.assertEqual(target.read_bytes(), payload)
        target.write_bytes(b"tampered again")
        with self.assertRaisesRegex(SystemExit, "identity mismatch"):
            acquire_archive(item, cache, mock.Mock(return_value=None))
        self.assertFalse(target.exists())

    def test_selected_runtime_bytes_come_from_archive_extraction_not_host(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        extracted = root / "extract/usr/bin/tool"
        host = root / "host/tool"
        extracted.parent.mkdir(parents=True)
        host.parent.mkdir()
        extracted.write_bytes(b"authenticated archive bytes")
        host.write_bytes(b"modified host bytes")
        self.assertEqual(extracted_file(extracted, root / "extract").read_bytes(), b"authenticated archive bytes")

    def test_wrappers_resolve_python_git_and_qemu_data_inside_runtime(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "bin").mkdir()
        (root / "programs").mkdir()
        for name in ("python3", "git", "qemu-system-x86_64"):
            path = root / "bin" / name
            write_wrapper(path, name)
            text = path.read_text()
            self.assertIn('"$root/programs/', text)
            self.assertNotIn("dirname", text)
            self.assertNotIn('="/usr/', text)
            self.assertNotIn(' -L "/usr/', text)
            self.assertIn('SSL_CERT_FILE="$root/payload/etc/ssl/certs/ca-certificates.crt"', text)
            self.assertIn('SSL_CERT_DIR="$root/payload/etc/ssl/certs-empty"', text)
            program = root / "programs" / name
            program.write_text("#!/bin/sh\nprintf '%s\\n' \"${PYTHONHOME-}\" \"${GIT_EXEC_PATH-}\" \"${GIT_TEMPLATE_DIR-}\" \"${SSL_CERT_FILE-}\" \"${SSL_CERT_DIR-}\" \"${GIT_SSL_CAINFO-}\" \"$*\"\n")
            program.chmod(0o755)
        self.assertIn("PYTHONHOME", (root / "bin/python3").read_text())
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", (root / "bin/python3").read_text())
        self.assertIn("GIT_EXEC_PATH", (root / "bin/git").read_text())
        self.assertIn("GIT_SSL_CAINFO", (root / "bin/git").read_text())
        self.assertIn('-L "$root/payload/usr/share/qemu"', (root / "bin/qemu-system-x86_64").read_text())
        environment = {
            "PATH": "/host-data-unavailable",
            "SSL_CERT_FILE": "/host-ca-unavailable",
            "SSL_CERT_DIR": "/host-ca-unavailable",
            "GIT_SSL_CAINFO": "/host-ca-unavailable",
        }
        python = subprocess.run([root / "bin/python3"], env=environment, check=True, capture_output=True, text=True).stdout
        git = subprocess.run([root / "bin/git"], env=environment, check=True, capture_output=True, text=True).stdout
        qemu = subprocess.run([root / "bin/qemu-system-x86_64", "-machine", "none"], env=environment, check=True, capture_output=True, text=True).stdout
        self.assertIn(str(root / "payload/usr"), python)
        self.assertIn(str(root / "payload/usr/lib/git-core"), git)
        self.assertIn(str(root / "payload/usr/share/git-core/templates"), git)
        for output in (python, git, qemu):
            values = output.splitlines()
            self.assertEqual(values[3], str(root / "payload/etc/ssl/certs/ca-certificates.crt"))
            self.assertEqual(values[4], str(root / "payload/etc/ssl/certs-empty"))
        self.assertEqual(git.splitlines()[5], str(root / "payload/etc/ssl/certs/ca-certificates.crt"))
        self.assertIn(f"-L {root / 'payload/usr/share/qemu'} -machine none", qemu)

    def test_ca_bundle_uses_only_sorted_verified_archive_certificates(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        certificates = root / "extract/usr/share/ca-certificates/mozilla"
        certificates.mkdir(parents=True)
        (certificates / "z.crt").write_bytes(b"Z")
        (certificates / "a.crt").write_bytes(b"A\n")
        payload = root / "payload"
        write_ca_bundle(root / "extract", payload)
        self.assertEqual((payload / "etc/ssl/certs/ca-certificates.crt").read_bytes(), b"A\nZ\n")
        self.assertTrue((payload / "etc/ssl/certs-empty").is_dir())

    def test_payload_copy_omits_empty_archive_markers(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source = root / "extract/data"
        source.mkdir(parents=True)
        (source / "empty.py").write_bytes(b"")
        (source / "module.py").write_bytes(b"import json\n")
        destination = root / "runtime"
        copy_payload_tree(source, destination, root / "extract")
        self.assertFalse((destination / "empty.py").exists())
        self.assertEqual((destination / "module.py").read_bytes(), b"import json\n")

    def test_existing_runtime_reuse_is_bound_to_current_source_lock(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        lock = {"schema_version": 1, "distribution": "Ubuntu 24.04", "archives": []}
        (root / "source-provenance.json").write_text(json.dumps(lock, sort_keys=True, separators=(",", ":")) + "\n")
        self.assertTrue(current_lock_matches(root, lock))
        changed = dict(lock, distribution="Ubuntu 24.04 changed")
        self.assertFalse(current_lock_matches(root, changed))

    @mock.patch("scripts.acquire_runtime_linux.load_lock")
    @mock.patch("scripts.acquire_runtime_linux.platform.machine", return_value="x86_64")
    @mock.patch("scripts.acquire_runtime_linux.platform.system", return_value="Linux")
    def test_construct_rejects_valid_but_stale_existing_runtime(self, _system, _machine, load):
        temporary, root, runtime, _application = self.fixture()
        self.addCleanup(temporary.cleanup)
        provenance = runtime / "source-provenance.json"
        provenance.write_text('{"lock":"old"}\n')
        manifest_path = runtime / "runtime-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"].append({"path": provenance.name, "size": provenance.stat().st_size, "sha256": hashlib.sha256(provenance.read_bytes()).hexdigest()})
        manifest_path.write_text(json.dumps(manifest, separators=(",", ":")))
        load.return_value = {"schema_version": 1, "distribution": "Ubuntu 24.04", "archives": []}
        with self.assertRaisesRegex(SystemExit, "does not match the current source lock"):
            construct(runtime, root / "cache", root / "lock.json")

    @mock.patch("scripts.acquire_runtime_linux.acquire_archive")
    @mock.patch("scripts.acquire_runtime_linux.load_lock")
    @mock.patch("scripts.acquire_runtime_linux.platform.machine", return_value="x86_64")
    @mock.patch("scripts.acquire_runtime_linux.platform.system", return_value="Linux")
    def test_linux_construction_failure_removes_transactional_output(self, _system, _machine, load, _acquire):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        output = root / "runtime"
        load.return_value = {"schema_version": 1, "distribution": "Ubuntu 24.04", "archives": []}
        with mock.patch("scripts.acquire_runtime_linux.extracted_file", side_effect=SystemExit("Required pinned runtime command is unavailable")):
            with self.assertRaisesRegex(SystemExit, "command is unavailable"):
                construct(output, root / "cache", root / "lock.json")
        self.assertFalse(output.exists())
        self.assertEqual(list(root.glob(".runtime.staging-*")), [])


    def test_windows_runtime_adds_exact_core_zstd_dependency(self):
        core_value = os.environ.get("OPEMOS_CORE_CONTRACT_ROOT")
        if not core_value:
            self.skipTest("exact canonical Core checkout is not supplied")
        temporary, root, runtime, _ = self.fixture("windows")
        self.addCleanup(temporary.cleanup)
        base_manifest_path = runtime / "runtime-manifest.json"
        base_manifest = json.loads(base_manifest_path.read_text())
        base_manifest["commands"].pop("zstd")
        base_manifest["files"] = [item for item in base_manifest["files"] if item["path"] != "bin/zstd"]
        (runtime / "bin/zstd").unlink()
        base_manifest_path.write_text(json.dumps(base_manifest, separators=(",", ":")))
        output = root / "prepared"
        prepare(runtime, Path(core_value), output)
        manifest = json.loads((output / "runtime-manifest.json").read_text())
        self.assertEqual(manifest["commands"]["zstd"], "bin/zstd.exe")
        self.assertEqual(hashlib.sha256((output / "bin/zstd.exe").read_bytes()).hexdigest(), "8076aae03feac7c66b319579e82172eed168deed2a3f25e5e2d3c60f55e84111")
        self.assertEqual([item["name"] for item in manifest["components"]][-1], "zstd")


if __name__ == "__main__":
    unittest.main()
