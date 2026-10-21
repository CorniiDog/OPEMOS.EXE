"""Execute the existing actual-guest normal/wrong-marker/closure test.

Compile the production consumer with exactly the shipped runtime/guest-selection
pins; supply the same immutable companion alongside the actual test executable.
Never override handshake, process control or readiness classification.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from stage_macos_app import verify_companion
from stage_runtime_bundle import digest, validate_runtime

root = Path(__file__).resolve().parents[1]
resources = root / "dist/macos/SteamOS NVIDIA Builder.app/Contents/Resources"
runtime = (resources / "runtime").resolve()
appliance = resources / "appliance"
validate_runtime(runtime, "macos")
verify_companion(appliance)
env = dict(os.environ, OPEMOS_RUNTIME_MANIFEST_SHA256=digest(runtime / "runtime-manifest.json"),
           OPEMOS_MACOS_X86_TCG="1", OPEMOS_RUNTIME_ROOT=str(runtime),
           PATH=str(runtime / "bin") + os.pathsep + os.environ["PATH"])
command = ["cargo", "test", "--manifest-path", "src-tauri/Cargo.toml", "--locked",
           "--target", "aarch64-apple-darwin", "live_appliance_reaches_ready_marker"]
build = subprocess.run(command + ["--no-run", "--message-format=json"], cwd=root,
                       env=env, text=True, stdout=subprocess.PIPE, timeout=1200)
print(build.stdout, flush=True)
build.check_returncode()
binaries = [Path(row["executable"]) for line in build.stdout.splitlines()
            if (row := json.loads(line)).get("reason") == "compiler-artifact"
            and row.get("profile", {}).get("test") and row.get("executable")
            and row.get("target", {}).get("name") == "steamos_nvidia_image_builder_lib"]
if len(binaries) != 1:
    raise ValueError("Ambiguous actual guest test executable")
binary = binaries[0]
destination = binary.parent / "appliance"
shutil.copytree(appliance, destination, symlinks=False)
verify_companion(destination)
before = digest(destination / "fedora-builder.qcow2")
result = subprocess.run([str(binary), "tests::live_appliance_reaches_ready_marker",
                         "--ignored", "--exact", "--nocapture", "--test-threads=1"],
                        cwd=root, env=env, timeout=300, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
print(result.stdout, flush=True)
verify_companion(destination)
if digest(destination / "fedora-builder.qcow2") != before:
    raise ValueError("Fault transaction altered original companion")
if subprocess.run(["/usr/bin/pgrep", "-f", "qemu-system-"], capture_output=True).returncode != 1:
    raise ValueError("Guest fault transaction closure unproven")
if result.returncode == 0 and ("ACTUAL_GUEST_WRONG_MARKER exit=0 consumer=Failed" not in result.stdout or "1 passed" not in result.stdout):
    raise ValueError("Actual fault test did not execute; zero matched tests is not acceptance")
sys.exit(result.returncode)
