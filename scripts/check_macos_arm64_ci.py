"""One native hosted-Mac build -> real GUI transaction; never installs guests.

Ordinary check failures are collected independently. Input/lifecycle failures
stop affected work. Every child has one process group, a deadline and a reaped
numeric exit. No credentials, signing, release or TCC mutations.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/macos-arm64-evidence"
TARGET = "aarch64-apple-darwin"
CORE = "01407aa6174b80e92cb7f3dcb534ade5cdd7bf00"
LOCKS = ["package-lock.json", "src-tauri/Cargo.lock", "src-tauri/tauri.conf.json"]


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def output(args, cwd=ROOT):
    return subprocess.check_output(args, cwd=cwd, text=True, timeout=30).strip()


def app_processes(binary):
    """Read actual macOS executable paths, not a broad application-name match."""
    rows = output(["/bin/ps", "-axo", "pid=,comm="]).splitlines()
    return [int(fields[0]) for row in rows if len(fields := row.strip().split(None, 1)) == 2
            and fields[1] == str(binary)]


def main():
    OUT.mkdir(parents=True, exist_ok=False)
    receipt = {"schemaVersion": 1, "stages": {}, "environment": {
        key: os.environ.get(key) for key in ["GITHUB_REPOSITORY", "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_REF", "GITHUB_SHA",
        "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA", "RUNNER_ARCH", "ImageOS", "ImageVersion"]},
        "publication": False, "target": TARGET,
        "productAcceptance": {
            "nativeAppBuildAndGuiChooser": "pending",
            "imageBuild": "not_run: no admitted hosted-M1 appliance or recovery image",
            "usbWriteReadback": "not_run: no owned USB test target",
            "steamosBoot": "not_run: requires a separate admitted x86 boot target",
        }}
    children_closed = True

    def save():
        (OUT / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")

    def run(name, args, seconds):
        nonlocal children_closed
        start = time.time()
        record = {"command": args, "started": start, "state": "running"}
        receipt["stages"][name] = record
        save()
        with (OUT / (name + ".log")).open("wb") as log:
            child = subprocess.Popen(args, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                     start_new_session=True)
            record["pid"] = child.pid
            try:
                record["exit"] = child.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                record["timeout"] = True
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
                record["exit"] = child.returncode
            # A leader exit does not prove descendants closed. Refuse overlap.
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                record["processGroupAbsent"] = True
            else:
                record["processGroupAbsent"] = False
                os.killpg(child.pid, signal.SIGKILL)
                children_closed = False
                raise RuntimeError(name + ": surviving process group; no further stages")
        record.update(ended=time.time(), state="passed" if record["exit"] == 0 and
                      not record.get("timeout") else "failed")
        save()
        return record["state"] == "passed"

    try:
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise RuntimeError("native Apple Silicon macOS required; no Intel/Rosetta fallback")
        head = output(["git", "rev-parse", "HEAD"])
        if head != os.environ["OPEMOS_EXE_COMMIT"]:
            raise RuntimeError("EXE source mismatch")
        core = Path(os.environ["OPEMOS_CORE_CONTRACT_ROOT"])
        if output(["git", "rev-parse", "HEAD"], core) != CORE or output(
                ["git", "remote", "get-url", "origin"], core).rstrip("/") != (
                "https://github.com/CorniiDog/open-gpu-kernel-modules-steamos-support"):
            raise RuntimeError("canonical immutable Core source mismatch")
        receipt.update(exe_source_commit=head, core_fixture_commit=CORE,
                       locks={name: digest(ROOT / name) for name in LOCKS},
                       freeBytesBefore=shutil.disk_usage(ROOT).free)
        if receipt["freeBytesBefore"] < 8_000_000_000:
            raise RuntimeError("less than 8GB free before native build")
        if not run("environment", ["/bin/sh", "-c",
                "sw_vers; uname -m; rustc -vV; cargo -V; node -v; npm -v; "
                "xcode-select -p; xcodebuild -version; xcrun --show-sdk-version; "
                "stat -f '%Su' /dev/console"], 60):
            raise RuntimeError("environment inspection failed")
        if "host: aarch64-apple-darwin" not in output(["rustc", "-vV"]):
            raise RuntimeError("non-native Rust host")
        if not run("npm-ci", ["npm", "ci"], 300):
            raise RuntimeError("locked JavaScript dependencies failed")
        helper = OUT / "macos-ui-smoke"
        helper_built = run("gui-helper-build", ["xcrun", "swiftc", "tests/macos-ui-smoke.swift",
                                              "-o", str(helper)], 120)
        receipt["stages"]["gui"] = {"state": "not_run", "reason": "awaiting native app" if helper_built else "helper compilation failed"}
        save()
        for name, args in [
            ("frontend", ["node", "--test", "tests/settings-accessibility.test.mjs", "tests/welcome-runtime.test.mjs"]),
            ("docs", ["npm", "run", "test:docs"]),
            ("hygiene", ["npm", "run", "test:hygiene"]),
            ("format", ["cargo", "fmt", "--manifest-path", "src-tauri/Cargo.toml", "--", "--check"]),
            ("clippy", ["cargo", "clippy", "--manifest-path", "src-tauri/Cargo.toml", "--locked",
                        "--target", TARGET, "--all-targets", "--all-features", "--", "-D", "warnings"]),
            ("darwin-cache-tests", ["cargo", "test", "--manifest-path", "src-tauri/Cargo.toml", "--locked",
                                   "--target", TARGET, "core_generation_cache"]),
            ("rust-tests", ["cargo", "test", "--manifest-path", "src-tauri/Cargo.toml", "--locked", "--target", TARGET,
                            "installation_media_welcome_is_bundled_with_a_bounded_privilege_boundary"])]:
            run(name, args, 1200)
        built = run("native-build", ["npm", "run", "build:app", "--", "--target", TARGET], 1800)
        if receipt["locks"] != {name: digest(ROOT / name) for name in LOCKS}:
            raise RuntimeError("build changed pinned lock/config bytes")
        if not built:
            raise RuntimeError("native build failed; no stale app GUI fallback")
        app = ROOT / f"src-tauri/target/{TARGET}/release/bundle/macos/SteamOS NVIDIA Builder.app"
        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        if info["CFBundleIdentifier"] != "dev.cornidog.steamos-nvidia-image-builder":
            raise RuntimeError("wrong bundle identifier")
        binary = app / "Contents/MacOS" / info["CFBundleExecutable"]
        if output(["lipo", "-archs", str(binary)]) != "arm64":
            raise RuntimeError("app is not arm64-only")
        receipt["artifact"] = {"app": str(app), "executable": str(binary),
            "bytes": binary.stat().st_size, "sha256": digest(binary), "architectures": "arm64"}
        run("artifact-inspection", ["/bin/sh", "-c",
            'file "$1"; otool -L "$1"; codesign -dv --verbose=2 "$2"',
            "inspect", str(binary), str(app)], 60)
        if helper_built:
            receipt["helperSHA256"] = digest(helper)
            if app_processes(binary):
                raise RuntimeError("pre-existing exact executable; refuse GUI interaction")
            try:
                run("gui", [str(helper), str(app), str(OUT)], 150)
            finally:
                survivors = app_processes(binary)
                receipt["appProcessSurvivors"] = survivors
                if survivors:
                    # Do not guess ownership or kill an unrelated concurrent launch.
                    # The helper persists its exact app PID before subsequent actions.
                    events_path = OUT / "gui-events.json"
                    events = json.loads(events_path.read_text()) if events_path.exists() else []
                    owned = {e["pid"]: e.get("launchDate") for e in events if e.get("kind") == "app" and
                             e.get("executable") == str(binary)}
                    for pid in survivors:
                        if pid in owned and app_processes(binary).count(pid) == 1:
                            birth = output(["/bin/ps", "-p", str(pid), "-o", "lstart="])
                            epoch = time.mktime(time.strptime(birth, "%a %b %d %H:%M:%S %Y"))
                            if isinstance(owned[pid], (int, float)) and abs(epoch - owned[pid]) < 1:
                                receipt.setdefault("ownedCleanupIdentities", []).append({"pid": pid, "start": birth, "executable": str(binary)})
                                os.kill(pid, signal.SIGTERM)
                    end = time.monotonic() + 5
                    while app_processes(binary) and time.monotonic() < end:
                        time.sleep(0.1)
                    receipt["appProcessSurvivorsAfterOwnedCleanup"] = app_processes(binary)
                    raise RuntimeError("GUI left app processes; cleanup evidence retained, not normal closure")
        if receipt["stages"].get("gui", {}).get("state") == "passed":
            events = json.loads((OUT / "gui-events.json").read_text())
            kinds = [event.get("kind") for event in events]
            clicks = [event.get("label") for event in events if event.get("kind") == "pointer-click"]
            required_events = {"native-image-chooser-observed", "native-image-chooser-closed-observed",
                               "normal-app-close"}
            if not required_events.issubset(kinds) or not {"choose-image", "cancel-image-chooser"}.issubset(clicks):
                raise RuntimeError("GUI exited without the actual chooser open/cancel and normal-close evidence")
            receipt["productAcceptance"]["nativeAppBuildAndGuiChooser"] = "passed"
        if digest(binary) != receipt["artifact"]["sha256"]:
            raise RuntimeError("executable changed during GUI transaction")
        archive = OUT / "SteamOS-NVIDIA-Builder-arm64.app.zip"
        if run("archive", ["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(app), str(archive)], 120):
            receipt["archive"] = {"bytes": archive.stat().st_size, "sha256": digest(archive)}
            if digest(binary) != receipt["artifact"]["sha256"]:
                raise RuntimeError("executable changed during archive")
    except Exception as error:
        receipt["error"] = str(error)
    finally:
        receipt["evidenceFiles"] = {p.name: {"bytes": p.stat().st_size, "sha256": digest(p)}
            for p in OUT.iterdir() if p.is_file() and p.name != "receipt.json"}
        receipt["freeBytesAfter"] = shutil.disk_usage(ROOT).free
        receipt["childProcessGroupsClosed"] = children_closed
        receipt["finished"] = time.time()
        save()
    required = ["frontend", "docs", "hygiene", "format", "clippy", "darwin-cache-tests", "rust-tests", "native-build", "gui", "archive"]
    return 0 if not receipt.get("error") and all(
        receipt["stages"].get(name, {}).get("state") == "passed" for name in required) else 1


if __name__ == "__main__":
    sys.exit(main())
