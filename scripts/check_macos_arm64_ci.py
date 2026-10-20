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
import re
import shutil
import signal
import subprocess
import sys
import time
from macos_transaction_evidence import native_session_snapshot, reconcile_gui, reconcile_pointer_input

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/macos-arm64-evidence"
TARGET = "aarch64-apple-darwin"
CORE = "01407aa6174b80e92cb7f3dcb534ade5cdd7bf00"
# Reviewed source lock is part of this exact Git head, never caller supplied.
RECOVERY_SHA256 = "f9aa0fa2dd618febf28a5e2a583d1e2b5a8ca3f1205be965da584602ac962f40"
RECOVERY_BYTES = 8120172544
LOCKS = ["package-lock.json", "src-tauri/Cargo.lock", "src-tauri/tauri.conf.json", "runtime/macos-arm64.sources.json"]


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


def verify_completed_image(events, recovery, expected_source_sha256=RECOVERY_SHA256):
    """Read the real exported operand; UI text and readiness are not acceptance."""
    completed = [e for e in events if e.get("kind") == "completed-image-ui-observed"]
    if len(completed) != 1:
        raise RuntimeError("One actual completed-image observation required")
    text = completed[0]["text"]
    def single(pattern):
        values = set(re.findall(pattern, text))
        if len(values) != 1:
            raise RuntimeError("Missing or ambiguous completed-image operand: " + pattern)
        return values.pop()
    image = Path(single(r"Exported image: ([^\n]+); [0-9]+ bytes; raw layout="))
    manifest = Path(single(r"Build manifest: ([^\n]+)\.\s*(?:\n|$)"))
    def regular(path, maximum=None):
        if not path.is_absolute() or path.resolve() != path or path.is_symlink():
            raise RuntimeError("Noncanonical exported operand")
        info = path.stat()
        if not path.is_file() or info.st_uid != os.getuid() or info.st_size <= 0 or (maximum and info.st_size > maximum):
            raise RuntimeError("Invalid exported file type/UID/size")
        return tuple(getattr(info, name) for name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns"))
    image_before = regular(image)
    manifest_before = regular(manifest, 1048576)
    if image == recovery.resolve() or manifest.parent != image.parent or manifest == image:
        raise RuntimeError("Exported image/manifest custody mismatch")
    raw = manifest.read_bytes()
    value = json.loads(raw)
    validation = value.get("validation", {})
    if (value.get("schemaVersion") != 1 or value.get("resultClass") != "nvidia-mutation-valid" or
            value.get("input", {}).get("sourceSha256") != expected_source_sha256 or
            value.get("output", {}).get("filename") != image.name or
            value["output"].get("format") != "raw" or value["output"].get("bytes") != image_before[5] or
            any(validation.get(key) is not True for key in ("passed", "sourceUnchanged", "candidateAttachedReadOnly", "layoutRecognized", "markerVerified", "nvidiaPayloadVerified"))):
        raise RuntimeError("Completed output manifest does not prove genuine NVIDIA image")
    actual = digest(image)
    if actual != value["output"].get("sha256") or actual == expected_source_sha256:
        raise RuntimeError("Full exported image hash differs from manifest or source")
    if regular(image) != image_before or regular(manifest, 1048576) != manifest_before or digest(recovery) != expected_source_sha256:
        raise RuntimeError("Completed image/manifest/source changed during independent full hash")
    return {"path": str(image), "bytes": image_before[5], "sha256": actual,
            "manifest": str(manifest), "manifestSHA256": hashlib.sha256(raw).hexdigest(),
            "sourceSHA256": expected_source_sha256, "fullFileRead": True,
            "imageIdentity": image_before, "manifestIdentity": manifest_before}


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
    fullstack = os.environ.get("OPEMOS_MACOS_FULLSTACK") == "1"
    receipt["requestedMode"] = "explicit-x86_64-tcg-cold-build" if fullstack else "native-app-chooser"
    recovery = Path.home() / "Documents/opemos-pinned-recovery.img"

    def save():
        (OUT / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")

    def fail(error, stage):
        detail = {"stage": stage, "error": str(error)}
        if "error" not in receipt:
            receipt["error"] = str(error)
            receipt["firstFailure"] = detail
        else:
            receipt.setdefault("secondaryErrors", []).append(detail)

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
        if helper_built:
            helper_built = run("ownership-birth-boundaries", [str(helper), "--birth-regression"], 30)
        if not run("completed-output-verifier-cases", ["python3", "tests/test_macos_completed_image.py"], 60):
            raise RuntimeError("Completed-image actual filesystem verification cases failed")
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
            ("rust-tests", ["cargo", "test", "--manifest-path", "src-tauri/Cargo.toml", "--locked", "--target", TARGET, "--", "--nocapture", "--test-threads=1"])]:
            run(name, args, 1200)
        # Compile and exercise changed cases before acquiring unchanged bulk inputs.
        # Failures retain their evidence; independent platform jobs continue.
        prerequisite_names = ["frontend", "docs", "hygiene", "format", "clippy", "darwin-cache-tests", "rust-tests"]
        if not helper_built or any(receipt["stages"][name]["state"] != "passed" for name in prerequisite_names):
            raise RuntimeError("Native source/changed-case prerequisite failed; no bulk producer replay")
        if fullstack:
            lock = ROOT / "runtime/macos-arm64.sources.json"
            # Git checkout binds source bytes; producer validates closed exact
            # provider identities and every downloaded bottle before extraction.
            if not lock.is_file() or lock.is_symlink():
                raise RuntimeError("Darwin runtime source lock missing")
            receipt["runtimeSourceLockSHA256"] = digest(lock)
            if not run("darwin-producer-boundaries", ["python3", "tests/test_macos_runtime_producer.py"], 120):
                raise RuntimeError("Actual Darwin producer boundary tests failed")
            if not run("fullstack-input-producer", ["python3", "scripts/prepare_macos_fullstack.py", str(OUT)], 3600):
                raise RuntimeError("Exact fullstack input producer failed; preserve evidence, no chooser-only fallback")
            from prepare_macos_fullstack import consume_input_receipt
            inputs, input_root = consume_input_receipt(OUT / "macos-input-producer.json", ROOT, recovery)
            runtime, appliance = input_root / "runtime", input_root / "appliance"
            receipt["inputCustody"] = inputs
            from stage_runtime_bundle import validate_runtime
            from stage_macos_app import verify_companion
            _, _, receipt["runtimeManifestSHA256"] = validate_runtime(runtime, "macos")
            verify_companion(appliance)
            receipt["productAcceptance"]["imageBuild"] = "not_run: exact inputs admitted; graphical transaction pending"
            if recovery.is_symlink() or not recovery.is_file() or recovery.stat().st_size != RECOVERY_BYTES or digest(recovery) != RECOVERY_SHA256:
                raise RuntimeError("Exact admitted Documents recovery image is unavailable")
            # Full image/output storage accounting is also rechecked by the
            # production consumer; do not replace its free-space guards.
            if shutil.disk_usage(ROOT).free < 2 * RECOVERY_BYTES + 4 * 1024**3 + 64 * 1024**2:
                raise RuntimeError("Insufficient actual free space for full raw-image transaction")
            if not run("companion-filesystem-regressions", ["python3", "tests/test_macos_companion_staging.py"], 60):
                raise RuntimeError("Mac companion filesystem regression failed")
        build_command = (["bash", "bundle_macos.sh", "--runtime-root", str(runtime),
                          "--appliance-root", str(appliance), "--diagnostic-x86-tcg"] if fullstack
                         else ["npm", "run", "build:app", "--", "--target", TARGET])
        built = run("native-build", build_command, 1800)
        if receipt["locks"] != {name: digest(ROOT / name) for name in LOCKS}:
            raise RuntimeError("build changed pinned lock/config bytes")
        if not built:
            raise RuntimeError("native build failed; no stale app GUI fallback")
        app = ROOT / f"src-tauri/target/{TARGET}/release/bundle/macos/SteamOS NVIDIA Builder.app"
        if fullstack:
            app = ROOT / "dist/macos/SteamOS NVIDIA Builder.app"
        info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        if info["CFBundleIdentifier"] != "dev.cornidog.steamos-nvidia-image-builder":
            raise RuntimeError("wrong bundle identifier")
        binary = app / "Contents/MacOS" / info["CFBundleExecutable"]
        if output(["lipo", "-archs", str(binary)]) != "arm64":
            raise RuntimeError("app is not arm64-only")
        receipt["artifact"] = {"app": str(app), "executable": str(binary),
            "bytes": binary.stat().st_size, "sha256": digest(binary), "architectures": "arm64"}
        if fullstack:
            provenance = app / "Contents/Resources/bundle-provenance.json"
            if provenance.is_symlink() or not provenance.is_file() or provenance.stat().st_size > 65536:
                raise RuntimeError("Packaged startup provenance missing or unbounded")
            receipt["artifact"]["startupProvenanceSHA256"] = digest(provenance)
        receipt["productAcceptance"]["nativeArm64PackagedBuild"] = "passed"
        run("artifact-inspection", ["/bin/sh", "-c",
            'file "$1"; otool -L "$1"; codesign -dv --verbose=2 "$2"',
            "inspect", str(binary), str(app)], 60)
        if helper_built:
            receipt["helperSHA256"] = digest(helper)
            if app_processes(binary):
                raise RuntimeError("pre-existing exact executable; refuse GUI interaction")
            sessions = Path.home() / "Library/Caches/dev.cornidog.steamos-nvidia-image-builder/sessions/native"
            if fullstack:
                receipt["nativeSessionBeforeGUI"] = native_session_snapshot(sessions, Path.home())
                if not receipt["nativeSessionBeforeGUI"]["qemuAbsent"] or receipt["nativeSessionBeforeGUI"]["entries"]:
                    raise RuntimeError("Pre-existing native session/QEMU state; refuse graphical overlap")
            try:
                arguments = [str(helper), str(app), str(OUT)] + ([str(recovery)] if fullstack else [])
                receipt["productAcceptance"]["nativeAppBuildAndGuiChooser"] = "attempted"
                receipt["productAcceptance"]["imageBuild"] = "not_started: awaiting actual Build event"
                gui_passed = run("gui", arguments, 510 if fullstack else 150)
                if not gui_passed:
                    event_error = None
                    try:
                        observed = json.loads((OUT / "gui-events.json").read_text())
                    except Exception as error:
                        observed, event_error = [], str(error)
                    first = next((e for e in observed if e.get("kind") == "failure"), None)
                    fail(first.get("error") if first else "Actual GUI failed without a failure event", "gui")
                    if event_error:
                        fail(event_error, "gui-event-capture")
                    receipt["productAcceptance"]["nativeAppBuildAndGuiChooser"] = "failed"
                    clicked = any(e.get("kind") == "pointer-click" and e.get("label") == "build-pinned-image" for e in observed)
                    intent = any(e.get("kind") == "build-request-intent" for e in observed)
                    receipt["productAcceptance"]["imageBuild"] = ("failed: actual Build clicked; no completed image" if clicked else
                        "unverified: Build intent without click evidence" if intent else "not_started: actual GUI failed before Build intent")
                    receipt["productAcceptance"]["coldBuildGuestHealthNextStage"] = "not proven: graphical transaction failed"
            finally:
                try:
                    receipt["pointerInputClosure"] = reconcile_pointer_input(OUT / "gui-events.json")
                except Exception as error:
                    receipt["pointerInputClosure"] = {"observedNeutral": False, "state": "unknown-or-failed",
                        "error": str(error), "productAcceptance": False}
                    fail(error, "native-pointer-input-closure")
                # Only our newly launched app's private current-UID session root.
                # Retain actual regular-file serial and bounded observer records;
                # missing numeric reap remains explicit, never inferred from pgrep.
                collected = []
                try:
                    if fullstack and sessions.is_dir() and not sessions.is_symlink():
                        for path in sorted(sessions.rglob("*")):
                            if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid():
                                continue
                            if path.name not in {"readiness.jsonl", "qemu.log", "resources.json"} and not path.name.endswith((".readiness.jsonl", ".resources.json", ".log")):
                                continue
                            with path.open("rb") as stream:
                                stream.seek(max(0, path.stat().st_size - 256 * 1024))
                                data = stream.read(256 * 1024)
                            target = OUT / ("cold-" + path.parent.name + "-" + path.name)
                            target.write_bytes(data)
                            collected.append({"source": str(path), "retained": target.name,
                                              "sourceBytes": path.stat().st_size, "tailBytes": len(data)})
                    receipt["coldReadinessEvidence"] = collected
                    if fullstack:
                        receipt["nativeSessionAfterGUI"] = native_session_snapshot(sessions, Path.home())
                        receipt["guiSessionReconciliation"] = reconcile_gui(OUT / "gui-events.json",
                            receipt["nativeSessionBeforeGUI"], receipt["nativeSessionAfterGUI"], binary)
                        primary = receipt["guiSessionReconciliation"]["firstGUIFailure"]
                        if primary and "error" not in receipt:
                            fail(primary.get("error", "Actual GUI failure"), "gui")
                except Exception as error:
                    fail(error, "gui-session-evidence")
                receipt["guiAppNumericExit"] = "unknown: Finder launched app is not a waitable child"
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
        if not receipt.get("pointerInputClosure", {}).get("observedNeutral"):
            raise RuntimeError("Native pointer pair/input closure unproven; no further GUI or fault guest")
        if fullstack:
            closures = []
            launches = []
            transports = []
            for item in receipt.get("coldReadinessEvidence", []):
                if item["retained"].endswith("readiness.jsonl"):
                    if item["sourceBytes"] >= 256 * 1024:
                        raise RuntimeError("Cold observer budget reached: evidence incomplete; no second guest")
                    records = [json.loads(line)["observation"] for line in
                               (OUT / item["retained"]).read_text().splitlines()]
                    if any(r.get("phase") == "observer-overflow" for r in records):
                        raise RuntimeError("Cold observer overflow: missing phases remain unknown; no second guest")
                    closures.extend(r for r in records if r.get("phase") == "qemu-reaped")
                    launches.extend(r for r in records if r.get("phase") == "launch")
                    transports.extend(r for r in records if r.get("phase") == "transport-completion")
            receipt["graphicalQemuNumericClosure"] = closures
            no_session = (receipt["guiSessionReconciliation"]["sessionState"] == "not-launched-observed"
                          and not launches and not closures and not transports)
            if no_session:
                receipt["stages"]["actual-guest-normal-wrong-marker-closure"] = {"state": "not_run",
                    "reason": "actual preBuild failure with real before/after empty session inventory and absent QEMU; NOT VM closure pass"}
            elif not launches or {r.get("pid") for r in launches} != {r.get("pid") for r in closures} or any(not r.get("processGroupAbsent") or
                    not r.get("status", "").startswith("Some(") or
                    r.get("transportClosure") != "Ok(())" for r in closures):
                raise RuntimeError("Graphical QEMU numeric reap/group/transport closure unproven; refuse separate fault guest")
            else:
                if not transports or any(not r.get("stdoutJoined") or not r.get("stderrJoined") or
                        not r.get("closure", "").startswith("Ok(") for r in transports):
                    raise RuntimeError("Actual graphical SSH stream/reap closure incomplete; no fault guest")
                if not receipt["nativeSessionAfterGUI"]["qemuAbsent"]:
                    raise RuntimeError("Graphical transaction left QEMU; refuse overlapping fault guest")
                run("actual-guest-normal-wrong-marker-closure", ["python3", "scripts/run_macos_guest_fault.py"], 1500)
        if receipt["stages"].get("gui", {}).get("state") == "passed":
            events = json.loads((OUT / "gui-events.json").read_text())
            kinds = [event.get("kind") for event in events]
            clicks = [event.get("label") for event in events if event.get("kind") == "pointer-click"]
            required_events = ({"native-usable-window-observed", "native-image-chooser-observed", "native-image-selected-observed",
                                "cold-build-next-stage-observed", "completed-image-ui-observed", "separate-build-cancel-observed", "actual-display-1600x900", "normal-app-close"} if fullstack else
                               {"native-usable-window-observed", "native-image-chooser-observed", "native-image-chooser-closed-observed", "normal-app-close"})
            required_clicks = ({"choose-image", "choose-pinned-image", "build-pinned-image", "close-build-progress", "build-for-separate-cancel", "cancel-separate-build", "close-separate-cancel"}
                               if fullstack else {"choose-image", "cancel-image-chooser"})
            if not required_events.issubset(kinds) or not required_clicks.issubset(clicks):
                raise RuntimeError("GUI exited without the requested exact pointer/observed-stage/normal-close evidence")
            if fullstack:
                receipt["productAcceptance"]["coldBuildGuestHealthNextStage"] = "passed"
                receipt["completedImage"] = verify_completed_image(events, recovery)
                receipt["productAcceptance"]["imageBuild"] = "passed: completed image and manifest independently full-hashed"
                if digest(recovery) != RECOVERY_SHA256:
                    raise RuntimeError("Original recovery bytes changed")
                qemu = subprocess.run(["/usr/bin/pgrep", "-f", "qemu-system-"], capture_output=True, text=True, timeout=10)
                receipt["qemuSurvivors"] = qemu.stdout.strip()
                if qemu.returncode != 1:
                    raise RuntimeError("QEMU closure unproven; no next job overlap")
            receipt["productAcceptance"]["nativeAppBuildAndGuiChooser"] = "passed"
        if digest(binary) != receipt["artifact"]["sha256"]:
            raise RuntimeError("executable changed during GUI transaction")
    except Exception as error:
        fail(error, "transaction")
    finally:
        # A GUI refusal must not skip the immutable-input post-state checks.
        # Keep the primary failure and independently retain secondary failures.
        if fullstack and receipt.get("inputCustody"):
            try:
                final_inputs, final_root = consume_input_receipt(OUT / "macos-input-producer.json", ROOT, recovery)
                if final_inputs != receipt["inputCustody"] or final_root / "runtime" != runtime:
                    raise RuntimeError("Producer custody changed during the transaction")
                if (recovery.is_symlink() or not recovery.is_file() or recovery.stat().st_size != RECOVERY_BYTES
                        or digest(recovery) != RECOVERY_SHA256):
                    raise RuntimeError("Original recovery changed during the transaction")
                _, _, final_manifest = validate_runtime(runtime, "macos")
                if final_manifest != receipt.get("runtimeManifestSHA256"):
                    raise RuntimeError("Original runtime manifest changed during the transaction")
                verify_companion(appliance)
                receipt["originalInputsUnchangedAfterAttempt"] = True
            except Exception as error:
                receipt.setdefault("finalizationErrors", []).append({"stage": "original-inputs", "error": str(error)})
        if receipt.get("artifact"):
            try:
                if digest(binary) != receipt["artifact"]["sha256"]:
                    raise RuntimeError("Packaged executable changed during the transaction")
                if fullstack:
                    if digest(provenance) != receipt["artifact"]["startupProvenanceSHA256"]:
                        raise RuntimeError("Packaged startup provenance changed during the transaction")
                    _, _, packaged_manifest = validate_runtime(app / "Contents/Resources/runtime", "macos")
                    if packaged_manifest != receipt.get("runtimeManifestSHA256"):
                        raise RuntimeError("Packaged runtime manifest changed during the transaction")
                    verify_companion(app / "Contents/Resources/appliance")
                    if not run("packaged-seal-finalizer", ["codesign", "--verify", "--deep", "--strict", str(app)], 60):
                        raise RuntimeError("Packaged native resource seal changed during the transaction")
                receipt["packagedInputsUnchangedAfterAttempt"] = True
                # Independent retention after failed GUI, never an acceptance
                # promotion. Exact sealed input/resource checks precede ZIP.
                if children_closed and (not fullstack or receipt.get("originalInputsUnchangedAfterAttempt")):
                    archive = OUT / "SteamOS-NVIDIA-Builder-arm64.app.zip"
                    if not run("archive", ["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(app), str(archive)], 120):
                        raise RuntimeError("Sealed current app archive failed")
                    if digest(binary) != receipt["artifact"]["sha256"]:
                        raise RuntimeError("executable changed during archive")
                    receipt["archive"] = {"bytes": archive.stat().st_size, "sha256": digest(archive),
                        "retainedAfterGUIFailure": receipt["stages"].get("gui", {}).get("state") != "passed",
                        "imageAcceptance": False}
            except Exception as error:
                receipt.setdefault("finalizationErrors", []).append({"stage": "packaged-inputs", "error": str(error)})
        receipt["evidenceFiles"] = {p.name: {"bytes": p.stat().st_size, "sha256": digest(p)}
            for p in OUT.iterdir() if p.is_file() and p.name != "receipt.json"}
        receipt["freeBytesAfter"] = shutil.disk_usage(ROOT).free
        receipt["childProcessGroupsClosed"] = children_closed
        receipt["finished"] = time.time()
        save()
    required = ["frontend", "docs", "hygiene", "format", "clippy", "darwin-cache-tests", "rust-tests", "native-build", "ownership-birth-boundaries", "gui", "archive"]
    if fullstack:
        required += ["darwin-producer-boundaries", "fullstack-input-producer", "companion-filesystem-regressions", "actual-guest-normal-wrong-marker-closure"]
    return 0 if not receipt.get("error") and not receipt.get("finalizationErrors") and all(
        receipt["stages"].get(name, {}).get("state") == "passed" for name in required) else 1


if __name__ == "__main__":
    sys.exit(main())
