"""Actual file/hash guards only; fixtures are never product acceptance."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_macos_arm64_ci import verify_completed_image
from macos_transaction_evidence import native_session_snapshot, reconcile_gui


class CompletedImageFiles(unittest.TestCase):
    def test_actual_prebuild_session_inventory_and_ambiguous_faults(self):
        with tempfile.TemporaryDirectory() as directory:
            anchor = Path(directory).resolve()
            root = anchor / "sessions"
            before = native_session_snapshot(root, anchor)
            events = anchor / "events.json"
            now = time.time()
            rows = [{"kind": "app", "pid": os.getpid(), "launchDate": now,
                     "executable": sys.executable, "time": now},
                    {"kind": "gui-pre-build-checkpoint", "pid": os.getpid(), "time": now},
                    {"kind": "failure", "error": "actual fixture refusal", "time": now}]
            events.write_text(json.dumps(rows))
            after = native_session_snapshot(root, anchor)
            result = reconcile_gui(events, before, after, sys.executable)
            # This is real filesystem/UID/pgrep observation, not a VM pass.
            self.assertFalse(result["VMClosurePassed"])
            if before["qemuAbsent"] and after["qemuAbsent"]:
                self.assertEqual(result["sessionState"], "not-launched-observed")
            rows.insert(1, {"kind": "build-request-intent"})
            events.write_text(json.dumps(rows))
            self.assertEqual(reconcile_gui(events, before, after, sys.executable)["sessionState"], "launched-or-ambiguous")
            rows.pop(1)
            events.write_text(json.dumps(rows))
            root.mkdir(mode=0o700)
            (root / "actual-session-marker").write_text("actual changed inventory")
            changed = native_session_snapshot(root, anchor)
            self.assertEqual(reconcile_gui(events, before, changed, sys.executable)["sessionState"], "launched-or-ambiguous")
            root.chmod(0o777)
            with self.assertRaises(ValueError):
                native_session_snapshot(root, anchor)
            root.chmod(0o700)
            (anchor / "linked").symlink_to(root)
            with self.assertRaises(ValueError):
                native_session_snapshot(anchor / "linked", anchor)

    def test_complete_transaction_and_faults(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source.img"
            source.write_bytes(b"immutable fixture source")
            source.chmod(0o444)
            image = root / "output.img"
            image.write_bytes(b"changed output" * 10000)
            manifest = root / "output.manifest.json"
            sha = hashlib.sha256(source.read_bytes()).hexdigest()
            value = {"schemaVersion": 1, "resultClass": "nvidia-mutation-valid",
                     "input": {"sourceSha256": sha},
                     "output": {"filename": image.name, "format": "raw", "bytes": image.stat().st_size,
                                "sha256": hashlib.sha256(image.read_bytes()).hexdigest()},
                     "validation": {key: True for key in ("passed", "sourceUnchanged", "candidateAttachedReadOnly", "layoutRecognized", "markerVerified", "nvidiaPayloadVerified")}}
            def store():
                manifest.write_text(json.dumps(value))
            store()
            events = [{"kind": "completed-image-ui-observed", "text":
                       f"Exported image: {image}; {image.stat().st_size} bytes; raw layout=gpt.\nBuild manifest: {manifest}.\n"}]
            result = verify_completed_image(events, source, sha)
            self.assertTrue(result["fullFileRead"])
            self.assertEqual(result["sha256"], value["output"]["sha256"])
            with self.assertRaises(RuntimeError):
                verify_completed_image([], source, sha)
            value["resultClass"] = "mutation-valid"
            store()
            with self.assertRaises(RuntimeError):
                verify_completed_image(events, source, sha)
            value["resultClass"] = "nvidia-mutation-valid"
            store()
            original = image.read_bytes()
            image.write_bytes(b"x" * len(original))
            with self.assertRaises(RuntimeError):
                verify_completed_image(events, source, sha)
            image.unlink()
            image.symlink_to(source)
            with self.assertRaises(RuntimeError):
                verify_completed_image(events, source, sha)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), sha)


if __name__ == "__main__":
    unittest.main()
