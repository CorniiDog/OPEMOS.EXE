import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).parents[1] / "scripts" / "local_target_retention.py"
spec = importlib.util.spec_from_file_location("retention", SOURCE)
retention = importlib.util.module_from_spec(spec); spec.loader.exec_module(retention)


class LocalTargetRetentionTests(unittest.TestCase):
    def make_tree(self):
        temp = tempfile.TemporaryDirectory(); root = Path(temp.name) / "repo"; wt = root / ".worktrees" / "one"
        (wt / "src-tauri" / "target").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(wt)], check=True)
        subprocess.run(["git", "-C", str(wt), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(wt), "config", "user.name", "test"], check=True)
        (wt / ".gitignore").write_text("src-tauri/target/\nsrc-tauri/.opemos-target-custody.json\n")
        (wt / "tracked").write_text("x")
        subprocess.run(["git", "-C", str(wt), "add", ".gitignore", "tracked"], check=True)
        subprocess.run(["git", "-C", str(wt), "commit", "-qm", "initial"], check=True)
        self.write_custody(wt)
        old = time.time() - retention.STALE_SECONDS - 5
        os.utime(wt / "src-tauri" / "target", (old, old)); return temp, root, wt

    def write_custody(self, wt, **overrides):
        path = wt / "src-tauri" / retention.CUSTODY_NAME
        path.touch(exist_ok=True)
        source = (wt / "src-tauri").stat(); target = (wt / "src-tauri" / "target").stat(); worktree = wt.stat()
        record = {"version": 1, "creatorUid": os.getuid(), "worktree": [worktree.st_dev, worktree.st_ino], "source": [source.st_dev, source.st_ino], "target": [target.st_dev, target.st_ino], "jobId": "fixture-stale-output", "jobState": "complete", "producerLease": "released", "requiredArtifact": None, "latestArtifact": None}
        record.update(overrides)
        path.write_text(json.dumps(record))

    def test_nested_marker_is_refused(self):
        temp, root, wt = self.make_tree()
        with temp:
            nested = wt / "src-tauri" / "target" / "nested"; nested.mkdir(); (nested / ".frozen-input").write_text("keep")
            old = time.time() - retention.STALE_SECONDS - 5
            for path in (nested / ".frozen-input", nested, wt / "src-tauri" / "target"): os.utime(path, (old, old))
            self.write_custody(wt)
            with patch.object(retention, "process_references", return_value=None):
                result = retention.evaluate(root, Path(temp.name) / "receipts", False)
            self.assertEqual(result["candidates"], [])
            self.assertIn("retained marker", result["refused"][0]["reason"])

    def test_actual_fd_consumer_and_producer_lease_are_refused(self):
        temp, root, wt = self.make_tree()
        with temp:
            target = wt / "src-tauri" / "target"
            held = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            duplicate = os.dup(held)
            try:
                target_stat = os.fstat(held)
                with self.assertRaisesRegex(RuntimeError, "live process (path|inode) reference"):
                    retention.process_pid_references(os.getpid(), target_stat, str(target), os.path.realpath(target) + os.sep, held)
                os.close(duplicate); duplicate = -1
                retention.process_pid_references(os.getpid(), target_stat, str(target), os.path.realpath(target) + os.sep, held)
            finally:
                if duplicate >= 0: os.close(duplicate)
                os.close(held)
            (target / ".opemos-producer-lease").write_text("active")
            old = time.time() - retention.STALE_SECONDS - 5
            for path in (target / ".opemos-producer-lease", target): os.utime(path, (old, old))
            self.write_custody(wt)
            with patch.object(retention, "process_references", return_value=None):
                result = retention.evaluate(root, Path(temp.name) / "receipts", False)
            self.assertEqual(result["candidates"], [])
            self.assertIn("producer lease", result["refused"][0]["reason"])

    def test_dirty_source_is_refused(self):
        temp, root, wt = self.make_tree()
        with temp:
            (wt / "tracked").write_text("changed")
            with patch.object(retention, "process_references", return_value=None):
                result = retention.evaluate(root, Path(temp.name) / "receipts", False)
            self.assertEqual(result["candidates"], [])
            self.assertIn("dirty", result["refused"][0]["reason"])

    def test_recent_descendant_and_mount_or_process_unknown_are_refused(self):
        temp, root, wt = self.make_tree()
        with temp:
            target = wt / "src-tauri" / "target"; (target / "debug").mkdir(); (target / "debug" / "new").write_text("x")
            self.write_custody(wt)
            with patch.object(retention, "process_references", return_value=None):
                result = retention.evaluate(root, Path(temp.name) / "receipts", False)
            self.assertIn("recent target descendant", result["refused"][0]["reason"])
            future = time.time() + retention.STALE_SECONDS + 5
            with patch.object(retention, "process_references", side_effect=RuntimeError("unknown process reference")), patch.object(retention.time, "time", return_value=future):
                result = retention.evaluate(root, Path(temp.name) / "receipts", False)
            self.assertIn("unknown process reference", result["refused"][0]["reason"])

    def test_symlinked_ancestry_and_internal_receipts_are_refused(self):
        temp, root, wt = self.make_tree()
        with temp:
            source = wt / "src-tauri"; external = Path(temp.name) / "external"; external.mkdir()
            source.rename(Path(temp.name) / "moved-src-tauri"); (external / "target").mkdir(); source.symlink_to(external, target_is_directory=True)
            result = retention.evaluate(root, Path(temp.name) / "receipts", False)
            self.assertEqual(result["candidates"], [])
            self.assertTrue(result["refused"])
            with self.assertRaisesRegex(RuntimeError, "outside repository"):
                retention.evaluate(root, root / "receipts", False)

    def test_execute_records_intent_then_result(self):
        temp, root, wt = self.make_tree()
        with temp:
            target = wt / "src-tauri" / "target"; (target / "debug").mkdir(); (target / "debug" / "old").write_text("x")
            old = time.time() - retention.STALE_SECONDS - 5
            for path in (target / "debug" / "old", target / "debug", target): os.utime(path, (old, old))
            self.write_custody(wt)
            future = time.time() + retention.STALE_SECONDS + 5
            with patch.object(retention, "process_references", return_value=None), patch.object(retention.time, "time", return_value=future):
                result = retention.evaluate(root, Path(temp.name) / "receipts", True)
            self.assertEqual(len(result["deleted"]), 1, result["refused"]); self.assertFalse(target.exists())
            names = [path.name for path in (Path(temp.name) / "receipts").iterdir()]
            self.assertTrue(any(name.startswith("target-retention-intent-") for name in names))
            self.assertTrue(any(name.startswith("target-retention-result-") for name in names))

    def test_actual_normal_producer_to_consumer_transaction(self):
        temp, root, wt = self.make_tree()
        with temp:
            target = wt / "src-tauri" / "target"; (target / "release").mkdir(); (target / "release" / "stale").write_text("x")
            old = time.time() - retention.STALE_SECONDS - 5
            for path in (target / "release" / "stale", target / "release", target): os.utime(path, (old, old))
            self.write_custody(wt)
            future = time.time() + retention.STALE_SECONDS + 5
            with patch.object(retention.time, "time", return_value=future):
                result = retention.evaluate(root, Path(temp.name) / "receipts", True)
            self.assertEqual(result["deleted"], [])
            self.assertTrue(target.exists())
            self.assertIn("unknown process reference", result["refused"][0]["reason"])
            self.assertFalse(result.get("closeErrors"))

    def test_late_symlink_fault_retains_progress_and_intent(self):
        temp, root, wt = self.make_tree()
        with temp:
            target = wt / "src-tauri" / "target"; (target / "debug").mkdir()
            (target / "debug" / "first").write_text("x"); (target / "debug" / "second").write_text("y")
            old = time.time() - retention.STALE_SECONDS - 5
            for path in (target / "debug" / "first", target / "debug" / "second", target / "debug", target): os.utime(path, (old, old))
            self.write_custody(wt)
            real_unlink = retention.os.unlink; injected = False
            def replace_peer(path, *args, **kwargs):
                nonlocal injected
                result = real_unlink(path, *args, **kwargs)
                if not injected:
                    injected = True; peer = "second" if path == "first" else "first"
                    real_unlink(peer, dir_fd=kwargs["dir_fd"])
                    retention.os.symlink("/outside", peer, dir_fd=kwargs["dir_fd"])
                return result
            future = time.time() + retention.STALE_SECONDS + 5
            with patch.object(retention, "process_references", return_value=None), patch.object(retention.time, "time", return_value=future), patch.object(retention.os, "unlink", side_effect=replace_peer):
                result = retention.evaluate(root, Path(temp.name) / "receipts", True)
            self.assertEqual(result["partialDeletion"]["removedEntries"], 1)
            self.assertEqual(result["partialDeletion"]["kind"], "delete-operation")
            self.assertIn("intent", result["partialDeletion"])

    def test_unreadable_inventory_is_refused_before_effect(self):
        temp, root, wt = self.make_tree()
        with temp:
            target = wt / "src-tauri" / "target"; blocked = target / "blocked"; blocked.mkdir()
            (blocked / "input").write_text("x"); os.chmod(blocked, 0)
            self.write_custody(wt)
            try:
                with patch.object(retention, "process_references", return_value=None):
                    result = retention.evaluate(root, Path(temp.name) / "receipts", False)
            finally:
                os.chmod(blocked, 0o700)
            self.assertEqual(result["candidates"], [])
            self.assertIn("target traversal error", result["refused"][0]["reason"])

    def test_partial_delete_records_current_count_and_result_receipt(self):
        temp, root, wt = self.make_tree()
        with temp:
            target = wt / "src-tauri" / "target"; (target / "debug").mkdir()
            (target / "debug" / "first").write_text("x"); (target / "debug" / "second").write_text("y")
            old = time.time() - retention.STALE_SECONDS - 5
            for path in (target / "debug" / "first", target / "debug" / "second", target / "debug", target): os.utime(path, (old, old))
            self.write_custody(wt)
            real_unlink = retention.os.unlink
            unlink_calls = 0
            def fail_second(path, *args, **kwargs):
                nonlocal unlink_calls
                unlink_calls += 1
                if unlink_calls == 2: raise OSError(5, "injected unlink failure")
                return real_unlink(path, *args, **kwargs)
            future = time.time() + retention.STALE_SECONDS + 5
            with patch.object(retention, "process_references", return_value=None), patch.object(retention.time, "time", return_value=future), patch.object(retention.os, "unlink", side_effect=fail_second):
                result = retention.evaluate(root, Path(temp.name) / "receipts", True)
            partial = result["partialDeletion"]
            self.assertEqual(partial["kind"], "delete-operation")
            self.assertEqual(partial["removedEntries"], 1)
            self.assertTrue(target.exists())
            self.assertEqual(len(list((target / "debug").iterdir())), 1)
            receipt = json.loads(Path(result["receipt"]).read_text())
            self.assertEqual(receipt["partialDeletion"]["removedEntries"], 1)


if __name__ == "__main__": unittest.main()
