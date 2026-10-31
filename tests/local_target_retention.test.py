import importlib.util
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
        (wt / ".gitignore").write_text("src-tauri/target/\n")
        (wt / "tracked").write_text("x")
        subprocess.run(["git", "-C", str(wt), "add", ".gitignore", "tracked"], check=True)
        subprocess.run(["git", "-C", str(wt), "commit", "-qm", "initial"], check=True)
        old = time.time() - retention.STALE_SECONDS - 5
        os.utime(wt / "src-tauri" / "target", (old, old)); return temp, root, wt

    def test_nested_marker_is_refused(self):
        temp, root, wt = self.make_tree()
        with temp:
            nested = wt / "src-tauri" / "target" / "nested"; nested.mkdir(); (nested / ".frozen-input").write_text("keep")
            old = time.time() - retention.STALE_SECONDS - 5
            for path in (nested / ".frozen-input", nested, wt / "src-tauri" / "target"): os.utime(path, (old, old))
            with patch.object(retention, "process_references", return_value=None):
                result = retention.evaluate(root, Path(temp.name) / "receipts", False)
            self.assertEqual(result["candidates"], [])
            self.assertIn("retention marker", result["refused"][0]["reason"])

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
            future = time.time() + retention.STALE_SECONDS + 5
            with patch.object(retention, "process_references", return_value=None), patch.object(retention.time, "time", return_value=future):
                result = retention.evaluate(root, Path(temp.name) / "receipts", True)
            self.assertEqual(len(result["deleted"]), 1, result["refused"]); self.assertFalse(target.exists())
            names = [path.name for path in (Path(temp.name) / "receipts").iterdir()]
            self.assertTrue(any(name.startswith("target-retention-intent-") for name in names))
            self.assertTrue(any(name.startswith("target-retention-result-") for name in names))


if __name__ == "__main__": unittest.main()
