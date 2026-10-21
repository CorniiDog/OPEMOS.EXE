"""Actual metadata-only workflow subprocess/filesystem; never macOS/VM proof."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
import xml.etree.ElementTree as ET


class MacOSRouteFailure(unittest.TestCase):
    def test_normal_preflight_is_red_and_retains_honest_reports(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/macos-arm64.yml").read_text()
        self.assertNotIn("runs-on: macos-15", workflow)
        body = textwrap.dedent(workflow.split("python3 - <<'PYOMEN'\n", 1)[1].split("\n          PYOMEN", 1)[0])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary = root / "summary.md"
            env = dict(os.environ, OPEMOS_EXE_COMMIT="1" * 40, GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="2",
                       GITHUB_STEP_SUMMARY=str(summary))
            result = subprocess.run([sys.executable, "-c", body], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("::error title=OMEN macOS unavailable::", result.stdout)
            out = root / "build/macos-arm64-evidence"
            value = json.loads((out / "receipt.json").read_text())
            self.assertEqual((value["status"], value["source"], value["run_id"], value["attempt"]),
                             ("unavailable", "1" * 40, "123", "2"))
            for field in ("macos_executed", "VMStarted", "productAcceptance"):
                self.assertIs(value[field], False)
            self.assertIs(value["diagnostic_only"], True)
            self.assertEqual(ET.parse(out / "output.xml").find("./suite/test/status").get("status"), "FAIL")
            self.assertEqual(ET.parse(out / "xunit.xml").getroot().get("failures"), "1")
            for name in ("report.html", "log.html", "route-error.log"):
                self.assertGreater((out / name).stat().st_size, 0)
            self.assertIn("Screenshots unavailable", summary.read_text())
            self.assertFalse(list(out.glob("*.png")))
            self.assertFalse((out / "gui-events.json").exists())
            self.assertFalse((root / "src-tauri").exists())


if __name__ == "__main__":
    unittest.main()
