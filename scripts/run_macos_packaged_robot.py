"""Actual same-job packaged transaction under the already pinned Robot runtime.

Robot runs the real native producer/GUI process, not a report synthesized from
old receipts. Its failure and numeric process closure remain separate evidence.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SHA = "5a194db36524604fafa1da89adebc837db9a95adf15ffd746e09ce98251e6c68"


def main():
    # This is the official provider/version/hash already declared by the Robot
    # source contract, not a moving pip resolution or new runtime dependency.
    with urllib.request.urlopen("https://pypi.org/pypi/robotframework/7.5/json", timeout=30) as response:
        metadata = json.loads(response.read(1048576))
    wheels = [item for item in metadata["urls"] if item["filename"] == "robotframework-7.5-py3-none-any.whl" and item["digests"]["sha256"] == SHA]
    if len(wheels) != 1 or not wheels[0]["url"].startswith("https://files.pythonhosted.org/packages/"):
        raise RuntimeError("Official pinned Robot wheel unavailable")
    with urllib.request.urlopen(wheels[0]["url"], timeout=30) as response:
        wheel = response.read(16 * 1024**2 + 1)
    if len(wheel) > 16 * 1024**2 or hashlib.sha256(wheel).hexdigest() != SHA:
        raise RuntimeError("Robot wheel size/hash mismatch")
    with tempfile.TemporaryDirectory(prefix="opemos-mac-robot-") as directory:
        private = Path(directory)
        archive = private / "runtime.whl"
        archive.write_bytes(wheel)
        runtime = private / "runtime"
        runtime.mkdir(mode=0o700)
        with zipfile.ZipFile(archive) as source:
            for item in source.infolist():
                path = Path(item.filename)
                if path.is_absolute() or ".." in path.parts or stat.S_ISLNK(item.external_attr >> 16):
                    raise RuntimeError("Unsafe pinned wheel member")
            source.extractall(runtime)
        sys.path.insert(0, str(runtime))
        import robot
        if robot.__version__ != "7.5":
            raise RuntimeError("Wrong actual Robot runtime")
        reports = ROOT / "build/macos-robot-evidence"
        reports.mkdir(parents=True, mode=0o700, exist_ok=False)
        os.environ["OPEMOS_MAC_ROBOT_PYTHON"] = sys.executable
        return robot.run(str(ROOT / "tests/macos-packaged.robot"), outputdir=str(reports),
                         output="output.xml", report="report.html", log="log.html", xunit="xunit.xml")


if __name__ == "__main__":
    raise SystemExit(main())
