#!/usr/bin/env python3
"""Install and purge the locally built test package in a disposable Debian container."""
from __future__ import annotations
import hashlib, json, os, subprocess
from pathlib import Path
from typing import Callable
PACKAGE_ID = "opemos-exe-linux-test"
BINARY = Path("usr/bin/steamos-nvidia-image-builder")
DESKTOP_DIR = Path("usr/share/applications")
Run = Callable[..., subprocess.CompletedProcess[str]]
def command(*args: str, run: Run = subprocess.run):
    return run(args, text=True, capture_output=True, timeout=60, check=False)
def digest(path: Path) -> str:
    with path.open("rb") as stream: return hashlib.file_digest(stream, "sha256").hexdigest()
def package_path(repo: Path):
    base = json.loads((repo / "src-tauri/tauri.conf.json").read_text())
    linux = json.loads((repo / "src-tauri/tauri.linux-test.conf.json").read_text())
    name = f'{linux["productName"]}_{base["version"]}_amd64'
    bundle = repo / "src-tauri/target/debug/bundle/deb"
    return bundle / f"{name}.deb", bundle / name / BINARY
def require_disposable_debian(root: Path, environ: dict[str, str]) -> None:
    if environ.get("OPEMOS_DISPOSABLE_DEBIAN_CONTAINER") != "1": raise ValueError("exact disposable-container opt-in is required")
    if not (root / ".dockerenv").is_file(): raise ValueError("refusing package mutation outside a disposable container")
    fields = {}
    for line in (root / "etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1); fields[key] = value.strip('"')
    if fields.get("ID") != "debian" or fields.get("VERSION_ID") != "12": raise ValueError("this smoke requires exact Debian 12 container identity")
    if os.geteuid() != 0: raise ValueError("the disposable package smoke must run as container root")
def verify_regular(path: Path, description: str) -> None:
    if path.is_symlink() or not path.is_file(): raise ValueError(f"{description} must be one regular non-symlink file")
def run_smoke(repo: Path, root: Path, environ: dict[str, str], run: Run = subprocess.run) -> None:
    require_disposable_debian(root, environ)
    package, staged_binary = package_path(repo)
    verify_regular(package, "generated Debian package"); verify_regular(staged_binary, "staged package binary")
    package_id = command("dpkg-deb", "--field", str(package), "Package", run=run)
    architecture = command("dpkg-deb", "--field", str(package), "Architecture", run=run)
    if (package_id.returncode or package_id.stdout.strip() != PACKAGE_ID or
            architecture.returncode or architecture.stdout.strip() != "amd64"):
        raise ValueError("generated package identity is not exact")
    initial = command("dpkg-query", "--show", "--showformat=${db:Status-Status}", PACKAGE_ID, run=run)
    if initial.returncode == 0: raise ValueError("refusing to touch a package that was already installed")
    attempted = False; failure: BaseException | None = None; installed_files: list[Path] = []
    try:
        attempted = True
        installed = command("dpkg", "--install", str(package), run=run)
        if installed.returncode: raise RuntimeError(f"dpkg install failed: {installed.stderr.strip()}")
        status = command("dpkg-query", "--show", "--showformat=${db:Status-Status}", PACKAGE_ID, run=run)
        if status.returncode or status.stdout != "installed": raise RuntimeError("package did not reach installed state")
        installed_binary = root / BINARY; verify_regular(installed_binary, "installed application binary")
        if not os.access(installed_binary, os.X_OK) or digest(installed_binary) != digest(staged_binary): raise RuntimeError("installed application binary identity or mode differs")
        entries = list((root / DESKTOP_DIR).glob("*.desktop"))
        matches = [path for path in entries if "Exec=steamos-nvidia-image-builder\n" in path.read_text()]
        if len(matches) != 1 or matches[0].is_symlink(): raise RuntimeError("installed desktop entry identity is missing or ambiguous")
        listed = command("dpkg-query", "--listfiles", PACKAGE_ID, run=run)
        if listed.returncode: raise RuntimeError("installed package file inventory is unavailable")
        for entry in listed.stdout.splitlines():
            candidate = Path(entry)
            if not candidate.is_absolute() or ".." in candidate.parts: raise RuntimeError("installed package file inventory is unsafe")
            rooted = root / candidate.relative_to("/")
            if rooted.is_file() or rooted.is_symlink(): installed_files.append(rooted)
        if installed_binary not in installed_files or matches[0] not in installed_files: raise RuntimeError("installed package inventory omits required files")
    except BaseException as error: failure = error
    finally:
        if attempted:
            purged = command("dpkg", "--purge", PACKAGE_ID, run=run)
            absent = command("dpkg-query", "--show", PACKAGE_ID, run=run)
            residues = [root / BINARY, *installed_files]
            if purged.returncode or absent.returncode == 0 or any(path.exists() or path.is_symlink() for path in residues):
                cleanup = RuntimeError("package purge did not restore the disposable container")
                if failure: raise RuntimeError(f"{failure}; additionally, {cleanup}") from failure
                raise cleanup
    if failure: raise failure
def main() -> None:
    run_smoke(Path(__file__).resolve().parent.parent, Path("/"), dict(os.environ))
    print("PASS: exact local test package installed, verified, purged, and left no package residue.")
    print("No graphical application launched.")
if __name__ == "__main__": main()
