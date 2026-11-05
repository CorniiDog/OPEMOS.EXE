#!/usr/bin/env python3
"""Stage exactly one Debian package and AppImage for CI artifact retention."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import tomllib
if __package__:
    from .acquire_appliance_windows import load_lock, exact_file, stage as stage_appliance
else:
    from acquire_appliance_windows import load_lock, exact_file, stage as stage_appliance


def fail(message):
    raise SystemExit(message)


def one_regular(directory, pattern, label):
    matches = list(directory.glob(pattern))
    if len(matches) != 1:
        fail(f"Expected exactly one {label}, found {len(matches)}")
    item = matches[0]
    metadata = item.lstat()
    if item.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a regular file, not a link or special file")
    return item, metadata


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def stage_native_executable(root, package, output):
    """Producer-only extraction of the actual ELF inside the built AppImage.

    AppImage is the package/runtime launcher; the window belongs to its inner
    application ELF. Export that exact binary as DATA in the same artifact so
    the existing descriptor can bind the real /proc executable independently.
    This runs only in the hosted producer, never on the OMEN control host.
    https://docs.appimage.org/user-guide/run-appimages.html#extract-the-contents-of-an-appimage
    """
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('GITHUB_REPOSITORY')!='CorniiDog/OPEMOS.EXE':
        fail('Native AppImage extraction is confined to the hosted executable producer')
    package_config=tomllib.loads((root/'src-tauri/Cargo.toml').read_text())
    name=package_config['package']['name']
    if not name or Path(name).name!=name or not all(c.isalnum()or c in '-_.'for c in name):
        fail('Exact current application binary name required')
    # AppImage's documented extraction flag exits without launching AppRun.
    # The candidate build already runs in this disposable hosted CI job.
    (root/'build').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='actual-appimage-native-',dir=root/'build')as directory:
        temp=Path(directory)
        with (temp/'extract.log').open('xb')as out:
            done=subprocess.run([str(package),'--appimage-extract'],cwd=temp,stdin=subprocess.DEVNULL,
                                stdout=out,stderr=subprocess.STDOUT,timeout=120,check=False)
        if done.returncode:
            raw=(temp/'extract.log').read_bytes()
            (root/'build/native-extraction-failure.log').write_bytes(raw)
            fail('Actual AppImage native extraction refused numeric='+str(done.returncode)+'; raw='+repr(raw[:8192]))
        source=temp/'squashfs-root/usr/bin'/name
        if source.resolve()!=source or not source.is_relative_to(temp)or source.is_symlink():
            fail('Native AppImage executable escapes extracted package')
        fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        identity=lambda value:tuple(getattr(value,k)for k in fields)
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode)or before.st_uid!=os.getuid()or before.st_nlink!=1 or not 0<before.st_size<=1024**3:
                fail('Finite actual native executable custody')
            first=os.read(fd,20);os.lseek(fd,0,os.SEEK_SET)
            if first[:6]!=b'\x7fELF\x02\x01'or int.from_bytes(first[18:20],'little')!=62:
                fail('Actual application is not x86_64 ELF')
            target=output/name;dest=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o500)
            value=hashlib.sha256();count=0
            try:
                while block:=os.read(fd,1048576):
                    count+=len(block)
                    if count>before.st_size:fail('Native executable grew')
                    value.update(block);view=memoryview(block)
                    while view:
                        n=os.write(dest,view)
                        if n<=0:fail('Native executable copy stalled')
                        view=view[n:]
                os.fsync(dest)
            finally:os.close(dest)
            if count!=before.st_size or identity(before)!=identity(os.fstat(fd))or identity(before)!=identity(source.lstat()):
                fail('Native AppImage executable changed during recording')
            return target,{'name':name,'bytes':count,'sha256':value.hexdigest(),
                'packageName':package.name,'packageSHA256':digest(package),
                'member':'usr/bin/'+name,'method':'actual-built-AppImage-extraction'}
        finally:os.close(fd)


def stage(root, output, source_commit, appliance_image=None, include_native_executable=False):
    if not source_commit or len(source_commit) != 40 or any(c not in "0123456789abcdef" for c in source_commit):
        fail("Source commit must be one lowercase 40-character Git commit")
    if output.exists():
        fail("Linux package artifact output must not already exist")

    deb, _ = one_regular(root / "src-tauri/target/debug/bundle/deb", "*.deb", "Debian package")
    appimage, app_metadata = one_regular(
        root / "src-tauri/target/debug/bundle/appimage", "*.AppImage", "AppImage"
    )
    if app_metadata.st_mode & 0o111 == 0:
        fail("AppImage must be executable")
    with deb.open("rb") as stream:
        deb_header = stream.read(8)
    if deb_header != b"!<arch>\n":
        fail("Debian package does not have an ar archive header")
    with appimage.open("rb") as stream:
        header = stream.read(20)
    if header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != 62:
        fail("AppImage is not an x86_64 ELF executable")

    lock = None
    if appliance_image is not None:
        # Reuse the existing exact Fedora identity and closed appliance format;
        # no new source, keys, schema or acquisition policy.
        lock = load_lock(root / "runtime/windows-fedora-appliance.json")
        if not exact_file(appliance_image, lock["size"], lock["sha256"]):
            fail("Linux appliance differs from the existing authenticated Fedora pin")

    output.mkdir(mode=0o755)
    staged = []
    for source in (deb, appimage):
        target = output / source.name
        shutil.copyfile(source, target)
        os.chmod(target, stat.S_IMODE(source.stat().st_mode))
        staged.append((target, digest(target)))
    native = None
    if include_native_executable:
        native_path, native = stage_native_executable(root, appimage, output)
        staged.append((native_path, native['sha256']))
    if appliance_image is not None:
        appliance_output = output / (appimage.name + ".runtime") / "appliance"
        stage_appliance(lock, appliance_image, root / "builder/appliance/cloud-init", appliance_output)
        if not exact_file(appliance_output / lock["filename"], lock["size"], lock["sha256"]):
            fail("Staged Linux appliance changed during copy; preserve failed artifact")
    (output / "SHA256SUMS.txt").write_text(
        "".join(f"{value}  {path.name}\n" for path, value in staged), encoding="utf-8"
    )
    provenance = {
        "schemaVersion": 1,
        "kind": "opemos-exe-linux-packages",
        "sourceCommit": source_commit,
        "nativeExecutable": native,
        "appImageRuntime": None if lock is None else {
            "directory": appimage.name + ".runtime",
            "applianceSha256": lock["sha256"],
            "applianceSize": lock["size"],
            "validation": "existing closed appliance-manifest and compiled file pins",
        },
        "packages": [
            {"filename": path.name, "sha256": value, "size": path.stat().st_size}
            for path, value in staged if path.suffix in (".deb", ".AppImage")
        ],
    }
    (output / "provenance.json").write_text(
        json.dumps(provenance, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return provenance


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path, default=Path("linux-package-artifact"))
    parser.add_argument("--source-commit", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--appliance-image", type=Path)
    parser.add_argument("--include-native-executable", action="store_true")
    args = parser.parse_args()
    print(json.dumps(stage(args.root.resolve(), args.output.resolve(), args.source_commit,
                           args.appliance_image, args.include_native_executable), indent=2))


if __name__ == "__main__":
    main()
