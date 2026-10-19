"""Pinned existing Homebrew bottles -> relocated, sealed native runtime.

Never installs a formula, runs its postinstall, or modifies the Homebrew prefix.
Only an exclusively created staging tree is written. Bottle provenance and every
Mach-O pre/post transformation identity are retained beside the runtime manifest.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

from stage_runtime_bundle import digest, validate_runtime

ROOTS = ["qemu", "python@3.14", "git", "gh", "bash", "gnu-tar", "openssh"]
COMMANDS = {
    "qemu-img": ("qemu", "bin/qemu-img"),
    "qemu-system-aarch64": ("qemu", "bin/qemu-system-aarch64"),
    "qemu-system-x86_64": ("qemu", "bin/qemu-system-x86_64"),
    "python3": ("python@3.14", "bin/python3.14"),
    "git": ("git", "bin/git"), "gh": ("gh", "bin/gh"),
    "bash": ("bash", "bin/bash"), "tar": ("gnu-tar", "bin/gtar"),
    "ssh": ("openssh", "bin/ssh"), "scp": ("openssh", "bin/scp"),
    "ssh-keygen": ("openssh", "bin/ssh-keygen"),
}
MAGIC = {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}


def run(args, seconds=120):
    print("+", " ".join(map(str, args)), flush=True)
    return subprocess.check_output(list(map(str, args)), text=True, timeout=seconds).strip()


def load_lock(path):
    lock = json.loads(path.read_bytes())
    if (set(lock) != {"schema_version", "platform", "architecture", "bottle_tag", "provider", "roots", "formulae"}
            or (lock["schema_version"], lock["platform"], lock["architecture"], lock["provider"], lock["bottle_tag"])
            != (1, "macos", "arm64", "homebrew/core", "arm64_sequoia") or lock["roots"] != ROOTS):
        raise ValueError("Darwin source lock identity changed")
    reached, pending = set(), set(ROOTS)
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        item = lock["formulae"][name]
        if item["name"] != name or item["bottle_tag"] not in ("all", "arm64_sequoia"):
            raise ValueError("Wrong formula or architecture")
        sha = item["bottle"]["sha256"]
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise ValueError("Invalid bottle hash")
        if item["bottle"]["url"] != f"https://ghcr.io/v2/homebrew/core/{name.replace('@', '/')}/blobs/sha256:{sha}":
            raise ValueError("Unexpected Homebrew bottle origin")
        if not item["license"]:
            raise ValueError("Missing provider license declaration")
        reached.add(name)
        pending.update(set(item["dependencies"]) - reached)
    if reached != set(lock["formulae"]):
        raise ValueError("Source lock is not a closed dependency graph")
    return lock


def confined(root, path):
    path.resolve().relative_to(root.resolve())
    return path


def acquire_bottle(item, cache):
    """Use the frozen provider address, not mutable installed brew metadata.

    GHCR's anonymous public-read bearer is transport-only, never a user identity
    or persisted credential. It is neither logged nor sent to another endpoint.
    """
    sha = item["bottle"]["sha256"]
    target = cache / (sha + ".tar.gz")
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file() or digest(target) != sha:
            raise ValueError("Retained bottle cache identity changed")
        return target
    repository = "homebrew/core/" + item["name"].replace("@", "/")
    token_url = "https://ghcr.io/token?" + urllib.parse.urlencode({
        "service": "ghcr.io", "scope": "repository:" + repository + ":pull"})
    with urllib.request.urlopen(token_url, timeout=30) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError("Public registry token response exceeds bound")
    token = json.loads(raw)["token"]
    request = urllib.request.Request(item["bottle"]["url"], headers={"Authorization": "Bearer " + token})
    # Never forward an authorization header across a registry storage redirect.
    class StorageRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not newurl.startswith("https://"):
                raise ValueError("Registry storage redirect must retain TLS")
            result = super().redirect_request(req, fp, code, msg, headers, newurl)
            if result is not None:
                result.remove_header("Authorization")
            return result
    partial = cache / (sha + ".partial")
    deadline = time.monotonic() + 600
    with urllib.request.build_opener(StorageRedirect()).open(request, timeout=60) as response, partial.open("xb") as output:
        received = 0
        while True:
            if time.monotonic() >= deadline:
                raise ValueError("Pinned bottle acquisition deadline")
            block = response.read(1024**2)
            if not block:
                break
            received += len(block)
            if received > 2 * 1024**3:
                raise ValueError("Pinned bottle exceeds storage bound")
            output.write(block)
        output.flush()
        os.fsync(output.fileno())
    if digest(partial) != sha:
        raise ValueError("Exact public bottle hash mismatch: " + item["name"])
    partial.rename(target)
    return target


def build_only_member(name):
    """Noninteractive tool payload: retain code/data, not SDK/man/test/pip trees."""
    path = "/" + name + "/"
    if any(part in path for part in (
            "/share/man/", "/share/doc/", "/share/info/", "/share/locale/", "/share/terminfo/",
            "/include/", "/Headers/", "/lib/pkgconfig/", "/lib/cmake/",
            "/lib/python3.14/test/", "/lib/python3.15/test/", "/idle_test/", "/tkinter/test/",
            "/site-packages/pip/", "/site-packages/wheel/", "/ensurepip/")):
        return True
    if name.endswith((".a", ".la", ".pc", ".cmake", ".h", ".hpp")):
        return True
    # Framework aliases are duplicated SDK/bundle views, not CLI dependencies.
    # Keep the actual versioned payload, not an invalid materialized framework.
    return any(part in path for part in (
        ".framework/Versions/Current/", ".framework/Resources/", ".framework/Python/"))


def relocated_relative(value):
    return Path(*(part + "-payload" if part.endswith(".framework") else part for part in Path(value).parts))


def extract(archive, root, component=None):
    """No archive owner/mode/device restoration; no writes through links."""
    links = []
    seen = set()
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        if len(members) > 200000 or sum(m.size for m in members) > 8 * 1024**3:
            raise ValueError("Bottle exceeds extraction budget")
        for member in members:
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                raise ValueError("Bottle member escapes root")
            if component is not None and relative.parts[0] != component:
                raise ValueError("Bottle member outside declared component")
            if member.name in seen:
                raise ValueError("Duplicate bottle member")
            seen.add(member.name)
            if member.isfile() and member.size and component is not None:
                basename = relative.name.upper()
                notice = basename.startswith(("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "LGPL", "GPL", "BSD-"))
                notice = notice or (component == "sqlite" and relative.name == "sqlite3.h")
                if notice:
                    destination = root / "licenses" / component / (str(len(seen)) + "-" + relative.name)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with source.extractfile(member) as stream, destination.open("xb") as output:
                        shutil.copyfileobj(stream, output)
            if component is not None and build_only_member(member.name):
                continue
            path = root / member.name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as target, source.extractfile(member) as stream:
                    shutil.copyfileobj(stream, target)
                path.chmod(0o755 if member.mode & 0o111 else 0o644)
            elif member.issym() or member.islnk():
                links.append((path, member.linkname, member.islnk()))
            else:
                raise ValueError("Special bottle member refused")
    for path, name, hard in links:
        path.parent.mkdir(parents=True, exist_ok=True)
        if hard:
            target = root / name
        elif name.startswith(("/opt/homebrew/Cellar/", "@@HOMEBREW_CELLAR@@/")):
            target = root / name.split("Cellar/", 1)[-1].removeprefix("@@HOMEBREW_CELLAR@@/")
        else:
            target = path.parent / name
        confined(root, target)
        path.symlink_to(os.path.relpath(target, path.parent))


def dependencies(path):
    return [line.strip().split(" (compatibility", 1)[0]
            for line in run(["/usr/bin/otool", "-L", path]).splitlines()[1:]]


def relocate(root, kegs):
    files = [p for p in root.rglob("*") if p.is_file()]
    native = []
    for path in files:
        with path.open("rb") as stream:
            if stream.read(4) in MAGIC:
                native.append(path)
    initial_hashes = {p: digest(p) for p in native}
    records = []
    for path in native:
        before = digest(path)
        arches = run(["/usr/bin/lipo", "-archs", path]).split()
        if "arm64" not in arches:
            raise ValueError("Non-native runtime Mach-O: " + str(path))
        changes = []
        for dep in dependencies(path):
            if dep.startswith(("/usr/lib/", "/System/Library/")):
                continue
            target = None
            for name, keg in kegs.items():
                for prefix in (f"/opt/homebrew/opt/{name}/", f"/opt/homebrew/Cellar/{name}/{keg.name}/",
                               f"@@HOMEBREW_PREFIX@@/opt/{name}/", f"@@HOMEBREW_CELLAR@@/{name}/{keg.name}/"):
                    if dep.startswith(prefix):
                        target = keg / relocated_relative(dep[len(prefix):])
            if dep.startswith("@loader_path/"):
                target = path.parent / dep.removeprefix("@loader_path/")
            if dep.startswith("@rpath/"):
                suffix = relocated_relative(dep.removeprefix("@rpath/")).as_posix()
                choices = [p for p in native if p.as_posix().endswith("/" + suffix)]
                if choices and len({initial_hashes[p] for p in choices}) == 1:
                    target = min(choices, key=lambda p: len(str(p)))
            if target is None or not confined(root, target).is_file():
                raise ValueError(f"Unresolved loader dependency: {path}: {dep}")
            new = "@loader_path/" + os.path.relpath(target, path.parent)
            if new != dep:
                changes += ["-change", dep, new]
        if changes:
            run(["/usr/bin/install_name_tool", *changes, path])
        ids = run(["/usr/bin/otool", "-D", path]).splitlines()[1:]
        if ids:
            run(["/usr/bin/install_name_tool", "-id", "@loader_path/" + path.name, path])
        run(["/usr/bin/codesign", "--force", "--sign", "-", path])
        run(["/usr/bin/codesign", "--verify", "--strict", path])
        for dep in dependencies(path):
            if dep.startswith(("/usr/lib/", "/System/Library/")):
                continue
            if not dep.startswith("@loader_path/") or not confined(root, path.parent / dep[13:]).is_file():
                raise ValueError("Post-relocation loader closure changed")
        records.append({"path": path.relative_to(root).as_posix(), "before": before, "after": digest(path), "architectures": arches})
    return records


def construct(lock_path, output, evidence, firmware):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("Native Apple Silicon required")
    if output.exists() or output.is_symlink():
        raise ValueError("Runtime output must be create-only")
    lock = load_lock(lock_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)
    provenance = {"sourceLockSHA256": digest(lock_path), "bottles": [], "loader": [], "complete": False}
    def save():
        (evidence / "darwin-runtime-producer.json").write_text(json.dumps(provenance, indent=2) + "\n")
    save()
    # Staging is deliberately retained on failure for causal investigation.
    stage = Path(tempfile.mkdtemp(prefix=".darwin-runtime-", dir=output.parent))
    unpacked, runtime = stage / "unpacked", stage / "runtime"
    unpacked.mkdir()
    runtime.mkdir()
    cache = stage / "bottles"
    cache.mkdir()
    for name, item in sorted(lock["formulae"].items()):
        print("Acquiring exact Homebrew bottle", name, item["bottle"]["sha256"], flush=True)
        archive = acquire_bottle(item, cache)
        provenance["bottles"].append({"name": name, "sha256": digest(archive), "bytes": archive.stat().st_size})
        save()
        extract(archive, unpacked, name)
    # All link targets must resolve inside the exact pinned bottle closure.
    for path in unpacked.rglob("*"):
        if path.is_symlink():
            confined(unpacked, path)
            if not path.exists() or path.resolve() in path.parents:
                raise ValueError("Dangling or recursive bottle link")
    shutil.copytree(unpacked, runtime / "kegs", symlinks=False)
    # Framework CLI builds do not require CFBundle framework discovery when
    # PYTHONHOME and all loader references are explicit. Preserve versioned data
    # as ordinary payload: materialized Current/Resources aliases are invalid
    # signed-framework structure (Apple TN2206), and aren't copied above.
    for framework in sorted(runtime.rglob("*.framework"), key=lambda p: len(p.parts), reverse=True):
        framework.rename(framework.with_name(framework.name + "-payload"))
    kegs = {}
    components = []
    notice_root = Path(__file__).resolve().parents[1] / "runtime/macos-licenses"
    notices = json.loads((notice_root / "source-notices.json").read_bytes())
    for name, item in sorted(lock["formulae"].items()):
        versions = list((runtime / "kegs" / name).iterdir())
        if len(versions) != 1 or not versions[0].is_dir():
            raise ValueError("Ambiguous bottle keg")
        kegs[name] = versions[0]
        licenses = list((runtime / "kegs/licenses" / name).glob("*"))
        for notice in notices.get(name, []):
            path = notice_root / notice["file"]
            if path.stat().st_size != notice["bytes"] or digest(path) != notice["sha256"]:
                raise ValueError("Vendored original license text changed")
            target = runtime / "kegs/licenses" / name / notice["file"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            licenses.append(target)
        if not licenses:
            raise ValueError("Bottle has no retained license text: " + name)
        components.append({"name": name, "version": item["version"],
                           "license_files": [p.relative_to(runtime).as_posix() for p in licenses]})
    provenance["loader"] = relocate(runtime, kegs)
    # Nested Homebrew frameworks/apps need their own ad-hoc bundle seal before
    # the outer .app seal. Hash inventory is created only after these changes.
    bundles = [p for p in runtime.rglob("*") if p.is_dir() and p.suffix == ".app"]
    for bundle in sorted(bundles, key=lambda p: len(p.parts), reverse=True):
        run(["/usr/bin/codesign", "--force", "--sign", "-", bundle])
        run(["/usr/bin/codesign", "--verify", "--deep", "--strict", bundle])
    for row in provenance["loader"]:
        row["afterBundleSeal"] = digest(runtime / row["path"])
    qemu_share = kegs["qemu"] / "share/qemu"
    shutil.copytree(qemu_share, runtime / "share/qemu", symlinks=False)
    from stage_macos_app import FIRMWARE
    for relative, (size, sha256) in FIRMWARE.items():
        source = firmware / Path(relative).name
        if source.is_symlink() or source.stat().st_size != size or digest(source) != sha256:
            raise ValueError("Existing firmware pin mismatch")
        shutil.copyfile(source, runtime / relative)
    (runtime / "bin").mkdir()
    commands = {}
    ca = kegs["ca-certificates"] / "share/ca-certificates/cacert.pem"
    if ca.stat().st_size != 188900 or digest(ca) != "a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505":
        raise ValueError("Pinned Mozilla CA data changed; no host keychain import")
    provenance["caBundle"] = {"path": ca.relative_to(runtime).as_posix(), "sha256": digest(ca),
                              "sourceBottleSHA256": lock["formulae"]["ca-certificates"]["bottle"]["sha256"],
                              "hostKeychainsRead": False, "postinstallExecuted": False}
    for command, (name, relative) in COMMANDS.items():
        target = kegs[name] / relative
        if not target.is_file():
            raise ValueError("Command missing from exact bottle: " + command)
        options = ' -L "$root/share/qemu"' if command.startswith("qemu-system-") else ""
        if command == "scp":
            # OpenSSH's compiled prefix must not select a host-installed peer.
            options = ' -S "$root/bin/ssh"'
        setup = f'export SSL_CERT_FILE="$root/{ca.relative_to(runtime)}"\n'
        if command == "python3":
            homes = list(kegs[name].glob("Frameworks/Python.framework-payload/Versions/3.14"))
            if len(homes) != 1:
                raise ValueError("Python framework home missing")
            setup += 'unset PYTHONPATH PYTHONSTARTUP PYTHONUSERBASE PYTHONINSPECT\n'
            setup += f'export PYTHONHOME="$root/{homes[0].relative_to(runtime)}" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1\n'
            # No Homebrew sitecustomize or ambient host/user site-packages.
            options = " -S"
        if command == "git":
            setup += f'export GIT_EXEC_PATH="$root/{kegs[name].relative_to(runtime)}/libexec/git-core"\n'
        wrapper = runtime / "bin" / command
        wrapper.write_text('#!/bin/sh\nset -eu\nroot=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)\n' + setup +
                           f'exec "$root/{target.relative_to(runtime)}"{options} "$@"\n')
        wrapper.chmod(0o755)
        commands[command] = wrapper.relative_to(runtime).as_posix()
    wrapper = runtime / "bin/hdiutil"
    wrapper.write_text('#!/bin/sh\nexec /usr/bin/hdiutil "$@"\n')
    wrapper.chmod(0o755)
    commands["hdiutil"] = "bin/hdiutil"
    provenance["systemHdiutil"] = {"path": "/usr/bin/hdiutil", "sha256": digest(Path("/usr/bin/hdiutil")), "os": run(["sw_vers"])}
    license_target = runtime / "licenses/OPEMOS-LICENSE"
    license_target.parent.mkdir(exist_ok=True)
    shutil.copyfile(Path(__file__).resolve().parents[1] / "LICENSE", license_target)
    shutil.copyfile(notice_root / "source-notices.json", runtime / "licenses/source-notices.json")
    components.append({"name": "opemos-darwin-adapters", "version": os.environ["OPEMOS_EXE_COMMIT"],
                       "license_files": ["licenses/OPEMOS-LICENSE"]})
    (runtime / "source-provenance.json").write_text(json.dumps(lock, sort_keys=True) + "\n")
    for path in runtime.rglob("*"):
        if path.is_file() and path.stat().st_size == 0:
            path.unlink()
    files = [{"path": p.relative_to(runtime).as_posix(), "size": p.stat().st_size, "sha256": digest(p)}
             for p in sorted(runtime.rglob("*")) if p.is_file()]
    manifest = {"schema_version": 1, "platform": "macos", "commands": commands, "files": files, "components": components}
    (runtime / "runtime-manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
    validate_runtime(runtime, "macos")
    # Real native loader invocation, no provider PATH fallback.
    for command in ["qemu-img", "qemu-system-aarch64", "qemu-system-x86_64", "python3", "git", "gh", "bash", "tar"]:
        run([runtime / commands[command], "--version"])
    provenance.update(complete=True, runtimeManifestSHA256=digest(runtime / "runtime-manifest.json"))
    save()
    if output.exists():
        raise ValueError("Runtime output appeared")
    runtime.rename(output)
    # Only this create-only producer's temporary extraction copy; original
    # checksum-bound bottle cache and durable evidence remain untouched.
    shutil.rmtree(stage)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=Path("runtime/macos-arm64.sources.json"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--firmware", type=Path, required=True)
    args = parser.parse_args()
    construct(args.lock, args.output, args.evidence, args.firmware)
