#!/usr/bin/env python3
"""Add Core's exact Windows publisher zstd dependency to an existing runtime."""
import argparse, hashlib, json, shutil, stat, tempfile, zipfile
from pathlib import Path
try:
    from stage_runtime_bundle import REQUIRED, validate_runtime
except ModuleNotFoundError:
    from scripts.stage_runtime_bundle import REQUIRED, validate_runtime
CONTRACT_PATH = "contracts/windows-publisher-zstd-v1.json"
EXPECTED_CONTRACT_SHA256 = "025463326bac7d99ef2486e6d6fdc10348797fe98904834f54124c5a42845fe0"
def fail(message): raise SystemExit(message)
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def regular(path, size, sha256):
    metadata = path.lstat()
    return not path.is_symlink() and stat.S_ISREG(metadata.st_mode) and metadata.st_size == size and digest(path) == sha256
def prepare(runtime_root, core_root, output):
    contract_path = core_root / CONTRACT_PATH
    if digest(contract_path) != EXPECTED_CONTRACT_SHA256: fail("Core Windows zstd contract does not match the pinned commit bytes")
    contract = json.loads(contract_path.read_bytes())
    if set(contract) != {"schemaVersion", "kind", "platform", "component", "source", "payload", "license", "consumer"}: fail("Core Windows zstd contract fields are not closed")
    if contract["schemaVersion"] != 1 or contract["kind"] != "opemos-windows-publisher-zstd-dependency" or contract["platform"] != "windows-x86_64": fail("Core Windows zstd contract identity is unsupported")
    asset, payload, license_item = contract["source"]["asset"], contract["payload"], contract["license"]
    archive, license_source = core_root / asset["localPath"], core_root / license_item["localPath"]
    if not regular(archive, asset["size"], asset["sha256"]): fail("Core Windows zstd archive identity changed")
    if not regular(license_source, license_item["size"], license_item["sha256"]): fail("Core Windows zstd license identity changed")
    if output.exists(): fail("Prepared runtime output must not already exist")
    manifest = json.loads((runtime_root / "runtime-manifest.json").read_bytes())
    if manifest.get("platform") != "windows" or set(manifest.get("commands", {})) != REQUIRED["windows"] - {"zstd"}: fail("Base Windows runtime command inventory is not the expected pre-zstd closure")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    try:
        shutil.rmtree(staging); shutil.copytree(runtime_root, staging, symlinks=False)
        zstd_target = staging / payload["runtimePath"]; zstd_target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as source:
            info = source.getinfo(payload["member"])
            if info.is_dir() or info.file_size != payload["size"]: fail("Core Windows zstd archive member identity changed")
            zstd_target.write_bytes(source.read(info))
        if digest(zstd_target) != payload["sha256"]: fail("Core Windows zstd payload identity changed")
        license_target = staging / license_item["runtimePath"]; license_target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(license_source, license_target)
        manifest["commands"]["zstd"] = payload["runtimePath"]
        for path, item in ((zstd_target, payload), (license_target, license_item)):
            manifest["files"].append({"path": path.relative_to(staging).as_posix(), "size": item["size"], "sha256": item["sha256"]})
        manifest["components"].append({"name": contract["component"]["name"], "version": contract["component"]["version"], "license_files": [license_item["runtimePath"]]})
        (staging / "runtime-manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        validate_runtime(staging, "windows"); staging.rename(output)
    finally:
        if staging.exists(): shutil.rmtree(staging)
def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--runtime-root", type=Path, required=True); parser.add_argument("--core-root", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(); prepare(args.runtime_root, args.core_root, args.output)
if __name__ == "__main__": main()
