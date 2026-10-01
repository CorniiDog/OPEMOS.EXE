#!/usr/bin/env python3
"""Validate a same-repository cached Windows runtime against current immutable inputs."""
import argparse, json
from pathlib import Path
from acquire_runtime_windows import current_lock_matches, load_lock
from prepare_windows_runtime import CONTRACT_PATH, EXPECTED_CONTRACT_SHA256, digest, regular
from stage_runtime_bundle import validate_runtime

def fail(message): raise SystemExit(message)

def validate(runtime, lock_path, core_root):
    runtime, _raw, manifest_sha256=validate_runtime(runtime,"windows")
    lock=load_lock(lock_path)
    if not current_lock_matches(runtime,lock): fail("Cached Windows runtime source provenance does not match the current lock")
    contract_path=core_root/CONTRACT_PATH
    if digest(contract_path)!=EXPECTED_CONTRACT_SHA256: fail("Core Windows zstd contract does not match the pinned commit bytes")
    contract=json.loads(contract_path.read_bytes()); asset, payload, license_item=contract["source"]["asset"],contract["payload"],contract["license"]
    if not regular(core_root/asset["localPath"],asset["size"],asset["sha256"]): fail("Core Windows zstd archive identity changed")
    if not regular(runtime/payload["runtimePath"],payload["size"],payload["sha256"]): fail("Cached Windows zstd payload identity changed")
    if not regular(runtime/license_item["runtimePath"],license_item["size"],license_item["sha256"]): fail("Cached Windows zstd license identity changed")
    manifest=json.loads((runtime/"runtime-manifest.json").read_bytes()); expected={"name":contract["component"]["name"],"version":contract["component"]["version"],"license_files":[license_item["runtimePath"]]}
    if expected not in manifest["components"] or manifest["commands"].get("zstd")!=payload["runtimePath"]: fail("Cached Windows zstd contract binding changed")
    print(manifest_sha256)

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--runtime",type=Path,required=True); parser.add_argument("--lock",type=Path,required=True); parser.add_argument("--core-root",type=Path,required=True); args=parser.parse_args(); validate(args.runtime,args.lock,args.core_root)
if __name__=="__main__": main()
