#!/usr/bin/env python3
"""Extract only a closed Windows runtime from an authenticated workflow artifact."""
import argparse, shutil, stat, tempfile, zipfile
from pathlib import Path, PurePosixPath

def fail(message): raise SystemExit(message)

def extract(archive, output):
    if output.exists() or output.is_symlink(): fail("Cached Windows runtime output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging=Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-",dir=output.parent)); seen=set()
    try:
        with zipfile.ZipFile(archive) as source:
            for item in source.infolist():
                path=PurePosixPath(item.filename)
                if not path.parts or path.parts[0]!="runtime": continue
                relative=PurePosixPath(*path.parts[1:])
                if not relative.parts or item.is_dir(): continue
                if path.is_absolute() or any(part in ("", ".", "..") for part in relative.parts) or "\\" in item.filename: fail("Cached Windows runtime member escapes its closed root")
                name=relative.as_posix()
                if name in seen: fail("Cached Windows runtime contains a duplicate member")
                if stat.S_IFMT(item.external_attr>>16)==stat.S_IFLNK: fail("Cached Windows runtime contains a symbolic link")
                seen.add(name); target=staging.joinpath(*relative.parts); target.parent.mkdir(parents=True,exist_ok=True)
                with source.open(item) as reader, target.open("xb") as writer: shutil.copyfileobj(reader,writer,1024*1024)
        if not seen or "runtime-manifest.json" not in seen or "source-provenance.json" not in seen: fail("Cached Windows runtime is incomplete")
        staging.rename(output)
    finally:
        if staging.exists(): shutil.rmtree(staging)

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--archive",type=Path,required=True); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args(); extract(args.archive,args.output)
if __name__=="__main__": main()
