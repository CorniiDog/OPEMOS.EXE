#!/usr/bin/env python3
"""Acquire the pinned x86_64 Windows runtime used by the application bundle."""
import argparse, hashlib, json, os, platform, re, shutil, subprocess, tarfile, tempfile, urllib.request, zipfile
from pathlib import Path
EXPECTED=("git-for-windows","github-cli","python","qemu","cdrtools-binary","cdrtools-source")
COMMANDS={"git":"git/cmd/git.exe","python":"python/python.exe","qemu-img":"qemu/qemu-img.exe","qemu-system-x86_64":"qemu/qemu-system-x86_64.exe","mkisofs":"cdrtools/mkisofs.exe","ssh":"git/usr/bin/ssh.exe","scp":"git/usr/bin/scp.exe","ssh-keygen":"git/usr/bin/ssh-keygen.exe","gh":"gh/bin/gh.exe","bash":"git/bin/bash.exe","tar":"git/usr/bin/tar.exe"}
def fail(message): raise SystemExit(message)
def digest(path):
    value=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""): value.update(block)
    return value.hexdigest()
def exact(path,item): return path.exists() and not path.is_symlink() and path.is_file() and path.stat().st_size==item["size"] and digest(path)==item["sha256"]
def load_lock(path):
    raw=json.loads(path.read_text(encoding="utf-8"))
    if set(raw)!={"schema_version","platform","architecture","sources"} or (raw["schema_version"],raw["platform"],raw["architecture"])!=(1,"windows","x86_64"): fail("Windows runtime source lock identity is invalid")
    sources=raw["sources"]
    if not isinstance(sources,list) or tuple(item.get("component") for item in sources)!=EXPECTED: fail("Windows runtime source lock must contain the exact component closure")
    names=set()
    for item in sources:
        if set(item)!={"component","version","url","file","size","sha256"} or not all(isinstance(item[k],str) and item[k] for k in ("component","version","url","file","sha256")) or not item["url"].startswith("https://") or Path(item["file"]).name!=item["file"] or item["file"] in names or not isinstance(item["size"],int) or item["size"]<=0 or not re.fullmatch(r"[0-9a-f]{64}",item["sha256"]): fail("Windows runtime source lock contains an invalid archive")
        names.add(item["file"])
    return raw
def acquire_source(item,cache,downloader=urllib.request.urlretrieve):
    target=cache/item["file"]
    if exact(target,item): return target
    if target.exists() or target.is_symlink(): target.unlink()
    cache.mkdir(parents=True,exist_ok=True); partial=cache/f".{item['file']}.part"
    if partial.exists() or partial.is_symlink(): partial.unlink()
    try:
        downloader(item["url"],partial)
        if not exact(partial,item): fail(f"Pinned Windows archive identity mismatch: {item['component']}")
        os.replace(partial,target)
    finally:
        if partial.exists() or partial.is_symlink(): partial.unlink()
    return target
def current_lock_matches(root,lock):
    path=root/"source-provenance.json"; expected=json.dumps(lock,sort_keys=True,separators=(",",":"))+"\n"
    return path.is_file() and not path.is_symlink() and path.read_text(encoding="utf-8")==expected
def validate_base(root):
    manifest=json.loads((root/"runtime-manifest.json").read_text(encoding="utf-8"))
    if set(manifest)!={"schema_version","platform","commands","files","components"} or manifest["schema_version"]!=1 or manifest["platform"]!="windows" or manifest["commands"]!=COMMANDS: fail("Windows base runtime manifest identity is invalid")
    declared=set()
    for item in manifest["files"]:
        if set(item)!={"path","sha256","size"} or item["path"] in declared or not exact(root/item["path"],item): fail("Windows base runtime file identity changed")
        declared.add(item["path"])
    if any(path not in declared for path in COMMANDS.values()): fail("Windows base runtime command is undeclared")
    names=set()
    for component in manifest["components"]:
        if set(component)!={"name","version","license_files"} or component["name"] in names or not component["license_files"] or any(path not in declared for path in component["license_files"]): fail("Windows base runtime component identity is invalid")
        names.add(component["name"])
    actual={path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file() and path.name!="runtime-manifest.json"}
    if actual!=declared: fail("Windows base runtime contains undeclared files")

def one(root,pattern,label):
    found=sorted(p for p in root.rglob(pattern) if p.is_file() and not p.is_symlink())
    if len(found)!=1: fail(f"Pinned Windows archive must provide exactly one {label}")
    return found[0]
def unzip(archive,destination):
    with zipfile.ZipFile(archive) as source:
        for item in source.infolist():
            try:(destination/item.filename).resolve().relative_to(destination.resolve())
            except ValueError:fail("Windows zip member escapes the extraction root")
        source.extractall(destination)
def run(args,label):
    result=subprocess.run(args,check=False)
    if result.returncode: fail(f"{label} failed with exit code {result.returncode}")
def move_tree(source,destination,temporary):
    shutil.move(str(source),destination)
    if temporary.exists(): shutil.rmtree(temporary)
def construct(output,cache,lock_path):
    if platform.system()!="Windows" or platform.machine() not in ("AMD64","x86_64"): fail("Pinned Windows runtime acquisition requires Windows x86_64")
    lock=load_lock(lock_path)
    if output.exists():
        validate_base(output)
        if current_lock_matches(output,lock): return output
        fail("Existing Windows runtime does not match the current source lock")
    sources={item["component"]:acquire_source(item,cache) for item in lock["sources"]}; output.parent.mkdir(parents=True,exist_ok=True); staging=Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-",dir=output.parent))
    try:
        git=staging/"git"; run([str(sources["git-for-windows"]),"-y",f"-o{git}"],"PortableGit extraction")
        for path in (git/"usr/share",git/"mingw64/share"):
            if path.exists(): shutil.rmtree(path)
        temp=staging/".gh"; temp.mkdir(); unzip(sources["github-cli"],temp); gh=one(temp,"gh.exe","GitHub CLI executable").parent.parent
        if not (gh/"LICENSE").is_file(): fail("Pinned GitHub CLI license is unavailable")
        move_tree(gh,staging/"gh",temp)
        python=staging/"python"; python.mkdir(); unzip(sources["python"],python); run([str(sources["qemu"]),"/S",f"/D={staging/'qemu'}"],"QEMU extraction")
        temp=staging/".cdr"; temp.mkdir(); seven=shutil.which("7z") or shutil.which("7zz")
        if not seven: fail("7-Zip is required to extract cdrtools")
        run([seven,"x","-y",f"-o{temp}",str(sources["cdrtools-binary"])],"cdrtools extraction"); cdr=staging/"cdrtools"; cdr.mkdir(); shutil.copy2(one(temp,"mkisofs.exe","cdrtools executable"),cdr/"mkisofs.exe"); shutil.rmtree(temp)
        with tarfile.open(sources["cdrtools-source"],"r:gz") as source:
            stream=source.extractfile(source.getmember("cdrtools-3.02/COPYING")); (cdr/"COPYING").write_bytes(stream.read() if stream else fail("Pinned cdrtools license is unavailable"))
        for relative in COMMANDS.values():
            if not (staging/relative).is_file(): fail(f"Pinned Windows runtime command is unavailable: {relative}")
        licenses={"git-for-windows":("2.55.0.windows.5",["git/LICENSE.txt"]),"python":("3.13.15",["python/LICENSE.txt"]),"github-cli":("2.100.0",["gh/LICENSE"]),"qemu":("11.1.0",["qemu/COPYING","qemu/COPYING.LIB"]),"cdrtools":("3.02a09",["cdrtools/COPYING"])}; components=[]
        for name,(version,files) in licenses.items():
            if any(not (staging/path).is_file() for path in files): fail(f"Pinned Windows runtime license is unavailable: {name}")
            components.append({"name":name,"version":version,"license_files":files})
        (staging/"source-provenance.json").write_text(json.dumps(lock,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8"); files=[{"path":path.relative_to(staging).as_posix(),"sha256":digest(path),"size":path.stat().st_size} for path in sorted(staging.rglob("*")) if path.is_file()]
        (staging/"runtime-manifest.json").write_text(json.dumps({"schema_version":1,"platform":"windows","commands":COMMANDS,"files":files,"components":components},sort_keys=True,separators=(",",":")),encoding="utf-8"); validate_base(staging)
        if output.exists(): fail("Windows runtime output appeared during acquisition")
        os.rename(staging,output)
    finally:
        if staging.exists(): shutil.rmtree(staging)
    return output
def main():
    root=Path(__file__).resolve().parent.parent; parser=argparse.ArgumentParser(); parser.add_argument("--output",type=Path,default=root/"build/runtime/windows"); parser.add_argument("--cache",type=Path,default=root/"build/runtime-cache/windows"); parser.add_argument("--lock",type=Path,default=root/"runtime/windows-x86_64.sources.json"); args=parser.parse_args(); print(construct(args.output,args.cache,args.lock))
if __name__=="__main__": main()
