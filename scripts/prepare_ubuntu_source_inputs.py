#!/usr/bin/env python3
"""Prepare locked downloads as guest DATA; never compile/package on GitHub.

Invoked only in the exact reviewed hosted input-preparation workflow. Its
archive is authenticated by the existing GitHub run/artifact API before the
Root controller admits a source-build guest. No Actions token enters it.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import urllib.request

PACKAGES = ('build-essential','ca-certificates','curl','file','genisoimage','git',
            'libayatana-appindicator3-dev','librsvg2-dev','libssl-dev',
            'libwebkit2gtk-4.1-dev','openssh-client','ovmf','patchelf',
            'pkg-config','python3','qemu-system-x86','qemu-utils','xdg-utils','xz-utils')


def need(ok, why):
    if not ok: raise ValueError(why)


def run(argv, cwd=None, env=None):
    return subprocess.run(argv, cwd=cwd, env=env, check=True, timeout=1800)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as source:
        while block := source.read(1048576): h.update(block)
    return h.hexdigest()


def safe_tree(output, path, name, member, base=None, parents=(), preserve_file_links=False):
    path = Path(path); base = path.resolve() if base is None else base
    actual = path.resolve(strict=True)
    need(actual == base or actual.is_relative_to(base), 'input link escapes its download/source root')
    info = actual.stat()
    need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'regular input tree only')
    if preserve_file_links and path.is_symlink() and stat.S_ISREG(info.st_mode):
        link = Path(os.readlink(path))
        need(not link.is_absolute(), 'relative contained toolchain file link required')
        item = tarfile.TarInfo(name); item.type = tarfile.SYMTYPE
        item.linkname = str(link); item.mode = stat.S_IMODE(info.st_mode)
        output.addfile(member(item))
    elif stat.S_ISDIR(info.st_mode):
        need(actual not in parents, 'cyclic input directory link')
        output.add(path, arcname=name, recursive=False, filter=member)
        for child in sorted(path.iterdir()):
            safe_tree(output, child, name+'/'+child.name, member, base,
                      (*parents, actual), preserve_file_links)
    else:
        output.add(path, arcname=name, recursive=False, filter=member)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', required=True)
    p.add_argument('--core', type=Path, required=True)
    p.add_argument('--appliance', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    need(os.environ.get('GITHUB_ACTIONS') == 'true' and
         os.environ.get('GITHUB_REPOSITORY') == 'CorniiDog/OPEMOS.EXE',
         'fixed Actions input-preparation context')
    need(re.fullmatch('[0-9a-f]{40}', args.source), 'exact candidate source')
    actual = subprocess.run(['git','rev-parse','HEAD'], capture_output=True,
                            text=True, check=True, timeout=10).stdout.strip()
    need(actual == args.source, 'checkout differs from candidate data identity')
    need(not args.output.exists(), 'fresh input output required')
    args.output.mkdir(mode=0o700, parents=True)
    cache = args.output/'downloads'; cache.mkdir(mode=0o700)
    npm = cache/'npm'; cargo = cache/'cargo'; debs = cache/'debs'
    for directory in (npm,cargo,debs): directory.mkdir(mode=0o755)
    # Download-only. Install hooks, Rust build scripts and project compilation
    # are deliberately absent here; they run in the admitted Ubuntu guest.
    run(['npm','ci','--ignore-scripts','--cache',str(npm.resolve())])
    env = dict(os.environ, CARGO_HOME=str(cargo.resolve()))
    run(['cargo','fetch','--locked','--manifest-path','src-tauri/Cargo.toml'], env=env)
    run(['sudo','apt-get','--yes','--download-only','--no-install-recommends',
         '-o','Dir::State::status=/dev/null','-o','Dir::Cache::archives='+str(debs.resolve()),
         'install',*PACKAGES])
    node = Path(shutil.which('node')).resolve().parent.parent
    rust = Path(subprocess.run(['rustc','--print','sysroot'], check=True,
                              capture_output=True, text=True, timeout=10).stdout.strip())
    need(subprocess.run(['node','--version'],capture_output=True,text=True,check=True).stdout.strip()
         == 'v22.23.2', 'same pinned Node toolchain')
    need(subprocess.run(['rustc','--version'],capture_output=True,text=True,check=True).stdout
         .startswith('rustc 1.98.1 '), 'same pinned Rust toolchain')
    need(args.core.is_dir() and args.appliance.is_file(), 'authenticated Core/appliance inputs')
    # Same tools requested by the locked Tauri CLI2.11.4 bundler, staged as
    # download DATA. They execute only in the guest; absence is not fallback.
    tauri = cache/'tauri'; tauri.mkdir(mode=0o700)
    tools = {
        'AppRun-x86_64':'https://github.com/tauri-apps/binary-releases/releases/download/apprun-old/AppRun-x86_64',
        'linuxdeploy-x86_64.AppImage':'https://github.com/tauri-apps/binary-releases/releases/download/linuxdeploy/linuxdeploy-x86_64.AppImage',
        'linuxdeploy-plugin-gtk.sh':'https://raw.githubusercontent.com/tauri-apps/linuxdeploy-plugin-gtk/master/linuxdeploy-plugin-gtk.sh',
        'linuxdeploy-plugin-gstreamer.sh':'https://raw.githubusercontent.com/tauri-apps/linuxdeploy-plugin-gstreamer/master/linuxdeploy-plugin-gstreamer.sh',
        'linuxdeploy-plugin-appimage.AppImage':'https://github.com/linuxdeploy/linuxdeploy-plugin-appimage/releases/download/continuous/linuxdeploy-plugin-appimage-x86_64.AppImage'}
    for name,url in tools.items():
        with urllib.request.urlopen(url,timeout=60) as source, (tauri/name).open('xb') as output:
            size = 0
            while block := source.read(1048576):
                size += len(block); need(size <= 200000000, 'bounded packaging tool download')
                output.write(block)
            need(size > 0, 'empty packaging tool download')
        (tauri/name).chmod(0o700)
    archive = args.output/'ubuntu-source-inputs.tar'
    expanded = 0; count = 0
    def member(info):
        nonlocal expanded,count
        need(info.isfile() or info.isdir() or info.issym(), 'regular input or contained toolchain file link')
        if info.isfile(): expanded += info.size
        count += 1
        need(count <= 250000, 'finite source/toolchain file inventory')
        info.uid = info.gid = 1000; info.uname = info.gname = ''
        return info
    # Git's archive excludes every runner cache and never follows a candidate
    # symlink into hosted-runner credentials or the output archive itself.
    source_tar = args.output/'source.tar'
    with source_tar.open('xb') as output:
        subprocess.run(['git','archive','--format=tar','--prefix=source/',args.source],
                       stdout=output,check=True,timeout=120)
    with tarfile.open(archive,'x',dereference=True) as output:
        # Preserve only safe source symlinks as DATA. The guest extractor
        # refuses absolute/escaping links before any build script executes.
        with tarfile.open(source_tar,'r') as candidate:
            for info in candidate:
                need(info.isfile() or info.isdir() or info.issym(), 'source archive member type')
                if info.issym():
                    path = Path(info.name); link = Path(info.linkname)
                    need(not link.is_absolute() and
                         Path(os.path.normpath(str(path.parent/link))).is_relative_to(Path('source')),
                         'source symlink cannot escape checkout')
                    count += 1
                else: member(info)
                output.addfile(info, candidate.extractfile(info) if info.isfile() else None)
        for name,path in [('core',args.core),('appliance/fedora-builder.qcow2',args.appliance),
                          ('node',node),('rust',rust),('cargo',cargo),('npm',npm),('cache/tauri',tauri)]:
            # npm's CLI requires modules relative to its real package path.
            # Flattening bin/npm into a regular file changes that Node context.
            safe_tree(output,path,name,member,preserve_file_links=(name=='node'))
        for file in sorted(debs.glob('*.deb')): safe_tree(output,file,'debs/'+file.name,member,base=debs.resolve())
    # This role is source input, never an executable/package success receipt.
    value = {'kind':'UBUNTU_GUEST_SOURCE_INPUT_V1','repository':'CorniiDog/OPEMOS.EXE',
             'source_commit':args.source,'producer_run_id':os.environ['GITHUB_RUN_ID'],
             'producer_attempt':os.environ['GITHUB_RUN_ATTEMPT'],
             'archive_name':archive.name,'archive_bytes':archive.stat().st_size,
             'archive_sha256':digest(archive),'expanded_bytes':expanded,'files':count,
             'packages':list(PACKAGES),'node':'22.23.2','rust':'1.98.1',
             'compiled_or_packaged':False}
    (args.output/'source-input.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    print(json.dumps(value,sort_keys=True))


if __name__ == '__main__': main()
