import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

# Inspect only this repository's locally generated test package, never an
# externally supplied archive. This check establishes no publication trust.
root = Path(__file__).resolve().parent.parent
version = json.loads((root / 'src-tauri/tauri.conf.json').read_text())['version']
product = json.loads((root / 'src-tauri/tauri.linux-test.conf.json').read_text())['productName']
bundle_root = root / 'src-tauri/target/debug/bundle/deb'
package_name = f'{product}_{version}_amd64'
package = bundle_root / f'{package_name}.deb'


def command(*args):
    return subprocess.check_output(args, text=True, timeout=60)

def verify_bundle_marker(build, packaged):
    """Require byte identity except Tauri's single UNK -> DEB bundle marker."""
    if build.stat().st_size != packaged.stat().st_size:
        raise ValueError('Packaged executable size differs from build output')
    differences = []
    with build.open('rb') as original, packaged.open('rb') as bundled:
        offset = 0
        while chunk := original.read(1024 * 1024):
            other = bundled.read(len(chunk))
            if chunk != other:
                for index, (left, right) in enumerate(zip(chunk, other)):
                    if left != right:
                        differences.append(offset + index)
                        if len(differences) > 3:
                            raise ValueError('Unexpected executable changes during packaging')
            offset += len(chunk)
        if len(differences) != 3 or differences != list(range(differences[0], differences[0] + 3)):
            raise ValueError('Missing or malformed Debian bundle marker patch')
        prefix = b'__TAURI_BUNDLE_TYPE_VAR_'
        start = differences[0] - len(prefix)
        if start < 0:
            raise ValueError('Missing bundle marker prefix')
        original.seek(start)
        bundled.seek(start)
        if original.read(len(prefix) + 3) != prefix + b'UNK' or bundled.read(len(prefix) + 3) != prefix + b'DEB':
            raise ValueError('Unexpected bundle marker transformation')


def main():
    metadata = command('dpkg-deb', '--field', str(package))
    for expected in ('Package: opemos-exe-linux-test\n', 'Architecture: amd64\n', f'Version: {version}\n',
                     'libc6 (>= 2.39)', 'libssl3t64 | libssl3', 'liblzma5',
                     'libwebkit2gtk-4.1-0', 'libgtk-3-0'):
        assert expected in metadata, expected
    print(metadata)
    with tempfile.TemporaryDirectory(prefix='opemos-linux-package-check-') as scratch:
        command('dpkg-deb', '--raw-extract', str(package), scratch)
        extracted = Path(scratch)
        binary = extracted / 'usr/bin/steamos-nvidia-image-builder'
        assert binary.is_file() and not binary.is_symlink() and os.access(binary, os.X_OK)
        assert stat.S_IMODE(binary.stat().st_mode) == 0o755
        for parent in (extracted / 'usr', extracted / 'usr/bin', extracted / 'usr/share/applications'):
            assert stat.S_IMODE(parent.stat().st_mode) == 0o755
        with binary.open('rb') as stream:
            header = stream.read(64)
        assert header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20], 'little') == 62
        def digest(path):
            with path.open('rb') as stream:
                return hashlib.file_digest(stream, 'sha256').hexdigest()
        staging = bundle_root / package_name / 'data/usr/bin/steamos-nvidia-image-builder'
        assert digest(binary) == digest(staging)
        verify_bundle_marker(root / 'src-tauri/target/debug/steamos-nvidia-image-builder', binary)
        linkage = command('ldd', str(binary))
        assert 'not found' not in linkage
        desktop = list((extracted / 'usr/share/applications').glob('*.desktop'))
        assert len(desktop) == 1
        assert stat.S_IMODE(desktop[0].stat().st_mode) == 0o644
        entry = desktop[0].read_text()
        assert '\nExec=steamos-nvidia-image-builder\n' in entry
        assert '\nName=OPEMOS EXE Linux Test\n' in entry
        assert not any((extracted / 'DEBIAN' / script).exists() for script in ('preinst', 'postinst', 'prerm', 'postrm'))
        print('PASS: amd64 ELF; packaged binary hash matches staging; only expected Tauri UNK-to-DEB marker differs from build; all shared libraries resolve; desktop entry and public read/execute modes match; no maintainer scripts.')
    print('Package SHA-256:', digest(package))
    print('No package installed and no graphical application launched.')


if __name__ == '__main__':
    main()
