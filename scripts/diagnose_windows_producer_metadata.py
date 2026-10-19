"""Finite native metadata collection, NOT producer or application acceptance."""
import ctypes
from ctypes import wintypes
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_birthtime_ns', 'st_file_attributes')


class Basic(ctypes.Structure):
    _fields_ = [(name, ctypes.c_longlong) for name in
                ('CreationTime', 'LastAccessTime', 'LastWriteTime', 'ChangeTime')] + [('FileAttributes', wintypes.DWORD)]


class FileID(ctypes.Structure):
    _fields_ = [('VolumeSerialNumber', ctypes.c_ulonglong), ('FileId', ctypes.c_ubyte * 16)]


def main():
    if os.name != 'nt':
        raise RuntimeError('Native Windows diagnostic only')
    import msvcrt
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL

    def native(handle):
        basic, identity = Basic(), FileID()
        for kind, value in [(0, basic), (18, identity)]:
            if not kernel.GetFileInformationByHandleEx(handle, kind, ctypes.byref(value), ctypes.sizeof(value)):
                raise ctypes.WinError(ctypes.get_last_error())
        return {'basic': {name: getattr(basic, name) for name, _ in Basic._fields_},
                'volume': identity.VolumeSerialNumber, 'file_id_hex': bytes(identity.FileId).hex()}

    def path_native(path):
        handle = kernel.CreateFileW(str(path), 0x80, 7, None, 3, 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return native(handle)
        finally:
            if not kernel.CloseHandle(handle):
                raise ctypes.WinError(ctypes.get_last_error())

    def fields(value):
        return {name: getattr(value, name, None) for name in FIELDS}

    def snapshot(path, fd=None):
        # Preserve actual observation ordering, including both path APIs before
        # and after acquiring an independent native handle. No sleeps/retries.
        value = {'lstat_first': fields(path.lstat()), 'stat_first': fields(path.stat()),
                 'native_path': path_native(path), 'lstat_after_native_open': fields(path.lstat())}
        if fd is not None:
            value['fstat'] = fields(os.fstat(fd))
            value['native_descriptor'] = native(msvcrt.get_osfhandle(fd))
        return value

    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if source != os.environ['OPEMOS_EXE_COMMIT']:
        raise RuntimeError('Exact diagnostic source mismatch')
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    spec = importlib.util.spec_from_file_location('actual_producer', Path(__file__).with_name('record_executable_artifact.py'))
    producer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(producer)
    result = {'diagnostic_only': True, 'source': source, 'argv': sys.argv,
              'python': sys.version, 'platform': platform.platform(), 'pid': os.getpid(), 'cases': [],
              'children_started': False, 'normal_or_readonly_producer_acceptance': False}
    output = Path('build/windows-metadata-diagnostic')
    output.mkdir(parents=True, exist_ok=False)
    try:
        for readonly in (False, True):
            row = {'readonly': readonly, 'observations': {}}
            result['cases'].append(row)
            with tempfile.TemporaryDirectory(prefix='opemos-producer-metadata-') as root:
                path = Path(root).resolve() / 'producer.exe'
                row['before_create_absent'] = not path.exists()
                data = b'finite native producer metadata diagnostic'
                with path.open('xb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                row['observations']['after_create_write_close'] = snapshot(path)
                try:
                    if readonly:
                        path.chmod(0o444)
                    row['observations']['after_chmod_path_only'] = {
                        'lstat': fields(path.lstat()), 'stat': fields(path.stat())}
                    # Preserve the first ordinary call BEFORE the independent
                    # Win32 observer opens a path handle and may refresh caches.
                    try:
                        value, _ = producer.held(path, 4096)
                        row['actual_producer_before_native_observer'] = {'returned': value}
                    except Exception as error:
                        row['actual_producer_before_native_observer'] = {
                            'error': type(error).__name__, 'message': str(error)}
                    row['observations']['after_chmod_before_open'] = snapshot(path)
                    fd = os.open(path, os.O_RDONLY | os.O_BINARY)
                    try:
                        row['observations']['after_descriptor_open'] = snapshot(path, fd)
                        raw = os.read(fd, 4096)
                        row['read_matches'] = raw == data
                        row['sha256'] = hashlib.sha256(raw).hexdigest()
                        row['observations']['after_read'] = snapshot(path, fd)
                    finally:
                        os.close(fd)
                    try:
                        os.fstat(fd)
                        raise RuntimeError('Diagnostic descriptor survived close')
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise
                        row['descriptor_closed'] = True
                    row['observations']['after_descriptor_close'] = snapshot(path)
                    try:
                        value, _ = producer.held(path, 4096)
                        row['actual_producer'] = {'returned': value}
                    except Exception as error:
                        row['actual_producer'] = {'error': type(error).__name__, 'message': str(error)}
                    row['observations']['after_actual_producer'] = snapshot(path)
                finally:
                    path.chmod(0o600)
            row['owned_temp_absent'] = not Path(root).exists()
    finally:
        with (output / 'metadata.json').open('x', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    print('Finite native metadata captured; production acceptance NOT established')


if __name__ == '__main__':
    main()
