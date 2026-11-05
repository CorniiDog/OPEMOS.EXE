"""Actual native producer path/descriptor transaction; no stat-method override.

Run in admitted native CI/VM only. A collection failure retains exact metadata
differences; it is not evidence of a particular Windows mechanism by itself.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('native_producer', ROOT / 'scripts/record_executable_artifact.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class NativeProducerCustody(unittest.TestCase):
    def test_actual_exe_path_descriptor_hash_and_readback(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve() / 'producer.exe'
            data = b'bounded native producer fixture, not an executable'
            path.write_bytes(data)
            value, raw = M.held(path, len(data), keep=True)
            self.assertEqual(raw, data)
            self.assertEqual(value, {'name': path.name, 'bytes': len(data),
                                    'sha256': hashlib.sha256(data).hexdigest()})
            self.assertEqual(path.read_bytes(), data)

    def test_actual_size_limit_remains_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve() / 'producer.exe'
            path.write_bytes(b'over cap')
            with self.assertRaisesRegex(ValueError, 'Actual non-reparse'):
                M.held(path, 1)

    def test_actual_readonly_exe_source_is_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve() / 'producer.exe'
            path.write_bytes(b'readonly native package')
            path.chmod(0o444)
            before = path.stat()
            try:
                value, raw = M.held(path, 128, keep=True)
                self.assertEqual(raw, b'readonly native package')
                self.assertEqual(value['bytes'], before.st_size)
                self.assertEqual(path.stat().st_mode, before.st_mode)
            finally:
                path.chmod(0o600)

    def test_actual_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError, 'Actual non-reparse'):
                M.held(Path(root).resolve(), 128)

    def test_actual_windows_layout_producer_to_descriptor(self):
        self._producer_transaction(False)

    def test_actual_readonly_windows_layout_producer_to_descriptor(self):
        self._producer_transaction(True)

    def _producer_transaction(self, readonly):
        with tempfile.TemporaryDirectory() as root:
            previous = Path.cwd()
            os.chdir(Path(root).resolve())
            try:
                path = Path('dist/windows/OPEMOS.EXE-windows-x86_64-unsigned.exe')
                path.parent.mkdir(parents=True)
                path.write_bytes(b'ordinary native producer transaction fixture')
                if readonly:
                    path.chmod(0o444)
                env = {'GITHUB_REPOSITORY': 'CorniiDog/OPEMOS.EXE',
                       'GITHUB_RUN_ID': '101', 'GITHUB_RUN_ATTEMPT': '2',
                       'GITHUB_WORKFLOW_REF': 'CorniiDog/OPEMOS.EXE/' +
                           M.PRODUCERS['windows']['workflow'] + '@refs/pull/200/merge',
                       'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_REF': 'refs/pull/200/merge'}
                with patch.dict(os.environ, env):
                    value = M.record('windows', 'a'*40, '201', 'fixture-not-upload', 'b'*64, 'producer-result')
                self.assertEqual(value['package_sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(value['package_sha256'], value['executable_sha256'])
                self.assertTrue(Path('producer-result/executable-producer.json').is_file())
            finally:
                path.chmod(0o600)
                os.chdir(previous)

    def test_ubuntu_descriptor_binds_package_and_actual_inner_executable_separately(self):
        import json
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory).resolve();previous=Path.cwd();os.chdir(root)
            try:
                artifact=root/'linux-package-artifact';artifact.mkdir()
                package=artifact/'current.AppImage';package.write_bytes(b'actual package representation')
                native=artifact/'current-native-application';native.write_bytes(b'actual inner executable representation')
                package_sha=hashlib.sha256(package.read_bytes()).hexdigest()
                native_sha=hashlib.sha256(native.read_bytes()).hexdigest()
                proof={'sourceCommit':'a'*40,'nativeExecutable':{'name':native.name,'bytes':native.stat().st_size,
                    'sha256':native_sha,'packageName':package.name,'packageSHA256':package_sha,
                    'method':'actual-built-AppImage-extraction'}}
                (artifact/'provenance.json').write_text(json.dumps(proof))
                env={'GITHUB_REPOSITORY':'CorniiDog/OPEMOS.EXE','GITHUB_RUN_ID':'101','GITHUB_RUN_ATTEMPT':'2',
                    'GITHUB_WORKFLOW_REF':'CorniiDog/OPEMOS.EXE/'+M.PRODUCERS['ubuntu']['workflow']+'@refs/heads/current',
                    'GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/current'}
                with patch.dict(os.environ,env):
                    value=M.record('ubuntu','a'*40,'201','actual-fixture-artifact','b'*64,'producer-result')
                    self.assertEqual(value['package_sha256'],package_sha)
                    self.assertEqual(value['executable_sha256'],native_sha)
                    self.assertNotEqual(value['package_sha256'],value['executable_sha256'])
                    native.write_bytes(b'changed inner application')
                    with self.assertRaisesRegex(ValueError,'native executable/package byte identity'):
                        M.record('ubuntu','a'*40,'201','actual-fixture-artifact','b'*64,'refused-producer')
                    self.assertFalse((root/'refused-producer').exists())
            finally:os.chdir(previous)

    def test_actual_hardlink_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve() / 'producer.exe'
            path.write_bytes(b'single link required')
            os.link(path, path.with_suffix('.alias'))
            with self.assertRaisesRegex(ValueError, 'Actual non-reparse'):
                M.held(path, 128)

    def test_actual_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve() / 'producer.exe'
            path.write_bytes(b'no reparse substitution')
            link = path.with_suffix('.link')
            try:
                link.symlink_to(path)
            except OSError as error:
                if os.name == 'nt' and getattr(error, 'winerror', None) == 1314:
                    self.skipTest('Windows symlink privilege unavailable; not a reparse pass')
                raise
            with self.assertRaises(ValueError):
                M.held(link, 128)

    @unittest.skipUnless(os.name == 'nt', 'Actual Win32 sharing contract')
    def test_full_hash_refuses_existing_writer_then_succeeds_after_close(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve() / 'producer.exe'
            path.write_bytes(b'no overlapping writer')
            writer = os.open(path, os.O_WRONLY | os.O_BINARY)
            try:
                with self.assertRaises(PermissionError):
                    M.held(path, 128)
                self.assertEqual(os.fstat(writer).st_size, 21)
            finally:
                os.close(writer)
            value, raw = M.held(path, 128, keep=True)
            self.assertEqual(raw, b'no overlapping writer')
            self.assertEqual(value['sha256'], hashlib.sha256(raw).hexdigest())

    @unittest.skipUnless(os.name == 'nt', 'Actual Win32 sharing contract')
    def test_native_binding_refuses_real_write_and_replacement(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve() / 'producer.exe'
            path.write_bytes(b'held bytes')
            replacement = path.with_suffix('.replacement')
            replacement.write_bytes(b'other bytes')
            before = path.lstat()
            fd = os.open(path, os.O_RDONLY | os.O_BINARY)
            try:
                with M.native_binding(path, fd, before, os.fstat(fd)):
                    with self.assertRaises(PermissionError):
                        with path.open('wb'):
                            self.fail('Writer opened during native read custody')
                    with self.assertRaises(PermissionError):
                        os.replace(replacement, path)
                    self.assertEqual(os.read(fd, 128), b'held bytes')
                # The real sharing restriction ends only when the context closes.
                os.close(fd)
                fd = None
                os.replace(replacement, path)
                self.assertEqual(path.read_bytes(), b'other bytes')
            finally:
                if fd is not None:
                    os.close(fd)


if __name__ == '__main__':
    unittest.main()
