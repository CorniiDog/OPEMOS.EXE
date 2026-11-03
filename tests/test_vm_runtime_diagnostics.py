"""No native admission or Codex service is used by optional diagnostics."""
from pathlib import Path
from types import SimpleNamespace
import importlib.util
import fcntl
import os
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "diagnostics", Path(__file__).parents[1] / "scripts/vm_runtime_diagnostics.py")
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


class DiagnosticBoundaryTests(unittest.TestCase):
    def backend(self, sink):
        return SimpleNamespace(root=sink, observer_captures=[],
                               observer_capture_receipt=None)

    def test_missing_unwritable_and_full_copy_sinks_cannot_veto_native_result(self):
        with tempfile.TemporaryDirectory() as directory:
            # A sealed Linux memfd really refuses append, including under Root.
            sealed = os.memfd_create('optional-report', os.MFD_ALLOW_SEALING)
            fcntl.fcntl(sealed, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            try:
                sinks = [Path(directory) / 'missing' / 'reports',
                         Path('/proc/self/fd') / str(sealed)]
                for sink in sinks:
                    with self.assertRaises(OSError):
                        with sink.open('ab') as output:
                            output.write(b'optional diagnostic')
                            output.flush()
                    backend = self.backend(sink)
                    for index in range(100):
                        diagnostics.capture_observation(backend.observer_captures,
                                                        {'observed': index})
                    self.assertEqual(len(backend.observer_captures), 32)
                    with diagnostics.readonly_observer_phase(None, backend):
                        with diagnostics.readonly_observer_transaction(None, None, backend):
                            native_result = {'validated': True}
                    self.assertTrue(native_result['validated'])
                    self.assertEqual(backend.observer_captures, [])
                    self.assertFalse((Path(directory) / 'missing').exists())
            finally:
                os.close(sealed)

    def test_genuine_first_failure_propagates_unchanged_and_fd_cleanup_runs(self):
        backend = self.backend(Path('/unavailable'))
        first = RuntimeError('native source/phase/FD proof refused')
        before = set(os.listdir('/proc/self/fd'))
        read_fd, write_fd = os.pipe()
        try:
            with self.assertRaises(RuntimeError) as caught:
                with diagnostics.readonly_observer_transaction(None, None, backend):
                    try:
                        raise first
                    finally:
                        os.close(read_fd)
                        os.close(write_fd)
            self.assertIs(caught.exception, first)
            self.assertEqual(backend.observer_first_failure['reason'], str(first))
            self.assertEqual(before, set(os.listdir('/proc/self/fd')))
        finally:
            for fd in (read_fd, write_fd):
                try:
                    os.close(fd)
                except OSError:
                    pass

    def test_installer_diagnostic_is_not_full_install_or_nvidia_acceptance(self):
        result = dict(MODEL_ONLY=False, first=None, runtimeAuthorized=True,
                      leaseMustRemainHeld=False, accepted=False,
                      installerDiagnosticComplete=True,
                      closure=dict(known=True, FDsClosed=True, logicalLeaseClosed=True))
        self.assertTrue(diagnostics.operational_complete(result, True))
        self.assertFalse(result['accepted'])
        for field, value in [('MODEL_ONLY', True), ('first', {'reason': 'native'}),
                             ('runtimeAuthorized', False), ('leaseMustRemainHeld', True),
                             ('installerDiagnosticComplete', False)]:
            with self.subTest(field=field):
                self.assertFalse(diagnostics.operational_complete(dict(result, **{field: value}), True))
        for field in result['closure']:
            bad = dict(result, closure=dict(result['closure'], **{field: False}))
            self.assertFalse(diagnostics.operational_complete(bad, True))
        self.assertFalse(diagnostics.operational_complete(result, False))


if __name__ == '__main__':
    unittest.main()
