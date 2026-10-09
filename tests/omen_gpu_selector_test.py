import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('selector', Path(__file__).parents[1] / 'scripts/omen_gpu_selector.py')
selector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selector)


class SelectorTest(unittest.TestCase):
    def test_vfio_and_unbound_nvidia_presentation_does_not_claim_host_rendering(self):
        for driver in ('vfio-pci', None):
            with self.subTest(driver=driver), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                display = root / '0000:01:00.0'
                display.mkdir()
                for name, value in [('class', '0x030000'), ('vendor', '0x10de'), ('boot_vga', '1')]:
                    (display / name).write_text(value)
                if driver:
                    (display / 'driver').symlink_to('/drivers/' + driver)
                result = selector.inspect(root)
                self.assertEqual(result['gpuLabel'], 'GPU — detected (active output unverified)')
                self.assertFalse(result['gpuHostDisplayInUse'])
                self.assertFalse(result['vmPassthroughAccepted'])
                self.assertFalse(result['applyAllowed'])

    def test_desktop_failure_removes_exact_generated_view_and_preserves_template(self):
        import subprocess
        template = Path(selector.__file__).with_name('omen-gpu-selector.qml')
        before = template.read_bytes()
        for failure in (subprocess.CalledProcessError(1, 'qmlscene'), subprocess.TimeoutExpired('qmlscene', 900)):
            views = []
            def fail(command, **kwargs):
                view = Path(command[1])
                views.append(view)
                rendered = view.read_text()
                self.assertNotIn('__OPEMOS_GPU_INVENTORY__', rendered)
                self.assertIn('Hardware inspection failed', rendered)
                import json
                expression = rendered.split('property var inventory: JSON.parse(', 1)[1].splitlines()[0]
                decoded = json.loads(json.loads(expression[:-1]))
                self.assertTrue(decoded['inspectionFailed'])
                self.assertEqual(kwargs['timeout'], 900)
                raise failure
            with self.subTest(failure=type(failure).__name__), patch.object(selector.shutil, 'which', return_value='/existing/qmlscene'), patch.object(selector, 'inspect', return_value={'inspectionFailed': True, 'applyReason': 'Hardware inspection failed'}), patch.object(selector.subprocess, 'run', side_effect=fail):
                with self.assertRaises(type(failure)):
                    selector.desktop()
            self.assertEqual(len(views), 1)
            self.assertFalse(views[0].parent.exists())
            self.assertEqual(template.read_bytes(), before)

    def test_missing_qt_refuses_without_install_or_process_creation(self):
        with patch.object(selector.shutil, 'which', return_value=None), patch.object(Path, 'is_file', return_value=False), patch.object(selector.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'no package installation or graphics change'):
                selector.desktop()
            run.assert_not_called()

    def test_intel_discrete_and_integrated_candidate_do_not_authorize_route(self):
        for address, candidate in [('0000:03:00.0', False), ('0000:00:02.0', True)]:
            with self.subTest(address=address), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                display = root / address
                display.mkdir()
                for name, value in [('class', '0x030000'), ('vendor', '0x8086'), ('boot_vga', '0')]:
                    (display / name).write_text(value)
                result = selector.inspect(root)
                self.assertEqual(result['internalGraphicsCandidateDetected'], candidate)
                self.assertFalse(result['internalGraphicsAvailable'])
                self.assertFalse(result['applyAllowed'])

    def test_sole_nvidia_does_not_invent_internal_graphics_or_passthrough(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            display = root / '0000:01:00.0'
            display.mkdir()
            for name, value in [('class', '0x030000'), ('vendor', '0x10de'), ('boot_vga', '1')]:
                (display / name).write_text(value)
            (display / 'driver').symlink_to('/drivers/nvidia')
            result = selector.probe(root)
            self.assertFalse(result['internalGraphicsAvailable'])
            self.assertIn('cannot be selected', result['internalGraphicsReason'])
            self.assertTrue(result['gpuHostDisplayInUse'])
            self.assertFalse(result['applyAllowed'])
            self.assertFalse(result['vmPassthroughAccepted'])

    def test_empty_inventory_and_unreadable_metadata_never_enable_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertFalse(selector.probe(root)['applyAllowed'])
            (root / 'incomplete').mkdir()
            with self.assertRaises(FileNotFoundError):
                selector.probe(root)
            result = selector.inspect(root)
            self.assertTrue(result['inspectionFailed'])
            self.assertFalse(result['applyAllowed'])
            (root / 'incomplete' / 'class').write_text('malformed')
            self.assertTrue(selector.inspect(root)['inspectionFailed'])
