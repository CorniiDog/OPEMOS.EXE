import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
import json
import subprocess
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import ubuntu_vm_runner as runner


class RunnerTest(unittest.TestCase):
    def test_firmware_lifecycle_accounts_and_preserves_record_after_export(self):
        with tempfile.TemporaryDirectory(prefix='opemos-gen2-cycle-') as directory:
            root = Path(directory)
            (root / '.opemos-migration-owned').write_text('OPEMOS.EXE\n')
            base, image = root / 'base.qcow2', root / 'active.qcow2'
            subprocess.run(['qemu-img', 'create', '-f', 'qcow2', str(base), '16M'], check=True, capture_output=True)
            subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(image)], check=True, capture_output=True)
            code, variables = root / 'code.fd', root / 'vars.fd'
            for path, size in ((code, 3653632), (variables, 540672)):
                path.write_bytes(b'\0' * size)
            info = variables.stat()
            firmware = {'code': code.name, 'codeSha256': runner.base_digest(code),
                        'vars': variables.name, 'varsIdentity': [info.st_dev, info.st_ino]}
            manifest = {'schemaVersion': 1, 'image': image.name, 'retained': [],
                        'base': base.name, 'baseSha256': runner.base_digest(base),
                        'writeCeilingBytes': 12000000, 'windowsFirmware': firmware}
            (root / 'manifest.json').write_text(json.dumps(manifest))
            expected_allocation = sum(p.stat().st_blocks * 512 for p in root.iterdir())
            with patch.object(runner, 'require_ntfs_envelope', return_value={}), patch.object(runner, 'launch_bounded', return_value=0) as launch:
                receipt = runner.run_owned_vm(root)
            launch.assert_called_once_with(image, 12000000, 300, firmware=firmware)
            updated = json.loads((root / 'manifest.json').read_text())
            self.assertEqual(updated['windowsFirmware'], firmware)
            self.assertEqual(runner.base_digest(base), manifest['baseSha256'])
            self.assertTrue(code.exists() and variables.exists())
            # The lock is created during admission and contributes no blocks.
            self.assertGreaterEqual(receipt['totalAfterAllocatedBytes'], expected_allocation)

    def test_firmware_changed_code_or_replaced_vars_refuses_preserving_files(self):
        with tempfile.TemporaryDirectory(prefix='opemos-firmware-') as directory:
            root = Path(directory)
            code, variables = root / 'code.fd', root / 'vars.fd'
            for path, size in ((code, 3653632), (variables, 540672)):
                with path.open('wb') as output:
                    output.truncate(size)
            info = variables.stat()
            record = {'code': code.name, 'codeSha256': runner.base_digest(code),
                      'vars': variables.name, 'varsIdentity': [info.st_dev, info.st_ino]}
            self.assertEqual(runner.validate_windows_firmware(root, record, ['active.qcow2', 'base.qcow2']), {'code.fd', 'vars.fd'})
            with code.open('r+b') as output:
                output.write(b'changed')
            with self.assertRaisesRegex(ValueError, 'CODE hash'):
                runner.validate_windows_firmware(root, record, [])
            record['codeSha256'] = runner.base_digest(code)
            variables.rename(root / 'preserved-vars.fd')
            with variables.open('wb') as output:
                output.truncate(540672)
            with self.assertRaisesRegex(ValueError, 'VARS identity'):
                runner.validate_windows_firmware(root, record, [])
            self.assertTrue((root / 'preserved-vars.fd').exists())

    def test_windows_refuses_changed_pool_limits(self):
        pool = '0::/opemos.slice/opemos-vm.slice/opemos-vm-pool.slice/owned.service\n'
        with patch.object(Path, 'read_text', side_effect=[pool, '34359738368', '1']):
            with self.assertRaisesRegex(ValueError, 'limits changed'):
                runner.require_windows_pool()

    def test_windows_command_preserves_gen2_resources_and_only_kvm_group(self):
        import os
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory(prefix='opemos-uefi-') as directory:
            root = Path(directory)
            image, code, variables = (root / name for name in ('active.qcow2', 'code.fd', 'vars.fd'))
            for path, size in ((image, 1), (code, 3653632), (variables, 540672)):
                with path.open('wb') as output:
                    output.truncate(size)
            real_stat = Path.stat
            device_group = os.getgid() + 10000
            def device_stat(path, *args, **kwargs):
                if str(path) == '/dev/kvm':
                    return SimpleNamespace(st_mode=0o020660, st_gid=device_group)
                return real_stat(path, *args, **kwargs)
            with patch.object(runner, 'require_windows_pool'), patch.object(runner, 'require_ntfs_envelope'), patch.object(Path, 'stat', device_stat), patch.object(runner.os, 'access', return_value=True), patch.object(runner.os, 'getgroups', return_value=[device_group, device_group + 1]), patch.object(runner.shutil, 'which', side_effect=lambda name: '/usr/bin/' + name):
                command = runner.windows_launch_command(image, code, variables)
            self.assertEqual(command[command.index('-m') + 1], '6152')
            self.assertEqual(command[command.index('-smp') + 1], '2')
            self.assertIn('q35,accel=kvm', command)
            self.assertNotIn('q35,accel=tcg', command)
            self.assertIn('--groups=' + str(device_group), command)
            self.assertNotIn('--groups=' + str(device_group + 1), command)
            self.assertIn('if=pflash,format=raw,readonly=on,file=' + str(code), command)
            self.assertIn('if=pflash,format=raw,file=' + str(variables), command)
            self.assertEqual(command[command.index('-nic') + 1], 'none')

    def test_windows_refuses_unadmitted_process_before_image_or_tools(self):
        with patch.object(Path, 'read_text', return_value='0::/user.slice/unrelated.service\n'), patch.object(runner.subprocess, 'run') as tools:
            with self.assertRaisesRegex(ValueError, 'inherit'):
                runner.windows_launch_command('/absent/image', '/absent/code', '/absent/vars')
            tools.assert_not_called()

    def test_windows_refuses_firmware_outside_envelope_before_kvm(self):
        with patch.object(runner, 'require_windows_pool'), patch.object(runner, 'require_ntfs_envelope'), patch.object(runner, 'launch_command') as launch:
            with self.assertRaisesRegex(ValueError, 'contained direct file'):
                runner.windows_launch_command('/owned/image', '/external/code', '/owned/vars')
            launch.assert_not_called()

    def test_backed_runtime_refuses_unknown_slot_ceiling_before_admission(self):
        for value in (None, True, 0, 60_000_000_000):
            with self.subTest(ceiling=value), tempfile.TemporaryDirectory(prefix='opemos-slot-') as directory:
                root=Path(directory)
                (root/'.opemos-migration-owned').write_text('OPEMOS.EXE\n')
                (root/'manifest.json').write_text(json.dumps({'schemaVersion':1,
                    'image':'active.qcow2','retained':[],'base':'base.qcow2',
                    'baseSha256':'unverified','writeCeilingBytes':value}))
                with patch.object(runner,'require_ntfs_envelope') as admission, patch.object(runner,'launch_bounded') as launch:
                    with self.assertRaisesRegex(ValueError,'exact backed-runtime write ceiling'):
                        runner.run_owned_vm(root)
                    admission.assert_not_called(); launch.assert_not_called()

    def test_active_image_not_double_charged_but_retained_image_is(self):
        import vm_write_ceiling
        with tempfile.TemporaryDirectory(prefix='opemos-admission-') as directory:
            root=Path(directory)
            (root / '.opemos-migration-owned').write_text('OPEMOS.EXE\n')
            image=root / 'generated.qcow2'
            subprocess.run(['qemu-img','create','-f','qcow2',str(image),'16M'],check=True,capture_output=True)
            subprocess.run(['qemu-io','-f','qcow2','-c','write -P 0x55 0 6M',str(image)],check=True,capture_output=True)
            identity=[image.stat().st_dev,image.stat().st_ino]
            (root / 'manifest.json').write_text(json.dumps({'schemaVersion':1,'image':image.name,'retained':[],'generated':{image.name:identity}}))
            def bounded_guest(path,ceiling,timeout):
                if path.stat().st_size > ceiling:
                    raise ValueError('image already exceeds write ceiling')
                return 0
            with patch.object(vm_write_ceiling,'VM_BUDGET_BYTES',16*1024*1024), patch.object(runner,'VM_BUDGET_BYTES',16*1024*1024), patch.object(runner,'launch_bounded',side_effect=bounded_guest):
                receipt=runner.run_owned_vm(root)
            self.assertFalse(image.exists())
            self.assertTrue(Path(receipt['export']).exists())
            self.assertLess(receipt['totalAfterAllocatedBytes'],16*1024*1024)
            # A separate retained file exhausts the reserved budget; it is not
            # an external Windows backup exemption and must refuse admission.
            retained=root / 'retained.bin'
            retained.write_bytes(b'x'*(15*1024*1024))
            manifest=json.loads((root / 'manifest.json').read_text())
            manifest['retained'].append(retained.name)
            (root / 'manifest.json').write_text(json.dumps(manifest))
            with patch.object(vm_write_ceiling,'VM_BUDGET_BYTES',16*1024*1024), patch.object(runner,'launch_bounded') as launch:
                with self.assertRaises(ValueError):
                    runner.run_owned_vm(root)
                launch.assert_not_called()

    def test_recovery_at_retirement_switch_and_unlink_boundaries(self):
        # Inject interruption only at the retirement boundaries; real QEMU
        # compare/check proves equivalent bytes before recovery may unlink.
        for phase in ('before-first-reference', 'journal-durable', 'references-durable', 'unlink-durable'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(prefix='opemos-crash-') as directory:
                root=Path(directory)
                (root / '.opemos-migration-owned').write_text('OPEMOS.EXE\n')
                source=root / 'source.qcow2'
                subprocess.run(['qemu-img','create','-f','qcow2',str(source),'16M'],check=True,capture_output=True)
                (root / 'manifest.json').write_text(json.dumps({'schemaVersion':1,'image':source.name,'retained':[]}))
                with patch.object(runner,'launch_bounded',return_value=0):
                    first=runner.run_owned_vm(root)
                old=Path(first['export'])
                real_sync=runner.sync_directory
                def interrupt(path):
                    real_sync(path)
                    journal=root / '.retirement.json'
                    if not journal.exists():
                        return
                    state=json.loads((root / 'manifest.json').read_text())
                    reached=(phase=='before-first-reference' and state['image']==old.name or
                             phase=='journal-durable' and old.name in state['retained'] or
                             phase=='references-durable' and old.name not in state['retained'] and old.exists() or
                             phase=='unlink-durable' and not old.exists())
                    if reached:
                        raise RuntimeError('injected interruption')
                with patch.object(runner,'launch_bounded',return_value=0), patch.object(runner,'sync_directory',side_effect=interrupt):
                    with self.assertRaisesRegex(RuntimeError,'injected interruption'):
                        runner.run_owned_vm(root)
                self.assertTrue((root / '.retirement.json').exists())
                manifest=json.loads((root / 'manifest.json').read_text())
                runner.recover_retirement(root,manifest)
                self.assertFalse(old.exists())
                self.assertTrue(source.exists())
                self.assertFalse((root / '.retirement.json').exists())
                recovered=json.loads((root / 'manifest.json').read_text())
                self.assertNotIn(old.name,recovered['retained'])
                self.assertTrue((root / recovered['image']).exists())

    def test_recovery_refuses_mismatched_identity(self):
        with tempfile.TemporaryDirectory(prefix='opemos-recovery-') as directory:
            root = Path(directory)
            old = root / 'generated.qcow2'
            old.write_bytes(b'preserve')
            (root / 'receipt-test.json').write_text(json.dumps({'retirementCandidate': old.name}))
            (root / '.retirement.json').write_text(json.dumps({'old': old.name,
                'identity': [-1, -1], 'replacement': 'replacement.qcow2', 'receipt': 'receipt-test.json'}))
            with self.assertRaises(ValueError):
                runner.recover_retirement(root, {'image': 'replacement.qcow2', 'retained': []})
            self.assertEqual(old.read_bytes(), b'preserve')
            self.assertTrue((root / '.retirement.json').exists())

    def test_missing_old_cannot_clear_journal_for_replaced_candidate(self):
        with tempfile.TemporaryDirectory(prefix='opemos-missing-old-') as directory:
            root=Path(directory)
            replacement=root/'replacement.qcow2'
            replacement.write_bytes(b'not the verified replacement')
            (root/'receipt-test.json').write_text(json.dumps({'retirementCandidate':'old.qcow2'}))
            (root/'.retirement.json').write_text(json.dumps({'old':'old.qcow2',
                'identity':[-1,-1],'replacement':replacement.name,
                'replacementIdentity':[-2,-2],'receipt':'receipt-test.json'}))
            with self.assertRaisesRegex(ValueError,'matching replacement identity'):
                runner.recover_retirement(root,{'image':replacement.name,'retained':[],
                    'generated':{replacement.name:[-2,-2]}})
            self.assertTrue((root/'.retirement.json').exists())
            self.assertEqual(replacement.read_bytes(),b'not the verified replacement')

    def test_missing_old_with_valid_replacement_preserves_dangling_references(self):
        for retained, generated_old in ((True, False), (False, True), (True, True)):
            with self.subTest(retained=retained, generated=generated_old), tempfile.TemporaryDirectory(prefix='opemos-dangling-') as directory:
                root=Path(directory)
                replacement=root/'replacement.qcow2'
                subprocess.run(['qemu-img','create','-f','qcow2',str(replacement),'16M'],check=True,capture_output=True)
                identity=[replacement.stat().st_dev,replacement.stat().st_ino]
                manifest={'image':replacement.name,'retained':['old.qcow2'] if retained else [],
                          'generated':{replacement.name:identity}}
                if generated_old:
                    manifest['generated']['old.qcow2']=[-1,-1]
                (root/'manifest.json').write_text(json.dumps(manifest))
                (root/'receipt-test.json').write_text(json.dumps({'retirementCandidate':'old.qcow2'}))
                journal=root/'.retirement.json'
                journal.write_text(json.dumps({'old':'old.qcow2','identity':[-1,-1],
                    'replacement':replacement.name,'replacementIdentity':identity,'receipt':'receipt-test.json'}))
                before={p.name:p.read_bytes() for p in root.iterdir()}
                with self.assertRaisesRegex(ValueError,'still referenced'):
                    runner.recover_retirement(root,manifest)
                self.assertEqual(before,{p.name:p.read_bytes() for p in root.iterdir()})

    def test_retirement_dotdot_refused_before_receipt_or_tools(self):
        for key in ('old','replacement','receipt'):
            with self.subTest(key=key), tempfile.TemporaryDirectory(prefix='opemos-path-') as directory:
                root=Path(directory)
                transaction={'old':'old.qcow2','identity':[-1,-1],
                    'replacement':'replacement.qcow2','receipt':'absent.json'}
                transaction[key]='..'
                journal=root/'.retirement.json'
                journal.write_text(json.dumps(transaction))
                before=journal.read_bytes()
                with patch.object(runner.subprocess,'run') as tools:
                    with self.assertRaisesRegex(ValueError,'unsafe retirement path'):
                        runner.recover_retirement(root,{'image':'replacement.qcow2','retained':[]})
                    tools.assert_not_called()
                self.assertEqual(journal.read_bytes(),before)

    def test_export_limit_failure_preserves_source(self):
        with tempfile.TemporaryDirectory(prefix='opemos-export-limit-') as directory:
            root = Path(directory)
            (root / '.opemos-migration-owned').write_text('OPEMOS.EXE\n')
            source = root / 'source.qcow2'
            subprocess.run(['qemu-img', 'create', '-f', 'qcow2', str(source), '16M'], check=True, capture_output=True)
            original = source.read_bytes()
            with self.assertRaises(subprocess.CalledProcessError):
                runner.compact_owned_image(root, source.name, 'partial.qcow2', export_ceiling=4096)
            self.assertEqual(source.read_bytes(), original)
            partial = root / 'partial.qcow2'
            if partial.exists():
                self.assertLessEqual(partial.stat().st_size, 4096)

    def test_repeated_lifecycle_real_export_and_failed_guest(self):
        with tempfile.TemporaryDirectory(prefix='opemos-lifecycle-') as directory:
            root = Path(directory)
            (root / '.opemos-migration-owned').write_text('OPEMOS.EXE\n')
            image = root / 'source.qcow2'
            subprocess.run(['qemu-img', 'create', '-f', 'qcow2', str(image), '16M'], check=True, capture_output=True)
            subprocess.run(['qemu-io', '-f', 'qcow2', '-c', 'write -P 0x55 0 8M', str(image)], check=True, capture_output=True)
            (root / 'manifest.json').write_text(json.dumps({'schemaVersion': 1, 'image': image.name, 'retained': []}))
            with patch.object(runner, 'launch_bounded', return_value=0) as launch:
                first = runner.run_owned_vm(root)
                second = runner.run_owned_vm(root)
                third = runner.run_owned_vm(root)
                self.assertEqual(launch.call_count, 3)
            self.assertFalse(Path(first['export']).exists())
            self.assertFalse(Path(second['export']).exists())
            self.assertTrue(Path(third['export']).exists())
            self.assertLess(third['totalAfterAllocatedBytes'], 16 * 1024 * 1024)
            final_receipts = [json.loads(path.read_text()) for path in root.glob('receipt-*.json')]
            self.assertTrue(any(record.get('retiredGeneratedImage') == Path(second['export']).name for record in final_receipts))
            self.assertTrue(first['referenceSwitched'])
            self.assertTrue(second['referenceSwitched'])
            self.assertTrue(image.exists())
            manifest = (root / 'manifest.json').read_bytes()
            with patch.object(runner, 'launch_bounded', return_value=1):
                with patch.object(runner, 'recover_retirement', wraps=runner.recover_retirement) as cleanup:
                    with self.assertRaises(RuntimeError):
                        runner.run_owned_vm(root)
                    self.assertEqual(cleanup.call_count, 2)
            self.assertEqual((root / 'manifest.json').read_bytes(), manifest)
            retained = Path(third['export']).stat()
            expected_identity = [retained.st_dev, retained.st_ino]
            failures=[json.loads(path.read_text()) for path in root.glob('receipt-failure-*.json')]
            self.assertEqual(len(failures),1)
            self.assertEqual(failures[0]['status'],'FAILED')
            self.assertTrue(failures[0]['currentImageRetained'])
            self.assertEqual(failures[0]['admittedImageIdentity'], expected_identity)
            self.assertEqual(failures[0]['retainedImageIdentity'], expected_identity)
            self.assertFalse(failures[0]['referenceSwitched'])
            self.assertGreater(failures[0]['totalAfterAllocatedBytes'],0)
            (root / 'unexpected').write_bytes(b'retain')
            with patch.object(runner, 'launch_bounded') as launch:
                with self.assertRaises(ValueError):
                    runner.run_owned_vm(root)
                launch.assert_not_called()

    def test_fixed_closed_launch(self):
        with tempfile.TemporaryDirectory(prefix='opemos-runner-') as directory:
            image = Path(directory) / 'owned.qcow2'
            image.write_bytes(b'fixture')
            with patch('shutil.which', side_effect=lambda name: '/usr/bin/' + name):
                command = runner.launch_command(image)
            self.assertEqual(command.count('--bind'), 1)
            self.assertIn('--unshare-all', command)
            self.assertEqual(command[command.index('--bind') + 1:command.index('--bind') + 3], [str(image), str(image)])
            self.assertEqual(command[command.index('-nic') + 1], 'none')
            with patch('shutil.which', side_effect=lambda name: '/usr/bin/' + name):
                privileged = runner.launch_command(image, memory_mib=30720, cpus=12, privileged_namespace=True)
            self.assertEqual(privileged[:2], ['/usr/bin/sudo', '-n'])
            self.assertIn('--clear-groups', privileged)
            self.assertIn('--no-new-privs', privileged)
            self.assertIn('--unshare-net', privileged)
            self.assertEqual(privileged[privileged.index('-smp') + 1], '12')
            with patch('shutil.which', return_value=None):
                with self.assertRaises(RuntimeError):
                    runner.launch_command(image)
            link = Path(directory) / 'link'
            link.symlink_to(image)
            with self.assertRaises(ValueError):
                runner.launch_command(link)


if __name__ == '__main__':
    unittest.main()
