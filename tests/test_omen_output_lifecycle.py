"""Source contract tests only: no model claims to be a native output VM.

Actual Root grants, source adoption, DAC, libvirt, guest and GPU tests remain
separate OMEN qualifications. No method under test is replaced by a fixture.
"""
import copy
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('output_lifecycle', SCRIPTS / 'omen_output_lifecycle.py')
life = importlib.util.module_from_spec(spec); spec.loader.exec_module(life)


class OutputLifecycleContracts(unittest.TestCase):
    def setUp(self):
        self.identity = {'source_commit': 'a'*40, 'run_id': '1', 'attempt': '1', 'operation_nonce': 'b'*32}
        self.request = {'leaseNonce': 'c'*32}
        self.candidate = {'identity': self.identity, 'nonce': 'c'*32, 'targetGeneration': 'new-target',
            'media': {'path': '/media.raw', 'bytes': 8_200_003_584, 'identity': {'st_dev': 1, 'st_ino': 2}},
            'target': {'path': '/target.raw', 'bytes': 12*1024**3, 'identity': {'st_dev': 1, 'st_ino': 3}},
            'coreContract': {'repository': 'CorniiDog/open-gpu-kernel-modules-steamos-support',
                             'commit': 'd'*40, 'manifestSHA256': 'e'*64}}
        self.candidate['original'] = self.candidate['media']; self.candidate['working'] = self.candidate['target']
        command = {'request': self.request, 'identity': self.identity, 'argv': ['/tool'],
            'toolPin': {'path': '/tool'}, 'sourcePins': [{'path': '/source'}], 'seconds': 120,
            'preflightArgv': ['/tool', 'preflight'], 'stoppedReadbackArgv': ['/tool', 'stopped']}
        self.grant = {'kind': life.ROOT_KIND, 'RootIssued': True, 'runtimeAuthorized': True,
            'request': self.request, 'candidate': self.candidate, 'bootID': 'host-boot',
            'issuedUnix': 100, 'startBeforeUnix': 200, 'wholeDeadlineUnix': 900,
            'phases': list(life.PHASES), 'maxBoots': 4, 'noNIC': True,
            'abruptRecoveryAuthorized': True,
            'phaseCommands': {p: {**command, 'phase': p,
                'stopMode': 'controller-autodestroy' if p == 'update' else 'guest-shutdown'} for p in life.PHASES}}

    def test_historical_grant_and_two_boot_scope_never_transfer(self):
        self.assertEqual(life.scope(self.grant, self.request, self.candidate, 'host-boot', 110), 900)
        for changes in ({'kind': 'ROOT_EXACT_LIBVIRT_TWO_BOOT_AUTHORITY_R2'}, {'maxBoots': 2},
                        {'runtimeAuthorized': False}, {'MODEL_ONLY': True}, {'noNIC': False},
                        {'wholeDeadlineUnix': 1001}, {'bootID': 'old-boot'}, {'startBeforeUnix': 101}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                life.scope({**self.grant, **changes}, self.request, self.candidate, 'host-boot', 110)
        with self.assertRaises(ValueError):
            life.scope({**self.grant, 'abruptRecoveryAuthorized': False}, self.request, self.candidate, 'host-boot', 110)

    def test_media_target_alias_and_undersized_target_are_rejected(self):
        for change in ({'target': self.candidate['media']},
                       {'target': {**self.candidate['target'], 'bytes': 6*1024**3}}):
            candidate = {**self.candidate, **change}; candidate['working'] = candidate['target']
            grant = {**self.grant, 'candidate': candidate}
            with self.assertRaises(ValueError): life.scope(grant, self.request, candidate, 'host-boot', 110)

    def value(self, phase, boot='12345678-1234-4234-8234-123456789012'):
        return {'kind': 'ROOT_OUTPUT_INSTALL_NATIVE_PHASE_V1', 'phase': phase, 'identity': self.identity,
            'targetGeneration': 'new-target', 'targetSerial': 'OPEMOSOUTPUTTARGET',
            'native': True, 'MODEL_ONLY': False, 'coreContract': self.candidate['coreContract'],
            'first': None, 'secondary': [], 'normalWelcomeInstall': True,
            'installedRootUUID': 'root-uuid', 'installedEFIUUID': '1234-ABCD',
            'targetDevice': '/dev/sda', 'mediaDevice': '/dev/sdb',
            'display': {'width': 1600, 'height': 900}, 'robotExit': 0, 'robotFailures': 0,
            'files': {k: {'pin': 'source-contract-only'} for k in
                      ('output.xml', 'report.html', 'log.html', 'xunit.xml', 'screenshot')},
            'actualWelcomePointer': True, 'installExit': 0, 'mediaDetached': phase != 'installation', 'bootID': boot,
            'sameTargetKernelTransition': True, 'nvidia575FiveModules': True, 'nvidiaRender': True,
            'driverReceiptVerified': True, 'recoveryVerified': True}

    def test_phase_contract_requires_same_target_distinct_boots_actual_prerequisites(self):
        installed = life.phase_result(self.value('installation'), 'installation', self.candidate, [])
        baseline = life.phase_result(self.value('baseline'), 'baseline', self.candidate, [installed])
        with self.assertRaises(ValueError):
            life.phase_result(self.value('update'), 'update', self.candidate, [installed, baseline])
        value = self.value('update', '22345678-1234-4234-8234-123456789012')
        for changes in ({'installedRootUUID': 'other'}, {'mediaDetached': False}, {'nvidiaRender': False},
                        {'nvidia575FiveModules': False}, {'MODEL_ONLY': True}, {'robotFailures': 1},
                        {'display': {'width': 1280, 'height': 720}}, {'installedRootUUID': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                life.phase_result({**value, **changes}, 'update', self.candidate, [installed, baseline])

    def test_duplicate_and_nonfinite_protected_json_are_refused(self):
        for raw in (b'{"kind":1,"kind":2}', b'{"clock":NaN}', b'{"clock":Infinity}'):
            with self.assertRaises(ValueError): life.strict(raw)

    @unittest.skipIf(os.getuid() == 0, 'requires a genuinely non-Root file owner')
    def test_untrusted_real_file_cannot_bootstrap_backend_or_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'grant.json'; path.write_bytes(b'{}'); path.chmod(0o400)
            ref = {'path': str(path), 'bytes': 2, 'sha256': '0'*64,
                   'identity': life.identity(path.stat())}
            with self.assertRaises(ValueError): life.protected_bytes(ref)
            with self.assertRaises(ValueError): life.backend({})


if __name__ == '__main__': unittest.main()
