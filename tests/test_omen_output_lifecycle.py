"""Source contract tests only: no model claims to be a native output VM.

Actual Root grants, source adoption, DAC, libvirt, guest and GPU tests remain
separate OMEN qualifications. No method under test is replaced by a fixture.
"""
import copy
import hashlib
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
            'reservedBytes':512*1024**2,
            'phasePreflights': {p: {**command, 'phase': p,
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
        intent={'generation':'txn-'+'1'*32,'phase':'pending-health','preparedBootId':boot,
                'kernel':'actual-kernel-contract-fixture','target':{'nvidia':'575.64.05'},
                'authoritySHA256':'a'*64,'filesSHA256':'b'*64,'attemptBootId':None}
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
            'driverReceiptVerified': True, 'recoveryVerified': True,
            'kernel':intent['kernel'],'nativeData':{'update_intent':intent}if phase=='update'else{}}

    def test_phase_contract_requires_same_target_distinct_boots_actual_prerequisites(self):
        installed = life.phase_result(self.value('installation'), 'installation', self.candidate, [])
        baseline = life.phase_result(self.value('baseline'), 'baseline', self.candidate, [installed])
        with self.assertRaises(ValueError):
            life.phase_result(self.value('update'), 'update', self.candidate, [installed, baseline])
        value = self.value('update', '22345678-1234-4234-8234-123456789012')
        updated=life.phase_result(value,'update',self.candidate,[installed,baseline])
        for changes in ({'installedRootUUID': 'other'}, {'mediaDetached': False}, {'nvidiaRender': False},
                        {'nvidia575FiveModules': False}, {'MODEL_ONLY': True}, {'robotFailures': 1},
                        {'display': {'width': 1280, 'height': 720}}, {'installedRootUUID': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                life.phase_result({**value, **changes}, 'update', self.candidate, [installed, baseline])
        # Core's ordinary update result is pending-health. A flag claiming a
        # kernel transition is neither the retained intent nor a new boot.
        for intent_change in ({'phase':'healthy'},{'generation':None},{'preparedBootId':baseline['bootID']},
                              {'kernel':'other-kernel'}):
            bad=copy.deepcopy(value);bad['nativeData']['update_intent'].update(intent_change)
            with self.assertRaises(ValueError):life.phase_result(bad,'update',self.candidate,[installed,baseline])
        recovered=self.value('recovery','32345678-1234-4234-8234-123456789012')
        recovered['nativeData']={'recovered_intent':dict(updated['nativeData']['update_intent'],
            phase='healthy',attemptBootId=recovered['bootID'])}
        life.phase_result(recovered,'recovery',self.candidate,[installed,baseline,updated])
        for changes in ({'phase':'restored'},{'generation':'txn-'+'2'*32},{'attemptBootId':updated['bootID']},
                        {'authoritySHA256':'f'*64},{'filesSHA256':'f'*64}):
            bad=copy.deepcopy(recovered);bad['nativeData']['recovered_intent'].update(changes)
            with self.assertRaises(ValueError):life.phase_result(bad,'recovery',self.candidate,[installed,baseline,updated])

    def test_duplicate_and_nonfinite_protected_json_are_refused(self):
        for raw in (b'{"kind":1,"kind":2}', b'{"clock":NaN}', b'{"clock":Infinity}'):
            with self.assertRaises(ValueError): life.strict(raw)

    def test_guest_observation_clock_is_not_part_of_stable_boot_identity(self):
        before={'virtualization':'kvm','numeric_exit':0,'boot_id':'12345678-1234-4234-8234-123456789012',
                'kernel':'actual-kernel-contract-fixture','architecture':'x86_64','uid':1000,'clock_ns':1000000000}
        self.assertTrue(life.same_guest_epoch(before,dict(before,clock_ns=1000000100)))
        for changes in ({'clock_ns':999999999},{'clock_ns':482000000000},{'clock_ns':True},
                        {'boot_id':'other'},{'uid':0},{'numeric_exit':False},{'architecture':'aarch64'},{'extra':'unknown'}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                life.same_guest_epoch(before,dict(before,**changes))

    def test_coalesced_stream_frames_do_not_become_a_false_size_overflow(self):
        first=life.canonical({'payload':'x'*44000})+b'\n'
        second=life.canonical({'payload':'y'*30000})+b'\n'
        wire=first+second
        buffer=bytearray(wire[:65537])
        self.assertEqual(life.pop_guest_frame(buffer),{'payload':'x'*44000})
        self.assertIsNone(life.pop_guest_frame(buffer))
        buffer.extend(wire[65537:])
        self.assertEqual(life.pop_guest_frame(buffer),{'payload':'y'*30000})
        self.assertEqual(buffer,bytearray())
        for bad in (b'x'*65537,b'\n',b'{"x":1,"x":2}\n',b'[]\n'):
            with self.subTest(size=len(bad)),self.assertRaises(ValueError):life.pop_guest_frame(bytearray(bad))

    def test_complete_public_graph_keeps_phase_closure_and_stopped_edges(self):
        # Pure contract data, deliberately not an OS/native/Root authority
        # fixture. No producer, SDK or method under test is replaced.
        phases=[self.value(phase,str(i+1)+'2345678-1234-4234-8234-123456789012')
                for i,phase in enumerate(life.PHASES)]
        phases[-1]['nativeData']={'recovered_intent':dict(phases[-2]['nativeData']['update_intent'],
            phase='healthy',attemptBootId=phases[-1]['bootID'])}
        closure={'unknown':[],**{key:True for key in
            ('domainAbsent','originalPIDStartAbsent','cgroupEmpty','VFIOFDsAbsent','hostRestored')}}
        stopped=[{'first':None,'secondary':[],'mountClosed':True,'loopClosed':True,
            'loopAllocationUnknown':False,'commandClosureUnknown':False,
            'identity':self.identity,'phase':row['phase'],'targetGeneration':'new-target',
            'phaseResultSHA256':hashlib.sha256(life.canonical(row)).hexdigest()}for row in phases]
        proof={'kind':'ROOT_VERIFIED_OUTPUT_INSTALL_FOUR_BOOT_V1','identity':self.identity,
            'image_sha256':'9'*64,'accepted':True,'first':None,'secondary':[],'MODEL_ONLY':False,
            'leaseNonce':'c'*32,'rootRequest':{'leaseNonce':'c'*32},
            'logicalLeaseClosed':True,'leaseMustRemainHeld':False,'launches':4,
            'closure':{'known':True,'FDsClosed':True},'rows':phases,'phaseClosures':[copy.deepcopy(closure)for _ in phases],
            'stoppedReadbacks':stopped,'targetGeneration':'new-target','coreContract':self.candidate['coreContract']}
        observed=life.validate_output_install_proof(proof,self.identity,'9'*64)
        self.assertEqual(observed['OS_kernel_transition'],'NOT_PROVEN')
        self.assertIs(observed['hardware_acceptance'],False)
        for mode in('restored','stream-unknown','loop-unknown','stale-row','missing-phase','wrong-image','secondary'):
            bad=copy.deepcopy(proof)
            if mode=='restored':bad['rows'][-1]['nativeData']['recovered_intent']['phase']='restored'
            elif mode=='stream-unknown':bad['phaseClosures'][2]['VFIOFDsAbsent']=False
            elif mode=='loop-unknown':bad['stoppedReadbacks'][1]['loopAllocationUnknown']=True
            elif mode=='stale-row':bad['stoppedReadbacks'][3]['phaseResultSHA256']='0'*64
            elif mode=='missing-phase':bad['rows'].pop()
            elif mode=='wrong-image':bad['image_sha256']='0'*64
            else:bad['secondary']=[{'reason':'original cleanup failure'}]
            with self.subTest(mode=mode),self.assertRaises(ValueError):
                life.validate_output_install_proof(bad,self.identity,'9'*64)

    @unittest.skipIf(os.getuid() == 0, 'requires a genuinely non-Root file owner')
    def test_untrusted_real_file_cannot_bootstrap_backend_or_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'grant.json'; path.write_bytes(b'{}'); path.chmod(0o400)
            ref = {'path': str(path), 'bytes': 2, 'sha256': '0'*64,
                   'identity': life.identity(path.stat())}
            with self.assertRaises(ValueError): life.protected_bytes(ref)
            with self.assertRaises(ValueError): life.backend({})


if __name__ == '__main__': unittest.main()
