"""UNRUN: only execute in admitted OMEN VMs.

Metadata cases prove the finite schema, not native/VM properties. Real capture
cases use actual children and files, never override capture or the validator.
They are not the required complete normal source workload/Root transaction.
"""
import copy
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0,str(Path(__file__).parents[1]/'scripts'))
from omen_source_capture import capture
from omen_source_ci import reports
from omen_source_workloads import (WORKLOADS,commands,dependencies,command_status,
    blocked_command,verify_diagnostics,verify_result,hard_stop_event,diagnostic_binding)


def metadata_result(workload='rust'):
    """Explicit schema fixtures, not invented real executions."""
    spec={'workload':workload,'controller_commit':'a'*40,'candidate_commit':'b'*40}
    identity={'nonce':'metadata-only'}
    rows=[]
    for i,argv in enumerate(commands(workload,'b'*40)):
        rows.append({'template_argv':argv,'status':'passed','numeric_exit':0,
            'first':None,'secondary':[],'pid':100+i,'birth':123,
            **{k:True for k in('reaped','stdoutEOF','stderrEOF','FDsClosed','descendantsAbsent')},
            **{k:{'sha256':hashlib.sha256(b'').hexdigest(),'bytes':0}for k in('stdout','stderr')}})
    value={'kind':'OMEN_GUEST_SOURCE_WORKLOAD_V1','identity':identity,'subject':spec,
        'guest':{'location':'OMEN_VM','virtualization':'qemu','platform':WORKLOADS[workload][0],
            'boot_id':'metadata-only','uid':'S-1-5-21-1-2-3-1000'if workload=='windows-build'else 1000,
            'controller_commit':'a'*40,'candidate_commit':'b'*40},
        'commands':rows,'status':'passed','first':None,'secondary':[],
        'controller_manifest_sha256':'c'*64,'hard_stop':None}
    return value,identity,spec


class FiniteOutcomeMetadata(unittest.TestCase):
    def test_every_existing_command_has_explicit_backward_only_dependencies(self):
        for workload in WORKLOADS:
            with self.subTest(workload=workload):
                value,identity,spec=metadata_result(workload)
                self.assertEqual(len(dependencies(workload)),len(value['commands']))
                self.assertEqual(verify_result(value,identity,spec),value)

    def test_ordinary_first_failure_and_later_independent_pass_remain_overall_failed(self):
        value,identity,spec=metadata_result()
        value['commands'][0].update(numeric_exit=7,status='failed')
        value.update(status='failed',first={'command_index':0,'numeric_exit':7})
        self.assertEqual(verify_diagnostics(value,identity,spec),value)
        self.assertEqual(value['commands'][3]['status'],'passed')
        with self.assertRaises(ValueError):verify_result(value,identity,spec)
        bad=copy.deepcopy(value);bad['status']='passed'
        with self.assertRaises(ValueError):verify_diagnostics(bad,identity,spec)

    def test_failed_npm_blocks_only_build_consumers_not_other_checks(self):
        for workload,index in(('frontend-and-docs',0),('windows-build',1),('macos-build',0),('appimage-package',0)):
            with self.subTest(workload=workload):
                value,identity,spec=metadata_result(workload);rows=value['commands'];graph=dependencies(workload)
                rows[index].update(numeric_exit=1,status='failed')
                for i in range(index+1,len(rows)):
                    if any(rows[p]['status']!='passed'for p in graph[i]):
                        rows[i]=blocked_command(rows[i]['template_argv'],graph[i],rows)
                value.update(status='failed',first={'command_index':index})
                verify_diagnostics(value,identity,spec)
                if workload=='windows-build':
                    self.assertEqual(rows[6]['status'],'passed');self.assertEqual(rows[8]['blocked_by'],[7])
                if workload=='macos-build':self.assertEqual(rows[4]['status'],'passed')

    def test_capture_unknown_overflow_signal_timeout_and_cleanup_are_hard_not_ordinary(self):
        value,_,_=metadata_result();base=value['commands'][0]
        faults=[{'numeric_exit':-15},{'birth':'UNKNOWN'},{'FDsClosed':False},
            {'first':{'reason':'timeout'}},{'secondary':[{'reason':'cleanup'}]},
            {'stdout':{'bytes':32*1024**2+1,'sha256':'a'*64}}]
        for change in faults:
            with self.subTest(change=change):self.assertEqual(command_status(dict(base,**change)),'hard-failed')

    def test_hard_stop_blocks_all_remaining_and_rejects_a_later_attempt(self):
        value,identity,spec=metadata_result();rows=value['commands'];graph=dependencies('rust')
        rows[0].update(status='hard-failed',first={'reason':'capture deadline'},numeric_exit=-15)
        cause={'kind':'source-hard-stop','phase':'command-capture','command_index':0,
               'type':'ValueError','reason':'capture deadline'}
        value.update(status='failed',first={'command_index':0,'reason':'capture deadline'},secondary=[cause])
        value['hard_stop']=hard_stop_event(value['controller_manifest_sha256'],'command-capture',0,rows[:1],1,cause)
        for i in range(1,len(rows)):rows[i]=blocked_command(rows[i]['template_argv'],graph[i],rows,value['hard_stop'])
        verify_diagnostics(value,identity,spec)
        bad=copy.deepcopy(value);bad['commands'][2]=metadata_result()[0]['commands'][2]
        with self.assertRaises(ValueError):verify_diagnostics(bad,identity,spec)

    def test_F1_ordinary_failure_plus_invented_stop_never_suppresses_independent_commands(self):
        value,identity,spec=metadata_result();rows=value['commands']
        rows[0].update(status='failed',numeric_exit=7)
        value.update(status='failed',first={'phase':'source-command','command_index':0,'numeric_exit':7,
                     'type':'CommandFailure','reason':'ordinary exit7'})
        for i in range(1,len(rows)):
            rows[i]={'template_argv':rows[i]['template_argv'],'status':'blocked','numeric_exit':None,
                     'blocked_by':[],'stop_reason':'Hard stop: invented','hard_stop_sha256':None}
        with self.assertRaises(ValueError):verify_diagnostics(value,identity,spec)
        # Even an event-shaped label cannot point at the ordinary first cause.
        fake=hard_stop_event(value['controller_manifest_sha256'],'command-preflight',1,rows[:1],0,value['first'])
        value['hard_stop']=fake
        for i in range(1,len(rows)):rows[i]=blocked_command(rows[i]['template_argv'],[],rows,fake)
        with self.assertRaises(ValueError):verify_diagnostics(value,identity,spec)

    def test_genuine_precommand_event_after_ordinary_failure_and_tamper_refusals(self):
        value,identity,spec=metadata_result();rows=value['commands']
        rows[0].update(status='failed',numeric_exit=7)
        first={'phase':'source-command','command_index':0,'numeric_exit':7}
        cause={'kind':'source-hard-stop','phase':'command-preflight','command_index':1,
               'type':'ValueError','reason':'sealed SDK tool hash changed'}
        value.update(status='failed',first=first,secondary=[cause])
        event=hard_stop_event(value['controller_manifest_sha256'],'command-preflight',1,rows[:1],1,cause)
        value['hard_stop']=event
        for i in range(1,len(rows)):rows[i]=blocked_command(rows[i]['template_argv'],[],rows,event)
        verify_diagnostics(value,identity,spec);self.assertEqual(value['first'],first)
        for fault in('missing','ordinal','phase','index','manifest','digest','cause','early','later-attempt','duplicate','misordered'):
            bad=copy.deepcopy(value)
            if fault=='missing':bad['hard_stop']=None
            elif fault=='ordinal':bad['hard_stop']['failure_ordinal']=0
            elif fault=='phase':bad['hard_stop']['phase']='command-capture'
            elif fault=='index':bad['hard_stop']['command_index']=2
            elif fault=='manifest':bad['hard_stop']['manifest_sha256']='d'*64
            elif fault=='digest':bad['commands'][2]['hard_stop_sha256']='e'*64
            elif fault=='cause':bad['secondary'][0]['reason']='different original error'
            elif fault=='early':bad['hard_stop']['stop_before']=0
            elif fault=='duplicate':bad['secondary'].append(copy.deepcopy(bad['secondary'][0]))
            elif fault=='misordered':bad['secondary'].append({'phase':'source-command','command_index':2,'numeric_exit':3})
            else:bad['commands'][3]=metadata_result()[0]['commands'][3]
            with self.subTest(fault=fault),self.assertRaises(ValueError):verify_diagnostics(bad,identity,spec)

    def test_postcommand_guard_error_binds_original_row_without_rewriting_capture(self):
        value,identity,spec=metadata_result();rows=value['commands'];original=copy.deepcopy(rows[0])
        cause={'kind':'source-hard-stop','phase':'command-finalize','command_index':0,
               'type':'ValueError','reason':'actual container cleanup observer failed'}
        value.update(status='failed',first=cause)
        event=hard_stop_event(value['controller_manifest_sha256'],'command-finalize',0,rows[:1],0,cause)
        value['hard_stop']=event
        for i in range(1,len(rows)):rows[i]=blocked_command(rows[i]['template_argv'],[],rows,event)
        verify_diagnostics(value,identity,spec);self.assertEqual(rows[0],original)
        bad=copy.deepcopy(value);bad['commands'][0]['stdout']['sha256']='f'*64
        with self.assertRaises(ValueError):verify_diagnostics(bad,identity,spec)

    def test_no_silent_omission_fake_block_or_nonzero_pass(self):
        value,identity,spec=metadata_result()
        for mutate in('omit','fakeblock','exit'):
            bad=copy.deepcopy(value)
            if mutate=='omit':bad['commands'].pop()
            elif mutate=='exit':bad['commands'][0]['numeric_exit']=1
            else:bad['commands'][1]={'template_argv':bad['commands'][1]['template_argv'],
                'status':'blocked','numeric_exit':None,'blocked_by':[],'stop_reason':None}
            with self.assertRaises(ValueError):verify_diagnostics(bad,identity,spec)

    def test_preparation_and_capture_events_require_exact_position_and_evidence(self):
        for phase in('input-preparation','source-validation'):
            value,identity,spec=metadata_result();rows=value['commands']
            cause={'kind':'source-hard-stop','phase':phase,'command_index':0,
                   'type':'ValueError','reason':'actual sealed input guard refused'}
            value.update(status='failed',first=cause)
            event=hard_stop_event(value['controller_manifest_sha256'],phase,0,[],0,cause)
            value['hard_stop']=event
            for i in range(len(rows)):rows[i]=blocked_command(rows[i]['template_argv'],[],rows,event)
            verify_diagnostics(value,identity,spec)
        value,identity,spec=metadata_result();rows=value['commands']
        rows[0].update(status='failed',numeric_exit=7)
        cause={'kind':'source-hard-stop','phase':'command-capture','command_index':0,
               'type':'ValueError','reason':'invented captured hard failure'}
        value.update(status='failed',first=cause)
        event=hard_stop_event(value['controller_manifest_sha256'],'command-capture',0,rows[:1],0,cause)
        value['hard_stop']=event
        for i in range(1,len(rows)):rows[i]=blocked_command(rows[i]['template_argv'],[],rows,event)
        with self.assertRaises(ValueError):verify_diagnostics(value,identity,spec)

    def test_report_retains_failed_passed_and_blocked_and_finalizer_failure(self):
        value,_,_=metadata_result('frontend-and-docs');rows=value['commands']
        rows[0].update(status='failed',numeric_exit=1)
        rows[1]=blocked_command(rows[1]['template_argv'],dependencies('frontend-and-docs')[1],rows)
        value.update(status='failed',first={'phase':'source-command','command_index':0,'numeric_exit':1})
        with tempfile.TemporaryDirectory()as d:
            reports(d,value,'original failure')
            suite=ET.parse(Path(d)/'xunit.xml').getroot()
            self.assertEqual((suite.get('tests'),suite.get('failures'),suite.get('skipped')),('3','1','1'))
            self.assertEqual(len(suite.findall('testcase/failure')),1)
            self.assertEqual(len(suite.findall('testcase/skipped')),1)
            self.assertIn('blocked_by',(Path(d)/'report.html').read_text())
        with tempfile.TemporaryDirectory()as d:
            reports(d,metadata_result()[0],'actual Root closure failure')
            suite=ET.parse(Path(d)/'xunit.xml').getroot();self.assertEqual(suite.get('failures'),'1')

    def test_binding_rejoins_actual_result_and_manifest_and_report_refuses_F1(self):
        value,identity,spec=metadata_result()
        binding=diagnostic_binding(value,identity,spec,value['controller_manifest_sha256'])
        self.assertEqual(binding['result_sha256'],hashlib.sha256(__import__('json').dumps(
            value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest())
        with self.assertRaises(ValueError):diagnostic_binding(value,identity,spec,'d'*64)
        rows=value['commands'];rows[0].update(status='failed',numeric_exit=7)
        value.update(status='failed',first={'command_index':0,'numeric_exit':7})
        for i in range(1,len(rows)):
            rows[i]={'template_argv':rows[i]['template_argv'],'status':'blocked','numeric_exit':None,
                     'blocked_by':[],'stop_reason':'Hard stop: invented','hard_stop_sha256':None}
        with self.assertRaises(ValueError):diagnostic_binding(value,identity,spec,value['controller_manifest_sha256'])
        with tempfile.TemporaryDirectory()as d:
            with self.assertRaises(ValueError):reports(d,value,'F1 original retained')
            self.assertFalse((Path(d)/'xunit.xml').exists())


class RealCaptureContinuationBoundary(unittest.TestCase):
    def test_actual_nonzero_then_independent_child_and_truthful_report(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);rows=[]
            for i,code in enumerate((7,0,3)):
                argv=[sys.executable,'-I','-c',"import sys;print('actual child');print('retained stderr',file=sys.stderr);sys.exit("+str(code)+")"]
                row=capture(argv,root,dict(os.environ),root/('child-'+str(i)),15)
                row['status']=command_status(row);row['template_argv']=argv;rows.append(row)
                self.assertEqual(row['numeric_exit'],code)
                self.assertEqual(row['status'],'passed'if code==0 else'failed')
                self.assertIsNone(row['first']);self.assertEqual(row['secondary'],[])
                for name in('stdout','stderr'):
                    raw=Path(row[name]['path']).read_bytes()
                    self.assertEqual(hashlib.sha256(raw).hexdigest(),row[name]['sha256'])
            out=root/'report';out.mkdir();reports(out,{'commands':rows},'two real nonzero exits')
            suite=ET.parse(out/'xunit.xml').getroot()
            self.assertEqual((suite.get('tests'),suite.get('failures')),('3','2'))
            self.assertNotEqual(rows[0]['pid'],rows[1]['pid'])


if __name__=='__main__':unittest.main()
