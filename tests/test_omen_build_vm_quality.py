"""UNRUN. Execute only inside OMEN; external API fixtures are metadata only.

No fake adapter establishes a guest, compiler, UID, clock or cleanup property.
Actual ordinary A->exact-output B->C transaction remains a separate requirement.
"""
import copy
from datetime import datetime,timezone
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parents[1]/'scripts'))
sys.path.insert(0,str(Path(__file__).parent))
from test_omen_required import Metadata,SOURCE,encoded_zip
from omen_quality import terminal_context,aggregate,QUALITY,context_selection,verify_root_late_scope
from omen_source_workloads import commands,dependencies,artifact_block


class ExternalAPI:
    def __init__(self,built=True):
        self.a=Metadata();stamp=datetime.now(timezone.utc).isoformat()
        self.a.run.update(status='completed',conclusion='success'if built else'failure',created_at=stamp,run_started_at=stamp)
        self.a.run['head_repository'].update(full_name='CorniiDog/OPEMOS.EXE',fork=False)
        self.a.jobs[0].update(completed_at=stamp,conclusion='success'if built else'failure')
        self.a.jobs=self.a.jobs[:1]
        for a in self.a.artifacts:a['created_at']=stamp
        self.b={'id':50,'run_attempt':1,'name':'04 SteamOS','status':'completed','conclusion':'failure',
            'path':'.github/workflows/omen-robot.yml','head_sha':SOURCE,'head_branch':'main',
            'repository':{'id':1,'full_name':'CorniiDog/OPEMOS.EXE'},
            'head_repository':{'id':1,'full_name':'CorniiDog/OPEMOS.EXE','fork':False},'event':'workflow_run','updated_at':stamp}
        self.result={'kind':'OMEN_REQUIRED_PRODUCER_RESULT_V1','consumer':{'run_id':'50','attempt':'1'},
            'status':'failed','diagnostic_only':True,'quality_source':{'kind':'OMEN_BUILD_VM_QUALITY_SOURCE_V1',
            'platform':'ubuntu','producer_run':'10','producer_attempt':'2','source_commit':SOURCE,
            'source_roles':None,'control_commit':SOURCE}}
        self.stamp=stamp;self.expired=False;self.proofs={};self.jobs=[];self.source=SOURCE

    def braw(self):return encoded_zip('required-result.json',self.result)

    def read(self,path):
        if path=='actions/runs/50':return copy.deepcopy(self.b)
        if path=='commits/'+SOURCE:return {'commit':{'tree':{'sha':'e'*40}}}
        if path.startswith('actions/runs/50/attempts/1/jobs?'):
            return {'total_count':1,'jobs':[{'name':'required-platform-result','status':'completed'}]}
        if path.startswith('actions/runs/50/artifacts?'):
            return {'total_count':1,'artifacts':[{'id':60,'name':'omen-required-result-50-1','expired':self.expired,
                'digest':'sha256:'+hashlib.sha256(self.braw()).hexdigest(),'created_at':self.stamp,
                'workflow_run':{'id':50,'head_sha':SOURCE,'repository_id':1,'head_repository_id':1}}]}
        if path=='actions/runs/70':return {'head_sha':self.source,'name':'Checks','path':'.github/workflows/checks.yml',
            'run_attempt':1,'event':'workflow_run','created_at':self.stamp,
            'repository':{'id':1,'full_name':'CorniiDog/OPEMOS.EXE'},
            'head_repository':{'id':1,'full_name':'CorniiDog/OPEMOS.EXE','fork':False}}
        if path.startswith('actions/runs/70/attempts/1/jobs?'):return {'total_count':len(self.jobs),'jobs':copy.deepcopy(self.jobs)}
        if path.startswith('actions/runs/70/artifacts?'):
            return {'total_count':len(self.proofs),'artifacts':[{'id':i,'name':'quality-proof-'+name+'-70-1','expired':False,
                'digest':'sha256:'+hashlib.sha256(encoded_zip('quality-outcome.json',proof)).hexdigest(),
                'workflow_run':{'id':70,'head_sha':self.source,'repository_id':1,'head_repository_id':1}}for i,(name,proof)in self.proofs.items()]}
        return self.a.read(path)

    def download(self,path):
        if path=='actions/artifacts/60/zip':return self.braw()
        for i,(_,proof)in self.proofs.items():
            if path=='actions/artifacts/'+str(i)+'/zip':return encoded_zip('quality-outcome.json',proof)
        return self.a.download(path)

    def late(self,ctx):
        for i,name in enumerate((*QUALITY,'ubuntu-quality'),100):
            self.jobs.append({'name':name,'status':'completed','conclusion':'success'})
            self.proofs[i]=(name,{'kind':'OMEN_REQUIRED_SOURCE_JOB_V1','status':'passed','parent_run':'70','parent_attempt':'1',
                'selection':context_selection(ctx,self.read('actions/runs/70'),'70','1',name),
                'closure':{'unknown':[]},'root_result_pin':{'sha256':'f'*64}})


class OrderingMetadata(unittest.TestCase):
    def test_A_lists_only_setup_build_and_structural_package_not_fmt_or_general_tests(self):
        for workload in('windows-build','appimage-package','macos-build'):
            rows=commands(workload,SOURCE)
            self.assertFalse(any('fmt'in r or 'clippy'in r or 'test'in r or 'unittest'in r for r in rows))
            self.assertEqual(len(rows),len(dependencies(workload)))
        self.assertEqual(len(commands('windows-quality',SOURCE)),7)
        self.assertEqual(len(commands('macos-quality',SOURCE)),4)

    def test_terminal_failed_B_still_selects_late_quality_and_retains_A(self):
        api=ExternalAPI();ctx=terminal_context(api.read,api.download,'50','1')
        self.assertTrue(ctx['after']['build_passed']);self.assertFalse(ctx['after']['vm_passed'])
        self.assertEqual(ctx['after']['build_artifact'],api.a.value)
        api.late(ctx);result=aggregate(api.read,api.download,ctx,'70','1')
        self.assertEqual(result['status'],'failed');self.assertEqual(len(result['quality']),5)

    def test_failed_A_blocks_only_true_output_consumers_in_C(self):
        api=ExternalAPI(False);ctx=terminal_context(api.read,api.download,'50','1')
        self.assertIsNone(ctx['after']['build_artifact'])
        for i in range(6):self.assertIsNone(artifact_block({'workload':'windows-quality','quality_after':ctx['after']},i))
        self.assertEqual(artifact_block({'workload':'windows-quality','quality_after':ctx['after']},6),'phase-A-package-unavailable')
        self.assertIsNone(artifact_block({'workload':'ubuntu-quality','quality_after':ctx['after']},0))

    def test_running_rerun_expired_foreign_or_missing_B_source_cannot_start_C(self):
        for change in('running','rerun','expired','foreign','source'):
            api=ExternalAPI()
            if change=='running':api.b['status']='in_progress'
            elif change=='rerun':api.b['run_attempt']=2
            elif change=='expired':api.expired=True
            elif change=='foreign':api.b['head_repository']['id']=7
            else:api.result['quality_source']=None
            with self.subTest(change=change),self.assertRaises(ValueError):terminal_context(api.read,api.download,'50','1')

    def test_C_main_status_is_not_a_different_candidate_required_check(self):
        api=ExternalAPI();ctx=terminal_context(api.read,api.download,'50','1');api.late(ctx)
        # Aggregate's subject is authoritative; a controller run at another SHA
        # is not silently relabelled or granted check-write credentials.
        api.source='b'*40
        result=aggregate(api.read,api.download,ctx,'70','1')
        self.assertEqual(result['candidate_required_contexts'],'UNAVAILABLE_existing_candidate_status_admission')
        self.assertEqual(result['status'],'failed')

    def test_existing_checks_context_names_are_late_and_no_producer_wait_cycle(self):
        root=Path(__file__).parents[1];raw=(root/'.github/workflows/checks.yml').read_text()
        self.assertIn('workflows: [04 SteamOS]',raw)
        self.assertNotIn('  push:',raw);self.assertNotIn('  pull_request:',raw)
        for name in QUALITY:self.assertIn('  '+name+':',raw)
        for path in('windows-portable.yml','ubuntu-executable.yml','macos-arm64.yml'):
            producer=(root/'.github/workflows'/path).read_text()
            self.assertNotIn('dispatch-and-wait',producer);self.assertNotIn('actions: write',producer)

    def test_Root_and_aggregate_bind_complete_workload_not_just_A_B(self):
        api=ExternalAPI();ctx=terminal_context(api.read,api.download,'50','1');api.late(ctx)
        spec=copy.deepcopy(api.proofs[100][1]['selection'])
        self.assertEqual(verify_root_late_scope(spec,api.read,api.download)['selection'],spec)
        spec['workload']='invented-quality'
        with self.assertRaises(ValueError):verify_root_late_scope(spec,api.read,api.download)
        api.proofs[100][1]['selection']=copy.deepcopy(api.proofs[101][1]['selection'])
        with self.assertRaises(ValueError):aggregate(api.read,api.download,ctx,'70','1')


if __name__=='__main__':unittest.main()
