"""Pure finite supplement for the EXISTING Root job-start/broker guard.

Root must separately adopt/pin this function and the complete safe workflow
bytes. It never replaces kernel UID/namespace/cgroup/birth, one-use token, job
hook or operational admission checks. No network, queue or VM effects.
"""
import hashlib
import re
from omen_source_workloads import REPO, PARENT_WORKLOADS, need

JOB_WORKLOAD={'frontend-and-docs':'frontend-and-docs','rust':'rust','linux-integration':'linux-integration',
    'debian-12-package':'debian-12-package','seed-runtime-source':'seed-runtime-source',
    'build':'windows-build','appimage-package':'appimage-package',
    'producer-metadata-diagnostic':'producer-metadata-diagnostic','native-app':'macos-build',
    'windows-quality':'windows-quality','ubuntu-quality':'ubuntu-quality','macos-quality':'macos-quality'}


def validate_controller(run,job,execution,workflow_raw,profile):
    """Finite policy for adoption by EXISTING Root job hook, not a new guard.

    Unlike the hosted heartbeat reader, this compares the qualification with
    independently protected Root profile data. Original kernel/one-use token
    checks still surround this policy and cannot be supplied by candidate B.
    """
    need(profile['schema']=='FINITE_VM_ONLY_V1'and profile['enabled']is True and
         type(workflow_raw)is bytes and 0<len(workflow_raw)<=131072 and
         run['repository']['full_name']==run['head_repository']['full_name']==REPO and
         run['repository']['id']==run['head_repository']['id']and
         run['path']=='.github/workflows/omen-robot.yml'and run['event']in('workflow_dispatch','workflow_run')and
         run['head_sha']==execution['implementation_commit']and
         execution['control_commit']==profile['controller_commit']and
         str(job['run_id'])==str(run['id'])and job['status']=='in_progress'and
         job['name']in('actual-robot-transactions','required-platform-robot'),
         'exact official controller run/job/implementation/current checkpoint')
    qualification=execution['qualification']
    if qualification is None:
        need(run['head_branch']=='main'and execution['implementation_commit']==profile['controller_commit'],
             'original Main controller invariant')
        expected=profile['workflowPins'][run['path']]
    else:
        need(qualification==profile['controller_qualification']and
             execution['workflow_ref']==REPO+'/'+run['path']+'@refs/heads/'+run['head_branch'],
             'Repo variable/branch label cannot replace independent protected Root qualification')
        expected=qualification['workflow_sha256']
    need(hashlib.sha256(workflow_raw).hexdigest()==expected,'whole controller workflow bytes changed')
    return {'kind':'ROOT_REVIEWED_CONTROLLER_JOB_SCOPE_V1','execution':execution,
            'run_id':str(run['id']),'attempt':str(run['run_attempt']),'job_id':str(job['id']),
            'allowed_actions':['execute-produced-platform']if job['name']=='required-platform-robot'else
                ['execute-vm','execute-platform','persist'],
            'retainsExistingKernelAndTokenGuards':True,'runtimeAuthorized':False}


def validate(run,job,repository,current_main,workflow_raw,profile,late_selection=None):
    need(type(workflow_raw)is bytes and 0<len(workflow_raw)<=128*1024,
         'complete finite workflow bytes, not API step-name labels')
    need(profile['schema']=='FINITE_VM_ONLY_V1'and profile['enabled']is True and
         profile['controller_commit']==current_main and run['repository']['full_name']==REPO and
         run['head_repository']['id']==repository['id']==run['repository']['id']and
         run['head_repository']['full_name']==REPO and run['path']in PARENT_WORKLOADS and
         run['event']in('push','pull_request','workflow_dispatch','workflow_run')and
         str(job['run_id'])==str(run['id'])and job['status']=='in_progress'and
         job['name']in JOB_WORKLOAD and JOB_WORKLOAD[job['name']]in PARENT_WORKLOADS[run['path']],
         'only exact live source-workload job; no GUI/platform/persist capability')
    need(hashlib.sha256(workflow_raw).hexdigest()==profile['workflowPins'][run['path']],
         'all candidate workflow steps/env/actions must equal the Root-adopted safe template')
    if run['path']=='.github/workflows/checks.yml':
        # Root obtains this by verify_root_late_scope using its independently
        # authenticated API adapters; never accept a client-supplied flag here.
        need(run['event']in('workflow_run','workflow_dispatch')and type(late_selection)is dict and
             late_selection.get('kind')=='ROOT_VERIFIED_LATE_QUALITY_SCOPE_V1'and
             late_selection['selection']['parent_run']==str(run['id'])and
             late_selection['selection']['parent_attempt']==str(run['run_attempt'])and
             late_selection['selection']['workload']==JOB_WORKLOAD[job['name']],
             'Root independently verified exact terminal B before admitting C')
    else:need(run['event']!='workflow_run','only late Checks consumes terminal workflow event')
    # A matching hash authorizes no candidate checkout, source import, shell,
    # credentials, arbitrary command, hardware or publication on the host.
    return {'kind':'ROOT_FIXED_A_SOURCE_JOB_SCOPE_V1','repository':REPO,
        'controller_commit':current_main,'candidate_commit':late_selection['selection']['candidate_commit']if late_selection else run['head_sha'],
        'controller_implementation_commit':run['head_sha'],
        'run_id':str(run['id']),'attempt':str(run['run_attempt']),'job_id':str(job['id']),
        'workload':JOB_WORKLOAD[job['name']],'allowed_action':'execute-source-workload',
        'workflow_sha256':hashlib.sha256(workflow_raw).hexdigest(),'late_selection':late_selection,
        'retainsExistingKernelAndTokenGuards':True,'runtimeAuthorized':False}
