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
    'producer-metadata-diagnostic':'producer-metadata-diagnostic'}


def validate(run,job,repository,current_main,workflow_raw,profile):
    need(type(workflow_raw)is bytes and 0<len(workflow_raw)<=128*1024,
         'complete finite workflow bytes, not API step-name labels')
    need(profile['schema']=='FINITE_VM_ONLY_V1'and profile['enabled']is True and
         profile['controller_commit']==current_main and run['repository']['full_name']==REPO and
         run['head_repository']['id']==repository['id']==run['repository']['id']and
         run['head_repository']['full_name']==REPO and run['path']in PARENT_WORKLOADS and
         run['event']in('push','pull_request','workflow_dispatch')and
         str(job['run_id'])==str(run['id'])and job['status']=='in_progress'and
         job['name']in JOB_WORKLOAD and JOB_WORKLOAD[job['name']]in PARENT_WORKLOADS[run['path']],
         'only exact live source-workload job; no GUI/platform/persist capability')
    need(hashlib.sha256(workflow_raw).hexdigest()==profile['workflowPins'][run['path']],
         'all candidate workflow steps/env/actions must equal the Root-adopted safe template')
    # A matching hash authorizes no candidate checkout, source import, shell,
    # credentials, arbitrary command, hardware or publication on the host.
    return {'kind':'ROOT_FIXED_A_SOURCE_JOB_SCOPE_V1','repository':REPO,
        'controller_commit':current_main,'candidate_commit':run['head_sha'],
        'run_id':str(run['id']),'attempt':str(run['run_attempt']),'job_id':str(job['id']),
        'workload':JOB_WORKLOAD[job['name']],'allowed_action':'execute-source-workload',
        'workflow_sha256':hashlib.sha256(workflow_raw).hexdigest(),
        'retainsExistingKernelAndTokenGuards':True,'runtimeAuthorized':False}
