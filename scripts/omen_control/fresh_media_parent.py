"""Normal fresh-generation parent producer; no old prepared-run constructor."""
import copy
import json
import time
from pathlib import Path


def produce(preparation, expectation, installed_contract_pin, execution_job, public):
    import libvirt_peer as p
    import queue_assignment
    import postqueue_issuer
    import runtime_entry
    from libvirt_native import held
    import source_contract

    c = preparation['candidate']
    p.need(c['jobId'] == execution_job and c['hostBoot'] == expectation['bootID'],
           'fresh candidate job/current boot, not an old execution continuation')
    contract = source_contract.validate(expectation['sourceRoles'], expectation['queuePrograms'],
                                        installed_contract_pin)
    p.need(c['operationContext']['deploymentId'] == contract['deployment']['id'] and c['lineageNonce'] == contract['guestNonce'], 'same protected deployment/guest lineage')
    q = preparation['qualification']
    qualified = json.loads(held(q['placementQualificationPin'], 1048576))
    pre = qualified['currentPreflight']; now = time.time()
    p.need(pre['bootID'] == c['hostBoot'] and pre['allOwnedFDsClosed'] is True
           and pre['preparedAccessPin'] == preparation['preparedAccessPin']
           and pre['working'] == preparation['preparedDiskPins']['working']
           and pre['original'] == c['original'] and pre['runtimeAuthorized'] is False
           and pre['observedUnix'] <= now <= pre['observedUnix'] + 30,
           'genuine complete fresh final preflight, not a new timestamp')
    p.need(now < expectation['wholeDeadlineUnix'] <= now + 900,
           'bounded original outer authority')
    parent = copy.deepcopy(contract['parentTemplate'])
    p.need(parent.get('noNIC') is True and parent.get('noInstall') is True
           and parent.get('maxBoots') == 1
           and parent.get('failureControl') == 'LIBVIRT_AUTODESTROY_CONTROLLER_CONNECTION',
           'installed firstboot-only operation profile')
    parent.pop('unbootedContinuationPin', None)
    parent['installedSchemaReceiptPin'] = None  # historical report is not launch authority
    parent.update(kind='ROOT_LIBVIRT_R4_FINITE_QUEUE_PARENT', RootIssued=True,
                  runtimeAuthorized=True, MODEL_ONLY=False, nonce=c['nonce'],
                  bootID=c['hostBoot'], candidate=c, jobId=execution_job,
                  sourceRoles=expectation['sourceRoles'], queuePrograms=expectation['queuePrograms'],
                  installedSourceContractPin=installed_contract_pin,
                  actualInstalledQueueFull9=expectation['queuePrograms'][0],
                  preparedAccessPin=preparation['preparedAccessPin'],
                  preparedDiskPins=preparation['preparedDiskPins'],
                  splitDiskCapturePins=expectation['splitDiskCapturePins'],
                  issuedUnix=now, startBeforeUnix=min(now + 299, expectation['wholeDeadlineUnix']),
                  wholeDeadlineUnix=expectation['wholeDeadlineUnix'],
                  priorHistory=expectation['priorHistory'],
                  priorHistoryCodecPin=expectation['priorHistoryCodecPin'],
                  workerLockPin=expectation['workerLockPin'],
                  workerStatePin=expectation['workerStatePin'],
                  workerLockMode=expectation['workerLockMode'],
                  nativeReadOnlyPin=expectation['nativeReadOnlyPin'],
                  priorLeases=expectation['priorLeases'],
                  unusedPaths=['/run/opemos-vfio-' + c['nonce'], '/run/opemos-libvirt-results-' + c['nonce']],
                  postqueueDelegation='ROOT_EXACT_CANONICAL_BINDING_ONLY_R5',
                  workerArgv=['/usr/bin/python3', expectation['queuePrograms'][0]['path'],
                              '--queue', parent['queueStateRoot'], 'run'],
                  contextPath=__import__('source_contract').candidate_paths(c)['runtimeRoot'] + '/context.json',
                  **{k: q[k] for k in ('sourcePlacementPin', 'placementQualificationPin', 'prequeuePreflightPin')})
    # Static privileged commands and tool identities come from the installed
    # reviewed profile; the per-run plan may not supply executable bodies.
    spec = parent['normalizedSpecTemplate']
    parent['guestContract'] = {'nonce': c['guestReporterNonce'], 'guestUUID': c['guestUUID']}
    parent['childGrantTemplate'].update(reservationMemory=10737418240, controllerMemory=2147483648,
                                       domainMemory=8589934592, noNIC=True, noInstall=True,
                                       maxBoots=1, physicalGroup=p.GROUP,
                                       failureControl='LIBVIRT_AUTODESTROY_CONTROLLER_CONNECTION')
    spec.update(id=execution_job,
                command=['sudo', '-n', '/usr/bin/python3', '-B',
                         parent['sourceRoles']['runtime_entry']['path'],
                         '--parent-pin-json', 'EXACT_PARENT_FULL_PIN_JSON'],
                files=[{k: pin[k] for k in ('path', 'bytes', 'sha256')}
                       for name, pin in sorted(parent['sourceRoles'].items())],
                libvirt_domain={'uuid': c['guestUUID'], 'name': c['name'],
                                'leaseNonce': c['nonce'],
                                'observer': {k: parent['sourceRoles']['libvirt_peer'][k]
                                             for k in ('path', 'bytes', 'sha256')}})
    p.need(parent['postqueueDelegation'] == 'ROOT_EXACT_CANONICAL_BINDING_ONLY_R5'
           and spec['approval'] == 'EXACT_PARENT_MINIMAL_PIN', 'normal queue delegation')
    queue_assignment.execution_job(c, parent)
    ref = public(Path(__import__('source_contract').candidate_paths(c)['parentPath']).name, parent)
    # Both actual normal consumers must accept the producer's output.
    postqueue_issuer.bind_placement(p, parent, ref)
    runtime_entry.bind_placement(p, parent, ref)
    raw_spec = postqueue_issuer.submission_manifest(parent, ref, '/run')
    manifest = public(Path(__import__('source_contract').candidate_paths(c)['jobPath']).name,
                      {'version': 1, 'jobs': [raw_spec]})
    p.need(time.time() < parent['startBeforeUnix']
           and time.time() <= pre['observedUnix'] + 30, 'fresh immediately before normal submit')
    return {'parentPin': ref, 'manifestPin': manifest, 'jobId': execution_job,
            'submitted': False, 'hardwareEffects': []}
