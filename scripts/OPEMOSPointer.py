"""Actual mouse keyword. Installed ordinary jobs supply fresh pinned context.

The audited existing sender APIs own destination/PID/socket/frame checking,
pre-effect output reservation, real QMP down/up and finite child custody.
This adapter never substitutes a label, old manual receipt, AXPress, or DOM.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parent))
from omen_robot import raw_file,strict,require,modules,identity,dump

class OPEMOSPointer:
    ROBOT_LIBRARY_SCOPE='SUITE'
    ROBOT_AUTO_KEYWORDS=False
    def __init__(self):
        self.actual_pointer_calls=0;self.last_action=None;self.last_context=None
    def get_keyword_names(self):return ['Click Observed Native Control','Assert Current Observed Result']
    def run_keyword(self,name,args,kwargs=None):
        if name=='Click Observed Native Control':return self.click(*args)
        if name=='Assert Current Observed Result':return self.observe(*args)
    def click(self,operation_path,operation_sha):
        operation=strict(raw_file(operation_path,1048576,operation_sha,os.getuid()))
        context=operation['pointer_context'];expected=identity()
        require(all(context['identity'][k]==expected[k]for k in ('source_commit','run_id','attempt')),'Pointer context belongs to another source/run/attempt')
        require(context['identity']['operation_nonce']==os.environ['OPEMOS_TRANSACTION_NONCE'],'Pointer nonce stale')
        platform=operation['platform']
        require(platform in ('windows','ubuntu'),'Current admitted native Mac sender absent; no invented Mac click')
        driver=operation['driver'];source=raw_file(driver['path'],1048576,driver['sha256'],os.getuid())
        # The external fixed hook's exact fresh admission binds the driver SHA;
        # no path/driver can come from workflow input or executable artifacts.
        admission=strict(raw_file(operation['admission']['path'],1048576,operation['admission']['sha256'],os.getuid()))
        require(admission['identity']==context['identity'] and admission['driver_sha256']==driver['sha256'] and admission['admitted']is True,'Driver/current runtime admission mismatch')
        require(admission['kind']=='OPEMOS_ROBOT_POINTER_ADMISSION'and admission['operation_sha256']==operation['operation_payload_sha256'],'Wrong pointer operation admission')
        payload={k:v for k,v in operation.items()if k not in ('admission','operation_payload_sha256')}
        require(hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()==operation['operation_payload_sha256'],'Operation/admission payload differs')
        stage=modules();reader=stage['_READER'];ns=reader.verified_namespace(source,driver['path'],'robot_existing_actual_sender')
        observed=Path(operation['observed_result_path'])
        require(observed.is_absolute()and not os.path.lexists(observed),'Old observed result refused before input')
        records=ns['ci10_reserve'](context,ns['ci10_inputs'](operation))
        primary=None;life=None;code_fd=None
        try:
            ns['ci10_pending'](records,context)
            payload="__file__="+repr(driver['path'])+"\nSOURCE="+repr(source)+"\nCONTEXT="+repr(context)+"\nRECORDS="+repr(records)+"\nOPERATION="+repr(operation)+"\n"
            payload+="ns={'__name__':'robot_existing_actual_sender','__file__':__file__};exec(compile(SOURCE,__file__,'exec'),ns);ns['CI10_RESERVATIONS']=RECORDS\n"
            if platform=='windows':
                payload+="sock,send=ns['connect']()\ntry:\n result=ns['pointer'](send,CONTEXT['point']['x'],CONTEXT['point']['y'],True,CONTEXT,OPERATION['driver']['sha256'],RECORDS)\nfinally:sock.close()\n"
            else:
                payload+="request=dict(OPERATION['sender_operation'],pointerContext=CONTEXT,sender_source_sha256=OPERATION['driver']['sha256']);assert request['kind']=='mouse';result=ns['transact'](request)\n"
            payload+="print(__import__('json').dumps(result,sort_keys=True))\n"
            import fcntl
            code_fd=os.memfd_create('opemos-actual-robot-pointer',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
            view=memoryview(payload.encode())
            while view:
                written=os.write(code_fd,view);require(written>0,'Short sealed sender source write');view=view[written:]
            fcntl.fcntl(code_fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
            life,out,err=ns['ci10_run_child']([sys.executable,'-I',f'/proc/self/fd/{code_fd}'],records,seconds=60,pass_fds=(code_fd,)+tuple(r['fd']for r in records.values()))
            require(life['numeric_exit']==0 and life['waited']is True and life['stdout_EOF']is True and life['stderr_EOF']is True and life['pipes_closed']is True and life['original_gone']is True and not life['first_failure']and not life['secondary_errors'],'Actual sender failure/closure unknown; exact raw streams retained')
            action=strict(out)
            self.last_action=action;self.last_context=context
            self.actual_pointer_calls+=1
            return {'actual_pointer_calls':self.actual_pointer_calls,'sender_source_sha256':driver['sha256']}
        except BaseException as error:
            primary=error;raise
        finally:
            try:
                if life is not None:
                    life.update(action_id=context['action_id'],sender={'source_sha256':driver['sha256'],'process':life['child_identity'],'host_boot_id':context['clock']['id']},raw_refs={'stdout':context['sender_stdout_ref'],'stderr':context['sender_stderr_ref']})
                    ns['ci10_json_finish'](records['sender_lifecycle_path'],life,'pointer-sender-lifecycle')
            except BaseException as error:
                if primary is None:raise
                os.write(2,(json.dumps({'secondary_failure':type(error).__name__,'phase':'sender-lifecycle'})+'\n').encode())
            finally:
                code_error=None
                if code_fd is not None:
                    try:os.close(code_fd)
                    except OSError as error:code_error=error
                close=ns['ci10_close_outputs'](records)
                if code_error is not None:
                    if primary is None:raise code_error
                    os.write(2,b'{"secondary_failure":"sealed_sender_source_close"}\n')
                if close:
                    if primary is None:raise ValueError('Sender output closure failed')
                    os.write(2,(json.dumps({'secondary_close_failures':close})+'\n').encode())

    def observe(self,path,sha):
        """Consume the fresh independent native/console observer after actual input.

        Observer is an ordinary queued producer, not a retrospective sender ack.
        Its full action/window/session/frame custody is rechecked by stage's
        validate_gui_pointer on the final complete transaction receipt.
        """
        operation=strict(raw_file(path,1048576,sha,os.getuid()));expected=identity()
        require(self.actual_pointer_calls>0 and self.last_context is not None,'No new click in this Robot execution')
        # This exact result path was absent before input. The ordinary queued
        # native observer writes it after the fresh nonce/action, never a sender
        # self-ack. It is read once through a held descriptor and revalidated in
        # the final complete GUI graph, including its actual observer raw bytes.
        import time
        target=Path(operation['observed_result_path']);deadline=time.monotonic()+30
        while not os.path.lexists(target):
            require(time.monotonic()<deadline,'Fresh native observer result unavailable')
            time.sleep(.1)
        raw=raw_file(target,1048576,owner=os.getuid());result=strict(raw)
        require(all(result['identity'][k]==expected[k]for k in ('source_commit','run_id','attempt'))and result['identity']['operation_nonce']==os.environ['OPEMOS_TRANSACTION_NONCE'],'Observed result is stale')
        require(result['observed']is True and result['expected_result']is True and result['native_observer']is True,'Expected real UI result was not observed')
        require(result['action_id']==self.last_context['action_id'] and result['runtime_instance_id']==self.last_context['identity']['runtime_instance_id'],'Observer belongs to another action/runtime')
        require(result['frame_sha256'] and result['window_id']and result['observer_source_sha256']==operation['observer_source_sha256'],'Observer frame/window/source identity missing')
        return {'observed_result_sha256':hashlib.sha256(raw).hexdigest(),'actual_pointer_calls':self.actual_pointer_calls}
