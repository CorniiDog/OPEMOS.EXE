"""Generated synthetic policy fixtures, never evidence of native GUI input.

Every test creates private files; no historical receipt or original is reused.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import stat
import zlib

ACTIONS=('chooser-open','chooser-confirm-exact-input','Build','virtualUSB-select-and-review','virtualUSB-Write-confirmation')


def synthetic_proof(E,executable,nonce,slot,run='900',attempt='3'):
    def sha(value):return hashlib.sha256(value.encode()).hexdigest()
    actions=[]
    for action in ACTIONS:
        tag=slot+action
        row={'action':action,'action_id':sha(tag)[:32]}
        for field in('record_sha256','transition_sha256','sender_lifecycle_sha256','target_observation_sha256'):row[field]=sha(tag+field)
        for side in('before','after'):
            row[side]={'capture_id':sha(tag+side)[:32],'frame_sha256':sha('same pixels allowed'),'capture_receipt_sha256':sha(tag+side+'capture')}
        actions.append(row)
    proof={'schema':1,'verified':True,'source_commit':executable['source_commit'],'run_id':run,'attempt':attempt,
        'operation_nonce':nonce,'executable':executable,'sender_sha256':sha('synthetic sender'),'actions':actions}
    proof['proof_sha256']=E['digest'](proof);return proof


def attach(stage,receipt,plan,operand,root,platform=None,expected_executable=None):
    root=Path(root);root.mkdir(mode=0o700,exist_ok=True);root.chmod(0o700)
    def store(name,kind,value):
        raw=value if isinstance(value,bytes)else json.dumps(value,sort_keys=True).encode()
        path=root/name;path.write_bytes(raw);path.chmod(0o600)
        receipt['files'][name]={'kind':kind,'path':str(path),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        return name
    source=root/'synthetic-observer-source.py';source.write_bytes(b'# Generated policy fixture, no real observer or sender execution\n');source.chmod(0o600)
    code={'path':str(source),'size':source.stat().st_size,'sha256':hashlib.sha256(source.read_bytes()).hexdigest()}
    receipt['gui_sender_ref']=store('sender-source.py','pointer-sender-source',source.read_bytes())
    receipt['gui_observer_ref']=store('observer-source.py','gui-observer-source',source.read_bytes())
    receipt['gui_converter_ref']=store('converter-source.py','gui-converter-source',source.read_bytes())
    host=receipt['roles']['imaging_host'];platform=platform or host['platform'];producer={'windows':'windows','linux':'ubuntu','darwin':'macos'}[platform]
    E=stage._EXECUTABLES
    executable={'schema':1,'repository':'CorniiDog/OPEMOS.EXE','source_commit':plan['source_commit'],'platform':producer,
        'workflow':E['PRODUCERS'][producer]['workflow'],'producer_run_id':'101','producer_attempt':'2','event':'push','ref':'refs/heads/main',
        'artifact_id':'201','artifact_name':'synthetic-package','artifact_archive_sha256':'a'*64,'package_name':'synthetic.zip','package_sha256':operand['package_sha256'],
        'package_bytes':1024,'executable_name':'synthetic-executable','executable_sha256':'f'*64,'executable_bytes':512}
    if expected_executable is not None:executable=copy.deepcopy(expected_executable)
    plan.update(run_id=plan.get('run_id','900'),attempt=plan.get('attempt','3'))
    receipt.update(run_id=plan['run_id'],attempt=plan['attempt'])
    session={'id':'synthetic-session','runtime_instance_id':host['id'],'boot_id':'synthetic-guest-boot','platform':platform,'architecture':host['architecture'],
        'display':{'id':'synthetic-display','width':64,'height':48,'scale':1,'coordinate_width':64,'coordinate_height':48,'origin_x':0,'origin_y':0,'coordinate_space':'logical-points'if platform=='darwin'else'physical-pixels'}}
    host['gui_session']=session
    operand.update(gui_session=session,gui_sender=code,gui_observer=code,gui_converter=code,gui_executable=executable,
        evidence_root=str(root),gui_input_path='synthetic-exact-input.img',gui_output_path='synthetic-planned-output.img')
    receipt['roles']['virtual_usb'].update(backing_identity='synthetic-owned-backing',device_identity='synthetic-device')
    identity={'source_commit':plan['source_commit'],'run_id':plan['run_id'],'attempt':plan['attempt'],'operation_nonce':plan['nonce'],
        'inventory_vm_id':operand['inventory_vm_id'],'runtime_instance_id':operand['runtime_instance_id'],'queue_job_ids':operand['job_ids'],
        'original_source':operand['original_source'],'executable':executable}
    clock={'domain':'monotonic-ns','id':'synthetic-host-boot'}
    operand['gui_clock']=clock
    pixels=b'\x20\x30\x40'*(64*48)
    def chunk(kind,data):return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
    png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',64,48,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(b''.join(b'\0'+pixels[y*64*3:(y+1)*64*3]for y in range(48))))+chunk(b'IEND',b'')
    ppm=b'P6\n64 48\n255\n'+pixels
    def capture(index,side,tick):
        tag=str(index)+'-'+side;capture_id=hashlib.sha256(('synthetic capture '+tag).encode()).hexdigest()[:32]
        ref=store(tag+'.png','screenshot',png)
        meta={'capture_id':capture_id,'clock':clock,'tick':tick,'frame_ref':ref,'frame_sha256':hashlib.sha256(png).hexdigest(),'session':session,'acquired':True}
        frame={'ref':ref,'capture_id':capture_id,'clock':clock,'tick':tick}
        if platform=='windows':
            original=store(tag+'.ppm','screenshot-original-ppm',ppm);meta['original_sha256']=hashlib.sha256(ppm).hexdigest()
            conversion={'capture_id':capture_id,'original_ref':original,'original_sha256':meta['original_sha256'],'derived_ref':ref,
                'derived_sha256':meta['frame_sha256'],'numeric_exit':0,'pixel_bytes_preserved':True,'converter_source_sha256':code['sha256']}
            frame.update(original_ref=original,conversion_ref=store(tag+'-conversion.json','frame-conversion',conversion))
        frame['capture_ref']=store(tag+'-capture.json','frame-capture',meta);return frame
    operand['gui_controls']={action:{'control_id':action,'role':'button'}for action in ACTIONS}
    destination={'qmp_name':'synthetic-qmp-host','qemu_process':{'pid':401,'start':402},'host_boot_id':clock['id'],
        'socket_path':str(root/'synthetic-qmp.sock'),'socket_identity':{'st_dev':1,'st_ino':2,'st_mode':stat.S_IFSOCK|0o600,'st_uid':os.getuid(),'st_gid':os.getgid(),'st_nlink':1,'st_size':0,'st_mtime_ns':1,'st_ctime_ns':1},
        'peer':{'pid':401,'uid':os.getuid(),'gid':os.getgid()},'disk':{'path':str(root/'synthetic-os.qcow2'),'read_only':False},'argv_sha256':'b'*64}
    admission={'schema':1,'kind':'OPEMOS_ADMITTED_POINTER_DESTINATION','admitted':True,'identity':identity,'session':session,'clock':clock,
        'app':{'process':host['app_process'],'executable_sha256':executable['executable_sha256'],'root_window_id':host['app_window_id']},'qmp':destination}
    admission_ref=store('destination-admission.json','pointer-destination-admission',admission)
    admission_item=receipt['files'][admission_ref]
    operand['gui_destination_admission']={k:admission_item[k]for k in('path','size','sha256')}
    receipt['pointer_actions']={}
    for index,action in enumerate(ACTIONS,1):
        action_id=hashlib.sha256(('synthetic action '+str(index)).encode()).hexdigest()[:32];before=capture(index,'before',index*1000+1);after=capture(index,'after',index*1000+80)
        app={'process':host['app_process'],'executable_sha256':executable['executable_sha256'],'root_window_id':host['app_window_id'],
            'window_id':'synthetic-window-'+str(index),'window_title':'Synthetic actual-window contract fixture','window_rect':{'x':0,'y':0,'width':64,'height':48}}
        target={'app_process':app['process'],'window_id':app['window_id'],'visible':True,'enabled':True,'control_id':action,
            'role':'button','rect':{'x':2,'y':2,'width':10,'height':10},'hit_observation':'native-same-control-unoccluded'if platform=='darwin'else'same-console-frame-review'}
        sender={'source_sha256':code['sha256'],'process':{'pid':100+index,'start':200+index},'host_boot_id':clock['id']}
        life={'action_id':action_id,'sender':sender,'numeric_exit':0,'deadline_expired':False,**{k:True for k in('waited','stdout_EOF','stderr_EOF','pipes_closed','original_gone')}}
        native={'schema':1,'identity':identity,'session':session,'app':app,'target':target,'observer_source_sha256':code['sha256'],
            'app_birth_rechecked':True,'before_frame_ref':before['ref'],'method':'native-readonly','capture_id':before['capture_id'],'delivery_clock':clock,'delivered_tick':index*1000+5}
        row={'schema':1,'kind':'OPEMOS_NATIVE_POINTER_ACTION','action':action,'action_id':action_id,'sequence':index,'identity':identity,
            'button':'left','click_count':1,'session':session,'clock':clock,'app':app,'target':target,'point':{'x':7,'y':7},'sender':sender,'before':before,'phases':[],
            'sender_lifecycle_ref':store(str(index)+'-lifecycle.json','pointer-sender-lifecycle',life),
            'target_observation_ref':store(str(index)+'-observation.json','gui-observation',native),'status':'sent','backend':'QMP'}
        for offset,phase in enumerate(('move','down','up')):
            request={'execute':'input-send-event','id':offset+1,'arguments':{'events':
                [{'type':'abs','data':{'axis':'x','value':round(7*32767/63)}},{'type':'abs','data':{'axis':'y','value':round(7*32767/47)}}]if offset==0 else
                [{'type':'btn','data':{'button':'left','down':offset==1}}]}}
            event={'phase':phase,'clock':clock,'sent_tick':index*1000+10+offset*10,'returned_tick':index*1000+11+offset*10,'request':request,'response':{'id':offset+1,'return':{}}}
            if platform=='darwin':event.update(event_type=('mouseMoved','leftMouseDown','leftMouseUp')[offset],posted=True,button='left',click_count=1)
            row['phases'].append(event)
        if platform=='darwin':row.update(backend='CGEvent',delivery_ack='UNAVAILABLE:CGEvent.post',observed_pointer=row['point'])
        states=stage.POINTER_TRANSITIONS[action]
        observation={'before_state':states[0],'after_state':states[1],'before_frame_ref':before['ref'],'after_frame_ref':after['ref'],
            'window_owner_process':app['process'],'actual_observation':True,'input_sha256':operand['input_sha256'],'input_path':operand['gui_input_path'],
            'planned_output':operand['gui_output_path'],'usb_id':receipt['roles']['virtual_usb']['id'],
            'usb_backing_identity':receipt['roles']['virtual_usb']['backing_identity'],'usb_device_identity':receipt['roles']['virtual_usb']['device_identity'],
            'output_image_sha256':receipt['output']['sha256']}
        transition={'delivery_clock':clock,'delivered_tick':index*1000+90,'status':'observed','action_id':action_id,'identity':identity,'session':session,'app_process':app['process'],'after':after,'observation':observation}
        row['transition_ref']=store(str(index)+'-transition.json','pointer-transition',transition)
        row['source_context']={k:copy.deepcopy(row[k])for k in('action','action_id','sequence','identity','session','app','target','point','clock','before','transition_ref','sender_lifecycle_ref','target_observation_ref')}
        if platform in('windows','linux'):
            row['actual_destination']={'observed':destination,'admission_ref':admission_ref,'admission_sha256':admission_item['sha256']}
            context=row['source_context']
            context.update(destination_admission_path=admission_item['path'],destination_admission_sha256=admission_item['sha256'],destination_admission_ref=admission_ref,
                before_path=receipt['files'][before['ref']]['path'],before_sha256=receipt['files'][before['ref']]['sha256'],
                before_capture_path=receipt['files'][before['capture_ref']]['path'],before_capture_sha256=receipt['files'][before['capture_ref']]['sha256'],
                action_result_path=str(root/(str(index)+'-action.json')),sender_lifecycle_path=receipt['files'][row['sender_lifecycle_ref']]['path'])
            life['raw']={};life['raw_refs']={};life['raw_complete']={'stdout':True,'stderr':True};life['stream_read_bytes']={'stdout':0,'stderr':0}
            for label in('stdout','stderr'):
                ref=store(str(index)+'-'+label+'.raw','pointer-sender-'+label,b'')
                item=receipt['files'][ref];path=Path(item['path']);info=path.lstat()
                full9={k:getattr(info,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
                life['raw'][label]={**item,'identity':full9,'custody':'verified-prefix','full9_unchanged':True};life['raw_refs'][label]=ref
                context['sender_'+label+'_ref']=ref;context['sender_'+label+'_path']=item['path']
            store(str(index)+'-lifecycle.json','pointer-sender-lifecycle',life)
            row['output_reservations']={}
            for key in('action_result_path','sender_lifecycle_path','sender_stdout_path','sender_stderr_path'):
                target=Path(context[key])
                if key=='action_result_path':target.write_bytes(b'pending synthetic action');target.chmod(0o600)
                info=target.lstat();created={k:getattr(info,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
                row['output_reservations'][key]={'path':str(target),'cap':1048576,'created_identity':created}
        row['source_context']['unknown_future']={'retained':True}
        receipt['pointer_actions'][action]=store(str(index)+'-action.json','pointer-action',row)
    for check,actions in {'graphical_chooser':ACTIONS[:2],'graphical_build':('Build',),'virtual_usb_write':ACTIONS[3:]}.items():
        receipt['checks'][check]['evidence'].extend(receipt['pointer_actions'][action]for action in actions)
    return receipt
