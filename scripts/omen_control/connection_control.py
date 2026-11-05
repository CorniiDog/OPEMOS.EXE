#!/usr/bin/env python3
"""One actual QMP pointer + independent native chooser proof in an owned VM.

This is a scoped connection diagnostic, never full image/USB/NVIDIA acceptance.
The normal queue job owns QEMU creation and final closure. Its binding is a
fresh private file, not an argument from a GitHub workflow.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import time

FULL9=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def need(ok,why):
    if not ok:raise RuntimeError(why)

def held(path,cap):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        first=os.fstat(fd);sig=lambda s:tuple(getattr(s,k)for k in FULL9)
        need(stat.S_ISREG(first.st_mode)and first.st_uid==os.getuid()and
             first.st_nlink==1 and not first.st_mode&0o077 and first.st_size<=cap,
             'private held file custody failed')
        raw=b''
        while chunk:=os.read(fd,min(65536,cap+1-len(raw))):
            raw+=chunk;need(len(raw)<=cap,'bounded held read overflow')
        need(len(raw)==first.st_size and
             sig(first)==sig(os.fstat(fd))==sig(os.lstat(path)),
             'held file/path identity changed')
        return raw
    finally:os.close(fd)

def save(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        need(os.write(fd,raw)==len(raw),'short receipt write');os.fsync(fd)
    finally:os.close(fd)
    return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def process(binding):
    pid=binding['pid'];need(type(pid)is int and pid>1,'exact VM PID missing')
    proc=Path('/proc')/str(pid);raw=(proc/'stat').read_text()
    start=raw[raw.rfind(')')+2:].split()[19]
    need(start==binding['start_ticks'] and
         Path('/proc/sys/kernel/random/boot_id').read_text().strip()==binding['host_boot_id'],
         'QEMU birth identity changed')
    need((proc/'exe').resolve()==Path('/usr/bin/qemu-system-x86_64').resolve(),
         'not the admitted QEMU binary')
    actual=[x.decode()for x in (proc/'cmdline').read_bytes().split(b'\0')if x]
    need(actual==binding['argv'],'QEMU argv changed')
    need((proc/'cgroup').read_text().strip()==binding['queue_cgroup'] and
         binding['queue_unit'] in binding['queue_cgroup'],
         'QEMU escaped exact admitted normal queue cgroup')
    return proc

def connect_owned(path,pid,timeout=35):
    info=os.lstat(path)
    need(stat.S_ISSOCK(info.st_mode)and info.st_uid==os.getuid()and
         not info.st_mode&0o077,'owned private VM socket required')
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(timeout);s.connect(str(path))
    peer=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    need(peer[0]==pid and peer[1]==os.getuid(),'socket peer is not exact QEMU')
    return s

class QMP:
    def __init__(self,s):
        self.s=s;self.f=s.makefile('rwb',buffering=0);self.n=0
        need('QMP'in self.read(),'QMP greeting absent');self.call('qmp_capabilities')
    def read(self):
        raw=self.f.readline(1048577);need(raw and len(raw)<=1048576,'QMP response missing/oversize')
        return json.loads(raw)
    def call(self,command,args=None):
        self.n+=1;packet={'execute':command,'id':self.n}
        if args is not None:packet['arguments']=args
        self.f.write((json.dumps(packet)+'\r\n').encode())
        while True:
            row=self.read()
            if row.get('id')==self.n:
                need('error'not in row,'QMP command error: '+repr(row.get('error')))
                return row['return']
    def close(self):self.f.close();self.s.close()

def frame(q,path):
    need(not os.path.lexists(path),'frame output must be absent')
    q.call('screendump',{'filename':str(path),'format':'png'})
    raw=held(path,16*1024*1024)
    need(raw[:8]==b'\x89PNG\r\n\x1a\n','real PNG frame absent')
    width,height=struct.unpack('>II',raw[16:24])
    need((width,height)==(1280,800),'actual disposable GUI geometry differs')
    return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'width':width,'height':height}

def observer_line(s,cap=65536):
    b=bytearray()
    while not b.endswith(b'\n'):
        part=s.recv(1);need(part,'observer channel EOF before native result')
        b.extend(part);need(len(b)<=cap,'observer line cap exceeded')
    return json.loads(b)

def next_native_event(s,nonce,receipt):
    row=observer_line(s)
    if row.get('kind')=='BOOTSTRAP_REFUSED':
        need(row.get('nonce')==nonce and
             row.get('phase') in ('verified_package','native_app_and_observer') and
             type(row.get('numeric')) is int and row['numeric']>0,
             'malformed or foreign typed guest bootstrap refusal')
        receipt['typed_guest_bootstrap_refusal']=row
        raise RuntimeError('exact guest bootstrap refused at '+row['phase']+
                           ' numeric='+str(row['numeric']))
    return row

def pointer(q,x,y,w,h,records=None,end=None):
    records=[] if records is None else records
    def send(args):
        if end is not None:
            remaining=end-time.monotonic();need(remaining>0,'original pointer deadline before QMP event')
            q.s.settimeout(min(10,remaining))
        event={'request':args,'response':None};records.append(event)
        event['response']=q.call('input-send-event',args)
        if end is not None:need(time.monotonic()<end,'original pointer deadline after QMP event')
    for axis,value,dimension in (('x',x,w),('y',y,h)):
        args={'events':[{'type':'abs','data':{'axis':axis,'value':round(value*32767/(dimension-1))}}]}
        send(args)
    for down in (True,False):
        args={'events':[{'type':'btn','data':{'button':'left','down':down}}]}
        send(args)
    return records

def main():
    need(len(sys.argv)==2,'one exact private queue binding required')
    raw=held(sys.argv[1],1048576);b=json.loads(raw)
    need(b.get('kind')=='ROBOT_DISPOSABLE_UBUNTU_CONNECTION'and
         re.fullmatch(r'[0-9a-f]{32}',b.get('nonce',''))and
         b.get('package_sha256')=='b252781da4a8af77c1439e0197208fc5c607d29bbc7ef18595ed550029ee9580'
         and b.get('artifact_source')=='01ae39dbe07ae3e5a2f45c6e4c4b354f735156b3',
         'fixed scoped package/nonce identity differs')
    root=Path(b['run_directory']);need(root.is_absolute()and
         root.name=='robot-connection-'+b['nonce'] and
         root.parent==Path('/home/connor/.local/state/opemos-runtime') and
         root.is_dir() and root.stat().st_uid==os.getuid() and
         stat.S_IMODE(root.stat().st_mode)==0o700,'fresh private ext4 VM root required')
    process(b)
    q=QMP(connect_owned(b['qmp_socket'],b['pid']))
    obs=connect_owned(b['observer_socket'],b['pid'],200)
    first=None;receipt={'kind':'ACTUAL_SCOPED_OMEN_NATIVE_CHOOSER_CONNECTION',
                        'nonce':b['nonce'],'artifact_source':b['artifact_source'],
                        'package_sha256':b['package_sha256'],
                        'dispatch_origin':b['dispatch_origin'],'full20Acceptance':False,
                        'imageUSBOrGPUAcceptance':False,'qemu_binding_sha256':hashlib.sha256(raw).hexdigest()}
    try:
        need(q.call('query-name')['name']==b['vm_name'] and
             q.call('query-status')['status']=='running','not actual running exact VM')
        ready=next_native_event(obs,b['nonce'],receipt)
        need(ready.get('kind')=='READY'and ready.get('nonce')==b['nonce'] and
             type(ready.get('app'))is dict and ready['app'].get('window_id') and
             ready.get('process',{}).get('pid')==ready['app'].get('pid') and
             ready['process'].get('start_ticks') and
             ready['process'].get('inherited_nonce')==b['nonce'] and
             re.fullmatch(r'[0-9a-f]{64}',ready['process'].get('exe_sha256','')),
             'real guest native app/PID/window birth missing')
        port=ready.get('port_custody',{})
        need(port.get('sysfs_name')=='opemos.robot.observer' and
             port.get('sudo_numeric') in ('0','NOT_NEEDED') and
             port.get('before','').startswith('character special file ') and
             port.get('after','').startswith('character special file 1000 ') and
             ' 600 ' in port.get('after',''),
             'guest exact native observer port custody not verified')
        app=ready['app'];rect=app.get('rect',[])
        need(len(rect)==4 and 700<=rect[2]<=900 and 400<=rect[3]<=1400,
             'reviewed current package window geometry differs')
        # Fixed same-package coordinate from retained actual PR197 GUI frame;
        # the post-click native dialog, not this label/coordinate, is the proof.
        x,y=755,455
        need(rect[0]<=x<rect[0]+rect[2]and rect[1]<=y<rect[1]+rect[3],
             'choose-input pointer point outside native app window')
        obs.sendall((json.dumps({'kind':'ARM','nonce':b['nonce'],
                                'app_window_id':app['window_id']})+'\n').encode())
        armed=next_native_event(obs,b['nonce'],receipt)
        need(armed.get('kind')=='ARMED'and armed.get('nonce')==b['nonce']and
             armed.get('app_window_id')==app['window_id'],
             'independent native observer did not arm')
        before=frame(q,root/'before-click.png')
        action=pointer(q,x,y,before['width'],before['height'])
        observed=next_native_event(obs,b['nonce'],receipt)
        need(observed.get('kind')=='CHOOSER_OBSERVED' and
             observed.get('nonce')==b['nonce'] and observed.get('observed')is True and
             observed.get('native_observer')is True and
             observed.get('process',{}).get('pid')==ready['process']['pid'] and
             observed.get('process',{}).get('start_ticks')==ready['process']['start_ticks'] and
             observed.get('chooser',{}).get('window_id') not in armed['baseline_ids'] and
             observed.get('chooser',{}).get('title') and
             (observed.get('chooser',{}).get('dialog_type')is True or
              observed.get('chooser',{}).get('transient_for')==app['window_id']),
             'new native same-app chooser result not observed')
        after=frame(q,root/'after-click.png')
        process(b)
        receipt.update(observed=True,ready=ready,armed=armed,
                       pointer={'button':'left','x':x,'y':y,'qmp_events':action},
                       chooser=observed,before_frame=before,after_frame=after,
                       actualQMPInput=True,independentNativeDialog=True)
    except BaseException as error:
        first={'type':type(error).__name__,'reason':str(error)}
        receipt.update(observed=False,first_failure=first)
        try:
            # If the port itself cannot open, no guest event is possible. The
            # exact current QMP terminal frame preserves visible diagnostic
            # text, but it is never promoted to an observed chooser result.
            receipt['failure_frame']=frame(q,root/'failure-diagnostic.png')
        except BaseException as frame_error:
            receipt['failure_frame_secondary']={'type':type(frame_error).__name__,
                                                'reason':str(frame_error)}
        raise
    finally:
        try:obs.close()
        finally:q.close()
        save(root/'connection-result.json',receipt)


class Pipeline:
    """Actual native observations and QMP input in the same owned Ubuntu VM."""
    def __init__(self,binding,config,q,observer,ready,root):
        self.binding=binding;self.cfg=config;self.q=q;self.observer=observer;self.ready=ready
        self.root=root;self.sequence=0;self.actions=[];self.observations=[]
        self.end=time.monotonic()+config['whole_seconds'];self.app=ready['app']
        need(binding['nonce']==config['nonce']==ready['nonce'] and
             binding['artifact_source']==config['source_commit'] and
             binding['package_sha256']==config['package_sha256'] and
             ready['process']['pid']==self.app['pid'] and
             ready['process']['inherited_nonce']==binding['nonce'],
             'same admitted candidate/app birth/normal operation')

    def request(self,kind,**operands):
        remaining=self.end-time.monotonic();need(remaining>0 and self.sequence<256,'original GUI operation clock/request bound')
        process(self.binding);self.sequence+=1;self.observer.settimeout(remaining)
        request={'nonce':self.binding['nonce'],'sequence':self.sequence,'kind':kind,**operands}
        self.observer.sendall((json.dumps(request,separators=(',',':'))+'\n').encode())
        response=observer_line(self.observer,1048576)
        need(time.monotonic()<self.end and response.get('kind')=='NATIVE_OBSERVATION' and
             response.get('nonce')==request['nonce'] and response.get('sequence')==self.sequence and
             response.get('request_kind')==kind and response.get('process')==self.ready['process'],
             'ordered same native app observation within original clock')
        self.observations.append(response);return response

    def windows(self):return self.request('WINDOWS')['value']['windows']

    def target(self,label,roles,window=None):
        window=self.app if window is None else window
        while True:
            response=self.request('CONTROL',window_id=window['window_id'],label=label,roles=roles,probe=True)
            if response['value'].get('available')is not False:return response
            remaining=self.end-time.monotonic();need(remaining>0,'native control did not become available')
            time.sleep(min(2,remaining))

    def click(self,name,label,roles=('push button',),window=None):
        target=self.target(label,list(roles),window);control=target['value'];point=control['point']
        native=self.app if window is None else window
        need(control['pid']==native['pid']and control['window_id']==native['window_id']and
             control['enabled']is True and control['visible']is True and control['readOnlyObservation']is True,
             'current genuine native control process/window/state')
        before=frame(self.q,self.root/(str(len(self.actions)).zfill(3)+'-'+name+'-before.png'))
        process(self.binding);need(time.monotonic()<self.end,'original deadline before actual pointer')
        rect=control['rect'];need(rect[0]<=point['x']<rect[0]+rect[2]<=before['width']and
            rect[1]<=point['y']<rect[1]+rect[3]<=before['height'],'actual native target and observed display point')
        record={'action':name,'nativeControl':target,'beforeFrame':before,'actualQMPInput':[],
                'point':point,'sameGuestPID':self.ready['process']}
        self.actions.append(record)
        pointer(self.q,point['x'],point['y'],before['width'],before['height'],record['actualQMPInput'],self.end)
        return record

    def key(self,qcode,modifiers=()):
        need(qcode in ('a','l','ret','tab')or re.fullmatch('[a-z0-9]|spc|dot|minus|slash|underscore',qcode),
             'bounded QMP text key')
        process(self.binding);need(time.monotonic()<self.end,'original clock before keyboard input')
        for code in modifiers:self.q.call('input-send-event',{'events':[{'type':'key','data':{'down':True,'key':{'type':'qcode','data':code}}}]})
        for down in (True,False):self.q.call('input-send-event',{'events':[{'type':'key','data':{'down':down,'key':{'type':'qcode','data':qcode}}}]})
        for code in reversed(modifiers):self.q.call('input-send-event',{'events':[{'type':'key','data':{'down':False,'key':{'type':'qcode','data':code}}}]})

    def text(self,value):
        need(type(value)is str and 0<len(value)<=512 and re.fullmatch('[A-Za-z0-9 /_.-]+',value),
             'declared ASCII image/folder/confirmation only')
        self.key('a',('ctrl',))
        for character in value:
            code={' ':'spc','.':'dot','-':'minus','/':'slash','_':'minus'}.get(character,character.lower())
            self.key(code,('shift',)if character.isupper()or character=='_'else())

    def choose(self,action,button,path,confirm):
        self.click(action,button)
        while True:
            dialogs=[w for w in self.windows()if w['window_id']!=self.app['window_id']and
                (w['transient_for']==self.app['window_id']or w['pid']==self.app['pid'])and w['dialog_type']]
            if dialogs:break
            remaining=self.end-time.monotonic();need(remaining>0,'native chooser absent');time.sleep(min(.5,remaining))
        need(len(dialogs)==1,'one actual same-app native chooser')
        self.key('l',('ctrl',));self.text(path)
        self.click(action+'-confirm',confirm,window=dialogs[0])

    def names(self):return self.request('NAMES',window_id=self.app['window_id'])['value']['names']

    def wait_text(self,text):
        while True:
            names=self.names()
            if text in names:return names
            errors=[name for name in names if name.startswith(('Build failed','USB write failed','Error:'))]
            need(not errors,'actual application failure: '+repr(errors))
            remaining=self.end-time.monotonic();need(remaining>0,'actual application completion absent');time.sleep(min(30,remaining))

    def build_write(self):
        labels=self.cfg['labels']
        self.choose('chooser-open',labels['choose_input'],self.cfg['input_path'],labels['open'])
        self.choose('choose-output-directory',labels['choose_output'],self.cfg['output_directory'],labels['select_folder'])
        input_image=self.request('FILE',role='input_path')
        need(input_image['value']['sha256']==self.cfg['input_sha256'],'actual selected original image hash')
        self.click('Build',labels['build'])
        self.wait_text(labels['build_success'])
        output=self.request('FILE',role='output_path')
        usb=self.request('USB')['value']
        need(usb['serial']=='opemos-'+self.binding['nonce']and usb['bytes']==self.cfg['usb_bytes'],
             'actual same-guest emulated USB identity')
        self.click('virtualUSB-select',labels['usb_target'],('combo box','list item'))
        choices=[name for name in self.names()if ' · '+usb['path']+' · 'in name]
        need(len(choices)==1,'one native device option for the actually observed emulated USB')
        self.click('virtualUSB-device',choices[0],('list item','menu item','text'))
        self.click('virtualUSB-select-and-review',labels['review'])
        self.click('virtualUSB-confirmation-entry',labels['confirmation'],('entry',))
        self.text('ERASE')
        self.click('virtualUSB-Write-confirmation',labels['write'])
        self.wait_text(labels['write_success'])
        repeated=self.request('FILE',role='output_path')
        need(repeated['value']==output['value'],'actual built image unchanged through GUI write/readback')
        after=frame(self.q,self.root/'gui-write-complete.png')
        self.request('CLOSE')
        return {'kind':'ACTUAL_UBUNTU_GUI_BUILD_WRITE_OBSERVATIONS','nonce':self.binding['nonce'],
            'source_commit':self.cfg['source_commit'],'package_sha256':self.cfg['package_sha256'],
            'input':input_image,'output':output,'usb':usb,'actions':self.actions,
            'nativeObservations':self.observations,'afterFrame':after,
            'hostReadbackOrSteamOSAcceptance':False}


def pipeline_main(binding_path):
    b=json.loads(held(binding_path,1048576));process(b)
    ref=b['pipelineConfigPin'];raw=held(ref['path'],65536)
    need(hashlib.sha256(raw).hexdigest()==ref['sha256'],'same normal planner pipeline config')
    cfg=json.loads(raw);need(cfg['kind']=='ROOT_ADMITTED_UBUNTU_GUI_BUILD_WRITE_V1' and
        type(cfg['whole_seconds'])is int and 0<cfg['whole_seconds']<=7200 and
        cfg['display']==[1280,800] and re.fullmatch('[0-9a-f]{40}',cfg['source_commit']),
        'finite source-bound normal GUI pipeline')
    root=Path(b['run_directory']);need(root.is_absolute()and root.resolve()==root and
        root.stat().st_uid==os.getuid()and stat.S_IMODE(root.stat().st_mode)==0o700,
        'same owned normal VM directory')
    q=QMP(connect_owned(b['qmp_socket'],b['pid']));obs=connect_owned(b['observer_socket'],b['pid'],200)
    result={'kind':'ACTUAL_UBUNTU_GUI_BUILD_WRITE_OBSERVATIONS','first':None,'accepted':False}
    try:
        need(q.call('query-name')['name']==b['vm_name']and q.call('query-status')['status']=='running','same actual live VM')
        ready=next_native_event(obs,b['nonce'],result)
        need(ready['kind']=='READY'and ready['port_custody']['held_node_stable']is True,'actual native observer READY/custody')
        operation=Pipeline(b,cfg,q,obs,ready,root)
        result=operation.build_write()
    except BaseException as error:
        result['first']={'type':type(error).__name__,'reason':str(error)}
        if 'operation'in locals():result.update(actions=operation.actions,nativeObservations=operation.observations)
        try:result['failureFrame']=frame(q,root/'pipeline-first-failure.png')
        except BaseException as secondary:result['frameFailure']=str(secondary)
        raise
    finally:
        try:obs.close()
        finally:q.close()
        save(root/'gui-build-write-result.json',result)


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--pipeline':pipeline_main(sys.argv[2])
    else:main()

