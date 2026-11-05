#!/usr/bin/env python3
"""Read-only X11 native chooser observer for one disposable Ubuntu VM.

Run in the real logged-in graphical guest. It never sends input. The host's
QMP sender is a separate process and cannot write this observer's result.
"""
import ctypes as C
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

PORT = '/dev/virtio-ports/opemos.robot.observer'
CAP = 200_000_000

def require(value, reason):
    if not value:
        raise RuntimeError(reason)

def proc_identity(pid):
    proc = Path('/proc') / str(pid)
    raw = (proc/'stat').read_text()
    start = raw[raw.rfind(')')+2:].split()[19]
    exe = (proc/'exe').resolve(strict=True)
    fd = os.open(proc/'exe', os.O_RDONLY|os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= CAP,
                'app executable outside bounded native proof')
        digest = hashlib.sha256()
        while block := os.read(fd, 1048576):
            digest.update(block)
        after_raw=(proc/'stat').read_text()
        require(os.fstat(fd).st_size == before.st_size and
                after_raw[after_raw.rfind(')')+2:].split()[19] == start,
                'app process changed while hashing')
    finally:
        os.close(fd)
    cmdline = (proc/'cmdline').read_bytes().replace(b'\0', b' ').decode('utf-8','replace')[:4096]
    env=(proc/'environ').read_bytes().split(b'\0')
    inherited_nonce=next((part.partition(b'=')[2].decode()for part in env
                          if part.startswith(b'OPROBOT_NONCE=')),None)
    return {'pid':pid,'start_ticks':start,'exe':str(exe),
            'exe_sha256':digest.hexdigest(),'cmdline':cmdline,
            'inherited_nonce':inherited_nonce}

class X11:
    class Attributes(C.Structure):
        _fields_=[('x',C.c_int),('y',C.c_int),('width',C.c_int),
                  ('height',C.c_int),('border_width',C.c_int),('depth',C.c_int),
                  ('visual',C.c_void_p),('root',C.c_ulong),('class_',C.c_int),
                  ('bit_gravity',C.c_int),('win_gravity',C.c_int),
                  ('backing_store',C.c_int),('backing_planes',C.c_ulong),
                  ('backing_pixel',C.c_ulong),('save_under',C.c_int),
                  ('colormap',C.c_ulong),('map_installed',C.c_int),
                  ('map_state',C.c_int),('all_event_masks',C.c_long),
                  ('your_event_mask',C.c_long),('do_not_propagate_mask',C.c_long),
                  ('override_redirect',C.c_int),('screen',C.c_void_p)]

    def __init__(self):
        name=ctypes.util.find_library('X11')
        require(name is not None, 'libX11 absent in actual guest')
        self.x=C.CDLL(name)
        self.x.XOpenDisplay.argtypes=[C.c_char_p];self.x.XOpenDisplay.restype=C.c_void_p
        self.d=self.x.XOpenDisplay(None)
        require(self.d, 'actual guest X11 display unavailable')
        self.x.XDefaultRootWindow.argtypes=[C.c_void_p];self.x.XDefaultRootWindow.restype=C.c_ulong
        self.x.XQueryTree.argtypes=[C.c_void_p,C.c_ulong,C.POINTER(C.c_ulong),C.POINTER(C.c_ulong),C.POINTER(C.POINTER(C.c_ulong)),C.POINTER(C.c_uint)]
        self.x.XQueryTree.restype=C.c_int
        self.x.XGetWindowAttributes.argtypes=[C.c_void_p,C.c_ulong,C.POINTER(self.Attributes)]
        self.x.XGetWindowAttributes.restype=C.c_int
        self.x.XTranslateCoordinates.argtypes=[C.c_void_p,C.c_ulong,C.c_ulong,C.c_int,C.c_int,C.POINTER(C.c_int),C.POINTER(C.c_int),C.POINTER(C.c_ulong)]
        self.x.XTranslateCoordinates.restype=C.c_int
        self.x.XFetchName.argtypes=[C.c_void_p,C.c_ulong,C.POINTER(C.c_void_p)]
        self.x.XFetchName.restype=C.c_int
        self.x.XInternAtom.argtypes=[C.c_void_p,C.c_char_p,C.c_int];self.x.XInternAtom.restype=C.c_ulong
        self.x.XGetWindowProperty.argtypes=[C.c_void_p,C.c_ulong,C.c_ulong,C.c_long,C.c_long,C.c_int,C.c_ulong,C.POINTER(C.c_ulong),C.POINTER(C.c_int),C.POINTER(C.c_ulong),C.POINTER(C.c_ulong),C.POINTER(C.c_void_p)]
        self.x.XGetWindowProperty.restype=C.c_int
        self.x.XGetTransientForHint.argtypes=[C.c_void_p,C.c_ulong,C.POINTER(C.c_ulong)]
        self.x.XGetTransientForHint.restype=C.c_int
        self.x.XFree.argtypes=[C.c_void_p];self.x.XCloseDisplay.argtypes=[C.c_void_p]
        self.root=self.x.XDefaultRootWindow(self.d)
        self.pid_atom=self.atom('_NET_WM_PID')
        self.type_atom=self.atom('_NET_WM_WINDOW_TYPE')
        self.dialog_atom=self.atom('_NET_WM_WINDOW_TYPE_DIALOG')
        self.name_atom=self.atom('_NET_WM_NAME')

    def atom(self,name):
        return self.x.XInternAtom(self.d,name.encode(),False)

    def property(self,window,atom):
        actual=C.c_ulong();fmt=C.c_int();count=C.c_ulong();remain=C.c_ulong();data=C.c_void_p()
        code=self.x.XGetWindowProperty(self.d,window,atom,0,32,False,0,
              C.byref(actual),C.byref(fmt),C.byref(count),C.byref(remain),C.byref(data))
        if code or not data.value:return []
        try:
            if fmt.value==32:return list(C.cast(data,C.POINTER(C.c_ulong))[:count.value])
            return []
        finally:self.x.XFree(data)

    def title(self,window):
        actual=C.c_ulong();fmt=C.c_int();count=C.c_ulong();remain=C.c_ulong();data=C.c_void_p()
        code=self.x.XGetWindowProperty(self.d,window,self.name_atom,0,256,False,0,
              C.byref(actual),C.byref(fmt),C.byref(count),C.byref(remain),C.byref(data))
        if code==0 and data.value:
            try:
                if fmt.value==8 and count.value:
                    return C.string_at(data,count.value).decode('utf-8','replace')[:256]
            finally:self.x.XFree(data)
        titlep=C.c_void_p()
        if self.x.XFetchName(self.d,window,C.byref(titlep)) and titlep.value:
            try:return C.string_at(titlep).decode('utf-8','replace')[:256]
            finally:self.x.XFree(titlep)
        return ''

    def windows(self):
        seen=set();todo=[self.root];rows=[]
        while todo and len(seen)<4096:
            window=todo.pop()
            if window in seen:continue
            seen.add(window)
            root=C.c_ulong();parent=C.c_ulong();children=C.POINTER(C.c_ulong)();n=C.c_uint()
            if self.x.XQueryTree(self.d,window,C.byref(root),C.byref(parent),C.byref(children),C.byref(n)):
                try:todo.extend(children[i] for i in range(min(n.value,4096-len(seen))))
                finally:
                    if children:self.x.XFree(children)
            attr=self.Attributes()
            if not self.x.XGetWindowAttributes(self.d,window,C.byref(attr)) or attr.map_state!=2:
                continue
            pids=self.property(window,self.pid_atom)
            if not pids:continue
            title=self.title(window)
            rootx=C.c_int();rooty=C.c_int();child=C.c_ulong()
            translated=self.x.XTranslateCoordinates(self.d,window,self.root,0,0,
                         C.byref(rootx),C.byref(rooty),C.byref(child))
            if not translated:continue
            transient=C.c_ulong()
            own=self.x.XGetTransientForHint(self.d,window,C.byref(transient))
            rows.append({'window_id':int(window),'pid':int(pids[0]),'title':title,
                         'rect':[rootx.value,rooty.value,attr.width,attr.height],
                         'dialog_type':self.dialog_atom in self.property(window,self.type_atom),
                         'transient_for':int(transient.value) if own else None})
        return rows

def accessible_descendants(root):
    """Existing native accessibility observation, bounded; never invoke actions."""
    pending=[(root,0)];seen=0
    while pending:
        node,depth=pending.pop();seen+=1
        require(seen<=4096 and depth<=32,'native accessibility tree bound')
        yield node
        children=node.get_child_count()
        require(type(children)is int and 0<=children<=4096,'native child count')
        for index in range(children-1,-1,-1):
            child=node.get_child_at_index(index)
            if child is not None:pending.append((child,depth+1))


def observed_control(desktop,window,label,roles,states,screen):
    """Fresh PID/window-owned native target geometry, without AX/DOM activation."""
    require(type(label)is str and 0<len(label)<=512 and roles
            and set(roles)<={'push button','entry','text','check box','list item','menu item','combo box'},
            'finite declared native label/roles')
    require(type(window.get('pid'))is int and window['pid']>1
            and type(window.get('window_id'))is int and window['window_id']>0,
            'actual mapped native window/PID')
    matches=[];count=desktop.get_child_count()
    require(type(count)is int and 0<=count<=4096,'native desktop application bound')
    for index in range(count):
        app=desktop.get_child_at_index(index)
        if app is None or app.get_process_id()!=window['pid']:continue
        for node in accessible_descendants(app):
            if node.get_name()!=label or node.get_role_name()not in roles:continue
            state=node.get_state_set()
            if not all(state.contains(states[k])for k in('enabled','sensitive','visible','showing')):
                continue
            if state.contains(states['defunct']):continue
            require(node.get_process_id()==window['pid'],'native target actual process owner')
            component=node.get_component_iface();require(component is not None,'native component geometry')
            box=component.get_extents(states['screen'])
            rect=[box.x,box.y,box.width,box.height];wx,wy,ww,wh=window['rect'];sw,sh=screen
            require(all(type(v)is int for v in rect+window['rect']+list(screen))and
                    0<box.width and 0<box.height and 0<=wx<=box.x and 0<=wy<=box.y
                    and box.x+box.width<=wx+ww<=sw and box.y+box.height<=wy+wh<=sh,
                    'native control inside actual mapped window and display')
            matches.append({'label':label,'role':node.get_role_name(),'rect':rect,
                'pid':window['pid'],'window_id':window['window_id'],
                'point':{'x':box.x+box.width//2,'y':box.y+box.height//2},
                'enabled':True,'visible':True,'readOnlyObservation':True})
    require(len(matches)==1,'one genuine enabled PID/window-owned native control')
    return matches[0]


def pipeline_requests(port,x,app,birth,nonce,config_path,config_sha):
    """Observe the same admitted GUI operation over its existing virtio channel.

    Requests return native facts only. All pointer input stays in the separate
    host QMP sender, and no request can fabricate a stage or activate a control.
    """
    import select
    import gi
    gi.require_version('Atspi','2.0')
    from gi.repository import Atspi
    config_file=Path(config_path)
    require(config_file==Path('/media/opemosgui/OPROBOT/operation.json')
            and re.fullmatch('[0-9a-f]{64}',config_sha),'same readonly observer medium config')
    fd=os.open(config_file,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd);raw=os.read(fd,65537)
        require(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_size==len(raw)<=65536
                and not st.st_mode&0o222 and not os.read(fd,1)
                and hashlib.sha256(raw).hexdigest()==config_sha
                and all(getattr(os.fstat(fd),k)==getattr(st,k)==getattr(config_file.lstat(),k)for k in
                    ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')),'whole readonly guest operation data')
    finally:os.close(fd)
    cfg=json.loads(raw)
    require(cfg['nonce']==nonce and re.fullmatch('[0-9a-f]{40}',cfg['source_commit'])
            and type(cfg['whole_seconds'])is int and 1<=cfg['whole_seconds']<=7200
            and cfg['usb_serial']=='opemos-'+nonce and type(cfg['usb_bytes'])is int
            and 0<cfg['usb_bytes']<=60_000_000_000,'same admitted source/operation/virtual USB')
    desktop=Atspi.get_desktop(0);deadline=time.monotonic()+cfg['whole_seconds'];sequence=0
    states={key:getattr(Atspi.StateType,name)for key,name in
            [('enabled','ENABLED'),('sensitive','SENSITIVE'),('visible','VISIBLE'),('showing','SHOWING'),('defunct','DEFUNCT')]}
    states['screen']=Atspi.CoordType.SCREEN
    def emit(value):
        wire=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
        require(len(wire)<=1048576 and os.write(port,wire)==len(wire),'bounded native observation channel')
    def file_observation(key):
        require(key in('input_path','output_path'),'declared guest image role only')
        path=Path(cfg[key]);require(path.is_absolute()and path.resolve()==path,'canonical declared image path')
        if key=='output_path':
            owned=Path.home()/('opemos-robot-'+nonce)
            require(path.is_relative_to(owned)and owned.stat().st_uid==os.getuid()
                    and stat.S_IMODE(owned.stat().st_mode)==0o700,'owned operation output only')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd);identity=lambda v:{k:getattr(v,k)for k in
                ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
            require(stat.S_ISREG(before.st_mode)and before.st_nlink==1
                    and 0<before.st_size<=60_000_000_000
                    and (before.st_uid==os.getuid()if key=='output_path'else not before.st_mode&0o222),
                    'actual finite declared image custody')
            digest=hashlib.sha256();size=0
            while block:=os.read(fd,1048576):
                require(time.monotonic()<deadline,'original observer whole clock')
                digest.update(block);size+=len(block);require(size<=before.st_size,'image grew')
            require(size==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),
                    'whole guest image identity/hash epoch')
            return {'path':str(path),'bytes':size,'sha256':digest.hexdigest(),'identity':identity(before)}
        finally:os.close(fd)
    while time.monotonic()<deadline and sequence<256:
        line=bytearray()
        while not line.endswith(b'\n'):
            remaining=deadline-time.monotonic();require(remaining>0,'original observer deadline')
            require(select.select([port],[],[],remaining)[0],'native request deadline')
            part=os.read(port,1);require(part,'native request EOF');line.extend(part)
            require(len(line)<=4096,'native request cap')
        request=json.loads(line);sequence+=1
        require(request['nonce']==nonce and request['sequence']==sequence,'exact ordered native operation request')
        require(proc_identity(app['pid'])==birth,'original app PID/start/executable/nonce unchanged')
        current=x.windows();owned=[w for w in current if w['pid']==app['pid']or w['transient_for']==app['window_id']]
        kind=request['kind'];value={}
        if kind=='CONTROL':
            window=next((w for w in owned if w['window_id']==request['window_id']),None)
            require(window is not None,'mapped original app or native transient window')
            value=observed_control(desktop,window,request['label'],request['roles'],states,cfg['display'])
        elif kind=='WINDOWS':value={'windows':owned}
        elif kind=='FILE':value=file_observation(request['role'])
        elif kind=='USB':
            matches=[]
            for device in Path('/sys/class/block').iterdir():
                if (device/'partition').exists():continue
                serial=[]
                for parent in (device.resolve(),*device.resolve().parents):
                    leaf=parent/'serial'
                    if leaf.is_file():serial.append(leaf.read_text().strip())
                if cfg['usb_serial']not in serial:continue
                require((device/'removable').read_text().strip()=='1'
                        and int((device/'size').read_text())*512==cfg['usb_bytes'],'actual guest removable USB capacity')
                node=Path('/dev')/device.name;st=node.stat();require(stat.S_ISBLK(st.st_mode),'guest USB block device')
                matches.append({'path':str(node),'serial':cfg['usb_serial'],'bytes':cfg['usb_bytes'],
                    'major':os.major(st.st_rdev),'minor':os.minor(st.st_rdev),'sysfs':str(device.resolve())})
            require(len(matches)==1,'one actual emulated USB with exact operation serial');value=matches[0]
        elif kind=='CLOSE':
            emit({'kind':'NATIVE_OBSERVATION','nonce':nonce,'sequence':sequence,'request_kind':kind,
                'value':{'observationsComplete':True,'GUIOrWriteAcceptance':False},'process':birth,'clock_ns':time.monotonic_ns()});return
        else:require(False,'unknown native observation request')
        emit({'kind':'NATIVE_OBSERVATION','nonce':nonce,'sequence':sequence,'request_kind':kind,
            'value':value,'process':birth,'clock_ns':time.monotonic_ns()})
    require(False,'finite native observation request/whole budget exhausted')


def main():
    pipeline=len(sys.argv)==6 and sys.argv[3]=='--pipeline'
    require((len(sys.argv)==3 or pipeline) and len(sys.argv[1])==32 and
            all(c in '0123456789abcdef' for c in sys.argv[1]),
            'exact fresh observer nonce required')
    expected_title=sys.argv[2]
    require(3<=len(expected_title)<=80, 'exact app title fragment required')
    x=X11();before=[];app=None;deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        before=x.windows()
        matches=[w for w in before if expected_title.lower() in w['title'].lower()]
        if len(matches)==1:
            app=matches[0];break
        time.sleep(.2)
    require(app is not None, 'unique actual app native X11 window absent')
    birth=proc_identity(app['pid'])
    require(birth['inherited_nonce']==sys.argv[1],
            'native window process did not inherit exact verified-package launch nonce')
    port_custody={'before':os.environ.get('OPROBOT_PORT_BEFORE'),
                  'after':os.environ.get('OPROBOT_PORT_AFTER'),
                  'sudo_numeric':os.environ.get('OPROBOT_PORT_SUDO'),
                  'sysfs_name':'opemos.robot.observer'}
    require(all(port_custody.values()) and port_custody['sudo_numeric'] in ('0','NOT_NEEDED'),
            'exact disposable virtio observer port custody missing')
    # udev exposes the named virtio port as a symlink. Resolve that one name,
    # then hold the actual character device without following another link.
    link_before=os.lstat(PORT)
    require(stat.S_ISLNK(link_before.st_mode),'named virtio port link absent')
    node=Path(os.path.realpath(PORT))
    require(node.parent==Path('/dev') and
            re.fullmatch(r'vport[0-9]+p[0-9]+',node.name),
            'named virtio port did not resolve to an exact vport node')
    require((Path('/sys/class/virtio-ports')/node.name/'name').read_text().strip()
            =='opemos.robot.observer','resolved virtio port sysfs name differs')
    node_before=os.lstat(node)
    require(stat.S_ISCHR(node_before.st_mode) and
            node_before.st_uid==os.getuid() and
            stat.S_IMODE(node_before.st_mode)==0o600,
            'resolved disposable virtio character-device custody differs')
    port=os.open(node,os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW)
    held=os.fstat(port)
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_rdev)
    require(identity(held)==identity(node_before)==identity(os.lstat(node)) and
            identity(os.lstat(PORT))==identity(link_before) and
            Path(os.path.realpath(PORT))==node,
            'resolved named virtio port changed across held open')
    port_custody.update({'resolved_node':str(node),'char_rdev':held.st_rdev,
                         'named_symlink_stable':True,'held_node_stable':True})
    def emit(event):
        wire=(json.dumps(event,sort_keys=True,separators=(',',':'))+'\n').encode()
        require(len(wire)<65536 and os.write(port,wire)==len(wire),
                'bounded private observer channel write failed')
    emit({'kind':'READY','nonce':sys.argv[1],'app':app,'process':birth,
          'baseline_windows':before,'port_custody':port_custody,
          'clock_ns':time.monotonic_ns()})
    if pipeline:
        try:pipeline_requests(port,x,app,birth,sys.argv[1],sys.argv[4],sys.argv[5])
        finally:os.close(port);x.x.XCloseDisplay(x.d)
        return
    # Host sends one narrow line after it has pinned a genuine visible chooser
    # control. That line authorizes observation, never supplies the result.
    line=bytearray();deadline=time.monotonic()+60
    while time.monotonic()<deadline and not line.endswith(b'\n'):
        ch=os.read(port,1)
        require(ch,'private observer channel closed before arm')
        line.extend(ch);require(len(line)<4096,'arm message cap exceeded')
    arm=json.loads(line)
    require(arm=={'kind':'ARM','nonce':sys.argv[1],'app_window_id':app['window_id']},
            'wrong app/nonce arm message')
    baseline={w['window_id'] for w in x.windows()}
    emit({'kind':'ARMED','nonce':sys.argv[1],'app_window_id':app['window_id'],
          'baseline_ids':sorted(baseline),'clock_ns':time.monotonic_ns()})
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        current=x.windows()
        # A real newly mapped native dialog, transient for the admitted app
        # or with that same PID, proves a chooser appeared after pointer input.
        dialogs=[w for w in current if w['window_id'] not in baseline and
                 w['title'] and (w['dialog_type'] or w['transient_for']==app['window_id']) and
                 (w['pid']==app['pid'] or w['transient_for']==app['window_id'])]
        if len(dialogs)==1:
            require(proc_identity(app['pid'])['start_ticks']==birth['start_ticks'],
                    'app PID reused during observer')
            emit({'kind':'CHOOSER_OBSERVED','nonce':sys.argv[1],
                  'observed':True,'native_observer':True,
                  'app':app,'process':birth,'chooser':dialogs[0],
                  'baseline_ids':sorted(baseline),'clock_ns':time.monotonic_ns()})
            os.close(port);x.x.XCloseDisplay(x.d);return
        time.sleep(.1)
    raise RuntimeError('no independently observed new native chooser dialog')

if __name__=='__main__':
    try:main()
    except Exception as error:
        print('native chooser observer refused: '+str(error),file=sys.stderr)
        sys.exit(1)
