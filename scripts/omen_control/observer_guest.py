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

def proc_identity(pid, expected=None):
    proc = Path('/proc') / str(pid)
    raw = (proc/'stat').read_text()
    start = raw[raw.rfind(')')+2:].split()[19]
    exe = (proc/'exe').resolve(strict=True)
    fd = os.open(proc/'exe', os.O_RDONLY|os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= CAP if expected is None else
                stat.S_ISREG(before.st_mode) and type(expected['bytes'])is int and
                0<before.st_size==expected['bytes']<=1073741824,
                'actual descriptor-bound native executable size')
        digest = hashlib.sha256()
        while block := os.read(fd, 1048576):
            digest.update(block)
        after_raw=(proc/'stat').read_text()
        require(os.fstat(fd).st_size == before.st_size and
                after_raw[after_raw.rfind(')')+2:].split()[19] == start,
                'app process changed while hashing')
    finally:
        os.close(fd)
    if expected is not None:require(digest.hexdigest()==expected['sha256'],'actual descriptor-bound native executable hash')
    cmdline = (proc/'cmdline').read_bytes().replace(b'\0', b' ').decode('utf-8','replace')[:4096]
    env=(proc/'environ').read_bytes().split(b'\0')
    inherited_nonce=next((part.partition(b'=')[2].decode()for part in env
                          if part.startswith(b'OPROBOT_NONCE=')),None)
    return {'pid':pid,'start_ticks':start,'exe':str(exe),
            'exe_sha256':digest.hexdigest(),'cmdline':cmdline,
            'inherited_nonce':inherited_nonce}


def native_process_owner(pid,birth):
    """Bind a native accessibility provider to this actual app process tree.

    A web control can be exported by the app's child rather than its X11 PID.
    Its ancestry, UID and inherited launch nonce are kernel observations, not
    permission inferred from the control's label or rectangle.
    """
    require(type(pid)is int and pid>1,'native provider PID')
    nonce=birth['inherited_nonce']
    require(type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce),'native provider launch nonce')
    def cut(current):
        proc=Path('/proc')/str(current)
        raw=(proc/'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
        uid=next(line.split()[1:]for line in(proc/'status').read_text().splitlines()
                 if line.startswith('Uid:'))
        require(len(uid)==4 and all(int(value)==os.getuid()for value in uid),
                'native provider same real/effective/saved/filesystem UID')
        require(b'OPROBOT_NONCE='+nonce.encode()in(proc/'environ').read_bytes().split(b'\0'),
                'native provider inherited original launch nonce')
        return {'pid':current,'ppid':int(fields[1]),'start_ticks':fields[19],
                'uids':[int(value)for value in uid]}
    chain=[];current=pid
    for _ in range(32):
        require(current>1 and current not in [row['pid']for row in chain],
                'native provider actual app ancestry')
        row=cut(current);chain.append(row)
        if current==birth['pid']:
            require(row['start_ticks']==birth['start_ticks'],'original app PID/start unchanged')
            break
        current=row['ppid']
    else:require(False,'finite native provider ancestry')
    require(all(cut(row['pid'])==row for row in chain),'native provider ancestry unchanged')
    return {'kind':'ACTUAL_NATIVE_PROVIDER_APP_ANCESTRY','pid':pid,
            'app_pid':birth['pid'],'app_start_ticks':birth['start_ticks'],
            'inherited_nonce':nonce,'uid':os.getuid(),'chain':chain}


def launched_window_matches(windows, expected_title, nonce, expected):
    """Select this launch before requiring a unique native window.

    Another app in the retained desktop can have the same title. Its window
    cannot become this operation's target. The selected process still passes
    the full executable/PID/start/nonce check before READY or pointer input.
    """
    matches=[];refused=[]
    for window in windows:
        if expected_title.lower() not in window['title'].lower():continue
        try:
            env=(Path('/proc')/str(window['pid'])/'environ').read_bytes().split(b'\0')
            if b'OPROBOT_NONCE='+nonce.encode() not in env:continue
            birth=proc_identity(window['pid'],expected)
            require(birth['inherited_nonce']==nonce,'current launch nonce changed during authentication')
            matches.append((window,birth))
        except (FileNotFoundError,ProcessLookupError,RuntimeError) as error:
            refused.append({'window_id':window['window_id'],'pid':window['pid'],
                            'reason':str(error)[:256]})
    return matches,refused

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

    def hit_window_chain(self,x,y):
        require(type(x)is int and type(y)is int,'native screen point')
        window=self.root;seen=[]
        for _ in range(32):
            rx=C.c_int();ry=C.c_int();child=C.c_ulong()
            require(self.x.XTranslateCoordinates(self.d,self.root,window,x,y,
                    C.byref(rx),C.byref(ry),C.byref(child)),'native topmost window translation')
            if not child.value:return seen
            require(child.value not in seen,'native child window cycle')
            seen.append(int(child.value));window=child.value
        require(False,'native window hit depth bound')


def accessible_descendants(root,defunct_state):
    """Existing native accessibility observation, bounded; never invoke actions."""
    pending=[(root,0)];seen=0
    while pending:
        node,depth=pending.pop();seen+=1
        require(seen<=4096 and depth<=32,'native accessibility tree bound')
        # Closed GTK/WebKit objects can remain in the native cache. Never
        # expand or return an object the provider explicitly marks defunct.
        if node.get_state_set().contains(defunct_state):continue
        children=node.get_child_count()
        if type(children)is not int or not 0<=children<=4096:
            # The object may have been disposed during the read. A live or
            # unclassified invalid count still refuses; retain its actual value.
            if node.get_state_set().contains(defunct_state):continue
            require(False,'native child count: '+repr(children)[:80]+
                    '; depth='+str(depth)+'; visited='+str(seen))
        if node.get_state_set().contains(defunct_state):continue
        yield node
        if node.get_state_set().contains(defunct_state):continue
        for index in range(children-1,-1,-1):
            child=node.get_child_at_index(index)
            if child is not None:pending.append((child,depth+1))


def observed_control(desktop,window,label,roles,states,screen,probe=False,hit_test=None,owner_check=None):
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
        for node in accessible_descendants(app,states['defunct']):
            if node.get_name()!=label or node.get_role_name()not in roles:continue
            state=node.get_state_set()
            if not all(state.contains(states[k])for k in('enabled','sensitive','visible','showing')):
                continue
            if state.contains(states['defunct']):continue
            provider=node.get_process_id()
            ownership={'kind':'SAME_NATIVE_WINDOW_PROCESS','pid':provider}
            if provider!=window['pid']:
                require(owner_check is not None,'native target actual process owner')
                ownership=owner_check(provider,window['pid'])
            component=node.get_component_iface();require(component is not None,'native component geometry')
            box=component.get_extents(states['screen'])
            rect=[box.x,box.y,box.width,box.height];wx,wy,ww,wh=window['rect'];sw,sh=screen
            require(all(type(v)is int for v in rect+window['rect']+list(screen))and
                    0<box.width and 0<box.height and 0<=wx<=box.x and 0<=wy<=box.y
                    and box.x+box.width<=wx+ww<=sw and box.y+box.height<=wy+wh<=sh,
                    'native control inside actual mapped window and display')
            point={'x':box.x+box.width//2,'y':box.y+box.height//2}
            hit=None if hit_test is None else hit_test(point['x'],point['y'])
            if hit is not None:require(window['window_id']in hit,'native target window occluded at actual click point')
            attributes=node.get_attributes()
            identifier=node.get_accessible_id()if hasattr(node,'get_accessible_id')else None
            matches.append({'label':node.get_name(),'role':node.get_role_name(),'rect':rect,
                'pid':provider,'window_pid':window['pid'],'window_id':window['window_id'],'point':point,
                'nativeAccessibleId':identifier,'nativeAttributes':attributes,
                'nativeProcessOwner':ownership,
                'nativeWindowHitChain':hit,'hitObservation':None if hit is None else 'native-same-control-unoccluded',
                'enabled':True,'visible':True,'readOnlyObservation':True})
    if probe and not matches:return {'available':False,'readOnlyObservation':True}
    require(len(matches)==1,'one genuine enabled PID/window-owned native control')
    return matches[0]


def observed_names(desktop,window,states,owner_check=None):
    """Visible native names in the original app, never editable/secret values."""
    count=desktop.get_child_count();require(type(count)is int and 0<=count<=4096,'bounded native desktop')
    names=[]
    for index in range(count):
        app=desktop.get_child_at_index(index)
        if app is None or app.get_process_id()!=window['pid']:continue
        for node in accessible_descendants(app,states['defunct']):
            if node.get_role_name()in('password text','entry'):continue
            provider=node.get_process_id()
            if provider!=window['pid']:
                if owner_check is None:continue
                owner_check(provider,window['pid'])
            state=node.get_state_set()
            if not state.contains(states['visible'])or not state.contains(states['showing'])or state.contains(states['defunct']):continue
            component=node.get_component_iface()
            if component is None:continue
            box=component.get_extents(states['screen']);wx,wy,ww,wh=window['rect']
            if not(0<box.width and 0<box.height and wx<=box.x and wy<=box.y
                    and box.x+box.width<=wx+ww and box.y+box.height<=wy+wh):continue
            name=node.get_name()
            require(type(name)is str and len(name)<=8192,'bounded native name')
            if name and name not in names:names.append(name)
            require(len(names)<=512 and sum(map(len,names))<=131072,'finite visible native names')
    return {'names':names,'pid':window['pid'],'window_id':window['window_id'],'readOnlyObservation':True}


def observed_chooser_location(desktop,window,declared,prefix_length,states,text_api,*,role='input_path'):
    """Read only the focused native chooser entry for the declared target.

    Return comparisons and offsets, never arbitrary editable/password contents.
    No accessibility mutation or activation is used.
    """
    require(window.get('dialog_type') is True and type(window.get('pid')) is int,
            'actual native chooser dialog')
    require(type(declared)is str and 0<len(declared)<=512 and
            type(prefix_length)is int and 0<prefix_length<=len(declared),
            'declared image prefix only')
    require(role in('input_path','output_directory')and
            (role!='output_directory'or not declared.endswith('/')),
            'declared file or canonical output directory role')
    count=desktop.get_child_count();require(type(count)is int and 0<=count<=4096,'bounded native desktop')
    matches=[]
    for index in range(count):
        app=desktop.get_child_at_index(index)
        if app is None or app.get_process_id()!=window['pid']:continue
        for node in accessible_descendants(app,states['defunct']):
            if node.get_process_id()!=window['pid']or node.get_role_name()not in('entry','text'):continue
            state=node.get_state_set()
            if state.contains(states['defunct'])or not all(state.contains(states[k])for k in('visible','showing','focused','editable')):continue
            component=node.get_component_iface()
            if component is None:continue
            box=component.get_extents(states['screen']);wx,wy,ww,wh=window['rect']
            if not(0<box.width and 0<box.height and wx<=box.x and wy<=box.y and
                   box.x+box.width<=wx+ww and box.y+box.height<=wy+wh):continue
            text=node.get_text_iface();require(text is not None,'native chooser text interface')
            # GI may return an Accessible implementing Text; its deprecated
            # get_text/get_selection methods shadow the interface methods.
            length=text_api.get_character_count(text);require(type(length)is int and 0<=length<=512,'bounded chooser location')
            value=text_api.get_text(text,0,length);caret=text_api.get_caret_offset(text);selections=text_api.get_n_selections(text)
            require(type(value)is str and len(value)==length and type(caret)is int and
                    0<=caret<=length and type(selections)is int and 0<=selections<=1,'native location offsets')
            committed=caret
            if selections:
                selection=text_api.get_selection(text,0);start,end=selection.start_offset,selection.end_offset
                require(type(start)is int and type(end)is int and 0<=start<=end<=length,'native location selection')
                committed=min(caret,start)
            native_committed=committed
            # GTK completes an existing folder with one terminal separator.
            # Only the separately declared output-directory role admits that
            # representation; image paths and all other suffixes stay exact.
            directory_completion=role=='output_directory'and value==declared+'/'
            if directory_completion:committed=min(committed,len(declared))
            matches.append(dict(available=True,window_id=window['window_id'],pid=window['pid'],
                requestedPrefixCharacters=prefix_length,observedCharacters=length,committedCharacters=committed,
                nativeCommittedCharacters=native_committed,directorySeparatorCompletion=directory_completion,
                declaredPrefixMatched=value.startswith(declared[:prefix_length]),
                exactDeclaredInput=value==declared or directory_completion,readOnlyObservation=True))
    require(len(matches)<=1,'one focused same-dialog native location entry')
    return matches[0]if matches else dict(available=False,readOnlyObservation=True)


def mounted_input(cfg):
    """Resolve only the QEMU-labelled readonly carrier in this admitted guest."""
    import subprocess
    nonce=cfg['nonce'];serial=cfg['input_carrier_serial']
    require(serial==nonce[:20],'same current virtual input carrier serial')
    relative=Path(cfg['input_relative_path'])
    require(not relative.is_absolute()and relative.parts and all(x not in('.','..')for x in relative.parts),
            'one declared relative original image path')
    listing=subprocess.run(['/usr/bin/lsblk','--json','--paths','--output','NAME,TYPE,RO,SERIAL,MOUNTPOINTS'],
        capture_output=True,timeout=10,check=False)
    require(listing.returncode==0 and listing.stderr==b''and len(listing.stdout)<=1048576,'actual guest readonly carrier inventory')
    rows=[];todo=json.loads(listing.stdout)['blockdevices']
    while todo:
        row=todo.pop();todo.extend(row.get('children',[]));rows.append(row)
        require(len(rows)<=4096,'finite actual guest block inventory')
    selected=[x for x in rows if x.get('serial')==serial]
    require(len(selected)==1 and selected[0]['type']=='rom'and selected[0]['ro']in(True,1),
            'one actual readonly declared QEMU optical source')
    device=Path(selected[0]['name']);st=device.stat()
    require(device.parent==Path('/dev')and stat.S_ISBLK(st.st_mode),'actual guest optical block device')
    mounted=subprocess.run(['/usr/bin/udisksctl','mount','--block-device',str(device),'--options','ro'],
        capture_output=True,timeout=20,check=False)
    # An existing desktop automount is fine. Both outcomes must converge to the
    # same actual readonly mount; no stderr text is treated as proof.
    listing=subprocess.run(['/usr/bin/findmnt','--json','--source',str(device),
        '--output','TARGET,SOURCE,FSTYPE,OPTIONS'],capture_output=True,timeout=10,check=False)
    require(listing.returncode==0 and listing.stderr==b''and len(listing.stdout)<=65536,
            'actual guest original carrier mount proof')
    mounts=json.loads(listing.stdout)['filesystems']
    require(len(mounts)==1 and mounts[0]['source']==str(device)and
            mounts[0]['fstype']in('iso9660','udf')and 'ro'in mounts[0]['options'].split(','),
            'same original readonly optical filesystem')
    root=Path(mounts[0]['target']);path=root/relative
    require(root.is_absolute()and root.resolve()==root and path.resolve()==path and
            path.is_relative_to(root)and path.is_file(),'canonical mounted original image within actual carrier')
    return str(path),{'device':str(device),'rdev':st.st_rdev,'serial':serial,'mount':mounts[0],
                     'mountNumeric':mounted.returncode,'relativePath':str(relative),'path':str(path)}


def pipeline_config(config_path,config_sha,nonce):
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
    require(type(cfg['native_executable_bytes'])is int and 0<cfg['native_executable_bytes']<=1073741824
            and re.fullmatch('[0-9a-f]{64}',cfg['native_executable_sha256']),'exact producer native executable role')
    cfg['input_path'],cfg['input_carrier_observation']=mounted_input(cfg)
    return cfg


def pipeline_requests(port,x,app,birth,nonce,cfg):
    """Observe the same admitted GUI operation over its existing virtio channel.

    Requests return native facts only. All pointer input stays in the separate
    host QMP sender, and no request can fabricate a stage or activate a control.
    """
    import select
    import gi
    gi.require_version('Atspi','2.0')
    from gi.repository import Atspi
    expected={'bytes':cfg['native_executable_bytes'],'sha256':cfg['native_executable_sha256']}
    desktop=Atspi.get_desktop(0);deadline=time.monotonic()+cfg['whole_seconds'];sequence=0
    states={key:getattr(Atspi.StateType,name)for key,name in
            [('enabled','ENABLED'),('sensitive','SENSITIVE'),('visible','VISIBLE'),('showing','SHOWING'),('defunct','DEFUNCT'),('focused','FOCUSED'),('editable','EDITABLE')]}
    states['screen']=Atspi.CoordType.SCREEN
    def owner_check(pid,window_pid):
        # Keep the existing exact-PID rule for separately owned native chooser
        # transients. Child-provider support is confined to the verified app.
        require(window_pid==birth['pid'],'native child provider belongs to original app window')
        try:return native_process_owner(pid,birth)
        except (RuntimeError,FileNotFoundError,ProcessLookupError) as error:
            raise RuntimeError('native provider pid='+str(pid)+' window_pid='+str(window_pid)+
                               ' refused: '+str(error))from error
    def emit(value):
        wire=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
        require(len(wire)<=1048576 and os.write(port,wire)==len(wire),'bounded native observation channel')
    def file_observation(key):
        require(key in('input_path','output_path'),'declared guest image role only')
        if key=='output_path'and not cfg.get('output_path'):
            root=Path(cfg['output_directory']);owned=Path.home()/('opemos-robot-'+nonce)
            require(root==owned/'output'and root.resolve()==root and root.stat().st_uid==os.getuid()
                    and stat.S_IMODE(root.stat().st_mode)==0o700,'same owned output directory')
            choices=[p for p in root.iterdir()if p.name.endswith('.img')and
                     Path(str(p)+'.manifest.json').is_file()]
            require(len(choices)==1,'one actual application-exported image and normal manifest')
            cfg[key]=str(choices[0])
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
    while time.monotonic()<deadline and sequence<4096:
        line=bytearray()
        while not line.endswith(b'\n'):
            remaining=deadline-time.monotonic();require(remaining>0,'original observer deadline')
            require(select.select([port],[],[],remaining)[0],'native request deadline')
            part=os.read(port,1);require(part,'native request EOF');line.extend(part)
            require(len(line)<=4096,'native request cap')
        request=json.loads(line);sequence+=1
        require(request['nonce']==nonce and request['sequence']==sequence,'exact ordered native operation request')
        require(proc_identity(app['pid'],expected)==birth,'original app PID/start/executable/nonce unchanged')
        current=x.windows();owned=[w for w in current if w['pid']==app['pid']or w['transient_for']==app['window_id']]
        kind=request['kind'];value={}
        if kind=='CONTROL':
            window=next((w for w in owned if w['window_id']==request['window_id']),None)
            require(window is not None,'mapped original app or native transient window')
            value=observed_control(desktop,window,request['label'],request['roles'],states,cfg['display'],
                probe=request.get('probe')is True,hit_test=x.hit_window_chain,owner_check=owner_check)
        elif kind=='WINDOWS':value={'windows':owned}
        elif kind=='CHOOSER_LOCATION':
            window=next((w for w in owned if w['window_id']==request['window_id']),None)
            require(window is not None and window['pid']==birth['pid'],'original app native chooser only')
            role=request['role'];require(role in ('input_path','output_directory'),'declared image/output location only')
            value=observed_chooser_location(desktop,window,cfg[role],request['prefix_length'],states,Atspi.Text,role=role)
        elif kind=='UI_STATE':
            # Read the actual mapped main/companion/chooser windows. No app
            # command, DOM mutation or accessibility activation is permitted.
            value={'windows':owned,'namesByWindow':[
                {'window_id':w['window_id'],'names':observed_names(desktop,w,states,owner_check)['names']}
                for w in owned]}
        elif kind=='NAMES':
            window=next((w for w in owned if w['window_id']==request['window_id']),None)
            require(window is not None,'original mapped app/native transient for visible names')
            value=observed_names(desktop,window,states,owner_check)
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
    cfg=pipeline_config(sys.argv[4],sys.argv[5],sys.argv[1])if pipeline else None
    expected={'bytes':cfg['native_executable_bytes'],'sha256':cfg['native_executable_sha256']}if pipeline else None
    selected_birth=None;refused=[]
    x=X11();before=[];matches=[];app=None;deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        before=x.windows()
        if pipeline:
            authenticated,refused=launched_window_matches(before,expected_title,sys.argv[1],expected)
            matches=[row for row,birth in authenticated]
        else:matches=[w for w in before if expected_title.lower() in w['title'].lower()]
        if len(matches)==1:
            app=matches[0]
            if pipeline:selected_birth=authenticated[0][1]
            break
        time.sleep(.2)
    if app is None:
        # A captured desktop can show an app even when the native identity
        # predicate fails. Retain its actual, bounded inventory rather than
        # translating this observation failure into 'the app never opened'.
        print(json.dumps({'kind':'NATIVE_WINDOW_SELECTION_REFUSED',
            'expected_title':expected_title,'match_count':len(matches),
            'mapped_pid_windows':[dict(row,title=row['title'][:96])for row in before[:8]],
            'current_launch_identity_refusals':refused[:8],
            'display':os.environ.get('DISPLAY'),
            'session_type':os.environ.get('XDG_SESSION_TYPE')},
            sort_keys=True),file=sys.stderr,flush=True)
    require(app is not None, 'unique actual app native X11 window absent')
    birth=proc_identity(app['pid'],expected)
    require(birth['inherited_nonce']==sys.argv[1],
            'native window process did not inherit exact verified-package launch nonce')
    if pipeline:
        require(birth==selected_birth,'selected native process changed before READY')
        mapped=[w for w in x.windows()if w['window_id']==app['window_id']and w['pid']==app['pid']]
        require(len(mapped)==1,'selected native window/PID changed before READY')
        app=mapped[0]
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
          'guest_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
          **({'input_path':cfg['input_path'],'input_carrier':cfg['input_carrier_observation']}if pipeline else{}),
          'display_connection':os.environ['DISPLAY'],'guest_uid':os.getuid(),
          'guest_architecture':os.uname().machine,
          'clock_ns':time.monotonic_ns()})
    if pipeline:
        try:pipeline_requests(port,x,app,birth,sys.argv[1],cfg)
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
