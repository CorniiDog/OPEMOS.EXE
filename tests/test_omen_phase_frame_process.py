"""Real process/pipe/file codec regression; run inside OMEN, not the host.

This exercises current production codec/creator/held-reader functions without
replacing them. It proves only this process/UID/data transaction, not a libvirt
channel, graphical guest, hardware, Root grant or completed output image.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'


def load(name):
    spec=importlib.util.spec_from_file_location(name,SCRIPTS/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


CHILD=r'''
import importlib.util,json,os,sys
from pathlib import Path
root=Path(sys.argv[1]);output=Path(sys.argv[2])
def load(name):
    spec=importlib.util.spec_from_file_location(name,root/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
life=load('omen_output_lifecycle');native=load('omen_steamos_native')
buffer=bytearray();frames=[]
while True:
    part=sys.stdin.buffer.read(65537-len(buffer))
    if not part:break
    buffer.extend(part)
    while True:
        value=life.pop_guest_frame(buffer)
        if value is None:break
        frames.append(value)
if buffer:raise ValueError('actual pipe EOF inside a frame, not a completed event')
if len(frames)!=2:raise ValueError('exact complete producer frame count')
pin=native.create(output,life.canonical(frames))
raw,identity=native.held(output,200000,pin['sha256'])
if identity!=pin['identity']:raise ValueError('actual persisted full9 changed')
print(json.dumps({'pin':pin,'actor':native.process(os.getpid(),os.getuid()),'EOF':True,'frames':len(frames)}),flush=True)
'''


class OrdinaryFrameProcess(unittest.TestCase):
    def child(self,wire,output):
        with subprocess.Popen([sys.executable,'-B','-c',CHILD,str(SCRIPTS),str(output)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)as process:
            try:stdout,stderr=process.communicate(wire,timeout=10)
            except subprocess.TimeoutExpired as original:
                try:process.kill();process.communicate(timeout=5)
                except BaseException as cleanup:original.add_note('owned test child closure UNKNOWN: '+type(cleanup).__name__)
                raise
            return process.returncode,stdout,stderr

    def test_current_producer_pipe_consumer_and_durable_held_file(self):
        life=load('omen_output_lifecycle');native=load('omen_steamos_native')
        frames=[{'payload':'x'*44000},{'payload':'y'*30000}]
        wire=b''.join(life.canonical(value)+b'\n'for value in frames)
        with tempfile.TemporaryDirectory()as directory:
            output=Path(directory)/'ordinary.json'
            code,stdout,stderr=self.child(wire,output)
            self.assertEqual(code,0,stderr.decode(errors='replace'))
            value=json.loads(stdout);self.assertIs(value['EOF'],True)
            self.assertEqual(value['actor']['uids'],[os.getuid()]*4)
            raw,identity=native.held(output,200000,value['pin']['sha256'])
            self.assertEqual(identity,value['pin']['identity']);self.assertEqual(json.loads(raw),frames)
            self.assertEqual(output.stat().st_uid,os.getuid())

    def test_actual_eof_duplicate_schema_and_size_failure_do_not_publish(self):
        for wire in (b'{"x":1}\n{"x":2',b'{"x":1}\n{"x":1,"x":2}\n',b'x'*65537,b'[]\n{}\n'):
            with self.subTest(bytes=len(wire)),tempfile.TemporaryDirectory()as directory:
                output=Path(directory)/'must-not-exist.json'
                code,stdout,stderr=self.child(wire,output)
                self.assertNotEqual(code,0)
                self.assertFalse(output.exists());self.assertFalse(stdout)


if __name__=='__main__':unittest.main()
