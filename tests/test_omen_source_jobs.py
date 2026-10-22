"""UNRUN authoring: execute only inside admitted OMEN source VMs.

Real child/files/clock cases test the ordinary capture, not a fake SDK/VM.
Metadata cases test schemas only and cannot prove Root/libvirt/OS properties.
"""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import stat

sys.path.insert(0,str(Path(__file__).parents[1]/'scripts'))
from omen_source_capture import capture
from omen_source_ci import unpack_tar
from omen_source_guest_parent import package_archive
from omen_source_guard import validate
from omen_source_workloads import commands,selection


class RealSourceChild(unittest.TestCase):
    def test_complete_real_numeric_reap_eof_and_both_raw_files(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d)
            result=capture([sys.executable,'-I','-c',"import sys;print('ordinary-child');print('actual-stderr',file=sys.stderr)"],
                p,dict(os.environ),p/'capture',15)
            self.assertEqual(result['numeric_exit'],0);self.assertIsNone(result['first'])
            self.assertEqual(result['secondary'],[])
            for key in('reaped','stdoutEOF','stderrEOF','FDsClosed','descendantsAbsent'):self.assertIs(result[key],True)
            self.assertGreater(result['pid'],0);self.assertNotEqual(result['birth'],'UNKNOWN')
            for name in('stdout','stderr'):
                raw=Path(result[name]['path']).read_bytes()
                self.assertEqual(len(raw),result[name]['bytes'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(),result[name]['sha256'])

    def test_actual_timeout_retains_failure_not_success(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d);result=capture([sys.executable,'-I','-c','import time;time.sleep(30)'],p,
                dict(os.environ),p/'timed',.5)
            self.assertIsNotNone(result['first']);self.assertNotEqual(result['numeric_exit'],0)
            self.assertIs(result['reaped'],True)

    def test_actual_pipe_size_overflow_is_not_a_pass(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d);result=capture([sys.executable,'-I','-c',
                'import os; b=b"x"*65536\nfor i in range(514): os.write(1,b)'],p,
                dict(os.environ),p/'overflow',30)
            self.assertIsNotNone(result['first'])
            self.assertGreater(result['stdout']['bytes'],32*1024**2)
            self.assertLessEqual(result['stdout']['bytes'],32*1024**2+65536)

    @unittest.skipUnless(os.name=='posix'and os.getuid()!=0,'Actual unprivileged Linux guest case')
    def test_real_nonroot_cannot_enter_Root_controller(self):
        import omen_source_root
        with self.assertRaisesRegex(ValueError,'actual Root'):omen_source_root.execute(None,None)


class ActualPackageData(unittest.TestCase):
    def test_complete_actual_archive_chunk_producer_to_extraction_consumer(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d);source=p/'package';source.mkdir();(source/'runtime').mkdir()
            original=bytes(range(256))*4096
            (source/'runtime/payload.bin').write_bytes(original)
            out=p/'producer';out.mkdir()
            value,leaves=package_archive(source,out,{'run':'actual-file-case'},{'workload':'test-data'})
            self.assertEqual(value['file_count'],1);self.assertEqual(value['file_bytes'],len(original))
            joined=p/'joined.tar'
            with joined.open('xb')as stream:
                for row,(name,path,kind)in zip(value['chunks'],leaves,strict=True):
                    raw=path.read_bytes();self.assertEqual(name,row['name'])
                    self.assertEqual(hashlib.sha256(raw).hexdigest(),row['sha256'])
                    self.assertEqual(stream.tell(),row['offset']);stream.write(raw)
            self.assertEqual(unpack_tar(joined,p/'consumer',value['bytes'],value['sha256']),1)
            self.assertEqual((p/'consumer/runtime/payload.bin').read_bytes(),original)

    def test_archive_empty_or_missing_package_never_produces_empty_pass(self):
        for present in(False,True):
            with self.subTest(present=present),tempfile.TemporaryDirectory()as d:
                p=Path(d);source=p/'package';out=p/'out';out.mkdir()
                if present:source.mkdir()
                with self.assertRaises(ValueError):package_archive(source,out,{}, {})

    @unittest.skipUnless(os.name=='posix','Actual Linux hardlink/symlink fault')
    def test_archive_actual_link_custody_refusal(self):
        for hard in(False,True):
            with self.subTest(hard=hard),tempfile.TemporaryDirectory()as d:
                p=Path(d);source=p/'package';source.mkdir();out=p/'out';out.mkdir()
                original=p/'original';original.write_bytes(b'preserve')
                if hard:os.link(original,source/'linked')
                else:os.symlink(original,source/'linked')
                with self.assertRaises(ValueError):package_archive(source,out,{}, {})
                self.assertEqual(original.read_bytes(),b'preserve')

    def test_actual_six_archive_seed_producer_to_guest_cache(self):
        from omen_source_guest import extract_seed
        with tempfile.TemporaryDirectory()as d:
            p=Path(d);source=p/'seed';source.mkdir();out=p/'producer';out.mkdir()
            for i in range(6):(source/('locked-'+str(i)+'.zip')).write_bytes(bytes([i])*31)
            value,_=package_archive(source,out,{},{});archive=out/'guest-package.tar';archive.chmod(0o444)
            result=extract_seed({'path':str(archive),'bytes':value['bytes'],'sha256':value['sha256']},p/'cache')
            self.assertEqual(len(result['files']),6)
            for i in range(6):self.assertEqual((p/'cache'/('locked-'+str(i)+'.zip')).read_bytes(),bytes([i])*31)

    def make(self,path,kind='file'):
        with tarfile.open(path,'w')as out:
            info=tarfile.TarInfo('runtime/file.bin');info.size=3
            if kind=='link':info.type=tarfile.SYMTYPE;info.linkname='/etc/passwd';info.size=0;out.addfile(info)
            elif kind=='escape':info.name='../escape';out.addfile(info,io.BytesIO(b'abc'))
            elif kind=='duplicate':out.addfile(info,io.BytesIO(b'abc'));out.addfile(info,io.BytesIO(b'abc'))
            else:out.addfile(info,io.BytesIO(b'abc'))

    def test_real_whole_tar_regular_data(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d);a=p/'package.tar';self.make(a);raw=a.read_bytes()
            self.assertEqual(unpack_tar(a,p/'out',len(raw),hashlib.sha256(raw).hexdigest()),1)
            self.assertEqual((p/'out/runtime/file.bin').read_bytes(),b'abc')

    def test_actual_link_escape_duplicate_and_wrong_hash_refuse(self):
        for kind in('link','escape','duplicate','hash'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory()as d:
                p=Path(d);a=p/'package.tar';self.make(a,kind);raw=a.read_bytes()
                with self.assertRaises(ValueError):unpack_tar(a,p/'out',len(raw),
                    '0'*64 if kind=='hash'else hashlib.sha256(raw).hexdigest())


@unittest.skipUnless(os.name=='posix','Actual Linux ledger/property case in OMEN guest')
class ActualSourceLedger(unittest.TestCase):
    def test_actual_file_union_and_explicit_windows_cap(self):
        from ubuntu_vm_runner import output_storage_ledger
        with tempfile.TemporaryDirectory()as d:
            p=Path(d)/'working';p.write_bytes(b'actual')
            ordinary=output_storage_ledger([str(p),str(p)],100)
            windows=output_storage_ledger([str(p)],100,platform='windows',mutable_paths=[str(p)])
            self.assertEqual(ordinary['uniqueInodes'],1)
            self.assertEqual(ordinary['hardBytes'],60_000_000_000)
            self.assertEqual(windows['hardBytes'],80_000_000_000)
            self.assertEqual(windows['chargedBytes'],ordinary['chargedBytes'])
            self.assertIn('afterIdentity',windows['files'][0])
            self.assertIs(ordinary['admissionClaimed'],False)
            with self.assertRaises(ValueError):output_storage_ledger([str(p)],mutable_paths=[str(p)+'-foreign'])


@unittest.skipUnless(os.name=='posix'and os.getuid()==0,'Requires separately admitted actual Root OMEN guest fixture')
class ActualProtectedEmptyRaw(unittest.TestCase):
    def test_root_empty_stderr_requires_explicit_raw_reader_not_empty_json(self):
        from omen_output_lifecycle import protected_bytes
        # /tmp's writable ancestry cannot provide Root custody. The real Root
        # fixture uses its own bounded /run child and removes only that child.
        with tempfile.TemporaryDirectory(prefix='opemos-source-raw-test-',dir='/run')as d:
            p=Path(d)/'stderr.raw';p.write_bytes(b'');p.chmod(0o400);meta=p.lstat()
            fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            pin={'path':str(p),'bytes':0,'sha256':hashlib.sha256(b'').hexdigest(),
                 'identity':{k:getattr(meta,k)for k in fields}}
            with self.assertRaises(ValueError):protected_bytes(pin)
            self.assertEqual(protected_bytes(pin,allow_empty=True),b'')
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o400)


class SourceVocabularyOnly(unittest.TestCase):
    def test_all_original_workloads_are_fixed_argv_not_caller_shell(self):
        for kind in('frontend-and-docs','rust','linux-integration','debian-12-package',
                    'seed-runtime-source','windows-build','appimage-package','producer-metadata-diagnostic'):
            rows=commands(kind,'b'*40)
            self.assertTrue(rows);self.assertTrue(all(type(row)is list and row for row in rows))
        with self.assertRaises(ValueError):commands('arbitrary-host-command','b'*40)

    def test_pure_guard_requires_complete_exact_workflow_blob(self):
        raw=b'fixed safe A template';main='a'*40
        repo={'id':1};run={'repository':{'id':1,'full_name':'CorniiDog/OPEMOS.EXE'},
            'head_repository':{'id':1,'full_name':'CorniiDog/OPEMOS.EXE'},'path':'.github/workflows/checks.yml',
            'event':'pull_request','id':12,'run_attempt':1,'head_sha':'b'*40}
        job={'run_id':12,'status':'in_progress','name':'rust','id':34}
        profile={'schema':'FINITE_VM_ONLY_V1','enabled':True,'controller_commit':main,
                 'workflowPins':{run['path']:hashlib.sha256(raw).hexdigest()}}
        self.assertFalse(validate(run,job,repo,main,raw,profile)['runtimeAuthorized'])
        with self.assertRaises(ValueError):validate(run,job,repo,main,raw+b' injected step',profile)


if __name__=='__main__':unittest.main()
