"""Source regressions only; run through required source CI/admitted OMEN VM.
No fake Root authority, method override, or native acceptance substitution.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

P=Path(__file__).resolve().parents[1]/"scripts/omen_ci_stage.py"
spec=importlib.util.spec_from_file_location("image_range_stage",P)
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)

class StoppedImageRange(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.backing=self.root/"usb.raw";self.backing.write_bytes(b"image"+b"\0"*3);self.backing.chmod(0o600)
        a=self.backing.stat();ident=stage._READER.identity(a)
        self.item={"path":str(self.backing),"size":5,"sha256":hashlib.sha256(b"image").hexdigest(),"kind":"output-image",
            "imageArtifactRange":{"backingFile":{"path":str(self.backing),"size":8,
                "sha256":hashlib.sha256(self.backing.read_bytes()).hexdigest(),"identity":ident,
                "allocatedBytes":a.st_blocks*512},"offset":0,"bytes":5,
                "sha256":hashlib.sha256(b"image").hexdigest(),"tailBytes":3,
                "root_final":{"path":str(self.root/"not-root.json"),"size":2,"sha256":hashlib.sha256(b"{}").hexdigest(),"identity":{}}}}
        self.context={"source_commit":"a"*40,"run_id":"1","attempt":"1","operation_nonce":"b"*32,
                      "executable":{"platform":"windows"},"consumer_job_ids":["build","heal"]}

    def test_full_file_and_real_copy_path_unchanged(self):
        item={"path":str(self.backing),"size":8,"sha256":hashlib.sha256(self.backing.read_bytes()).hexdigest(),"kind":"output-image"}
        actual=stage.artifact_read(item,8)
        self.assertEqual(actual["identity"]["st_size"],8)
        target=self.root/item["sha256"]
        charge,copied=stage.retain_pin(item,target,8,8)
        self.assertEqual(charge,8);self.assertEqual(target.read_bytes(),self.backing.read_bytes())
        self.assertEqual(copied["sha256"],item["sha256"])
        self.assertEqual(stage.retain_pin(item,target,8,8)[0],0)

    def test_prefix_cannot_be_relabelled_as_whole_file(self):
        item={k:v for k,v in self.item.items()if k!="imageArtifactRange"}
        with self.assertRaises(ValueError):stage.artifact_read(item,8)

    def test_range_needs_current_context_and_cannot_implicitly_export(self):
        with self.assertRaises(ValueError):stage.artifact_read(self.item,8)
        target=self.root/self.item["sha256"]
        with self.assertRaises(ValueError):stage.artifact_read(self.item,8,target,context=self.context)
        self.assertFalse(target.exists())

    def test_nonprefix_wrong_size_tail_bool_allocation_are_rejected(self):
        for field,value in [("offset",1),("bytes",True),("tailBytes",4)]:
            item=copy.deepcopy(self.item);item["imageArtifactRange"][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                stage.artifact_read(item,8,context=self.context)
        item=copy.deepcopy(self.item);item["imageArtifactRange"]["backingFile"]["allocatedBytes"]=True
        with self.assertRaises(ValueError):stage.artifact_read(item,8,context=self.context)

    def test_real_user_owned_receipt_is_not_root_authority_and_fds_close(self):
        path=Path(self.item["imageArtifactRange"]["root_final"]["path"])
        path.write_bytes(b"{}");path.chmod(0o444)
        before=set(os.listdir("/proc/self/fd"))
        with self.assertRaises(ValueError):stage.artifact_read(self.item,8,context=self.context)
        self.assertEqual(set(os.listdir("/proc/self/fd")),before)
        self.assertEqual(self.backing.read_bytes(),b"image"+b"\0"*3)

    def test_actual_raw_manifest_is_not_reserialized_object(self):
        original=b'{\r\n  "output": {"bytes": 5}\r\n}\r\n'
        file=self.root/"manifest.json";file.write_bytes(original);file.chmod(0o600)
        pin={"path":str(file),"sha256":hashlib.sha256(original).hexdigest(),"size":len(original)}
        self.assertEqual(stage.pinned(pin),original)
        file.write_bytes(json.dumps(json.loads(original),sort_keys=True).encode())
        with self.assertRaises(ValueError):stage.pinned(pin)

    def test_only_exact_registered_operand_can_bind_context(self):
        build={"job_ids":["build"],"inputs":[]};heal={"job_ids":["heal"],"inputs":[]}
        entry={"operation_nonce":"b"*32,"build_operand":build,"heal_operand":heal}
        plan={"executable_acceptance":{"windows":entry}}
        request={"source_commit":"a"*40,"run_id":"1","attempt":"1"}
        expected={"windows":{"platform":"windows"}}
        context=stage.operand_image_range_context(heal,plan,request,expected)
        self.assertEqual(context,self.context)
        stale={**heal,"inputs":[{"sha256":"0"*64}]}
        with self.assertRaises(ValueError):stage.operand_image_range_context(stale,plan,request,expected)
        plan["executable_acceptance"]["duplicate"]=copy.deepcopy(entry);expected["duplicate"]=expected["windows"]
        with self.assertRaises(ValueError):stage.operand_image_range_context(heal,plan,request,expected)

if __name__=="__main__":unittest.main()
