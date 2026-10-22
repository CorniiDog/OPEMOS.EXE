"""Ordinary real-file/UID source tests, to run inside an admitted OMEN VM.

No display adapter, native SDK replacement, policy override or GPU/VM pass is
provided. Graphical actions and whole lifecycle need their actual transaction.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SOURCE=Path(__file__).resolve().parents[1]/'scripts/omen_steamos_native.py'
SPEC=importlib.util.spec_from_file_location('native_file_tests',SOURCE)
native=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(native)


class NativeFileCustody(unittest.TestCase):
    def test_create_only_held_eof_hash_and_actual_modes(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);path=root/'raw.json'
            pin=native.create(path,b'{"raw":true}\n')
            raw,identity=native.held(path,1024,pin['sha256'])
            self.assertEqual(raw,b'{"raw":true}\n');self.assertEqual(identity,pin['identity'])
            self.assertEqual(pin['sha256'],hashlib.sha256(raw).hexdigest())
            with self.assertRaises(RuntimeError):native.create(path,b'overwrite')
            with self.assertRaises(RuntimeError):native.held(path,2)
            with self.assertRaises(RuntimeError):native.held(path,1024,'0'*64)
            link=root/'link';link.symlink_to(path)
            with self.assertRaises(OSError):native.held(link,1024)
            path.chmod(0o622)
            with self.assertRaises(RuntimeError):native.held(path,1024)

    def test_real_process_status_uid_not_proc_inode_owner(self):
        actual=native.process(os.getpid(),os.getuid())
        self.assertEqual(actual['uids'],[os.getuid()]*4)
        self.assertGreater(actual['start'],0);self.assertEqual(len(actual['exe_sha256']),64)
        with self.assertRaises(RuntimeError):native.process(os.getpid(),os.getuid()+1)

    def test_no_native_permission_or_sdk_override(self):
        with self.assertRaises(RuntimeError):native.require_guest(0)


if __name__=='__main__':unittest.main()
