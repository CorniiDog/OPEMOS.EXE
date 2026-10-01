import tempfile, unittest, zipfile
from pathlib import Path
from scripts.extract_windows_runtime_cache import extract

class WindowsRuntimeCacheExtractionTests(unittest.TestCase):
    def test_extracts_only_closed_runtime_and_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); archive=root/"artifact.zip"; output=root/"runtime"
            with zipfile.ZipFile(archive,"w") as target:
                target.writestr("runtime/runtime-manifest.json","{}")
                target.writestr("runtime/source-provenance.json","{}")
                target.writestr("runtime/qemu/qemu.exe",b"qemu")
                target.writestr("appliance/disk.raw",b"ignored")
            extract(archive,output)
            self.assertEqual((output/"qemu/qemu.exe").read_bytes(),b"qemu")
            self.assertFalse((output/"appliance").exists())
            with self.assertRaisesRegex(SystemExit,"already exists"): extract(archive,output)

    def test_refuses_escape_duplicate_link_and_incomplete_archives(self):
        cases=(("runtime/../escape",None,"escapes"),("runtime/file",b"twice","duplicate"),("runtime/link",b"link","symbolic link"))
        for index,(member,second,error) in enumerate(cases):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary); archive=root/"artifact.zip"
                with zipfile.ZipFile(archive,"w") as target:
                    target.writestr("runtime/runtime-manifest.json","{}")
                    target.writestr("runtime/source-provenance.json","{}")
                    info=zipfile.ZipInfo(member)
                    if error=="symbolic link": info.external_attr=(0o120777<<16)
                    target.writestr(info,b"one")
                    if second is not None and error=="duplicate": target.writestr(member,second)
                with self.assertRaisesRegex(SystemExit,error): extract(archive,root/f"out-{index}")
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); archive=root/"artifact.zip"
            with zipfile.ZipFile(archive,"w") as target: target.writestr("other/file",b"x")
            with self.assertRaisesRegex(SystemExit,"incomplete"): extract(archive,root/"out")

if __name__=="__main__": unittest.main()
