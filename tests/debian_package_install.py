"""Failure-path tests for the disposable Debian package install smoke."""
import importlib.util, json, os, subprocess, tempfile, unittest
from pathlib import Path
from unittest import mock
spec = importlib.util.spec_from_file_location("debian_install", Path(__file__).resolve().parents[1] / "scripts/check_debian_package_install.py")
install = importlib.util.module_from_spec(spec); spec.loader.exec_module(install)
class FakeRunner:
    def __init__(self, root, staged, fail_install=False, fail_verify=False, fail_purge=False):
        self.root, self.staged = root, staged; self.fail_install, self.fail_verify, self.fail_purge = fail_install, fail_verify, fail_purge; self.calls=[]
    def __call__(self, args, **_kwargs):
        self.calls.append(tuple(args))
        if args[:2] == ("dpkg-deb", "--field"):
            value = "opemos-exe-linux-test\n" if args[-1] == "Package" else "amd64\n"
            return subprocess.CompletedProcess(args,0,value,"")
        if args[:2] == ("dpkg-query", "--listfiles"):
            return subprocess.CompletedProcess(args,0,"/usr/bin/steamos-nvidia-image-builder\n/usr/share/applications/opemos-exe-linux-test.desktop\n","")
        if args[:2] == ("dpkg-query", "--show"):
            present=(self.root/install.BINARY).exists(); output="installed" if present and not self.fail_verify else ""
            return subprocess.CompletedProcess(args,0 if present else 1,output,"")
        if args[:2] == ("dpkg", "--install"):
            if not self.fail_install:
                binary=self.root/install.BINARY; binary.parent.mkdir(parents=True,exist_ok=True); binary.write_bytes(self.staged.read_bytes()); binary.chmod(0o755)
                desktop=self.root/install.DESKTOP_DIR/"opemos-exe-linux-test.desktop"; desktop.parent.mkdir(parents=True,exist_ok=True); desktop.write_text("[Desktop Entry]\nExec=steamos-nvidia-image-builder\n")
            return subprocess.CompletedProcess(args,1 if self.fail_install else 0,"","partial" if self.fail_install else "")
        if args[:2] == ("dpkg", "--purge"):
            if not self.fail_purge:
                (self.root/install.BINARY).unlink(missing_ok=True); (self.root/install.DESKTOP_DIR/"opemos-exe-linux-test.desktop").unlink(missing_ok=True)
            return subprocess.CompletedProcess(args,1 if self.fail_purge else 0,"","")
        raise AssertionError(args)
class DebianInstallSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="opemos-debian-install-test-"); base=Path(self.temp.name); self.repo,self.root=base/"repo",base/"root"
        (self.root/"etc").mkdir(parents=True); (self.root/".dockerenv").write_text(""); (self.root/"etc/os-release").write_text('ID=debian\nVERSION_ID="12"\n')
        (self.repo/"src-tauri").mkdir(parents=True); (self.repo/"src-tauri/tauri.conf.json").write_text(json.dumps({"version":"0.1.0"})); (self.repo/"src-tauri/tauri.linux-test.conf.json").write_text(json.dumps({"productName":"OPEMOS EXE Linux Test"}))
        self.package,self.staged=install.package_path(self.repo); self.package.parent.mkdir(parents=True); self.package.write_bytes(b"deb"); self.staged.parent.mkdir(parents=True); self.staged.write_bytes(b"binary"); self.staged.chmod(0o755); self.env={"OPEMOS_DISPOSABLE_DEBIAN_CONTAINER":"1"}
    def tearDown(self): self.temp.cleanup()
    def run_it(self, runner):
        with mock.patch.object(os,"geteuid",return_value=0): install.run_smoke(self.repo,self.root,self.env,runner)
    def test_success_installs_verifies_and_purges(self):
        runner=FakeRunner(self.root,self.staged); self.run_it(runner); self.assertFalse((self.root/install.BINARY).exists()); self.assertIn(("dpkg","--purge",install.PACKAGE_ID),runner.calls)
    def test_partial_install_and_failed_verification_are_always_purged(self):
        for option in ("fail_install","fail_verify"):
            with self.subTest(option=option):
                runner=FakeRunner(self.root,self.staged,**{option:True})
                with self.assertRaises(RuntimeError): self.run_it(runner)
                self.assertIn(("dpkg","--purge",install.PACKAGE_ID),runner.calls)
    def test_cleanup_failure_is_reported(self):
        with self.assertRaisesRegex(RuntimeError,"purge did not restore"): self.run_it(FakeRunner(self.root,self.staged,fail_purge=True))
    def test_wrong_context_and_symlink_refuse_before_mutation(self):
        for mode in ("no-opt-in","ubuntu","symlink"):
            with self.subTest(mode=mode):
                env=self.env
                if mode=="no-opt-in": env={}
                if mode=="ubuntu": (self.root/"etc/os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
                if mode=="symlink": self.package.unlink(); self.package.symlink_to(self.staged)
                runner=FakeRunner(self.root,self.staged)
                with self.assertRaises(ValueError):
                    with mock.patch.object(os,"geteuid",return_value=0): install.run_smoke(self.repo,self.root,env,runner)
                self.assertFalse(any(call[:1]==("dpkg",) for call in runner.calls))
                (self.root/"etc/os-release").write_text('ID=debian\nVERSION_ID="12"\n')
                if self.package.is_symlink(): self.package.unlink(); self.package.write_bytes(b"deb")
    def test_preinstalled_package_is_never_touched(self):
        binary=self.root/install.BINARY; binary.parent.mkdir(parents=True); binary.write_bytes(b"preexisting"); runner=FakeRunner(self.root,self.staged)
        with self.assertRaisesRegex(ValueError,"already installed"): self.run_it(runner)
        self.assertEqual(binary.read_bytes(),b"preexisting"); self.assertFalse(any(call[:1]==("dpkg",) for call in runner.calls))
if __name__=="__main__": unittest.main()
