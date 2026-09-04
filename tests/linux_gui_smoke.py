"""Corner cases for the bounded packaged Linux GUI smoke harness."""
import importlib.util
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
spec = importlib.util.spec_from_file_location("linux_gui_smoke", Path(__file__).resolve().parent.parent / "scripts/linux_gui_smoke.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

class FakeNode:
    def __init__(self, name="", children=(), actionable=False, role="text"):
        self.name, self.children, self.actionable, self.invoked, self.role = name, list(children), actionable, False, role
    def get_name(self): return self.name
    def get_child_count(self): return len(self.children)
    def get_child_at_index(self, index): return self.children[index]
    def get_action_iface(self): return self if self.actionable else None
    def get_role_name(self): return self.role
    def get_n_actions(self): return 1
    def do_action(self, index): self.invoked = index == 0; return self.invoked

class GuiSmokeTests(unittest.TestCase):
    def test_launch_validation_rejects_missing_opt_in_display_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "app"
            executable.write_text("#!/bin/sh\n")
            executable.chmod(0o700)
            base = {"OPEMOS_EXPERIMENTAL_LINUX": "1", "DISPLAY": ":0"}
            self.assertEqual(smoke.validate_launch(executable, 1, base), executable.resolve())
            executable.chmod(0o600)
            with self.assertRaises(ValueError): smoke.validate_launch(executable, 1, base)
            executable.chmod(0o700)
            with self.assertRaises(ValueError): smoke.validate_launch(Path(directory) / "missing", 1, base)
            for env in ({"DISPLAY": ":0"}, {"OPEMOS_EXPERIMENTAL_LINUX": "1"}):
                with self.assertRaises(ValueError): smoke.validate_launch(executable, 1, env)
            link = Path(directory) / "link"
            link.symlink_to(executable)
            with self.assertRaises(ValueError): smoke.validate_launch(link, 1, base)
            for timeout in (0, 61, float("inf")):
                with self.assertRaises(ValueError): smoke.validate_launch(executable, timeout, base)

    def test_exact_lookup_rejects_missing_duplicate_and_tree_overflow(self):
        with self.assertRaises(RuntimeError): smoke.exactly_one(FakeNode(), "target")
        duplicate = FakeNode(children=[FakeNode("target"), FakeNode("target")])
        with self.assertRaises(RuntimeError): smoke.exactly_one(FakeNode(children=[FakeNode("target"), FakeNode("target")]), "target")
        chain = FakeNode()
        for _ in range(34): chain = FakeNode(children=[chain])
        self.assertEqual(len(list(smoke.descendants(chain, max_depth=3))), 4)
        with self.assertRaises(RuntimeError): list(smoke.descendants(FakeNode(children=[FakeNode(), FakeNode()]), max_nodes=2))

    def test_stubborn_process_group_is_killed_and_reaped(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"],
            start_new_session=True,
        )
        time.sleep(0.1)
        smoke.stop_process_group(process, grace=0.05)
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertFalse(smoke.process_group_exists(process.pid))

    def test_action_rejects_non_actionable_and_failed_control(self):
        with self.assertRaises(RuntimeError): smoke.invoke(FakeNode("plain"))
        failed = FakeNode("failed", actionable=True)
        failed.do_action = lambda _index: False
        with self.assertRaises(RuntimeError): smoke.invoke(failed)
        control = FakeNode("works", actionable=True)
        smoke.invoke(control)
        self.assertTrue(control.invoked)
        wrapped = FakeNode(children=[FakeNode("Close", actionable=True), FakeNode("Close", actionable=True, role="push button")])
        self.assertIs(smoke.exactly_one_action(wrapped, "Close", {"push button"}), wrapped.children[1])
        with self.assertRaises(RuntimeError): smoke.exactly_one_action(FakeNode(), "Close")
        self.assertIs(smoke.first_action(wrapped, "Close", {"push button"}), wrapped.children[1])
        dialog = FakeNode("Inspector", role="dialog")
        self.assertIs(smoke.exactly_one_role(FakeNode(children=[dialog]), "Inspector", "dialog"), dialog)
        with self.assertRaises(RuntimeError): smoke.exactly_one_role(FakeNode(), "Inspector", "dialog")
        with self.assertRaises(RuntimeError): smoke.first_action(FakeNode(), "Close", {"push button"})

if __name__ == "__main__": unittest.main()
