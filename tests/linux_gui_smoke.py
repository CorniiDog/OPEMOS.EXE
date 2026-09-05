"""Corner cases for the bounded packaged Linux GUI smoke harness."""
import importlib.util
import os
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

class FakeStateSet:
    def __init__(self, states): self.states = set(states)
    def contains(self, state): return state in self.states

class FakeNode:
    def __init__(self, name="", children=(), actionable=False, role="text", pid=10, states=()):
        self.name, self.children, self.actionable = name, list(children), actionable
        self.invoked, self.role, self.pid, self.states = False, role, pid, states
    def get_name(self): return self.name
    def get_child_count(self): return len(self.children)
    def get_child_at_index(self, index): return self.children[index]
    def get_action_iface(self): return self if self.actionable else None
    def get_role_name(self): return self.role
    def get_process_id(self): return self.pid
    def get_state_set(self): return FakeStateSet(self.states)
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

    def test_pinned_executable_survives_path_replacement_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app"
            path.write_bytes(b"original")
            path.chmod(0o700)
            original = path.stat()
            descriptor = smoke.open_pinned_executable(path)
            try:
                replacement = Path(directory) / "replacement"
                replacement.write_bytes(b"replacement")
                replacement.chmod(0o700)
                replacement.replace(path)
                self.assertEqual(os.fstat(descriptor).st_ino, original.st_ino)
                self.assertNotEqual(os.fstat(descriptor).st_ino, path.stat().st_ino)
            finally:
                os.close(descriptor)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(ValueError): smoke.open_pinned_executable(link)
            path.chmod(0o600)
            with self.assertRaises(ValueError): smoke.open_pinned_executable(path)

    def test_exact_lookup_rejects_missing_duplicate_and_tree_overflow(self):
        with self.assertRaises(RuntimeError): smoke.exactly_one(FakeNode(), "target")
        duplicate = FakeNode(children=[FakeNode("target"), FakeNode("target")])
        with self.assertRaises(RuntimeError): smoke.exactly_one(FakeNode(children=[FakeNode("target"), FakeNode("target")]), "target")
        chain = FakeNode()
        for _ in range(34): chain = FakeNode(children=[chain])
        self.assertEqual(len(list(smoke.descendants(chain, max_depth=3))), 4)
        with self.assertRaises(RuntimeError): list(smoke.descendants(FakeNode(children=[FakeNode(), FakeNode()]), max_nodes=2))

    def test_cleared_result_rejects_stale_fields_and_wrong_focus(self):
        focused = "focused"
        clear = FakeNode("Clear", actionable=True, states={focused})
        dialog = FakeNode(children=[clear])
        smoke.validate_cleared_result(dialog, focused)
        dialog.children.append(FakeNode("Core status"))
        with self.assertRaisesRegex(RuntimeError, "Expected no accessible"):
            smoke.validate_cleared_result(dialog, focused)
        dialog.children.pop()
        clear.states = set()
        with self.assertRaisesRegex(RuntimeError, "Expected one focused action"):
            smoke.validate_cleared_result(dialog, focused)
        clear.states = {focused}
        dialog.children.append(FakeNode("Unverified Core result"))
        with self.assertRaisesRegex(RuntimeError, "Expected no accessible"):
            smoke.validate_cleared_result(dialog, focused)

    def test_compatible_rows_preserve_repeated_values_and_reject_stale_action(self):
        names = [value for row in smoke.EXPECTED_COMPATIBLE_ROWS for value in row]
        end = "Available generations — development fixture"
        root = FakeNode(children=[FakeNode(name) for name in [*names, end]])
        smoke.validate_named_rows(root, smoke.EXPECTED_COMPATIBLE_ROWS, end)
        root.children.insert(-1, FakeNode("Next action reported by Core"))
        with self.assertRaisesRegex(RuntimeError, "result rows changed"):
            smoke.validate_named_rows(root, smoke.EXPECTED_COMPATIBLE_ROWS, end)
        root.children.pop(-2)
        root.children[-2].name = "trusted"
        with self.assertRaisesRegex(RuntimeError, "result rows changed"):
            smoke.validate_named_rows(root, smoke.EXPECTED_COMPATIBLE_ROWS, end)

    def test_no_artifact_rows_require_exact_order_and_boundaries(self):
        names = [value for row in smoke.EXPECTED_NO_ARTIFACT_ROWS for value in row]
        end = "Available generations — development fixture"
        root = FakeNode(children=[FakeNode(name) for name in [*names, end]])
        smoke.validate_named_rows(root, smoke.EXPECTED_NO_ARTIFACT_ROWS, end)
        root.children[2], root.children[3] = root.children[3], root.children[2]
        with self.assertRaisesRegex(RuntimeError, "result rows changed"):
            smoke.validate_named_rows(root, smoke.EXPECTED_NO_ARTIFACT_ROWS, end)
        root.children[2], root.children[3] = root.children[3], root.children[2]
        root.children.insert(-1, FakeNode("Unexpected policy"))
        with self.assertRaisesRegex(RuntimeError, "result rows changed"):
            smoke.validate_named_rows(root, smoke.EXPECTED_NO_ARTIFACT_ROWS, end)
        root.children.pop(-2)
        root.children.append(FakeNode(end))
        with self.assertRaisesRegex(RuntimeError, "row boundaries changed"):
            smoke.validate_named_rows(root, smoke.EXPECTED_NO_ARTIFACT_ROWS, end)

    def test_focused_action_requires_exactly_one_matching_control(self):
        focused = "focused"
        first = FakeNode("Open", actionable=True, states={focused})
        root = FakeNode(children=[first, FakeNode("Open", actionable=True)])
        self.assertIs(smoke.exactly_one_focused_action(root, "Open", focused), first)
        first.states = set()
        with self.assertRaises(RuntimeError):
            smoke.exactly_one_focused_action(root, "Open", focused)
        first.states = {focused}
        root.children[1].states = {focused}
        with self.assertRaises(RuntimeError):
            smoke.exactly_one_focused_action(root, "Open", focused)

    def test_settings_focus_controls_reject_wrong_or_duplicate_focus(self):
        focused = "focused"
        close = FakeNode("Close settings", actionable=True, states={focused})
        open_control = FakeNode("Open settings", actionable=True)
        root = FakeNode(children=[close, open_control])
        self.assertIs(
            smoke.exactly_one_focused_action(root, "Close settings", focused), close
        )
        close.states = set()
        open_control.states = {focused}
        self.assertIs(
            smoke.exactly_one_focused_action(root, "Open settings", focused), open_control
        )
        root.children.append(FakeNode("Open settings", actionable=True, states={focused}))
        with self.assertRaises(RuntimeError):
            smoke.exactly_one_focused_action(root, "Open settings", focused)

    def test_settings_focus_requires_exact_order_and_single_initial_close(self):
        focusable, focused = "focusable", "focused"
        controls = [FakeNode(name, role=role, states={focusable})
                    for name, role in smoke.EXPECTED_SETTINGS_FOCUS_ORDER]
        controls[0].states = {focusable, focused}
        settings = FakeNode(children=controls)
        smoke.validate_settings_focus(settings, focusable, focused)
        settings.children[1], settings.children[2] = settings.children[2], settings.children[1]
        with self.assertRaisesRegex(RuntimeError, "focus order changed"):
            smoke.validate_settings_focus(settings, focusable, focused)
        settings.children[1], settings.children[2] = settings.children[2], settings.children[1]
        settings.children.append(FakeNode("Unexpected", actionable=True, states={focusable}))
        with self.assertRaisesRegex(RuntimeError, "focus order changed"):
            smoke.validate_settings_focus(settings, focusable, focused)
        settings.children.pop()
        controls[1].states = {focusable, focused}
        with self.assertRaisesRegex(RuntimeError, "initial focus changed"):
            smoke.validate_settings_focus(settings, focusable, focused)

    def test_reopened_dialog_rejects_stale_result_and_wrong_initial_focus(self):
        focusable, focused = "focusable", "focused"
        controls = [FakeNode(name, role=role, states={focusable})
                    for name, role in smoke.EXPECTED_FOCUS_ORDER]
        controls[0].states = {focusable, focused}
        dialog = FakeNode(children=controls)
        smoke.validate_reopened_dialog(dialog, focusable, focused)
        dialog.children.append(FakeNode("Core status"))
        with self.assertRaisesRegex(RuntimeError, "Expected no accessible"):
            smoke.validate_reopened_dialog(dialog, focusable, focused)
        dialog.children.pop()
        controls[0].states = {focusable}
        controls[1].states = {focusable, focused}
        with self.assertRaisesRegex(RuntimeError, "initial focus changed"):
            smoke.validate_reopened_dialog(dialog, focusable, focused)

    def test_dialog_focus_requires_exact_order_and_single_initial_close(self):
        focusable, focused = "focusable", "focused"
        controls = [FakeNode(name, role=role, states={focusable})
                    for name, role in smoke.EXPECTED_FOCUS_ORDER]
        controls[0].states = {focusable, focused}
        dialog = FakeNode(children=controls)
        smoke.validate_dialog_focus(dialog, focusable, focused)
        dialog.children.reverse()
        with self.assertRaises(RuntimeError):
            smoke.validate_dialog_focus(dialog, focusable, focused)
        dialog.children.reverse()
        controls[1].states = {focusable, focused}
        with self.assertRaises(RuntimeError):
            smoke.validate_dialog_focus(dialog, focusable, focused)

    def test_application_selection_is_bound_to_spawned_pid(self):
        settings = lambda: FakeNode(children=[FakeNode("Open settings")])
        stale = settings()
        stale.pid = 41
        current = settings()
        current.pid = 42
        desktop = FakeNode(children=[stale, current])
        self.assertIs(smoke.application_for_pid(desktop, 42), current)
        with self.assertRaises(RuntimeError): smoke.application_for_pid(desktop, 43)
        with self.assertRaises(RuntimeError): smoke.application_for_pid(desktop, 1)
        duplicate = settings()
        duplicate.pid = 42
        desktop.children.append(duplicate)
        with self.assertRaises(RuntimeError): smoke.application_for_pid(desktop, 42)

    def test_wait_fails_immediately_when_packaged_process_exits(self):
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "exited with 23 while waiting for startup"):
            smoke.wait_for(lambda: (_ for _ in ()).throw(RuntimeError("missing")),
                           started + 10, "startup", process_poll=lambda: 23)
        self.assertLess(time.monotonic() - started, 0.5)

        with self.assertRaisesRegex(RuntimeError, "Timed out waiting for missing control"):
            smoke.wait_for(lambda: (_ for _ in ()).throw(RuntimeError("missing")),
                           time.monotonic() + 0.01, "missing control")

    def test_qemu_inventory_is_bounded_and_rejects_malformed_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pid, name in (("12", "qemu-system-x86_64\n"), ("13", "python3\n")):
                child = root / pid
                child.mkdir()
                (child / "comm").write_text(name)
                fields = ["S"] + ["0"] * 18 + ["100"]
                (child / "stat").write_text(f"{pid} (name with ) parenthesis) " + " ".join(fields) + "\n")
            before = smoke.qemu_processes(root)
            self.assertEqual(before, {(12, 100, "qemu-system-x86_64")})
            fields = ["S"] + ["0"] * 18 + ["101"]
            (root / "12" / "stat").write_text("12 (reused) " + " ".join(fields) + "\n")
            after = smoke.qemu_processes(root)
            self.assertEqual(after - before, {(12, 101, "qemu-system-x86_64")})
            (root / "12" / "comm").write_bytes(b"qemu-system-" + b"x" * 60 + b"\n")
            with self.assertRaises(RuntimeError): smoke.qemu_processes(root)
            (root / "12" / "comm").write_bytes(b"qemu-system-x86_64")
            with self.assertRaises(RuntimeError): smoke.qemu_processes(root)
            (root / "12" / "comm").write_text("qemu-system-x86_64\n")
            (root / "12" / "stat").write_text("12 (bad) S 0\n")
            with self.assertRaises(RuntimeError): smoke.qemu_processes(root)
            fields = ["S"] + ["0"] * 18 + ["100"]
            (root / "12" / "stat").write_text("99 (wrong pid) " + " ".join(fields) + "\n")
            with self.assertRaises(RuntimeError): smoke.qemu_processes(root)
            (root / "12" / "stat").write_text("12 (restored) " + " ".join(fields) + "\n")
            (root / "14").symlink_to(root / "12", target_is_directory=True)
            with self.assertRaises(RuntimeError): smoke.qemu_processes(root)
            (root / "14").unlink()
            link = root.parent / (root.name + "-link")
            link.symlink_to(root)
            try:
                with self.assertRaises(RuntimeError): smoke.qemu_processes(link)
            finally:
                link.unlink()

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
