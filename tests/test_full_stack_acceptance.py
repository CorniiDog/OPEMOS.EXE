"""Acceptance decision tests, not VM/USB/SteamOS acceptance evidence."""
import copy
from contextlib import redirect_stdout
from http.client import IncompleteRead
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("acceptance", Path(__file__).parents[1] / "scripts/check_full_stack_acceptance.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
SHA = "a" * 40


def run(identity=10):
    return {"id": identity, "head_sha": SHA, "head_branch": "main",
            "repository": {"full_name": gate.REPOSITORY}, "head_repository": {"full_name": gate.REPOSITORY},
            "path": gate.WORKFLOW, "name": "04 SteamOS", "event": "workflow_dispatch",
            "run_attempt": 2, "run_started_at": f"2026-10-19T12:00:{identity:02d}Z",
            "status": "completed", "conclusion": "success"}


def fixture():
    return {"runs": [run()], "jobs": [{"name": gate.JOB, "run_id": 10, "head_sha": SHA,
            "status": "completed", "conclusion": "success", "steps": [
                {"name": name, "status": "completed", "conclusion": "success"} for name in gate.PROOF_STEPS]}],
            "artifacts": [{"name": "robot-actual-10-2", "expired": False,
                           "size_in_bytes": 100, "digest": "sha256:" + "b" * 64}]}


def reader(value):
    calls = []

    def read(path):
        calls.append(path)
        if path.startswith("actions/workflows/"):
            rows = value.get("final_runs", value["runs"]) if len(calls) > 1 else value["runs"]
            return {"total_count": len(rows), "workflow_runs": copy.deepcopy(rows)}
        if "/jobs?" in path:
            return {"total_count": len(value["jobs"]), "jobs": copy.deepcopy(value["jobs"])}
        if "/artifacts?" in path:
            return {"total_count": len(value["artifacts"]), "artifacts": copy.deepcopy(value["artifacts"])}
        raise AssertionError(path)
    return read


class FullStackAcceptance(unittest.TestCase):
    def test_only_complete_same_commit_attempt_passes(self):
        result = gate.evaluate(reader(fixture()), SHA)
        self.assertEqual((result["status"], result["source_commit"], result["steamOS_run"], result["steamOS_attempt"]),
                         ("passed", SHA, 10, 2))

    def test_no_workflow_or_run_cannot_use_packaging_success(self):
        def absent(_):
            raise gate.Refusal("04 SteamOS is not installed")
        with self.assertRaises(gate.Refusal):
            gate.evaluate(absent, SHA)
        value = fixture()
        value["runs"] = []
        with self.assertRaises(gate.Refusal):
            gate.evaluate(reader(value), SHA)

    def test_latest_failed_pending_or_skipped_attempt_cannot_fall_back_to_green(self):
        for status, conclusion in [("completed", "failure"), ("in_progress", None), ("completed", "skipped")]:
            with self.subTest(status=status, conclusion=conclusion):
                value = fixture()
                newer = run(11)
                newer.update(status=status, conclusion=conclusion)
                value["runs"].append(newer)
                with self.assertRaises(gate.Refusal):
                    gate.evaluate(reader(value), SHA)

    def test_foreign_stale_branch_and_wrong_workflow_refused(self):
        for key, wrong in [("head_sha", "c" * 40), ("head_branch", "topic"),
                           ("head_repository", {"full_name": "foreign/fork"}),
                           ("path", ".github/workflows/windows-portable.yml"), ("event", "pull_request")]:
            with self.subTest(field=key):
                value = fixture()
                value["runs"][0][key] = wrong
                with self.assertRaises(gate.Refusal):
                    gate.evaluate(reader(value), SHA)

    def test_missing_ambiguous_or_skipped_actual_acceptance_job_refused(self):
        for mode in ["missing", "duplicate", "skipped", "wrong-source"]:
            with self.subTest(mode=mode):
                value = fixture()
                if mode == "missing": value["jobs"] = []
                if mode == "duplicate": value["jobs"] *= 2
                if mode == "skipped": value["jobs"][0]["conclusion"] = "skipped"
                if mode == "wrong-source": value["jobs"][0]["head_sha"] = "c" * 40
                with self.assertRaises(gate.Refusal):
                    gate.evaluate(reader(value), SHA)

    def test_missing_or_skipped_executable_and_vm_proof_steps_refused(self):
        for mode in ["missing", "skipped"]:
            with self.subTest(mode=mode):
                value = fixture()
                if mode == "missing": value["jobs"][0]["steps"].pop()
                else: value["jobs"][0]["steps"][0]["conclusion"] = "skipped"
                with self.assertRaises(gate.Refusal):
                    gate.evaluate(reader(value), SHA)

    def test_missing_expired_wrong_attempt_or_unbound_receipt_refused(self):
        for mode in ["missing", "expired", "old-attempt", "no-digest"]:
            with self.subTest(mode=mode):
                value = fixture()
                if mode == "missing": value["artifacts"] = []
                if mode == "expired": value["artifacts"][0]["expired"] = True
                if mode == "old-attempt": value["artifacts"][0]["name"] = "robot-actual-10-1"
                if mode == "no-digest": value["artifacts"][0].pop("digest")
                with self.assertRaises(gate.Refusal):
                    gate.evaluate(reader(value), SHA)

    def test_legacy_artifact_cannot_substitute_for_current_robot_receipt(self):
        value = fixture()
        value["artifacts"][0]["name"] = "steamos-acceptance-10-2"
        with self.assertRaises(gate.Refusal):
            gate.evaluate(reader(value), SHA)

    def test_new_run_or_rerun_during_inspection_refused(self):
        for changed in [run(11), {**run(), "run_attempt": 3}]:
            value = fixture()
            value["final_runs"] = [changed]
            with self.assertRaises(gate.Refusal):
                gate.evaluate(reader(value), SHA)

    def test_later_rerun_of_lower_run_id_cannot_reuse_newer_id_success(self):
        for status, conclusion in [("completed", "failure"), ("in_progress", None), ("queued", None)]:
            with self.subTest(status=status):
                value = fixture()
                older = {**run(9), "run_attempt": 3, "run_started_at": "2026-10-19T12:01:00Z",
                         "status": status, "conclusion": conclusion}
                value["runs"].append(older)
                with self.assertRaises(gate.Refusal): gate.evaluate(reader(value), SHA)

    def test_changes_to_unselected_attempt_inventory_refused(self):
        for field, changed in [("run_attempt", 3), ("conclusion", "failure"),
                               ("status", "in_progress"), ("head_branch", "topic")]:
            with self.subTest(field=field):
                value = fixture()
                value["runs"].append(run(9))
                value["final_runs"] = copy.deepcopy(value["runs"])
                value["final_runs"][1][field] = changed
                with self.assertRaises(gate.Refusal): gate.evaluate(reader(value), SHA)

    def test_lower_id_rerun_starting_between_samples_refused(self):
        value = fixture()
        value["runs"].append(run(9))
        value["final_runs"] = [run(), {**run(9), "run_attempt": 3,
            "run_started_at": "2026-10-19T12:01:00Z", "status": "in_progress", "conclusion": None}]
        with self.assertRaises(gate.Refusal): gate.evaluate(reader(value), SHA)

    def test_unchanged_historical_failure_does_not_poison_newer_success(self):
        value = fixture()
        value["runs"].append({**run(9), "conclusion": "failure"})
        self.assertEqual(gate.evaluate(reader(value), SHA)["status"], "passed")

    def test_attempt_order_missing_malformed_or_ambiguous_refused(self):
        for started in [None, "unknown", "2026-02-30T12:00:10Z", "2026-10-19T12:00:10Z"]:
            with self.subTest(started=started):
                value = fixture()
                value["runs"].append({**run(9), "run_started_at": started})
                with self.assertRaises(gate.Refusal): gate.evaluate(reader(value), SHA)

    def test_incomplete_run_inventory_cannot_hide_newer_failure(self):
        def read(_):
            return {"total_count": 101, "workflow_runs": [run()]}
        with self.assertRaises(gate.Refusal):
            gate.evaluate(read, SHA)

    def test_bounded_strict_json_refuses_overflow_duplicate_and_nonfinite(self):
        for raw in [b" " * (gate.MAX_RESPONSE + 1), b'{"id":1,"id":2}', b'{"n":NaN}']:
            with self.subTest(size=len(raw)):
                with self.assertRaises(gate.Refusal): gate.parse_response(raw)
        self.assertEqual(gate.parse_response(json.dumps({"status": "success"}).encode()), {"status": "success"})

    def test_workflow_run_cannot_green_current_main_from_an_older_commit(self):
        env = {"GITHUB_REPOSITORY": gate.REPOSITORY, "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": SHA,
               "GITHUB_EVENT_NAME": "workflow_run", "OPEMOS_UPSTREAM_SHA": "c" * 40,
               "OPEMOS_UPSTREAM_REPOSITORY": gate.REPOSITORY, "OPEMOS_UPSTREAM_ACTION": "completed"}
        with self.assertRaises(gate.Refusal): gate.event_target(env)
        env["OPEMOS_UPSTREAM_SHA"] = SHA
        self.assertEqual(gate.event_target(env), SHA)
        env["GITHUB_REF"] = "refs/pull/1/merge"
        with self.assertRaises(gate.Refusal): gate.event_target(env)

    def test_requested_or_running_event_refuses_previous_green_metadata(self):
        env = {"GITHUB_REPOSITORY": gate.REPOSITORY, "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": SHA,
               "GITHUB_EVENT_NAME": "workflow_run", "OPEMOS_UPSTREAM_SHA": SHA,
               "OPEMOS_UPSTREAM_REPOSITORY": gate.REPOSITORY}
        for action in ["requested", "in_progress", "unknown", None]:
            with self.subTest(action=action):
                env["OPEMOS_UPSTREAM_ACTION"] = action
                with self.assertRaises(gate.Refusal): gate.event_target(env)

    def _main_result(self):
        env = {"GITHUB_REPOSITORY": gate.REPOSITORY, "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": SHA,
               "GITHUB_EVENT_NAME": "push", "GITHUB_TOKEN": "PRIVATE_TEST_TOKEN"}
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, env, clear=True):
            previous = os.getcwd()
            try:
                os.chdir(directory)
                with redirect_stdout(output): numeric = gate.main()
                result = json.loads(Path("full-stack-acceptance.json").read_text())
            finally:
                os.chdir(previous)
        self.assertNotIn("PRIVATE_TEST_TOKEN", output.getvalue() + json.dumps(result))
        return numeric, result

    def test_main_retains_normal_positive_result(self):
        with mock.patch.object(gate, "api_reader", return_value=reader(fixture())):
            numeric, result = self._main_result()
        self.assertEqual((numeric, result["status"]), (0, "passed"))

    def test_incomplete_http_body_is_closed_and_retained_as_failed_result(self):
        class Response:
            closed = False
            def __enter__(self): return self
            def __exit__(self, *_): self.closed = True
            def read(self, _): raise IncompleteRead(b"PRIVATE_PARTIAL_BODY", 100)
        response = Response()
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(gate.request, "build_opener", return_value=opener):
            numeric, result = self._main_result()
        self.assertEqual((numeric, result["status"]), (1, "failed"))
        self.assertTrue(response.closed)
        self.assertIn("IncompleteRead", result["reason"])
        self.assertNotIn("PRIVATE_PARTIAL_BODY", json.dumps(result))

    def test_http_refusal_closes_body_and_retains_numeric_reason(self):
        for code in [404, 403]:
            with self.subTest(code=code):
                body = io.BytesIO(b"PRIVATE_ERROR_BODY")
                fault = gate.error.HTTPError("https://api.github.com/", code, "private", {}, body)
                opener = mock.Mock()
                opener.open.side_effect = fault
                with mock.patch.object(gate.request, "build_opener", return_value=opener):
                    numeric, result = self._main_result()
                self.assertEqual((numeric, result["status"]), (1, "failed"))
                self.assertTrue(body.closed)
                self.assertIn(str(code), result["reason"])
                self.assertNotIn("PRIVATE_ERROR_BODY", json.dumps(result))

    def test_redirect_refusal_closes_response_and_preserves_close_failure(self):
        body = io.BytesIO(b"PRIVATE_REDIRECT_BODY")
        with self.assertRaises(gate.Refusal):
            gate.NoRedirect().redirect_request(None, body, 302, None, {}, "https://foreign.invalid/")
        self.assertTrue(body.closed)
        broken = mock.Mock()
        broken.close.side_effect = OSError("PRIVATE_CLOSE_DETAIL")
        with self.assertRaises(gate.Refusal) as result:
            gate.NoRedirect().redirect_request(None, broken, 302, None, {}, "https://foreign.invalid/")
        self.assertIn("redirected", str(result.exception))
        self.assertIn("close failed: OSError", str(result.exception))
        self.assertNotIn("PRIVATE_CLOSE_DETAIL", str(result.exception))


if __name__ == "__main__":
    unittest.main()
