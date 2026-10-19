"""Acceptance decision tests, not VM/USB/SteamOS acceptance evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("acceptance", Path(__file__).parents[1] / "scripts/check_full_stack_acceptance.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
SHA = "a" * 40


def run(identity=10):
    return {"id": identity, "head_sha": SHA, "head_branch": "main",
            "repository": {"full_name": gate.REPOSITORY}, "head_repository": {"full_name": gate.REPOSITORY},
            "path": gate.WORKFLOW, "name": "04 SteamOS", "event": "workflow_dispatch",
            "run_attempt": 2, "status": "completed", "conclusion": "success"}


def fixture():
    return {"runs": [run()], "jobs": [{"name": gate.JOB, "run_id": 10, "head_sha": SHA,
            "status": "completed", "conclusion": "success", "steps": [
                {"name": name, "status": "completed", "conclusion": "success"} for name in gate.PROOF_STEPS]}],
            "artifacts": [{"name": "steamos-acceptance-10-2", "expired": False,
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
                if mode == "old-attempt": value["artifacts"][0]["name"] = "steamos-acceptance-10-1"
                if mode == "no-digest": value["artifacts"][0].pop("digest")
                with self.assertRaises(gate.Refusal):
                    gate.evaluate(reader(value), SHA)

    def test_new_run_or_rerun_during_inspection_refused(self):
        for changed in [run(11), {**run(), "run_attempt": 3}]:
            value = fixture()
            value["final_runs"] = [changed]
            with self.assertRaises(gate.Refusal):
                gate.evaluate(reader(value), SHA)

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
               "OPEMOS_UPSTREAM_REPOSITORY": gate.REPOSITORY}
        with self.assertRaises(gate.Refusal): gate.event_target(env)
        env["OPEMOS_UPSTREAM_SHA"] = SHA
        self.assertEqual(gate.event_target(env), SHA)
        env["GITHUB_REF"] = "refs/pull/1/merge"
        with self.assertRaises(gate.Refusal): gate.event_target(env)


if __name__ == "__main__":
    unittest.main()
