"""Concurrency, incremental persistence and artifact recovery contracts."""

from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
from threading import Event
import unittest
from unittest.mock import Mock, patch

from general_auditor.github import APIError
from general_auditor.pipeline import Actions, assemble, coordinate, merge_result, result_name
from general_auditor.report import read_json, write_json
from general_auditor.runner import run
from general_auditor.scanner import failed_result
from tools.check_contribution import validate


def inventory():
    return [{"repository": "LicoLand/" + name, "default_branch": "only", "visibility": "public", "archived": False} for name in ("A", "B")]


def packet(name, *, age=0, head="a"):
    repository = "LicoLand/" + name
    time = (datetime.now(timezone.utc) - timedelta(seconds=age)).isoformat()
    result = failed_result(repository, head * 40, "branch")
    result.pop("error")
    result.update(status="completed", finished_at=time)
    return {"repository": repository, "observed_at": time, "runs": [result], "observations": {repository + ":branch:only": head * 40}}


class ConcurrencyTests(unittest.TestCase):
    def test_completed_repository_is_persisted_while_another_is_still_running(self):
        ready, release = Event(), Event()
        a, b = packet("A"), packet("B")

        def scan(root, row, observations, **kwargs):
            if row["repository"] == "LicoLand/B":
                ready.set()
                if not release.wait(10):
                    raise AssertionError("Fast result was blocked behind slow repository")
                return b["runs"], b["observations"]
            self.assertTrue(ready.wait(10))
            return a["runs"], a["observations"]

        def persisted(root, repository, results):
            if repository == "LicoLand/A":
                ledger = read_json(root / "reports/data.json", None)
                self.assertEqual({row["repository"] for row in ledger["runs"]}, {"LicoLand/A"})
                release.set()

        with tempfile.TemporaryDirectory() as directory, patch("general_auditor.runner.audit_repository", side_effect=scan), redirect_stdout(io.StringIO()):
            try:
                summary = run(directory, repository="all", api=Mock(repositories=lambda: inventory()), on_repository=persisted)
                self.assertEqual(summary["scans"], 2)
            finally:
                release.set()

    def test_discovery_dispatches_ready_repository_without_waiting_for_slow_metadata(self):
        ready, release = Event(), Event()
        dispatched = []

        def candidates(repository, branch):
            if repository.endswith("/A"):
                ready.set()
                self.assertTrue(release.wait(10), "Dispatcher waited for all discovery results")
            else:
                self.assertTrue(ready.wait(10))
            return [{"repository": repository, "key": repository + ":branch:only", "head": "a" * 40, "base": None, "trigger": "branch"}]

        def dispatch(workflow, inputs):
            dispatched.append(inputs["repository"])
            release.set()

        api = Mock(repositories=lambda: inventory(), candidates=candidates)
        actions = Mock(restore=lambda root: None, dispatch=dispatch)
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            try:
                result = coordinate(directory, api=api, actions=actions)
            finally:
                release.set()
        self.assertEqual(dispatched, ["LicoLand/B", "LicoLand/A"])
        self.assertEqual(result["incomplete"], 0)

    def test_one_dispatch_failure_does_not_prevent_other_repositories(self):
        api = Mock(repositories=lambda: inventory(), candidates=lambda name, branch: [])
        actions = Mock(restore=lambda root: None)
        actions.dispatch.side_effect = lambda workflow, inputs: (_ for _ in ()).throw(APIError("unavailable")) if inputs["repository"].endswith("/A") else None
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            result = coordinate(directory, force=True, api=api, actions=actions)
        self.assertEqual(result["dispatched"], ["LicoLand/B"])
        self.assertEqual(result["dispatch_failures"], ["LicoLand/A"])

    def test_visibility_change_requests_publication_without_scanning_removed_repositories(self):
        api = Mock(repositories=lambda: [])
        actions = Mock(restore=lambda root: None)
        with tempfile.TemporaryDirectory() as directory:
            write_json(Path(directory) / "reports/inventory.json", {"repositories": inventory()})
            result = coordinate(directory, api=api, actions=actions)
        actions.dispatch.assert_called_once_with("publish-report.yml", {})
        self.assertEqual(result["dispatched"], [])
        api.candidates.assert_not_called()


class PersistenceTests(unittest.TestCase):
    def test_independent_results_and_out_of_order_delivery_cannot_overwrite_new_heads(self):
        old, new, other = packet("A", age=60), packet("A", head="b"), packet("B")
        with tempfile.TemporaryDirectory() as directory:
            for item in (new, other, old, new):
                merge_result(directory, item, {"LicoLand/A", "LicoLand/B"})
            root = Path(directory) / "reports"
            self.assertEqual(len(read_json(root / "data.json", None)["runs"]), 3)
            self.assertEqual(read_json(root / "state.json", None)["observations"], {**new["observations"], **other["observations"]})

    def test_cross_repository_or_private_artifact_is_rejected_before_persistence(self):
        for field in ("scope", "privacy", "observations"):
            item = packet("A")
            if field == "scope":
                item["runs"][0]["repository"] = "LicoLand/B"
            elif field == "privacy":
                item["runs"][0]["visibility"] = "private"
            else:
                item["observations"] = {"LicoLand/B:branch:only": "a" * 40}
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                merge_result(directory, item, {"LicoLand/A", "LicoLand/B"})

    def test_publisher_recovers_durable_results_without_completion_events_and_replay_is_idempotent(self):
        packets = {1: packet("A"), 2: packet("B")}
        artifacts = [{"id": identity, "name": result_name(item["repository"]), "created_at": item["observed_at"]} for identity, item in packets.items()]
        actions = Mock(restore=lambda root: None, artifacts=lambda: iter(artifacts))
        actions.read.side_effect = lambda row, names: {"result.json": packets[row["id"]]}
        api = Mock(repositories=lambda: inventory())
        with tempfile.TemporaryDirectory() as directory:
            first = assemble(directory, api=api, actions=actions)
            second = assemble(directory, api=api, actions=actions)
            self.assertEqual(first["retained_runs"], 2)
            self.assertEqual(second["retained_runs"], 2)
            self.assertEqual(actions.read.call_count, 2)
            self.assertIn("2 repositories", (Path(directory) / "reports/index.html").read_text())

    def test_artifact_discovery_excludes_pr_branches_forks_and_expired_results(self):
        valid = {"id": 1, "expired": False, "workflow_run": {"head_branch": "only", "head_repository_id": 8, "repository_id": 8}}
        rows = [valid, {**valid, "expired": True}, {**valid, "workflow_run": {**valid["workflow_run"], "head_branch": "work/untrusted"}}, {**valid, "workflow_run": {**valid["workflow_run"], "head_repository_id": 9}}]
        actions = Actions()
        with patch.object(actions, "request", return_value={"artifacts": rows}):
            self.assertEqual(list(actions.artifacts()), [valid])

    def test_duplicate_completion_skips_deployment_but_missing_worker_artifact_is_reported(self):
        actions = Mock(restore=lambda root: None, artifacts=lambda: iter([]))
        api = Mock(repositories=lambda: inventory())
        event = {"workflow_run": {"id": 123, "run_attempt": 1, "display_title": "Audit repository · LicoLand/A", "conclusion": "success", "updated_at": datetime.now(timezone.utc).isoformat()}}
        with tempfile.TemporaryDirectory() as directory:
            assemble(directory, api=api, actions=actions)
            self.assertFalse(assemble(directory, api=api, actions=actions, event=event)["changed"])
            event["workflow_run"]["conclusion"] = "failure"
            self.assertTrue(assemble(directory, api=api, actions=actions, event=event)["changed"])
            rows = read_json(Path(directory) / "reports/data.json", None)["runs"]
            self.assertEqual(rows[0]["error"], "repository_workflow_failed")


class ContributionTests(unittest.TestCase):
    def test_only_named_maintainer_from_temporary_upstream_branch_can_contribute(self):
        from copy import deepcopy
        event = {"repository": {"full_name": "Owner/Auditor"}, "pull_request": {"base": {"ref": "only"}, "head": {"ref": "work/fix", "repo": {"full_name": "Owner/Auditor"}}, "user": {"login": "Owner"}}}
        validate(event, ["Owner"])
        changes = [lambda p: p["base"].update(ref="main"), lambda p: p["head"].update(ref="main"), lambda p: p["head"].update(repo={"full_name": "Other/Fork"}), lambda p: p["user"].update(login="Other")]
        for change in changes:
            altered = deepcopy(event)
            change(altered["pull_request"])
            with self.assertRaises(ValueError):
                validate(altered, ["Owner"])


if __name__ == "__main__":
    unittest.main()
