"""Concurrency, incremental persistence and artifact recovery contracts."""

from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess
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

    def test_completion_burst_coalesces_and_skips_repeated_archive_walks(self):
        packets = {1: packet("A"), 2: packet("B")}
        artifacts = [{"id": identity, "name": result_name(item["repository"]), "created_at": item["observed_at"], "workflow_run": {"id": identity}} for identity, item in packets.items()]
        actions = Mock(restore=lambda root: None)
        actions.artifacts.side_effect = lambda: iter(artifacts)
        actions.read.side_effect = lambda row, names: {"result.json": packets[row["id"]]}
        actions.worker_completion.side_effect = lambda run_id: {"id": int(run_id), "conclusion": "success"}
        event = {"inputs": {"source_run_id": "1"}}
        api = Mock(repositories=lambda: inventory())
        with tempfile.TemporaryDirectory() as directory:
            first = assemble(directory, api=api, actions=actions, event=event)
            self.assertTrue(first["changed"])
            self.assertEqual(first["retained_runs"], 2)
            event["inputs"]["source_run_id"] = "2"
            second = assemble(directory, api=api, actions=actions, event=event)
            self.assertFalse(second["changed"])
            self.assertEqual(actions.artifacts.call_count, 1)
            self.assertEqual(actions.read.call_count, 2)
            # Reconciliation still walks durable state when events are missing.
            assemble(directory, api=api, actions=actions)
            self.assertEqual(actions.artifacts.call_count, 2)

    def test_artifact_discovery_excludes_pr_branches_forks_and_expired_results(self):
        valid = {"id": 1, "expired": False, "workflow_run": {"head_branch": "only", "head_repository_id": 8, "repository_id": 8}}
        rows = [valid, {**valid, "expired": True}, {**valid, "workflow_run": {**valid["workflow_run"], "head_branch": "work/untrusted"}}, {**valid, "workflow_run": {**valid["workflow_run"], "head_repository_id": 9}}]
        actions = Actions()
        with patch.object(actions, "request", return_value={"artifacts": rows}):
            self.assertEqual(list(actions.artifacts()), [valid])

    def test_duplicate_completion_skips_deployment_but_missing_worker_artifact_is_reported(self):
        actions = Mock(restore=lambda root: None, artifacts=lambda **kwargs: iter([]))
        api = Mock(repositories=lambda: inventory())
        worker = {"id": 123, "run_attempt": 1, "display_title": "Audit repository · LicoLand/A", "conclusion": "success", "updated_at": datetime.now(timezone.utc).isoformat()}
        actions.worker_completion.return_value = worker
        event = {"inputs": {"source_run_id": "123"}}
        with tempfile.TemporaryDirectory() as directory:
            assemble(directory, api=api, actions=actions)
            self.assertFalse(assemble(directory, api=api, actions=actions, event=event)["changed"])
            worker["conclusion"] = "failure"
            self.assertTrue(assemble(directory, api=api, actions=actions, event=event)["changed"])
            rows = read_json(Path(directory) / "reports/data.json", None)["runs"]
            self.assertEqual(rows[0]["error"], "repository_workflow_failed")


class WorkerNotificationTests(unittest.TestCase):
    def worker(self, **changes):
        from general_auditor.pipeline import CENTRAL
        return {"id": 123, "run_attempt": 2, "path": ".github/workflows/audit-repository.yml",
                "event": "workflow_dispatch", "head_branch": "only",
                "repository": {"full_name": CENTRAL}, "head_repository": {"full_name": CENTRAL},
                "status": "completed", "conclusion": "failure", "updated_at": "2026-10-05T10:00:00Z",
                "display_title": "Audit repository · LicoLand/A", **changes}

    def test_notification_resolves_actual_worker_metadata_not_supplied_outcomes(self):
        actions = Actions()
        with patch.object(actions, "request", return_value=self.worker()) as request:
            self.assertEqual(actions.worker_completion("123"), self.worker())
            request.assert_called_once_with("/actions/runs/123")

    def test_notification_rejects_invalid_or_untrusted_source_runs(self):
        actions = Actions()
        for identity in ("../other", "-1", "0", "１２３", 123):
            with self.subTest(identity=identity), patch.object(actions, "request") as request:
                with self.assertRaises(ValueError): actions.worker_completion(identity)
                request.assert_not_called()
        for changes in ({"path": ".github/workflows/verify.yml"}, {"head_branch": "work/untrusted"},
                        {"event": "pull_request"}, {"repository": {"full_name": "Other/Source"}},
                        {"head_repository": {"full_name": "Other/Fork"}}):
            with self.subTest(changes=changes), patch.object(actions, "request", return_value=self.worker(**changes)):
                with self.assertRaises(ValueError): actions.worker_completion("123")

    def test_publication_can_start_while_notifier_finishes_without_guessing_scan_state(self):
        actions = Actions()
        worker = self.worker(status="in_progress", conclusion=None)
        for outcome in ("success", "failure", "cancelled"):
            jobs = {"jobs": [{"name": "scan", "status": "completed", "conclusion": outcome,
                              "completed_at": "2026-10-05T10:01:00Z"},
                             {"name": "notify", "status": "in_progress", "conclusion": None}]}
            with self.subTest(outcome=outcome), patch.object(actions, "request", side_effect=[worker, jobs]) as request:
                result = actions.worker_completion("123")
                self.assertEqual(result["conclusion"], outcome)
                self.assertEqual(result["updated_at"], "2026-10-05T10:01:00Z")
                self.assertEqual(request.call_args.args, ("/actions/runs/123/attempts/2/jobs?per_page=100",))
        with patch.object(actions, "request", side_effect=[worker, {"jobs": [{"name": "scan", "status": "in_progress"}]}]):
            self.assertEqual(actions.worker_completion("123"), {})

    def test_actual_workflow_notifier_dispatches_after_scan_with_only_its_own_write_token(self):
        root = Path(__file__).resolve().parents[1]
        worker = (root / ".github/workflows/audit-repository.yml").read_text()
        publisher = (root / ".github/workflows/publish-report.yml").read_text()
        scanner, notifier = worker.split("  notify:\n", 1)
        self.assertIn("  actions: read", scanner)
        self.assertNotIn("actions: write", scanner)
        self.assertIn("    needs: scan", notifier)
        self.assertIn("if: always() && github.ref == 'refs/heads/only'", notifier)
        self.assertIn("    permissions:\n      actions: write", notifier)
        self.assertNotIn("checkout", notifier)
        self.assertNotIn("  workflow_run:", publisher)
        self.assertIn("      source_run_id:", publisher)
        script = "\n".join(line[10:] for line in notifier.split("        run: |\n", 1)[1].splitlines())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "gh"
            executable.write_text('#!/bin/sh\ncat > "$NOTIFY_BODY"\nprintf "%s\\n" "$@" > "$NOTIFY_ARGS"\n')
            executable.chmod(0o755)
            environment = {**os.environ, "PATH": directory + os.pathsep + os.environ["PATH"],
                           "GITHUB_RUN_ID": "123", "GITHUB_REPOSITORY": "Unka-Malloc/General-Auditor",
                           "NOTIFY_BODY": str(root / "body"), "NOTIFY_ARGS": str(root / "args")}
            subprocess.run(["bash", "-e", "-c", script], env=environment, check=True, capture_output=True)
            self.assertEqual(json.loads((root / "body").read_text()), {"ref": "only", "inputs": {"source_run_id": "123"}})
            self.assertEqual((root / "args").read_text().splitlines(), ["api", "--method", "POST",
                "repos/Unka-Malloc/General-Auditor/actions/workflows/publish-report.yml/dispatches", "--input", "-"])


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
