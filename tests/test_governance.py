"""Settings enforcement, role boundaries and read-only API visibility."""

from copy import deepcopy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from general_auditor.governance import expected_ruleset, violations
from general_auditor.config import default_profile
from general_auditor.github import GitHub
from general_auditor.runner import run


class AccessPolicyTests(unittest.TestCase):
    metadata = {"has_pull_requests": True, "pull_request_creation_policy": "collaborators_only", "permissions": {"admin": True}}

    def test_maintainers_are_allowed_but_writers_cannot_bypass(self):
        policy = expected_ruleset()
        self.assertEqual({row["actor_id"] for row in policy["bypass_actors"] if row["actor_type"] == "RepositoryRole"}, {2, 5})
        self.assertEqual(violations(self.metadata, policy), [])
        policy["bypass_actors"].append({"actor_type": "RepositoryRole", "actor_id": 4, "bypass_mode": "always"})
        self.assertEqual(violations(self.metadata, policy)[0][0], "governance.maintainer-branches")

    def test_public_api_omission_is_not_a_false_configuration_verdict(self):
        policy = expected_ruleset()
        del policy["bypass_actors"]
        self.assertEqual([rule for rule, _ in violations(self.metadata, policy)], ["governance.bypass-visibility"])

    def test_partial_branches_disabled_rules_and_upstream_bypass_are_detected(self):
        mutations = [
            lambda p: p.update(enforcement="disabled"),
            lambda p: p["conditions"]["ref_name"].update(include=["~DEFAULT_BRANCH"]),
            lambda p: p["conditions"]["ref_name"].update(exclude=["refs/heads/unprotected"]),
            lambda p: p["rules"][1]["parameters"].update(update_allows_fetch_and_merge=True),
        ]
        for change in mutations:
            with self.subTest(change=change):
                policy = expected_ruleset()
                change(policy)
                self.assertTrue(violations(self.metadata, policy))

    def test_external_pr_access_and_disabled_prs_are_detected(self):
        for metadata in [{**self.metadata, "pull_request_creation_policy": "all"}, {**self.metadata, "has_pull_requests": False}]:
            self.assertEqual(violations(metadata, expected_ruleset())[0][0], "governance.pull-request-access")

    def test_selected_repository_governance_is_reported_without_auditing_others(self):
        api = GitHub(token="")
        repository = "LicoLand/A"
        inventory = [{"repository": "LicoLand/" + name, "default_branch": "main", "archived": False, "visibility": "public"} for name in ("A", "B")]
        candidate = {"repository": repository, "key": repository + ":empty", "head": None, "base": None, "trigger": "empty_repository"}
        issues = [("governance.bypass-visibility", "Bypass identities are unavailable to the reader.")]
        with tempfile.TemporaryDirectory() as directory, patch.object(api, "repositories", return_value=inventory), patch.object(api, "candidates", return_value=[candidate]) as discover, patch.object(api, "access_policy", return_value=issues) as inspect, redirect_stdout(io.StringIO()):
            root = Path(directory)
            for name in ("A", "B"):
                path = root / ("profiles/LicoLand/" + name + ".json")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({**default_profile("LicoLand/" + name), "category": "website"}))
            result = run(root, repository=repository, api=api)
            ledger = json.loads((root / "reports/data.json").read_text())
            html = (root / "reports/index.html").read_text()
        discover.assert_called_once_with(repository, "main")
        inspect.assert_called_once_with(repository)
        self.assertEqual(result["incomplete"], 0)
        self.assertEqual(ledger["runs"][0]["status"], "completed_with_warnings")
        self.assertEqual(ledger["runs"][0]["findings"][0]["judgment"], "unverified")
        self.assertEqual(ledger["runs"][0]["findings"][0]["source"], "github-settings")
        self.assertIn('data-repository="LicoLand/A"', html)

    def test_admin_tool_is_read_only_by_default_and_preserves_unrelated_rules(self):
        path = Path(__file__).resolve().parents[1] / "tools/configure_access.py"
        spec = importlib.util.spec_from_file_location("configure_access", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        state = {"metadata": {**self.metadata, "pull_request_creation_policy": "all"}, "ruleset": None}
        writes = []
        def api(endpoint, method="GET", payload=None):
            if method != "GET":
                writes.append((endpoint, method))
                if method == "PATCH":
                    state["metadata"].update(payload)
                    return state["metadata"]
                if method == "POST":
                    state["ruleset"] = {**deepcopy(payload), "id": 2}
                    return state["ruleset"]
                self.fail("Existing unrelated Ruleset must not be overwritten")
            if endpoint.endswith("/rulesets/2"):
                return state["ruleset"]
            if endpoint.endswith("/rulesets"):
                return [{"id": 1, "name": "Existing review gate"}] + ([state["ruleset"]] if state["ruleset"] else [])
            return state["metadata"]
        with patch.object(module, "api", side_effect=api):
            self.assertEqual(module.configure("LicoLand/Synthetic")["status"], "changes_required")
            self.assertEqual(writes, [])
            self.assertEqual(module.configure("LicoLand/Synthetic", apply=True)["status"], "compliant")
        self.assertEqual(writes, [("repos/LicoLand/Synthetic", "PATCH"), ("repos/LicoLand/Synthetic/rulesets", "POST")])


if __name__ == "__main__":
    unittest.main()
