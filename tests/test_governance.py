"""Settings enforcement, role boundaries and read-only API visibility."""

from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from general_auditor.governance import expected_ruleset, violations
from general_auditor.config import default_profile
from general_auditor.github import APIError, GitHub
from general_auditor.governance import check_repository
from tools.check_contribution import validate


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

    def test_selected_repository_governance_checks_only_its_metadata(self):
        api = GitHub(token="")
        profile = {**default_profile("LicoLand/Synthetic"), "category": "website"}
        issues = [("governance.bypass-visibility", "Bypass identities are unavailable to the reader.")]
        with patch.object(api, "access_policy", return_value=issues) as inspect:
            result = check_repository("LicoLand/Synthetic", profile, "a" * 40, api=api)
        inspect.assert_called_once_with("LicoLand/Synthetic")
        self.assertEqual(result[0]["judgment"], "unverified")
        self.assertEqual(result[0]["source"], "github-settings")
        with patch.object(api, "access_policy") as inspect:
            self.assertEqual(check_repository("LicoLand/Synthetic", default_profile("LicoLand/Synthetic"), "a" * 40, api=api), [])
        inspect.assert_not_called()

    def test_unavailable_governance_metadata_is_not_confirmed_drift(self):
        api = GitHub(token="")
        profile = {**default_profile("LicoLand/Synthetic"), "category": "website"}
        with patch.object(api, "access_policy", side_effect=APIError("synthetic request failure")):
            findings = check_repository("LicoLand/Synthetic", profile, "a" * 40, api=api)
        self.assertEqual(findings[0]["judgment"], "unverified")
        self.assertEqual(findings[0]["rule"], "governance.verification-unavailable")
        self.assertNotIn("synthetic request failure", str(findings))

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
