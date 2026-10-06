"""Deterministic acceptance coverage using only synthetic temporary repositories."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from general_auditor.config import default_profile, initialize, load_profile, repository_name, validate_profile
from general_auditor.gitdata import git
from general_auditor.scanner import BlobAnalysis, scan
from general_auditor.rules import selected_rules


class GitFixture(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repo = self.root / "target"
        self.repo.mkdir()
        git(self.repo, "init", "--quiet", "-b", "main")
        git(self.repo, "config", "user.name", "Synthetic Test")
        git(self.repo, "config", "user.email", "test@example.invalid")

    def save(self, path, content):
        file = self.repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content if isinstance(content, bytes) else content.encode())

    def commit(self):
        git(self.repo, "add", ".")
        git(self.repo, "commit", "--quiet", "--allow-empty", "-m", "synthetic fixture")
        return git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()

    def audit(self, **options):
        return scan(self.repo, "SymPolicy/Synthetic", policy_root=self.root, **options)

    def test_missing_layout_uses_mandatory_common_policy_and_never_echoes_values(self):
        secret = "SYNTHETIC_NOT_A_VALID_CREDENTIAL_927"
        self.save("unusual/notes.data", 'api_key = "' + secret + '"\n')
        self.commit()
        result = self.audit(profile={**default_profile("SymPolicy/Synthetic"), "additional_rule_groups": []})
        self.assertEqual(result["status"], "completed_with_warnings")
        self.assertEqual(result["findings"][0]["line"], 1)
        self.assertEqual(result["findings"][0]["rule"], "privacy.credential.binding")
        self.assertEqual(result["findings"][0]["judgment"], "unreviewed")
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(result["agent_review"], "not_performed")
        self.assertFalse(any(row["rule"] == "repository.required-path" for row in result["findings"]))

    def test_intermediate_secret_is_seen_even_when_removed_before_head(self):
        self.save("entry", "synthetic base\n")
        base = self.commit()
        self.save("removed.env", "API_KEY=SYNTHETIC_INVALID_TOKEN_381\n")
        introduced = self.commit()
        (self.repo / "removed.env").unlink()
        self.save("entry", "synthetic final\n")
        self.commit()
        result = self.audit(base=base)
        hit = next(row for row in result["findings"] if row["file"] == "removed.env")
        self.assertEqual(hit["commit"], introduced)
        self.assertEqual(result["coverage"]["commits"], 2)
        self.assertEqual(result["scope"], "commit-range")

    def test_diverged_pr_uses_common_ancestor_and_includes_transient_changes(self):
        base = self.commit()
        git(self.repo, "checkout", "--quiet", "-b", "candidate")
        self.save("candidate.env", "PASSWORD=SYNTHETIC_INVALID_PASSWORD\n")
        self.commit()
        (self.repo / "candidate.env").unlink()
        head = self.commit()
        git(self.repo, "checkout", "--quiet", "main")
        self.save("base-update", "synthetic upstream change")
        advanced = self.commit()
        result = self.audit(head=head, base=advanced)
        self.assertEqual(result["base"], base)
        self.assertEqual(result["scope"], "commit-range-after-divergence")
        self.assertTrue(result["findings"])

    def test_exclusions_do_not_follow_symlinks_or_execute_target(self):
        external = self.root / "outside"
        external.write_text('password="SYNTHETIC_OUTSIDE_VALUE"')
        (self.repo / "link").symlink_to(external)
        self.save("blob", b"binary\0data")
        self.save("large", b"z" * (2 * 1024 * 1024 + 1))
        self.save("lfs", "version https://git-lfs.github.com/spec/v1\noid sha256:synthetic\nsize 5\n")
        self.save("danger.py", 'raise RuntimeError("target code must never execute")\n')
        self.commit()
        result = self.audit()
        self.assertEqual(len(result["coverage"]["excluded"]), 3)
        self.assertEqual(result["coverage"]["text_versions"], 2)
        self.assertEqual(result["findings"], [])
        self.assertNotIn(str(self.root), json.dumps(result))


    def test_action_entry_does_not_import_target_python_modules(self):
        self.save("json.py", 'raise RuntimeError("untrusted module executed")\n')
        self.save("general_auditor/__init__.py", 'raise RuntimeError("untrusted module executed")\n')
        self.commit()
        entry = Path(__file__).resolve().parents[1] / "action_entry.py"
        import sys
        process = subprocess.run([sys.executable, "-I", str(entry), "check", "--repository", "LicoLand/Synthetic"], cwd=self.repo, capture_output=True)
        self.assertEqual(process.returncode, 0)
        self.assertFalse((self.root / "action.json").exists())

    def test_only_current_repository_profile_is_loaded(self):
        self.commit()
        initialize(self.root, "SymPolicy/Synthetic", profile_only=True)
        other = self.root / "profiles/SymPolicy/Other.json"
        other.write_text("intentionally invalid unrelated policy")
        profile, source = load_profile(self.root, "SymPolicy/Synthetic")
        profile["required_paths"] = ["specific.contract"]
        result = self.audit(profile=profile)
        self.assertEqual(source, "repository")
        self.assertEqual([row["file"] for row in result["findings"]], ["specific.contract"])


    def test_blob_analysis_is_reused_across_heads_without_losing_commit_locations(self):
        self.save("settings", 'password="SYNTHETIC_INVALID_PASSWORD"')
        first = self.commit()
        self.save("other", "synthetic branch change")
        second = self.commit()
        with BlobAnalysis(self.repo, selected_rules([])) as analysis:
            original = self.audit(head=first, analysis=analysis)
            updated = self.audit(head=second, analysis=analysis)
            self.assertGreaterEqual(analysis.inspect.cache_info().hits, 1)
            self.assertEqual(original["findings"][0]["commit"], first)
            self.assertEqual(updated["findings"][0]["commit"], second)
            self.assertEqual(original["findings"][0]["evidence"], updated["findings"][0]["evidence"])


class PolicyAndReportTests(unittest.TestCase):
    def test_initialize_is_non_destructive_and_fills_missing_template_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            created = initialize(root, "LicoLand/Synthetic")
            self.assertIn(".general-auditor/config.json", created)
            self.assertIn("/.general-auditor/local/", (root / ".gitignore").read_text().splitlines())
            path = root / ".general-auditor/config.json"
            profile = json.loads(path.read_text())
            profile["required_paths"] = ["owned.asset"]
            path.write_text(json.dumps(profile))
            created = initialize(root, "LicoLand/Synthetic", with_workflow=True)
            self.assertEqual(created, [".github/workflows/general-auditor.yml"])
            self.assertEqual(json.loads(path.read_text())["required_paths"], ["owned.asset"])
            self.assertEqual(initialize(root, "LicoLand/Synthetic", with_workflow=True), [])
            self.assertFalse((root / "src").exists())
            self.assertFalse((root / "docs").exists())

    def test_initialize_from_nested_directory_ignores_only_local_reports_at_git_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git(root, "init", "--quiet")
            nested = root / "custom" / "layout"
            nested.mkdir(parents=True)
            (root / ".gitignore").write_text("existing.asset\n")
            initialize(nested, "LicoLand/Synthetic", with_workflow=True)
            self.assertTrue((root / ".general-auditor/config.json").is_file())
            self.assertFalse((nested / ".general-auditor").exists())
            self.assertEqual(git(root, "check-ignore", ".general-auditor/local/report.html").returncode, 0)
            self.assertNotEqual(git(root, "check-ignore", ".general-auditor/config.json", check=False).returncode, 0)
            self.assertTrue((root / ".gitignore").read_text().startswith("existing.asset\n"))

    def test_profile_cannot_disable_common_rules_or_escape_owner_directory(self):
        for name in ["../repo", "owner/..", "owner/repo/child", "-x;invalid"]:
            with self.assertRaises(ValueError):
                repository_name(name)
        profile = default_profile("LicoLand/Synthetic")
        profile["disable_common"] = True
        with self.assertRaises(ValueError):
            validate_profile(profile, "LicoLand/Synthetic")


if __name__ == "__main__":
    unittest.main()
