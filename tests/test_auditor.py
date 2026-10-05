"""Deterministic acceptance coverage using only synthetic temporary repositories."""

from contextlib import nullcontext, redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from general_auditor.cli import main
from general_auditor.config import default_profile, initialize, load_profile, repository_name, validate_profile
from general_auditor.github import APIError, GitHub
from general_auditor.gitdata import git
from general_auditor.report import merge, publish, unpack_report, write_json
from general_auditor.runner import execute, plan, run
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

    def test_cli_advisories_exit_zero_and_explicit_bad_config_fails(self):
        self.save("file.txt", 'password="SYNTHETIC_INVALID_VALUE"\n')
        self.commit()
        arguments = ["scan", "--repository", "SymPolicy/Synthetic", "--directory", str(self.repo), "--policy-root", str(self.root), "--output", str(self.root / "result.json")]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(arguments + ["--html", str(self.root / "local.html")]), 0)
        self.assertEqual(json.loads((self.root / "result.json").read_text())["visibility"], "private")
        self.assertIn("Local audit report. No result is published", (self.root / "local.html").read_text())
        with patch("sys.stderr", io.StringIO()):
            self.assertEqual(main(arguments + ["--profile", str(self.root / "missing.json")]), 1)

    def test_action_entry_does_not_import_target_python_modules(self):
        self.save("json.py", 'raise RuntimeError("untrusted module executed")\n')
        self.save("general_auditor/__init__.py", 'raise RuntimeError("untrusted module executed")\n')
        self.commit()
        entry = Path(__file__).resolve().parents[1] / "action_entry.py"
        import sys
        process = subprocess.run([sys.executable, "-I", str(entry), "scan", "--repository", "LicoLand/Synthetic", "--output", str(self.root / "action.json")], cwd=self.repo, capture_output=True)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(json.loads((self.root / "action.json").read_text())["status"], "completed")

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

    def test_public_html_and_json_are_redacted_and_html_escapes_filenames(self):
        secret = "SYNTHETIC_INVALID_PASSWORD_731"
        self.save("<script>alert(1)</script>.txt", 'password="' + secret + '"')
        self.commit()
        result = self.audit(visibility="public")
        publish(self.root / "reports", [result], inventory={"SymPolicy/Synthetic"})
        html = (self.root / "reports/index.html").read_text()
        self.assertNotIn(secret, html)
        self.assertNotIn(secret, (self.root / "reports/data.json").read_text())
        self.assertNotIn("<script>alert(1)", html)
        payload = html.split('<script id="audit-data" type="application/json">', 1)[1].split('</script>', 1)[0]
        packed = json.loads(payload)
        self.assertEqual(unpack_report(packed), json.loads((self.root / "reports/data.json").read_text()))

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

    def test_repository_worker_scans_real_git_objects_and_persists_its_result(self):
        self.save("source.txt", 'password="SYNTHETIC_WORKER_SIGNAL"\n')
        head = self.commit()
        repository = "SymPolicy/Synthetic"
        candidate = {"repository": repository, "key": repository + ":branch:main",
                     "head": head, "base": None, "trigger": "branch"}
        api = GitHub(token="")
        inventory = [{"repository": repository, "default_branch": "main", "visibility": "public", "archived": False}]
        with patch.object(api, "repositories", return_value=inventory), patch.object(api, "candidates", return_value=[candidate]), \
                patch("general_auditor.runner.public_repository", return_value=nullcontext(self.repo)) as fetch, \
                redirect_stdout(io.StringIO()):
            result = run(self.root, repository=repository, api=api)
        fetch.assert_called_once()
        self.assertEqual(result["scans"], 1)
        self.assertEqual(result["incomplete"], 0)
        ledger = json.loads((self.root / "reports/data.json").read_text())
        self.assertEqual(ledger["runs"][0]["status"], "completed_with_warnings")
        self.assertEqual(ledger["runs"][0]["findings"][0]["commit"], head)
        self.assertNotIn("SYNTHETIC_WORKER_SIGNAL", json.dumps(ledger))
        state = json.loads((self.root / "reports/state.json").read_text())
        self.assertEqual(state["observations"], {candidate["key"]: head})
        self.assertTrue((self.root / "reports/index.html").is_file())

    def test_failed_policy_artifact_round_trip_restores_worker_and_publisher(self):
        from io import BytesIO
        from urllib.parse import parse_qs, urlsplit
        from zipfile import ZipFile
        from general_auditor.pipeline import Actions, audit, assemble, result_name

        class ArtifactStore(Actions):
            def __init__(self):
                self.records, self.archives = [], {}

            def add(self, name, members):
                identity = len(self.records) + 1
                buffer = BytesIO()
                with ZipFile(buffer, 'w') as archive:
                    for member, value in members.items():
                        archive.writestr(member, json.dumps(value))
                self.archives[identity] = buffer.getvalue()
                self.records.append({'id': identity, 'name': name, 'expired': False,
                    'created_at': datetime.now(timezone.utc).isoformat(),
                    'workflow_run': {'id': identity, 'head_branch': 'only',
                                     'head_repository_id': 1, 'repository_id': 1}})

            def request(self, path, **kwargs):
                if path.endswith('/zip'):
                    return self.archives[int(path.split('/')[-2])]
                name = parse_qs(urlsplit(path).query).get('name', [None])[0]
                return {'artifacts': [row for row in self.records if name is None or row['name'] == name]}

        self.save('source.env', 'password="SYNTHETIC_ARTIFACT_SIGNAL"\n')
        head = self.commit()
        repository = 'SymPolicy/Synthetic'
        profile = default_profile(repository)
        profile['required_paths'] = ['missing.contract']
        write_json(self.root / 'profiles/SymPolicy/Synthetic.json', profile)
        inventory = [{'repository': repository, 'default_branch': 'main', 'visibility': 'public', 'archived': False}]
        candidate = {'repository': repository, 'key': repository + ':branch:main',
                     'head': head, 'base': None, 'trigger': 'branch'}
        api, actions = GitHub(token=''), ArtifactStore()
        with patch.object(api, 'repositories', return_value=inventory), patch.object(api, 'candidates', return_value=[candidate]), \
                patch('general_auditor.runner.public_repository', return_value=nullcontext(self.repo)) as fetch, redirect_stdout(io.StringIO()):
            with patch('general_auditor.report.render', side_effect=AssertionError('Artifact workers must not render HTML')) as render:
                result = audit(self.root, repository, api=api, actions=actions)
            render.assert_not_called()
            self.assertFalse((self.root / 'reports/index.html').exists())
            self.assertEqual(result['policy_failures'], 1)
            packet = json.loads((self.root / 'out/result/result.json').read_text())
            self.assertEqual(packet['runs'][0]['status'], 'policy_failure')
            actions.add(result_name(repository), {'result.json': packet})
            publisher = self.root / 'publisher'
            self.assertTrue(assemble(publisher, api=api, actions=actions)['changed'])
            reports = publisher / 'reports'
            self.assertNotIn('SYNTHETIC_ARTIFACT_SIGNAL', (reports / 'index.html').read_text())
            checkpoint = {name: json.loads((reports / name).read_text()) for name in ('data.json', 'state.json', 'inventory.json')}
            actions.add('audit-checkpoint', checkpoint)
            recovered = self.root / 'recovered-worker'
            with patch('general_auditor.report.render', side_effect=AssertionError('Recovered workers must not render HTML')) as render:
                second = audit(recovered, repository, api=api, actions=actions)
            render.assert_not_called()
            self.assertEqual(second['scans'], 0)
            retained = json.loads((recovered / 'out/result/result.json').read_text())
            self.assertEqual(retained['runs'], packet['runs'])
            self.assertEqual(retained['observations'], packet['observations'])
            fetch.assert_called_once()


class PolicyAndReportTests(unittest.TestCase):
    def test_output_write_replaces_symlink_without_following_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "preserve"
            outside.write_text("synthetic existing data")
            destination = root / "result.json"
            destination.symlink_to(outside)
            (root / "result.json.tmp").symlink_to(outside)
            write_json(destination, {"redacted": True})
            self.assertEqual(outside.read_text(), "synthetic existing data")
            self.assertEqual(json.loads(destination.read_text()), {"redacted": True})

    def test_initialize_is_non_destructive_and_fills_missing_template_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            created = initialize(root, "LicoLand/Synthetic")
            self.assertIn(".general-auditor/config.json", created)
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

    def test_profile_cannot_disable_common_rules_or_escape_owner_directory(self):
        for name in ["../repo", "owner/..", "owner/repo/child", "-x;invalid"]:
            with self.assertRaises(ValueError):
                repository_name(name)
        profile = default_profile("LicoLand/Synthetic")
        profile["disable_common"] = True
        with self.assertRaises(ValueError):
            validate_profile(profile, "LicoLand/Synthetic")

    def test_retention_dedup_and_visibility(self):
        now = datetime(2026, 10, 6, tzinfo=timezone.utc)
        def row(identity, age):
            return {"id": identity, "repository": "LicoLand/Synthetic", "visibility": "public", "finished_at": (now - age).isoformat()}
        old = row("old", timedelta(days=30, seconds=1))
        boundary = row("boundary", timedelta(days=30))
        recent = row("recent", timedelta(days=1))
        ledger = merge({"runs": [old, boundary, recent]}, [recent], now=now)
        self.assertEqual([r["id"] for r in ledger["runs"]], ["recent", "boundary"])
        self.assertEqual(merge(ledger, [], now=now, public_repositories=set())["runs"], [])
        with self.assertRaises(ValueError):
            merge({"runs": []}, [{**recent, "visibility": "private"}], now=now)


class DiscoveryTests(unittest.TestCase):
    def test_empty_public_repository_is_reported_and_observed_once(self):
        api = GitHub(token="")
        with patch.object(api, "pages", return_value=[]):
            candidates = api.candidates("LicoLand/Synthetic", "main")
        jobs = plan(candidates, {})
        self.assertEqual(len(jobs), 1)
        with tempfile.TemporaryDirectory() as directory:
            result = execute(jobs[0], directory)
        self.assertEqual(result["scope"], "empty-repository")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(plan(candidates, {candidates[0]["key"]: None}), [])

    def test_manual_repository_selection_never_discovers_other_repository_heads(self):
        api = GitHub(token="")
        inventory = [{"repository": "LicoLand/" + name, "default_branch": "main", "archived": False, "visibility": "public"} for name in ["A", "B"]]
        with tempfile.TemporaryDirectory() as directory, patch.object(api, "repositories", return_value=inventory), patch.object(api, "candidates", return_value=[]) as candidates:
            other = Path(directory) / "profiles/LicoLand/B.json"
            other.parent.mkdir(parents=True)
            other.write_text("invalid unrelated profile")
            result = run(directory, repository="LicoLand/A", api=api)
        candidates.assert_called_once_with("LicoLand/A", "main")
        self.assertEqual(result["repositories"], 1)

    def test_bad_selected_profile_does_not_block_other_selected_repositories(self):
        api = GitHub(token="")
        inventory = [{"repository": "LicoLand/" + name, "default_branch": "main", "archived": False, "visibility": "public"} for name in ["A", "B"]]
        candidates = [[{"repository": row["repository"], "key": row["repository"] + ":empty", "head": None, "base": None, "trigger": "empty_repository"}] for row in inventory]
        with tempfile.TemporaryDirectory() as directory, patch.object(api, "repositories", return_value=inventory), patch.object(api, "candidates", side_effect=lambda name, branch: next(items for items in candidates if items[0]["repository"] == name)), redirect_stdout(io.StringIO()):
            broken = Path(directory) / "profiles/LicoLand/B.json"
            broken.parent.mkdir(parents=True)
            broken.write_text("invalid selected profile")
            result = run(directory, repository="all", api=api)
            ledger = json.loads((Path(directory) / "reports/data.json").read_text())
        self.assertEqual(result["incomplete"], 1)
        statuses = {row["repository"]: row["status"] for row in ledger["runs"]}
        self.assertEqual(statuses, {"LicoLand/A": "completed", "LicoLand/B": "incomplete"})

    def test_pagination_and_private_inventory_exclusion(self):
        api = GitHub(token="")
        with patch.object(api, "get", side_effect=[list(range(100)), [100]]) as request:
            self.assertEqual(len(list(api.pages("/synthetic"))), 101)
            self.assertEqual(request.call_args.kwargs["page"], 2)
        with patch.object(api, "pages", side_effect=[[
            {"full_name": "SymPolicy/Public", "private": False, "visibility": "public", "default_branch": "release", "archived": False},
            {"full_name": "SymPolicy/Private", "private": True, "visibility": "private"}], [], []]):
            self.assertEqual([row["repository"] for row in api.repositories()], ["SymPolicy/Public"])

    def test_only_changed_repository_heads_are_scheduled(self):
        a = {"repository": "LicoLand/A", "key": "LicoLand/A:branch:release", "head": "b" * 40, "base": None, "trigger": "branch"}
        b = {"repository": "LicoLand/B", "key": "LicoLand/B:branch:main", "head": "c" * 40, "base": None, "trigger": "branch"}
        jobs = plan([a, b], {a["key"]: "a" * 40, b["key"]: b["head"]})
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["repository"], "LicoLand/A")
        self.assertEqual(jobs[0]["base"], "a" * 40)

    def test_shared_head_is_scanned_once_per_repository_and_scope(self):
        candidate = {"repository": "LicoLand/A", "key": "LicoLand/A:branch:main", "head": "a" * 40, "base": None, "trigger": "branch"}
        jobs = plan([candidate, {**candidate, "key": "LicoLand/A:branch:stable"}], {})
        self.assertEqual(len(jobs), 1)
        self.assertEqual(len(jobs[0]["keys"]), 2)

    def test_failed_scans_are_not_acknowledged_and_retry_without_other_repositories(self):
        api = GitHub(token="")
        repository = "LicoLand/Synthetic"
        item = {"repository": repository, "default_branch": "main", "archived": False, "visibility": "public"}
        candidate = {"repository": repository, "key": repository + ":branch:main", "head": "a" * 40, "base": None, "trigger": "branch"}
        from general_auditor.scanner import failed_result
        failure = failed_result(repository, candidate["head"], "branch")
        with tempfile.TemporaryDirectory() as directory, patch.object(api, "repositories", return_value=[item]), patch.object(api, "candidates", return_value=[candidate]), patch("general_auditor.runner.audit_repository", return_value=([failure], {})) as execute, redirect_stdout(io.StringIO()):
            self.assertEqual(run(directory, watch=True, api=api)["incomplete"], 1)
            state = json.loads((Path(directory) / "reports/state.json").read_text())
            self.assertEqual(state["observations"], {})
            self.assertEqual(run(directory, watch=True, api=api)["incomplete"], 1)
            self.assertEqual(execute.call_count, 2)

    def test_prs_include_fork_heads_but_skip_private_sources(self):
        api = GitHub(token="")
        branch = {"name": "main", "commit": {"sha": "a" * 40}}
        pull = {"number": 1, "head": {"sha": "b" * 40, "repo": {"private": False}}, "base": {"sha": "a" * 40}}
        with patch.object(api, "pages", side_effect=[[branch], [pull, {**pull, "number": 2, "head": {"sha": "c" * 40, "repo": {"private": True}}}]]):
            candidates = api.candidates("LicoLand/Synthetic", "main")
        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[1]["trigger"], "pull_request")


if __name__ == "__main__":
    unittest.main()
