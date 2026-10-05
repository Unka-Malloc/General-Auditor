"""Scope and entrypoint integration against synthetic Git objects."""
import io
import os
import json
import unittest
import tempfile
import subprocess
from contextlib import redirect_stdout
from pathlib import Path
from tests.test_auditor import git
from general_auditor.cli import main
from general_auditor.scanner import scan
from general_auditor.config import default_profile, load_profile
from general_auditor.review import create_review_request
from tests.test_review import valid_receipt


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-b", "main")
        git(self.repo, "config", "user.name", "Synthetic")
        git(self.repo, "config", "user.email", "synthetic@example.invalid")

    def save(self, path, value):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)

    def commit(self):
        git(self.repo, "add", ".")
        git(self.repo, "commit", "--allow-empty", "-m", "Synthetic change")
        return git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()

    def audit(self, **kwargs):
        return scan(self.repo, "SymPolicy/Synthetic", policy_root=self.root, **kwargs)

    def test_staged_and_worktree_are_independent_inputs(self):
        self.commit()
        self.save('value.env', 'PASSWORD="FAKE_STAGED_MATERIAL_983"\n')
        git(self.repo, 'add', 'value.env')
        self.save('value.env', 'plain text\n')
        staged = self.audit(scope='staged')
        worktree = self.audit(scope='worktree')
        self.assertTrue(staged['findings'])
        self.assertFalse(worktree['findings'])
        self.assertEqual(staged['scope'], 'staged')
        self.assertTrue(all(row['commit'] is None for row in staged['findings']))
        self.assertEqual(staged['coverage']['commit_ids'], [])
        self.assertEqual(staged['local_review_files'][0]['commits'], [])
        create_review_request(staged)
        create_review_request(worktree)

    def test_subdirectory_invocation_retains_whole_repository_scope(self):
        base = self.commit()
        self.save('root.env', 'PASSWORD="SYNTHETIC_ROOT_SIGNAL"\n')
        self.save('nested/ordinary.txt', 'plain text')
        self.commit()
        for scope in ('snapshot', 'history', 'range', 'staged', 'worktree'):
            with self.subTest(scope=scope):
                options = {'base': base} if scope == 'range' else {}
                result = scan(self.repo / 'nested', 'SymPolicy/Synthetic', policy_root=self.root, scope=scope, **options)
                self.assertTrue(any(row['file'] == 'root.env' for row in result['findings']))
                self.assertEqual({row['path'] for row in result['local_review_files']}, {'root.env', 'nested/ordinary.txt'})

    def test_local_scopes_before_first_commit_have_no_false_baseline(self):
        self.save('first.env', 'PASSWORD="SYNTHETIC_FIRST_COMMIT"\n')
        git(self.repo, 'add', 'first.env')
        for scope in ('staged', 'worktree'):
            result = self.audit(scope=scope)
            self.assertIsNone(result['head'])
            self.assertEqual(result['coverage']['commit_ids'], [])
            self.assertTrue(result['findings'])
            self.assertTrue(all(row['commit'] is None for row in result['findings']))
            create_review_request(result)

    def test_bare_repository_snapshot_retains_object_scope(self):
        self.save('source.env', 'PASSWORD="SYNTHETIC_BARE_SIGNAL"\n')
        self.commit()
        bare = self.root / 'bare.git'
        git(self.root, 'clone', '--bare', str(self.repo), str(bare))
        result = scan(bare, 'SymPolicy/Synthetic', policy_root=self.root)
        self.assertEqual(result['scope'], 'snapshot')
        self.assertTrue(any(row['file'] == 'source.env' for row in result['findings']))

    def test_history_retains_deleted_outgoing_content_and_large_text(self):
        self.save('secret.env', 'PASSWORD="FAKE_HISTORY_MATERIAL_983"\n')
        first = self.commit()
        (self.repo / 'secret.env').unlink()
        self.save('large.txt', 'ordinary text\n' * 170000 + 'PASSWORD="FAKE_LARGE_MATERIAL_983"\n')
        self.commit()
        result = self.audit(scope='history')
        self.assertTrue(any(row['commit'] == first and row['file'] == 'secret.env' for row in result['findings']))
        self.assertTrue(any(row['file'] == 'large.txt' for row in result['findings']))
        self.assertFalse(result['coverage']['excluded'])
        create_review_request(result)

    def test_composite_action_auto_and_history_scopes_use_same_cli(self):
        self.save('sample.txt', 'synthetic base')
        base = self.commit()
        self.save('sample.txt', 'synthetic next')
        head = self.commit()
        auditor = Path(__file__).resolve().parents[1]
        action = (auditor / 'action.yml').read_text()
        script = '\n'.join(line[8:] for line in action.split('      run: |\n', 1)[1].splitlines())
        event = self.root / 'event.json'
        event.write_text('{}')
        for scope, expected in [('auto', 'commit-range'), ('history', 'history')]:
            output = self.root / (scope + '.json')
            env = dict(os.environ, AUDITOR_PATH=str(auditor), AUDIT_REPOSITORY='SymPolicy/Synthetic', AUDIT_DIRECTORY=str(self.repo), AUDIT_HEAD=head, AUDIT_BASE=base, AUDIT_SCOPE=scope, AUDIT_OUTPUT=str(output), AUDIT_TRIGGER='push', AUDIT_EVENT=str(event))
            completed = subprocess.run(['bash', '-e'], input=script, text=True, capture_output=True, env=env, cwd=self.repo)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(output.read_text())['scope'], expected)

    def test_removed_historical_data_files_retain_their_format_policy(self):
        base = self.commit()
        (self.repo / 'removed.db').write_bytes(b'SQLite format 3\x00synthetic')
        self.save('removed.csv', 'column\nsynthetic\n')
        self.save('removed.json', '{"synthetic": true}')
        introduced = self.commit()
        for name in ('removed.db', 'removed.csv', 'removed.json'):
            (self.repo / name).unlink()
        self.commit()
        profile = default_profile('SymPolicy/Synthetic')
        profile['repository_policy'] = {'data_profile': 'common'}
        for options in ({'scope': 'history'}, {'base': base}):
            result = self.audit(profile=profile, **options)
            findings = {row['file']: row for row in result['findings']}
            self.assertEqual(result['status'], 'policy_failure')
            self.assertEqual(findings['removed.db']['severity'], 'error')
            self.assertEqual(findings['removed.csv']['severity'], 'error')
            self.assertEqual(findings['removed.json']['severity'], 'warning')
            self.assertTrue(all(row['commit'] == introduced for row in findings.values()))
            self.assertIn('repository.data-file-admission', result['coverage']['policy']['blocking'])

    def test_historical_data_policy_does_not_duplicate_final_tree_findings(self):
        self.save('retained.csv', 'column\nsynthetic\n')
        self.commit()
        profile = default_profile('SymPolicy/Synthetic')
        profile['repository_policy'] = {'data_profile': 'common'}
        result = self.audit(scope='history', profile=profile)
        self.assertEqual(len(result['findings']), 1)

    def test_trusted_fixture_admissions_remain_effective_across_scope_states(self):
        policy_root = Path(__file__).resolve().parents[1]
        profile, _ = load_profile(policy_root, 'LicoLand/LicoUp')
        paths = ['tests/integration/v71_usage_sources/fixtures/otlp-' + case + '.json'
                 for case in ('cumulative', 'regressed', 'restarted')]
        paths.append('docs/functionality/ui-interactions.json')
        # Exercise only the selected production data contract, avoiding unrelated
        # LicoUp tree requirements in this intentionally small Git repository.
        profile['required_paths'] = []
        profile['repository_policy'] = {key: value for key, value in profile['repository_policy'].items()
                                        if key in {'data_profile', 'json_admissions', 'schema_fixtures'}}
        base = self.commit()
        for path in paths:
            self.save(path, '{"points": []}')
        worktree = scan(self.repo, 'LicoLand/LicoUp', profile=profile, scope='worktree')
        self.assertFalse(any(row['file'] in paths for row in worktree['findings']))
        self.commit()
        for path in paths:
            (self.repo / path).unlink()
        self.commit()
        result = scan(self.repo, 'LicoLand/LicoUp', profile=profile, base=base)
        self.assertFalse(result['coverage']['policy']['blocking'])
        self.assertFalse(any(row['file'] in paths for row in result['findings']))

    def test_historical_attribution_retains_removed_files_and_actual_commit_identity(self):
        self.save('AUTHORS', 'Cursor\n')
        git(self.repo, 'add', '.')
        git(self.repo, 'commit', '-m', 'Synthetic change\n\nGenerated-by: Cursor')
        first = git(self.repo, 'rev-parse', 'HEAD').stdout.decode().strip()
        (self.repo / 'AUTHORS').unlink()
        self.commit()
        result = self.audit(scope='history')
        source = [row for row in result['findings'] if row['rule'] == 'contribution.cursor-attribution']
        metadata = [row for row in result['findings'] if row['rule'] == 'contribution.commit-attribution']
        self.assertEqual([(row['file'], row['commit']) for row in source], [('AUTHORS', first)])
        self.assertEqual([row['commit'] for row in metadata], [first])
        self.assertIn('contribution.cursor-attribution', result['rule_ids'])
        self.assertEqual(result['status'], 'completed_with_warnings')

    def test_policy_failure_is_distinct_from_advisory_and_incomplete(self):
        self.commit()
        profile = default_profile('SymPolicy/Synthetic')
        profile['required_paths'] = ['explicit-required-contract']
        result = self.audit(profile=profile)
        self.assertEqual(result['status'], 'policy_failure')
        path = self.root / 'profile.json'
        path.write_text(json.dumps(profile))
        with redirect_stdout(io.StringIO()):
            status = main(['scan', '--directory', str(self.repo), '--repository', 'SymPolicy/Synthetic', '--profile', str(path), '--output', str(self.root / 'result.json')])
        self.assertEqual(status, 2)

    def test_review_cli_preserves_source_result_and_produces_local_html(self):
        self.save('secret.env', 'PASSWORD="FAKE_REVIEW_MATERIAL_983"\n')
        self.commit()
        result = self.audit()
        source = self.root / 'scan.json'
        source.write_text(json.dumps(result))
        request = self.root / 'request.json'
        template = self.root / 'template.json'
        receipt = self.root / 'receipt.json'
        receipt.write_text(json.dumps(valid_receipt(result)))
        output = self.root / 'review.json'
        html = self.root / 'review.html'
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(['review-request', '--scan', str(source), '--output', str(request), '--template', str(template)]), 0)
            self.assertEqual(main(['review-complete', '--scan', str(source), '--receipt', str(receipt), '--output', str(output), '--html', str(html)]), 0)
        self.assertEqual(json.loads(source.read_text())['agent_review'], 'not_performed')
        self.assertEqual(json.loads(output.read_text())['publication'], 'local_only')
        self.assertIn('Local contextual review', html.read_text())
        self.assertNotIn('FAKE_REVIEW_MATERIAL_983', html.read_text())
