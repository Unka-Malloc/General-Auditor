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
from general_auditor.config import default_profile
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
        create_review_request(staged)
        create_review_request(worktree)

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
