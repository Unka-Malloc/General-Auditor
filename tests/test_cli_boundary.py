"""The CI entry point never persists or prints source evidence."""
import io
import json
import os
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

from general_auditor.cli import main


class CliBoundaryTests(unittest.TestCase):
    def test_local_commands_reject_ci_before_source_or_storage_access(self):
        for command in ('scan', 'review-request', 'review-complete'):
            args = [command, '--directory', '/synthetic/unread']
            if command == 'scan':
                args += ['--repository', 'SymPolicy/Synthetic']
            with self.subTest(command=command), patch.dict(os.environ, {'CI': 'true'}), \
                    patch('general_auditor.cli.scan') as scan, \
                    redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(main(args), 1)
                scan.assert_not_called()
                self.assertEqual(stdout.getvalue(), '')
                self.assertNotIn('/synthetic/unread', stderr.getvalue())

    def test_check_whitelists_summary_and_disables_source_capture(self):
        secret = 'SYNTHETIC_DO_NOT_PRINT_23848'
        result = {'status': 'completed_with_warnings', 'head': 'synthetic',
                  'findings': [{'source_evidence': {'matched_text': secret}}],
                  'agent_review': 'not_performed'}
        with patch('general_auditor.cli.scan', return_value=result) as scan, \
                patch('general_auditor.governance.check_repository', return_value=[]), \
                patch('general_auditor.local_store.LocalStore') as store, \
                redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(main(['check', '--repository', 'SymPolicy/Synthetic']), 0)
            self.assertFalse(scan.call_args.kwargs['include_source'])
            store.assert_not_called()
            self.assertEqual(json.loads(stdout.getvalue()), {
                'status': 'completed_with_warnings', 'findings': 1, 'agent_review': 'not_performed'})
            self.assertNotIn(secret, stdout.getvalue())

    def test_unverified_governance_does_not_pass(self):
        result = {'status': 'completed', 'head': 'synthetic', 'findings': [], 'agent_review': 'not_performed'}
        with patch('general_auditor.cli.scan', return_value=result), \
                patch('general_auditor.governance.check_repository', return_value=[{'judgment': 'unverified'}]), \
                redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(main(['check', '--repository', 'SymPolicy/Synthetic']), 1)
            self.assertEqual(json.loads(stdout.getvalue())['status'], 'incomplete')

    def test_errors_do_not_echo_source_exception(self):
        with patch('general_auditor.cli.scan', side_effect=ValueError('SYNTHETIC_PRIVATE_VALUE')), \
                redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(main(['check', '--repository', 'SymPolicy/Synthetic']), 1)
            self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', stderr.getvalue())
