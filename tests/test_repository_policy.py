import json
from pathlib import Path
import unittest
from unittest.mock import patch

from general_auditor.config import default_profile, load_profile, validate_profile
from general_auditor.repository_policy import evaluate


class RepositoryPolicyTests(unittest.TestCase):
    def run_policy(self, policy, files, **event):
        profile = default_profile('Example/Source')
        profile['repository_policy'] = policy
        rows = [{'path': p, 'size': len(t), 'kind': 'blob', 'mode': '100644'} for p,t in files.items()]
        return evaluate('Example/Source', profile, rows, files.__getitem__, {'head':'a'*40,'branch_refs':[], 'commit_metadata':[], **event})

    def test_profiles_validate(self):
        root = Path(__file__).resolve().parents[1]
        for path in (root/'profiles').glob('*/*.json'):
            with self.subTest(profile=path.name):
                load_profile(root, path.parent.name+'/'+path.stem)

    def test_unavailable_ignore_engine_records_incomplete_coverage(self):
        with patch('general_auditor.repository_policy._ignored_candidates', side_effect=ValueError('unavailable')):
            result = self.run_policy({'documentation_profile': 'lico-project'}, {'.gitignore': 'docs/plans/\n'})
        rule = 'repository.documentation-local-asset-ignore'
        self.assertIn(rule, result['coverage']['evaluated'])
        self.assertTrue(any(row['rule'] == rule for row in result['coverage']['incomplete']))
        self.assertFalse(any(row['rule'] == rule for row in result['findings']))

    def test_exact_admission_and_shape_are_enforced(self):
        policy={'data_profile':'common','json_admissions':[{'path':'configuration.json','kind':'string-map'}]}
        good=self.run_policy(policy,{'configuration.json':'{"name":"example"}'})
        self.assertFalse(good['coverage']['blocking'])
        bad=self.run_policy(policy,{'configuration.json':'{"name":12}', 'unapproved.json':'{}'})
        self.assertEqual({f['rule'] for f in bad['findings']},{'repository.json-shape-invalid','repository.json-not-allowlisted'})

    def test_duplicate_json_is_not_accepted(self):
        result=self.run_policy({'data_profile':'common'},{'package.json':'{"name":"a","name":"b"}'})
        self.assertIn('repository.json-invalid',result['coverage']['blocking'])

    def test_large_text_is_evaluated_without_scan_cutoff(self):
        text=json.dumps({'name':'x'*(3*1024*1024)})
        result=self.run_policy({'data_profile':'common'},{'package.json':text})
        self.assertFalse(result['coverage']['incomplete'])
        self.assertFalse(result['coverage']['blocking'])

    def test_structural_hygiene_and_content_signals_differ(self):
        result=self.run_policy({'hygiene_profile':'styio-default','server_boundary':{'required_manifest_groups':[]}}, {'cache.log':'anything','sample.py':'os.system(command)'})
        self.assertIn('repository.hygiene',result['coverage']['blocking'])
        warnings=[x for x in result['findings'] if x['rule']=='repository.server-security-signal']
        self.assertTrue(warnings)
        self.assertTrue(all(x['severity']=='warning' for x in warnings))
        self.assertNotIn('repository.server-security-signal',result['coverage']['blocking'])

    def test_content_policy_signals_retain_actual_source_lines(self):
        files = {'sample.py': '# Synthetic marker\nos.system(command)\n',
                 'package.json': '{\n"description":"commercial license"\n}'}
        result = self.run_policy({'server_boundary': {'required_manifest_groups': []},
                                  'dependencies': {'boundary_files': ['DEPENDENCY-USAGE.md']}}, files)
        signals = [row for row in result['findings'] if row['severity'] == 'warning']
        self.assertEqual({(row['file'], row['line']) for row in signals}, {('sample.py', 2), ('package.json', 2)})

    def test_schema_fixture_cannot_admit_runtime_rows(self):
        policy={'data_profile':'licoup','schema_fixtures':['tests/synthetic.sql']}
        good=self.run_policy(policy,{'tests/synthetic.sql':'CREATE TABLE sample (id INTEGER);'})
        self.assertFalse(good['coverage']['blocking'])
        bad=self.run_policy(policy,{'tests/synthetic.sql':'CREATE TABLE sample (id INTEGER); INSERT INTO sample VALUES (1);'})
        self.assertIn('repository.data-file-admission',bad['coverage']['blocking'])

    def test_branch_rules_only_apply_to_selected_profile(self):
        self.assertFalse(self.run_policy({}, {}, trigger='pull_request',base_ref='main',head_ref='feature')['coverage']['blocking'])
        policy={'branch':{'development_bases':['nightly'],'pr_flows':[{'head':'nightly','base':'stable'},{'head':'stable','base':'release'}]}}
        self.assertFalse(self.run_policy(policy,{},trigger='pull_request',base_ref='nightly',head_ref='feature')['coverage']['blocking'])
        self.assertIn('repository.branch-promotion-flow',self.run_policy(policy,{},trigger='pull_request',base_ref='release',head_ref='feature')['coverage']['blocking'])

    def test_required_ci_job_detects_missing_gate(self):
        policy={'ci_contract':{'test_gates':{'smoke':'test / smoke'}}}
        result=self.run_policy(policy,{'.github/workflows/test.yml':'name: Testing\njobs:\n  smoke:\n    name: test / smoke\n    runs-on: ubuntu-latest\n'})
        self.assertFalse(result['coverage']['blocking'])
        self.assertIn('repository.ci-gate-contract',self.run_policy(policy,{})['coverage']['blocking'])

    def test_defect_closure_evidence_not_just_closed_label(self):
        policy={'defect_records':{'root':'docs/audit/defects','required_audit_fields':['**Evidence:**'],'required_closure_fields':['**Closure evidence:**'],'closed_statuses':['closed']}}
        result=self.run_policy(policy,{'docs/audit/defects/item.md':'**Status:** closed\n**Evidence:** observed\n**Closure evidence:** TBD'})
        self.assertIn('repository.defect-record-closure',result['coverage']['blocking'])

    def test_missing_required_public_path_is_a_violation(self):
        profile=default_profile('Example/Source');profile['required_paths']=['public-contract.md']
        result=evaluate('Example/Source',profile,[],lambda path:None,{'branch_refs':[],'commit_metadata':[]})
        self.assertIn('repository.required-path',result['coverage']['blocking'])

    def test_invalid_resource_transition_rejected(self):
        profile=default_profile('Example/Source')
        profile['repository_policy']={'resource_contracts':[{'id':'resource'}]}
        with self.assertRaises(ValueError):validate_profile(profile,'Example/Source')

    def test_repository_scope_has_independent_public_domain_admissions(self):
        root=Path(__file__).resolve().parents[1]
        profile,_=load_profile(root,'Meshrix-Platform/meshrix.io')
        self.assertEqual({'meshrix.io','img.shields.io'},{x['host'] for x in profile['privacy_policy']['privacy_domain_allowlist']})
        blank=default_profile('Example/Source')
        self.assertFalse(blank['privacy_policy'])


class DocumentationAndAttributionTests(unittest.TestCase):
    run_policy = RepositoryPolicyTests.run_policy
    def test_named_action_step_satisfies_workflow_contract(self):
        workflow = """name: General-Auditor
on:
  pull_request:
  push:
jobs:
  audit:
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Audit selected repository
        uses: Unka-Malloc/General-Auditor@only
"""
        result = self.run_policy({'require_workflow': True}, {'.github/workflows/general-auditor.yml': workflow})
        self.assertFalse(result['coverage']['blocking'])

    def test_documentation_contract_retains_missing_and_broken_link_evidence(self):
        files = {'README.md': '# Public project', 'README.zh-CN.md': '# Overview', 'docs/README.md': '[missing](missing.md)'}
        result = self.run_policy({'documentation_profile': 'lico-project'}, files)
        rules = {row['rule'] for row in result['findings']}
        self.assertIn('repository.documentation-readme-cross-link', rules)
        self.assertIn('repository.documentation-required-section', rules)
        self.assertIn('repository.documentation-link-target', rules)
        link = next(row for row in result['findings'] if row['rule'] == 'repository.documentation-link-target')
        self.assertEqual(link['severity'], 'error')
        self.assertEqual(link['file'], 'docs/README.md')
        self.assertEqual(link['line'], 1)
        self.assertFalse(self.run_policy({}, files)['coverage']['blocking'])

    def test_contribution_metadata_is_advisory_and_source_values_withheld(self):
        result = self.run_policy({}, {'AUTHORS.md': '# Contributors\nCursor <redacted@example.invalid>\n'}, branch_refs=['refs/heads/codex/sample'], commit_metadata=[{'author': 'Cursor <author@example.invalid>', 'committer': 'Synthetic <committer@example.invalid>', 'trailers': []}])
        rules = {row['rule'] for row in result['findings']}
        self.assertEqual(rules, {'contribution.cursor-attribution', 'contribution.commit-attribution', 'contribution.branch-prefix'})
        self.assertFalse(result['coverage']['blocking'])
        self.assertNotIn('redacted@example.invalid', json.dumps(result))
        self.assertTrue(all(row['severity'] == 'warning' for row in result['findings']))
        ordinary = self.run_policy({}, {'README.md': 'A cursor selects a character in the editor.'}, branch_refs=['refs/heads/work/edit'])
        self.assertFalse(ordinary['findings'])


class DocumentationPolicyParityTests(unittest.TestCase):
    def evaluate_documents(self, files):
        profile = default_profile('Example/Source')
        profile['repository_policy'] = {'documentation_profile': 'lico-project'}
        rows = [{'path': path, 'kind': 'blob', 'mode': '100644', 'size': len(text)}
                for path, text in files.items()]
        return evaluate('Example/Source', profile, rows, files.__getitem__,
                        {'branch_refs': [], 'commit_metadata': []})

    def test_root_contributing_broken_link_is_structural(self):
        result = self.evaluate_documents({'CONTRIBUTING.md': '[Guide](missing.md)'})
        findings = [row for row in result['findings']
                    if row['rule'] == 'repository.documentation-link-target']
        self.assertEqual(['CONTRIBUTING.md'], [row['file'] for row in findings])
        self.assertEqual(['error'], [row['severity'] for row in findings])
        self.assertIn('repository.documentation-link-target', result['coverage']['blocking'])

    def test_non_docs_generated_markdown_requires_provenance_and_update(self):
        result = self.evaluate_documents({'reference.generated.md': '# Reference\n'})
        rules = {row['rule'] for row in result['findings'] if row['file'] == 'reference.generated.md'}
        self.assertIn('repository.documentation-generated-source', rules)
        self.assertIn('repository.documentation-generated-update', rules)
        result = self.evaluate_documents({
            'reference.generated.md': 'Generated from source.py. Regenerate with the project generator.\n'})
        self.assertFalse([row for row in result['findings']
                          if row['file'] == 'reference.generated.md'])

    def test_root_readmes_remain_excluded_from_generic_link_scan(self):
        result = self.evaluate_documents({'README.md': '[External guide](missing.md)'})
        self.assertNotIn('repository.documentation-link-target',
                         {row['rule'] for row in result['findings']})

    def test_nested_ignore_cannot_ignore_root_build_or_docs_assets(self):
        from general_auditor.repository_policy import _ignored_candidates
        paths = ['build/local.txt', 'docs/reports/local.md', 'nested/build/local.txt']
        ignored = _ignored_candidates(paths, [('nested/.gitignore', 'build/\ndocs/reports/\n')])
        self.assertEqual({'nested/build/local.txt'}, ignored)
        result = self.evaluate_documents({'nested/.gitignore': 'build/\ndocs/reports/\n'})
        self.assertIn('repository.documentation-local-asset-ignore', result['coverage']['blocking'])

    def test_ignored_ancestor_prevents_file_negation_until_directory_reincluded(self):
        from general_auditor.repository_policy import _ignored_candidates
        path = 'build/keep.txt'
        self.assertEqual({path}, _ignored_candidates([path], [
            ('.gitignore', 'build/\n!build/keep.txt\n')]))
        self.assertEqual(set(), _ignored_candidates([path], [
            ('.gitignore', 'build/\n!build/\nbuild/*\n!build/keep.txt\n')]))
        self.assertEqual({path}, _ignored_candidates([path], [
            ('.gitignore', 'build/\n'), ('build/.gitignore', '!keep.txt\n')]))

    def test_nested_negation_overrides_parent_pattern_with_correct_scope(self):
        from general_auditor.repository_policy import _ignored_candidates
        paths = ['root.tmp', 'nested/keep.tmp', 'nested/discard.tmp']
        self.assertEqual({'root.tmp', 'nested/discard.tmp'}, _ignored_candidates(paths, [
            ('.gitignore', '*.tmp\n'), ('nested/.gitignore', '!keep.tmp\n')]))


class ContributionPolicyParityTests(unittest.TestCase):
    def test_extensionless_registries_and_citation_are_inspected(self):
        profile = default_profile('Example/Source')
        files = {name: 'Cursor <fixture@example.invalid>\n' for name in (
            'AUTHORS', 'CONTRIBUTORS', '.mailmap', '.all-contributorsrc')}
        files['CITATION.cff'] = 'authors:\n  - name: Cursor\n'
        rows = [{'path': path, 'kind': 'blob'} for path in files]
        result = evaluate('Example/Source', profile, rows, files.__getitem__,
                          {'head': 'a'*40, 'branch_refs': [], 'commit_metadata': []})
        self.assertEqual(set(files), {finding['file'] for finding in result['findings']})
        self.assertTrue(all(finding['severity'] == 'warning' for finding in result['findings']))
        self.assertNotIn('fixture@example.invalid', json.dumps(result))

    def test_text_helper_has_no_extension_filter_and_retains_each_location(self):
        from general_auditor.repository_policy import evaluate_contribution_text
        findings, evaluated = [], set()
        def add(rule, path, message, **kwargs):
            findings.append({'rule': rule, 'file': path, 'message': message, **kwargs})
        evaluate_contribution_text('source.py', 'Generated-by: Cursor\nAssisted-by: Cursor\n', add, evaluated.add)
        self.assertEqual([1, 2], [finding['line'] for finding in findings])
        self.assertEqual({'contribution.cursor-attribution'}, evaluated)
        self.assertNotIn('Cursor', json.dumps(findings))
        findings.clear()
        evaluate_contribution_text('source.py', 'authors = "Cursor"\n', add, evaluated.add)
        self.assertEqual([], findings, 'An arbitrary source field is not project metadata')

    def test_complete_commit_identity_and_all_attribution_trailers_keep_commit_locations(self):
        profile = default_profile('Example/Source')
        metadata = [
            {'commit': '1'*40, 'author': 'Synthetic <cursor@example.invalid>',
             'committer': 'Synthetic <fixture@example.invalid>', 'trailers': []},
            {'commit': '2'*40, 'author': 'Synthetic <fixture@example.invalid>',
             'committer': 'Synthetic <cursor@example.invalid>', 'trailers': []},
        ]
        for index, key in enumerate(('Co-authored-by', 'Signed-off-by', 'Authored-by',
                                     'Committed-by', 'Generated-by', 'Assisted-by', 'Made-with'), 3):
            metadata.append({'commit': str(index)*40, 'author': 'Synthetic',
                             'committer': 'Synthetic', 'trailers': [key + ': Cursor']})
        result = evaluate('Example/Source', profile, [], lambda _: None,
                          {'head': 'a'*40, 'branch_refs': [], 'commit_metadata': metadata})
        self.assertEqual({item['commit'] for item in metadata},
                         {finding['commit'] for finding in result['findings']})
        self.assertTrue(all(finding['severity'] == 'warning' for finding in result['findings']))
        self.assertNotIn('example.invalid', json.dumps(result))

    def test_meshrix_site_retains_common_data_policy_and_exact_domain_admissions(self):
        profile, _ = load_profile(Path(__file__).resolve().parents[1], 'Meshrix-Platform/meshrix.io')
        self.assertEqual('common', profile['repository_policy']['data_profile'])
        self.assertEqual({'meshrix.io', 'img.shields.io'},
                         {item['host'] for item in profile['privacy_policy']['privacy_domain_allowlist']})
        result = evaluate('Meshrix-Platform/meshrix.io', profile,
                          [{'path': 'runtime.csv', 'kind': 'blob'}], lambda _: 'id\n',
                          {'branch_refs': [], 'commit_metadata': []})
        self.assertIn('repository.data-file-admission', result['coverage']['blocking'])


class SchemaDefinitionFixtureTests(unittest.TestCase):
    def evaluate_fixture(self, text):
        profile = default_profile('Example/Source')
        profile['repository_policy'] = {
            'data_profile': 'licoup', 'schema_fixtures': ['tests/fixtures/structure.sql']}
        return evaluate('Example/Source', profile,
                        [{'path': 'tests/fixtures/structure.sql', 'kind': 'blob'}],
                        lambda _: text, {'branch_refs': [], 'commit_metadata': []})

    def test_reviewed_definition_fixture_admits_table_index_and_partial_index(self):
        source = '''-- Synthetic structure only.
CREATE TABLE retained_items (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL DEFAULT 'fixture',
  amount INTEGER CHECK (amount >= 0)
);
CREATE INDEX item_label ON retained_items (label);
CREATE UNIQUE INDEX tagged_label ON retained_items (label) WHERE label LIKE 'tag:%';
'''
        result = self.evaluate_fixture(source)
        self.assertFalse(result['coverage']['blocking'])
        self.assertEqual([{'rule': 'repository.data-file-admission',
                           'path': 'tests/fixtures/structure.sql', 'count': 1}],
                         result['coverage']['exempted'])

    def test_quoted_semicolons_comments_and_escaped_quotes_preserve_definitions(self):
        source = '''/* CREATE TRIGGER ignored; INSERT ignored; */
CREATE TABLE sample (
  "column;name" TEXT DEFAULT 'value; -- text /* literal */ it''s (safe)',
  `other;column` TEXT,
  [final;column] TEXT,
  quantity INTEGER CHECK (quantity >= 0)
); -- trailing source comment
CREATE INDEX sample_name ON sample ("column;name");
'''
        self.assertFalse(self.evaluate_fixture(source)['coverage']['blocking'])
        bad = source + '/* harmless comment */ INSERT INTO sample VALUES (1, 2);'
        self.assertIn('repository.data-file-admission',
                      self.evaluate_fixture(bad)['coverage']['blocking'])

    def test_mutations_triggers_source_queries_and_external_commands_are_denied(self):
        rejected = [
            'ALTER TABLE sample ADD COLUMN data TEXT;',
            'DROP TABLE sample;',
            'PRAGMA user_version = 7;',
            'CREATE TRIGGER change_sample AFTER UPDATE ON sample BEGIN UPDATE sample SET id = 1; END;',
            'CREATE TABLE copied AS SELECT * FROM sample;',
            'CREATE TABLE copied (id INT) AS WITH source AS (SELECT 1) SELECT * FROM source;',
            'CREATE VIEW copied AS SELECT * FROM sample;',
            'CREATE VIRTUAL TABLE sample USING external_module;',
            "ATTACH DATABASE 'fixture.db' AS other;",
            "SELECT load_extension('fixture');",
            'BEGIN; CREATE TABLE sample (id INTEGER); COMMIT;',
            'CREATE TABLE sample (id INTEGER); UPDATE sample SET id=1;',
            'CREATE TABLE sample (id INTEGER); DELETE FROM sample;',
            "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO metadata (key,value) VALUES ('version','1');",
        ]
        for source in rejected:
            with self.subTest(source=source):
                result = self.evaluate_fixture(source)
                self.assertIn('repository.data-file-admission', result['coverage']['blocking'])
                self.assertEqual([], result['coverage']['exempted'])

    def test_empty_truncated_unbalanced_and_unterminated_payloads_are_denied(self):
        for source in ('', '-- comment only', '/* comment only */',
                       'CREATE TABLE sample (id INTEGER)',
                       'CREATE TABLE sample (id INTEGER;',
                       "CREATE TABLE sample (label TEXT DEFAULT 'unfinished);",
                       'CREATE TABLE sample (id INTEGER); /* unfinished comment',
                       'CREATE TABLE sample (id INTEGER));',
                       'CREATE TABLE sample (id INTEGER);;'):
            with self.subTest(source=source):
                self.assertIn('repository.data-file-admission',
                              self.evaluate_fixture(source)['coverage']['blocking'])
