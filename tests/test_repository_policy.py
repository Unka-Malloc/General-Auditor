import json
from pathlib import Path
import unittest

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
        self.assertEqual(link['severity'], 'warning')
        self.assertEqual(link['file'], 'docs/README.md')
        self.assertEqual(link['line'], 1)
        self.assertFalse(self.run_policy({}, files)['coverage']['blocking'])

    def test_contribution_metadata_is_advisory_and_source_values_withheld(self):
        result = self.run_policy({}, {'AUTHORS.md': '# Contributors\nCursor <redacted@example.invalid>\n'}, branch_refs=['refs/heads/codex/sample'], commit_metadata=[{'author_name': 'Cursor', 'committer_name': 'Synthetic', 'trailers': []}])
        rules = {row['rule'] for row in result['findings']}
        self.assertEqual(rules, {'contribution.cursor-attribution', 'contribution.commit-attribution', 'contribution.branch-prefix'})
        self.assertFalse(result['coverage']['blocking'])
        self.assertNotIn('redacted@example.invalid', json.dumps(result))
        self.assertTrue(all(row['severity'] == 'warning' for row in result['findings']))
        ordinary = self.run_policy({}, {'README.md': 'A cursor selects a character in the editor.'}, branch_refs=['refs/heads/work/edit'])
        self.assertFalse(ordinary['findings'])
