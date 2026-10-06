import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from general_auditor.config import default_profile
from general_auditor.detection import scan_text
from general_auditor.scanner import scan, _worktree_read


class SourceFidelityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init','-q')
        self.git('config','user.name','Synthetic Tester')
        self.git('config','user.email','fixture@example.invalid')
        self.profile = default_profile('Example/Source')

    def git(self,*args):
        return subprocess.check_output(['git','-C',str(self.root),*args],stderr=subprocess.DEVNULL).decode().strip()

    def save(self,text,path='example.txt'):
        target=self.root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)

    def commit(self):
        self.git('add','.');self.git('commit','-qm','Synthetic source')
        return self.git('rev-parse','HEAD')

    def run_scan(self,**kw):
        return scan(self.root,'Example/Source',profile=self.profile,**kw)

    def test_local_evidence_is_actual_unicode_source_with_exact_location_and_git_object(self):
        text='prefix α\naddress = "10.23.45.67"\nsuffix\n'
        path='fixtures/person@example.invalid.txt'
        self.save(text,path);revision=self.commit()
        result=self.run_scan(include_source=True)
        finding=next(f for f in result['findings'] if f['rule']=='privacy.endpoint.ip-address')
        evidence=finding['source_evidence']
        self.assertEqual(path,finding['file'])
        self.assertEqual(text[evidence['span']['start']:evidence['span']['end']],evidence['matched_text'])
        self.assertEqual('10.23.45.67',evidence['matched_text'])
        self.assertEqual(2,finding['line'])
        self.assertEqual(text,evidence['context']['text'])
        self.assertEqual(revision,evidence['provenance']['commit'])
        self.assertEqual(self.git('rev-parse',revision+':'+path),evidence['provenance']['object'])
        self.assertEqual('local_raw',result['source_mode'])
        ci=self.run_scan()
        self.assertNotIn('10.23.45.67',json.dumps(ci))
        self.assertNotIn(path,json.dumps(ci))
        self.assertTrue(all('source_evidence' not in f for f in ci['findings']))

    def test_staged_evidence_reads_index_not_modified_worktree(self):
        self.save('address="10.20.30.40"\n');self.commit()
        self.save('address="10.20.30.41"\n');self.git('add','example.txt')
        self.save('address="10.20.30.42"\n')
        result=self.run_scan(scope='staged',include_source=True)
        values=[f['source_evidence']['matched_text'] for f in result['findings'] if f['rule']=='privacy.endpoint.ip-address']
        self.assertEqual(['10.20.30.41'],values)
        self.assertEqual('index_blob',result['findings'][0]['source_evidence']['provenance']['source_kind'])

    def test_worktree_detector_and_policy_use_same_captured_read(self):
        self.save('address="10.20.30.40"\n');self.commit()
        reads=[]
        def read_then_change(root,path):
            data=_worktree_read(root,path);reads.append(path)
            self.save('address="10.20.30.99"\n')
            return data
        with patch('general_auditor.scanner._worktree_read',side_effect=read_then_change):
            result=self.run_scan(scope='worktree',include_source=True)
        self.assertEqual(1,len(reads))
        self.assertIn('10.20.30.40',json.dumps(result))
        self.assertNotIn('10.20.30.99',json.dumps(result))

    def test_removed_historical_source_keeps_original_evidence(self):
        self.save('ordinary\n');base=self.commit()
        self.save('address="10.20.30.40"\n');introduced=self.commit()
        self.save('ordinary again\n');self.commit()
        result=self.run_scan(base=base,include_source=True)
        finding=next(f for f in result['findings'] if f['rule']=='privacy.endpoint.ip-address')
        self.assertEqual(introduced,finding['commit'])
        self.assertEqual('10.20.30.40',finding['source_evidence']['matched_text'])

    def test_structural_missing_path_does_not_fabricate_literal_evidence(self):
        self.save('ordinary\n');self.commit();self.profile['required_paths']=['absent.md']
        result=self.run_scan(include_source=True)
        evidence=next(f['source_evidence'] for f in result['findings'] if f['rule']=='repository.required-path')
        self.assertEqual('derived',evidence['kind'])
        self.assertNotIn('matched_text',evidence)
        self.assertNotIn('context',evidence)

    def test_ipv6_partial_identifiers_are_not_ip_addresses(self):
        for path,text in [('sample.kt','Factory::class\nNamedObject::create\nA::B'),
                          ('sample.rs','SomeType::default\ncrate::abc\nA::B')]:
            with self.subTest(path=path):
                result=scan_text(text,path,include_source=True)
                self.assertFalse([f for f in result['findings'] if f['rule']=='privacy.endpoint.ip-address'])
        result=scan_text('address = "fd12:3456:789a::1"\n', 'sample.rs', include_source=True)
        self.assertEqual(['fd12:3456:789a::1'],[f['source_evidence']['matched_text'] for f in result['findings'] if f['rule']=='privacy.endpoint.ip-address'])

    def test_same_line_unicode_and_escaped_key_preserve_original_spelling(self):
        text = 'α = "10.20.30.40"; β = "10.20.30.41"\r\n'
        text += 'key="-----BEGIN PRIVATE KEY-----\\nU1lOVEhFVElDX0ZJWFRVUkU=\\n-----END PRIVATE KEY-----"\r\n'
        result = scan_text(text, 'synthetic.txt', include_source=True)
        ips = [f for f in result['findings'] if f['rule'] == 'privacy.endpoint.ip-address']
        self.assertEqual([f['source_evidence']['matched_text'] for f in ips], ['10.20.30.40', '10.20.30.41'])
        self.assertNotEqual(ips[0]['column'], ips[1]['column'])
        keys = [f for f in result['findings'] if 'PRIVATE KEY' in f.get('source_evidence', {}).get('matched_text', '')]
        self.assertTrue(keys)
        for finding in ips + keys:
            evidence = finding['source_evidence']
            self.assertEqual(evidence['matched_text'], text[evidence['span']['start']:evidence['span']['end']])
            self.assertIn('\r\n', evidence['context']['text'])
        self.assertIn('\\n', keys[0]['source_evidence']['matched_text'])
