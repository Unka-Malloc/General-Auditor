"""Lossless compact reports and bounded lazy presentation."""
import json
import re
import shutil
import subprocess
import unittest

from general_auditor.report import unpack_report, render, render_review, _REPORT_SCRIPT


def fixture(count=151):
    findings = [{"file": "src/file.txt", "line": index+1, "commit": "a"*40,
                 "rule": "privacy.example", "evidence": "[source withheld] " + "repeat "*50,
                 "judgment": "unreviewed", "basis": "Context required", "impact": "Review ownership",
                 "action": "Review locally", "category": "Synthetic", "extra": {"start": index}}
                for index in range(count)]
    run = {"id": "first", "repository": "Example/Source", "head": "a"*40,
           "finished_at": "2026-10-06T00:00:00Z", "status": "completed_with_warnings",
           "scope": "range", "trigger": "push", "findings": findings,
           "coverage": {"commits": 3, "text_versions": 2, "excluded": [
               {"file": "blob.bin", "commit": "b"*40, "reason": "binary"}],
               "policy": {"blocking": [], "incomplete": [], "evaluated": ["structural"]}},
           "local_review": ["Review synthetic context"], "unknown_future_field": [None, True, 1, 1.0, -0.0]}
    second = {**run, "id": "second", "head": "b"*40,
              "findings": [{**row, "commit": "b"*40, "line": row["line"]+1000} for row in findings]}
    return {"runs": [run, second], "generated_at": "2026-10-06T01:00:00Z", "retention_days": 30}


def embedded(html):
    return json.loads(re.search(r'<script id="audit-data" type="application/json">(.*?)</script>', html, re.S).group(1))


class ReportRenderingTests(unittest.TestCase):
    def test_complete_ledger_round_trip_preserves_every_field_and_run_location(self):
        ledger = fixture()
        restored = unpack_report(embedded(render(ledger)))
        self.assertEqual(restored, ledger)
        self.assertEqual(json.dumps(restored), json.dumps(ledger))
        self.assertEqual(restored['runs'][0]['findings'][0]['commit'], 'a'*40)
        self.assertEqual(restored['runs'][1]['findings'][0]['line'], 1001)

    def test_repeated_data_is_interned_and_initial_dom_contains_no_finding_rows(self):
        ledger = fixture(1000)
        html = render(ledger)
        self.assertLess(len(html), len(json.dumps(ledger)) * 0.30)
        shell = html[:html.index('<script id="audit-data"')]
        self.assertNotIn('<tbody>', shell)
        self.assertNotIn('<tr>', shell)
        self.assertEqual(shell.count('data-runs='), 1)
        self.assertIn('2000 findings', shell)
        self.assertLess(len(shell), 10000)

    def test_malicious_fields_are_inert_lossless_json_not_markup(self):
        ledger = fixture(1)
        attack = '</script><img src=x onerror="alert(1)"> & \u2028'
        ledger['runs'][0]['findings'][0]['file'] = attack
        ledger['runs'][0]['findings'][0]['basis'] = attack
        ledger['runs'][0]['coverage']['policy']['__proto__'] = {'polluted': True}
        html = render(ledger)
        self.assertNotIn(attack, html)
        self.assertNotIn('<img', html)
        self.assertNotIn('</script><img', html)
        self.assertEqual(unpack_report(embedded(html)), ledger)
        self.assertNotIn('innerHTML', _REPORT_SCRIPT)
        self.assertNotIn('fetch(', _REPORT_SCRIPT)

    def test_private_contextual_report_retains_judgments_and_additions(self):
        scan = fixture(1)['runs'][0]
        finding = {'index': 0, 'verdict': 'false_positive', 'basis': 'Synthetic fixture context',
                   'impact': 'No established disclosure', 'action': 'Retain fixture'}
        additional = {**scan['findings'][0], 'file': 'src/other.txt', 'verdict': 'confirmed',
                      'basis': 'Synthetic contextual review', 'rule': 'local.contextual-review'}
        context = {'finding_reviews': [finding], 'additional_findings': [additional],
                   'receipt_status': 'validated', 'disposition': 'reviewed', 'summary': 'Synthetic local review',
                   'semantic_reviews': [{'id': 'synthetic-duty', 'conclusion': 'Reviewed', 'evidence': 'Source values withheld'}],
                   'limitations': ['No external service inspected']}
        html = render_review({'scan': scan, 'contextual_review': context})
        restored = unpack_report(embedded(html))['runs'][0]
        self.assertEqual([row['judgment'] for row in restored['findings']], ['false_positive', 'confirmed'])
        self.assertEqual(restored['findings'][1]['file'], 'src/other.txt')
        self.assertEqual(scan['findings'][0]['judgment'], 'unreviewed')
        self.assertIn('Local audit report. No result is published by this command.', html)
        self.assertIn('Local contextual review', html)
        self.assertIn('No external service inspected', html)

    @unittest.skipUnless(shutil.which('node'), 'Node required for deterministic DOM-contract test')
    def test_actual_script_switches_projects_rules_and_retained_history(self):
        harness = r'''
const vm=require('vm');const fs=require('fs');const input=JSON.parse(fs.readFileSync(0,'utf8'));
class Element{
 constructor(tag){this.tag=tag;this.children=[];this.listeners={};this.dataset={};this.open=false;this.textContent='';}
 append(...items){for(const x of items){x.parent=this;this.children.push(x);}}
 replaceChildren(...items){this.children=[];this.append(...items);}
 addEventListener(name,fn){this.listeners[name]=fn;}
 setAttribute(name,value){this[name]=value;}
 querySelectorAll(selector){return this.children.flatMap(x=>[...(selector==='button[data-repository]'&&x.dataset.repository?[x]:[]),...x.querySelectorAll(selector)]);}
 remove(){this.parent.children=this.parent.children.filter(x=>x!==this);}
}
const projects=input.projects.map(data=>Object.assign(new Element('button'),{dataset:data,disabled:true}));
const groups=[new Element('div')];groups[0].append(...projects);
const filter=new Element('input'),status=new Element('p'),panel=new Element('section');
const document={getElementById:id=>id==='audit-data'?{textContent:JSON.stringify(input.envelope)}:id==='report-status'?status:id==='project-panel'?panel:filter,
 createElement:tag=>new Element(tag),createTextNode:text=>Object.assign(new Element('#text'),{textContent:text}),
 querySelectorAll:selector=>selector==='button[data-repository]'?projects:selector==='[data-organization]'?groups:[]};
let decompressions=0;class CountedDecompression{constructor(format){decompressions++;return new DecompressionStream(format);}}
vm.runInNewContext(input.script,{document,Map,JSON,console,Blob,Response,DecompressionStream:CountedDecompression,Uint8Array,atob}).then(async()=>{
if(status.textContent!=='Project list ready. Audit details load when selected.')throw Error('initialization failed');
if(decompressions!==1)throw Error('unselected runs decompressed');
function collect(el,tag){return [el,...el.children.flatMap(x=>collect(x,tag))].filter(x=>x.tag===tag);}
function requireState(condition,message){if(!condition)throw Error(message);}
requireState(projects.every(x=>!x.disabled),'projects unavailable after decode');
requireState(collect(panel,'h2')[0].textContent==='Example/Source','default project incorrect');
requireState(collect(panel,'tbody')[0].children.length===50,'initial page unbounded');
requireState(collect(panel,'a')[0].href.endsWith('/blob/'+ 'a'.repeat(40)+'/src/file.txt#L1'),'location lost');
const ruleButtons=collect(panel,'button').filter(x=>x.dataset.rule);
requireState(ruleButtons.length===3,'unhit rules displayed');
const selected=ruleButtons.find(x=>x.dataset.rule==='privacy.other');
requireState(selected.textContent==='privacy.other (51)','selected run rule count incorrect');
selected.listeners.click();requireState(selected['aria-pressed']==='true','rule not selected accessibly');
requireState(collect(panel,'tbody')[0].children.length===50,'selected rule first page wrong');
let next=collect(panel,'button').find(x=>x.textContent==='Next');next.listeners.click();
requireState(collect(panel,'tbody')[0].children.length===1&&next.disabled,'last selected-rule finding lost');
const history=collect(panel,'select')[0];requireState(history.children.length===2,'history dropped');
history.value=history.children[1].value;await history.listeners.change();
requireState(collect(panel,'a')[0].href.endsWith('/blob/'+ 'b'.repeat(40)+'/src/file.txt#L1001'),'history location not updated');
requireState(collect(panel,'button').filter(x=>x.dataset.rule).length===2,'rules from previous run retained');
await projects.find(x=>x.dataset.repository==='Other/Project').listeners.click();
requireState(collect(panel,'h2')[0].textContent==='Other/Project','project switch failed');
requireState(collect(panel,'tbody')[0].children.length===1,'previous project findings retained');
requireState(collect(panel,'a').length===0,'redacted path became source link');
await projects.find(x=>x.dataset.repository==='Other/Empty').listeners.click();
requireState(collect(panel,'tbody').length===0,'empty project retained old details');
await projects.find(x=>x.dataset.repository==='Other/Settings').listeners.click();
requireState(collect(panel,'a')[0].href==='https://github.com/Other/Settings/settings','governance location lost');
requireState(collect(panel,'a')[0].textContent==='GitHub repository settings','governance link label lost');
const stale=projects[0].listeners.click();await projects.find(x=>x.dataset.repository==='Other/Empty').listeners.click();await stale;
requireState(collect(panel,'h2')[0].textContent==='Other/Empty'&&collect(panel,'tbody').length===0,'late decode overwrote selected project');
filter.value='missing';filter.listeners.input.call(filter);requireState(projects.every(x=>x.hidden)&&groups[0].hidden,'sidebar filtering incorrect');
filter.value='Example';filter.listeners.input.call(filter);requireState(!projects[0].hidden&&!groups[0].hidden,'filtered project not restored');
process.stdout.write('ok');
}).catch(error=>{console.error(error);process.exitCode=1;});
'''
        ledger = fixture()
        for row in ledger['runs'][0]['findings'][100:]:
            row['rule'] = 'privacy.other'
        ledger['runs'].append({**ledger['runs'][0], 'id': 'third', 'repository': 'Other/Project',
                               'findings': [{**ledger['runs'][0]['findings'][0], 'file': '[redacted]'}]})
        ledger['runs'].append({**ledger['runs'][0], 'id': 'fourth', 'repository': 'Other/Settings',
                               'findings': [{**ledger['runs'][0]['findings'][0], 'source': 'github-settings'}]})
        html = render(ledger, inventory=['Other/Empty'])
        envelope = json.loads(re.search(r'<script id="audit-data" type="application/json">(.*?)</script>', html, re.S).group(1))
        projects = [{'repository': repo, 'runs': runs} for repo,runs in re.findall(r'data-repository="([^"]*)" data-runs="([^"]*)"', html)]
        result = subprocess.run(['node', '-e', harness], input=json.dumps({'projects':projects, 'envelope':envelope, 'script':_REPORT_SCRIPT}), text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'ok')


if __name__ == '__main__':
    unittest.main()
