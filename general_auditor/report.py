"""Single rolling HTML report, backed by a 30-day JSON ledger."""

import base64
from datetime import datetime, timedelta, timezone
import gzip
from html import escape
import json
from pathlib import Path
import tempfile

from .config import repository_name


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def read_json(path, default):
    return json.loads(Path(path).read_text()) if Path(path).exists() else default


def write_text(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(content)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path, data):
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def merge(ledger, results, *, now=None, public_repositories=None):
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=30)
    by_id = {}
    for result in [*ledger.get("runs", []), *results]:
        repository_name(result["repository"])
        if result.get("visibility") != "public":
            raise ValueError("Private audit results cannot enter the public report")
        if public_repositories is not None and result["repository"] not in public_repositories:
            continue
        if timestamp(result["finished_at"]) >= cutoff:
            by_id[result["id"]] = result
    runs = sorted(by_id.values(), key=lambda row: (row["finished_at"], row["id"]), reverse=True)
    return {"schema_version": 1, "generated_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "retention_days": 30, "runs": runs}


def _intern(ledger):
    """Losslessly intern repeated JSON values without retaining source snippets.

    Nodes form an acyclic graph: children precede parents. Equal strings, records
    and arrays share a node; per-run locations remain ordinary data in the graph.
    """
    nodes, known = [], {}

    def encode(value):
        if isinstance(value, dict):
            tag, data = "object", tuple((encode(key), encode(item)) for key, item in value.items())
        elif isinstance(value, list):
            tag, data = "array", tuple(encode(item) for item in value)
        elif value is None:
            tag, data = "null", None
        elif isinstance(value, bool):
            tag, data = "boolean", value
        elif isinstance(value, int):
            tag, data = "integer", value
        elif isinstance(value, float):
            tag, data = "number", value
        elif isinstance(value, str):
            tag, data = "string", value
        else:
            raise TypeError("Report data must be JSON-compatible")
        key = (tag, repr(data) if tag == "number" else data)
        if key not in known:
            known[key] = len(nodes)
            nodes.append([tag, data])
        return known[key]

    root = encode(ledger)
    return {"format": "interned-json", "root": root, "nodes": nodes}


def _restore(packed):
    """Reconstruct the complete embedded ledger for offline inspection."""
    decoded = []
    for kind, value in packed["nodes"]:
        if kind == "object":
            decoded.append({decoded[key]: decoded[item] for key, item in value})
        elif kind == "array":
            decoded.append([decoded[item] for item in value])
        else:
            decoded.append(value)
    return decoded[packed["root"]]


def _pack_value(value):
    raw = json.dumps(_intern(value), ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    return base64.b64encode(gzip.compress(raw, mtime=0)).decode('ascii')


def pack_report(ledger):
    """Keep all records self-contained while allowing one-run decompression."""
    return {
        "format": "interned-json-runs",
        "metadata": _pack_value({key: None if key == "runs" else value for key, value in ledger.items()}),
        "runs": [{"data": _pack_value(run), "finished_at": run["finished_at"],
                  "status": run["status"], "scope": run["scope"]} for run in ledger["runs"]],
    }


def unpack_report(packed):
    """Reconstruct every field from the HTML's complete embedded envelope."""
    def unpack(value):
        return _restore(json.loads(gzip.decompress(base64.b64decode(value))))
    ledger = unpack(packed["metadata"])
    ledger["runs"] = [unpack(run["data"]) for run in packed["runs"]]
    return ledger


_REPORT_SCRIPT = r"""
'use strict';
let packed,selection=0;
function decode(id,nodes,memo=new Map()){
  if(memo.has(id))return memo.get(id);
  const [type,data]=nodes[id];
  if(type==='array'){const result=[];memo.set(id,result);for(const child of data)result.push(decode(child,nodes,memo));return result;}
  if(type==='object'){const result=Object.create(null);memo.set(id,result);for(const [key,value] of data)result[decode(key,nodes,memo)]=decode(value,nodes,memo);return result;}
  return data;
}
function node(tag,text){const el=document.createElement(tag);if(text!==undefined)el.textContent=String(text);return el;}
function source(run,item){
  const path=String(item.file??item.path??''),line=item.line;
  const label=path+(line?':'+line:'');
  const revision=item.commit===undefined?run.head:item.commit;
  let href;
  if(item.source==='github-settings')href='https://github.com/'+run.repository+'/settings';
  else if(!path.includes('[')&&!['staged','worktree'].includes(run.scope)&&typeof revision==='string'&&/^[0-9a-f]{40}$/.test(revision)){
    href='https://github.com/'+run.repository.split('/').map(encodeURIComponent).join('/')+'/blob/'+revision+'/'+path.split('/').map(encodeURIComponent).join('/');
    if(Number.isInteger(line)&&line>0)href+='#L'+line;
  }
  const el=node(href?'a':'span',item.source==='github-settings'?'GitHub repository settings':label);
  if(href){el.href=href;el.rel='noreferrer';}
  return el;
}
function pager(items,draw,label){
  const wrap=node('div'),controls=node('nav'),previous=node('button','Previous'),next=node('button','Next'),status=node('span'),body=node('div');
  controls.setAttribute('aria-label',label+' pagination');status.setAttribute('aria-live','polite');
  previous.type=next.type='button';let page=0;const size=50;
  function refresh(){const start=page*size;body.replaceChildren(draw(items.slice(start,start+size),start));status.textContent=items.length?`${start+1}–${Math.min(start+size,items.length)} of ${items.length}`:'0 items';previous.disabled=page===0;next.disabled=start+size>=items.length;}
  previous.addEventListener('click',()=>{page--;refresh();});next.addEventListener('click',()=>{page++;refresh();});
  controls.append(previous,status,next);wrap.append(controls,body);refresh();return wrap;
}
function inspector(value,label){
  if(value===null||typeof value!=='object')return node('p',label+': '+JSON.stringify(value));
  const details=node('details'),entries=Array.isArray(value)?value.map((v,i)=>[i,v]):Object.entries(value);
  details.append(node('summary',label+' ('+entries.length+(Array.isArray(value)?' items':' fields')+')'));
  let body;
  details.addEventListener('toggle',()=>{
    if(details.open&&!body){body=pager(entries,part=>{const container=node('div');for(const [key,item] of part)container.append(inspector(item,String(key)));return container;},label);details.append(body);}
    else if(!details.open&&body){body.remove();body=null;}
  });return details;
}
function findings(run,items=run.findings??[]){
  return pager(items,part=>{
    const scroll=node('div'),table=node('table'),head=node('thead'),tr=node('tr'),body=node('tbody');scroll.className='scroll';
    table.append(node('caption','Located findings; source values withheld'));
    for(const title of ['File / line / commit','Rule / category','Redacted evidence','Judgment and basis','Impact and action']){const th=node('th',title);th.scope='col';tr.append(th);}head.append(tr);table.append(head,body);
    for(const item of part){const row=node('tr'),place=node('td');place.append(source(run,item),node('br'),node('small',item.commit??'Uncommitted'));
      const rule=node('td');rule.append(node('p',item.rule??''),node('small',item.category??''));
      const judgment=node('td');judgment.append(node('strong',item.judgment??'unreviewed'),node('p',item.basis??''));
      const action=node('td');action.append(node('p',item.impact??''),node('p',item.action??''));
      row.append(place,rule,node('td',item.evidence??''),judgment,action);body.append(row);
    }scroll.append(table);return scroll;
  },'Findings');
}
async function showRun(id,target){
  const selected=++selection;
  target.replaceChildren(node('p','Loading selected audit…'));
  let run;
  try{
    const bytes=Uint8Array.from(atob(packed.runs[id].data),character=>character.charCodeAt(0));
    const stream=new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    const values=JSON.parse(await new Response(stream).text());
    if(selected!==selection)return;
    run=decode(values.root,values.nodes);
  }catch{
    if(selected===selection)target.replaceChildren(node('p','Selected audit could not be decoded. Use a current browser with gzip DecompressionStream support, or inspect the embedded data offline.'));
    return;
  }
  const body=node('div');body.className='run-body';
  body.append(node('p',run.finished_at+' · '+run.status+' · Commit '+(run.head??'unavailable')+' · '+run.scope+' · '+run.trigger+' · '+run.coverage.text_versions+' text versions / '+run.coverage.commits+' commits'));
  if(run.error){const error=node('p','Infrastructure failure: '+run.error);error.className='error';body.append(error);}
  const groups=new Map();for(const item of run.findings??[]){const rule=String(item.rule??'Unspecified');if(!groups.has(rule))groups.set(rule,[]);groups.get(rule).push(item);}
  body.append(node('h3','Rules hit in this run ('+groups.size+')'),node('p','Counts are finding occurrences in this selected run. They are not confirmed leaks; the same material can recur in retained history.'));
  const rules=node('nav'),rows=node('div');rules.className='rule-list';rules.setAttribute('aria-label','Filter findings by hit rule');
  const buttons=[];
  function choose(button,items){for(const other of buttons)other.setAttribute('aria-pressed',String(other===button));rows.replaceChildren(items.length?findings(run,items):node('p','No pattern warnings in the inspected scope. This is not a privacy clearance.'));}
  for(const [label,items] of [['All findings',run.findings??[]],...groups]){
    const button=node('button',label+' ('+items.length+')');button.type='button';button.dataset.rule=label;buttons.push(button);button.addEventListener('click',()=>choose(button,items));rules.append(button);
  }
  body.append(rules,rows);choose(buttons[0],run.findings??[]);
  const policy=run.coverage.policy??{};body.append(node('p','Policy violations: '+(policy.blocking?.length??0)+'. Incomplete policy checks: '+(policy.incomplete?.length??0)+'.'));
  const exclusions=node('details');exclusions.append(node('summary','Coverage exclusions ('+(run.coverage.excluded?.length??0)+')'));
  exclusions.addEventListener('toggle',()=>{if(exclusions.open&&exclusions.children.length===1)exclusions.append(pager(run.coverage.excluded??[],part=>{const list=node('ul');for(const item of part){const row=node('li');row.append(source(run,item),document.createTextNode(' — '+item.reason));list.append(row);}return list;},'Exclusions'));});
  body.append(exclusions,inspector(run.local_review??[],'Repository-specific local Agent review'),inspector(policy,'Policy coverage'),inspector(run,'Complete run record (all fields)'));target.replaceChildren(body);
}
async function selectProject(button){
  selection++;
  const panel=document.getElementById('project-panel');
  for(const other of document.querySelectorAll('button[data-repository]'))other.setAttribute('aria-pressed',String(other===button));
  const title=node('h2',button.dataset.repository);title.id='project-title';panel.replaceChildren(title);
  const ids=button.dataset.runs?button.dataset.runs.split(',').map(Number):[];
  if(!ids.length){panel.append(node('p','No retained scan in the last 30 days.'));return;}
  const label=node('label','Audit history ('+ids.length+' retained runs)'),select=node('select'),target=node('div');
  label.setAttribute('for','run-select');select.id='run-select';select.setAttribute('aria-label','Select retained audit run');
  for(const [index,id] of ids.entries()){
    const {finished_at:timestamp,status,scope}=packed.runs[id];
    const option=node('option',(index===0?'Latest · ':'')+timestamp+' · '+status+' · '+scope);option.value=String(id);select.append(option);
  }
  select.value=String(ids[0]);select.addEventListener('change',()=>showRun(Number(select.value),target));
  panel.append(label,select,target);await showRun(ids[0],target);
}
document.getElementById('filter').addEventListener('input',function(){
  const q=this.value.toLowerCase();
  for(const button of document.querySelectorAll('button[data-repository]'))button.hidden=!button.dataset.repository.toLowerCase().includes(q);
  for(const group of document.querySelectorAll('[data-organization]'))group.hidden=Array.from(group.querySelectorAll('button[data-repository]')).every(button=>button.hidden);
});
async function initialize(){
  packed=JSON.parse(document.getElementById('audit-data').textContent);
  const projects=document.querySelectorAll('button[data-repository]');
  for(const button of projects){button.disabled=false;button.addEventListener('click',()=>selectProject(button));}
  if(projects.length)await selectProject(Array.from(projects).find(button=>!button.hidden)??projects[0]);
  document.getElementById('report-status').textContent='Project list ready. Audit details load when selected.';
}
initialize().catch(()=>{document.getElementById('report-status').textContent='Report details could not be decoded. Use a current browser with gzip DecompressionStream support, or inspect the embedded data offline.';});
"""


def render(ledger, inventory=(), *, local=False):
    runs = ledger["runs"]
    repositories = sorted(set(inventory) | {row["repository"] for row in runs})
    packed = pack_report(ledger)
    histories = {repository: [] for repository in repositories}
    for run_id, run in enumerate(runs):
        histories[run["repository"]].append((run, run_id))
    organizations = {}
    for repository, history in histories.items():
        organization, name = repository.split("/", 1)
        ids = ",".join(str(run_id) for _run, run_id in history)
        count = len(history[0][0]["findings"]) if history else 0
        button = ('<button type="button" disabled data-repository="' + escape(repository, quote=True)
                  + '" data-runs="' + ids + '" aria-pressed="false"><span>' + escape(name)
                  + '</span><small>' + str(count) + ' latest findings · ' + str(len(history)) + ' runs</small></button>')
        organizations.setdefault(organization, []).append(button)
    sidebar = ''.join('<div class="organization" data-organization="' + escape(organization, quote=True)
                      + '"><h3>' + escape(organization) + '</h3>' + ''.join(buttons) + '</div>'
                      for organization, buttons in organizations.items())
    # Metadata labels are inert JSON; escape HTML parser delimiters. Record
    # bodies remain independently compressed so unselected runs stay encoded.
    payload = json.dumps(packed, ensure_ascii=False, separators=(',', ':'))
    payload = payload.replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
    findings_count = sum(len(run["findings"]) for run in runs)
    incomplete = sum(run["status"] == "incomplete" for run in runs)
    latest = runs[0]["finished_at"] if runs else 'Not yet audited'
    notice = 'Local audit report. No result is published by this command.' if local else 'Rolling 30-day public audit report.'
    return '''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>General-Auditor · rolling audit report</title>
<style>
:root{color-scheme:light dark;font-family:system-ui,sans-serif;background:#10151b;color:#e8edf3}body{max-width:1500px;margin:auto;padding:36px 24px}h1{font-size:2rem}h2{font-size:1.25rem}p,li{line-height:1.6}a{color:#87c9ff}small,.muted,footer{color:#aab7c5}.stats{display:flex;flex-wrap:wrap;gap:12px;margin:24px 0}.stats span{border:1px solid #354557;padding:12px 18px;border-radius:8px}input,button,select{font:inherit;padding:10px;background:#19232f;color:inherit;border:1px solid #526477;border-radius:6px}input{width:min(90%,520px)}button:disabled{opacity:.5}nav{display:flex;gap:16px;align-items:center;margin:12px 0}section{margin:28px 0;padding:20px;background:#17212c;border:1px solid #354557;border-radius:10px}details details{margin:12px 0}summary{cursor:pointer;font-weight:600;line-height:1.6}.scroll{overflow:auto;margin:16px 0}table{border-collapse:collapse;width:100%;font-size:13px}caption{text-align:left;margin:8px 0}td,th{padding:12px;text-align:left;vertical-align:top;border:1px solid #354557;min-width:155px;overflow-wrap:anywhere}th{background:#233141}code,p,summary{overflow-wrap:anywhere}.error{color:#ffb3ae}[hidden]{display:none}footer{margin-top:36px;font-size:.9rem}
.workspace{display:grid;grid-template-columns:280px minmax(0,1fr);gap:24px;align-items:start}.sidebar{position:sticky;top:16px;max-height:90vh;overflow:auto;border:1px solid #354557;border-radius:10px;padding:16px}.sidebar input{box-sizing:border-box;width:100%}.organization button{display:block;text-align:left;width:100%;margin:8px 0}.organization button span,.organization button small{display:block}button[aria-pressed=true]{border-color:#87c9ff;background:#244058}.project-panel{min-width:0;margin:0}.project-panel select{display:block;max-width:100%;margin:12px 0}.rule-list{flex-wrap:wrap;align-items:stretch}.rule-list button{text-align:left;font-size:13px;overflow-wrap:anywhere}button:focus-visible,summary:focus-visible,select:focus-visible,input:focus-visible{outline:2px solid #87c9ff;outline-offset:3px}@media(max-width:800px){body{padding:20px 12px}.workspace{grid-template-columns:1fr}.sidebar{position:static;max-height:320px}.stats span{padding:8px}nav{flex-wrap:wrap}}
</style>
<header><p class="muted">COMMON POLICY + REPOSITORY POLICY</p><h1>General-Auditor</h1><p>''' + notice + ''' Pattern signals are advisory. No cloud Agent runs here. CI contextual judgments remain pending local review; deterministic structural contract violations are reported separately.</p><p>Last audit: ''' + escape(str(latest)) + ' · Report refreshed: ' + escape(str(ledger['generated_at'])) + '''</p></header>
<div class="stats"><span>''' + str(len(repositories)) + ' repositories</span><span>' + str(len(runs)) + ' retained runs</span><span>' + str(findings_count) + ' findings</span><span>' + str(incomplete) + ''' incomplete scans</span></div>
<p>Select a project on the left, then inspect rules hit in its selected audit. History includes every retained run; findings are paginated in groups of 50. All report data is embedded.</p>
<p id="report-status" role="status">Loading the embedded report records…</p>
<noscript><p>JavaScript is required for project details. Complete losslessly encoded data remains embedded in the audit-data JSON element for offline inspection.</p></noscript>
<main><div class="workspace"><aside class="sidebar" aria-label="Projects by organization"><label for="filter">Filter projects</label><input id="filter" type="search" placeholder="Organization or project" autocomplete="off"><nav aria-label="Select project" style="display:block">''' + sidebar + '''</nav></aside><section id="project-panel" class="project-panel" aria-labelledby="project-title"><h2 id="project-title">Select a project</h2><p>Project details will appear here.</p></section></div></main>
<footer>Source values, PR bodies and runtime logs are never copied into this report. Coverage exclusions and policy results remain in each run. ''' + ('' if local else 'The current report retains 30 days; Git history and external copies are not erased.') + '''</footer>
<script id="audit-data" type="application/json">''' + payload + '</script>\n<script>' + _REPORT_SCRIPT + '</script></html>\n'


def publish(root, results, *, inventory=None, now=None, render_html=True):
    root = Path(root)
    ledger = merge(read_json(root / "data.json", {"runs": []}), results, now=now, public_repositories=inventory)
    root.mkdir(parents=True, exist_ok=True)
    write_json(root / "data.json", ledger)
    if render_html:
        write_text(root / "index.html", render(ledger, inventory or ()))
    return ledger


def render_review(review):
    """Render a private review beside its unchanged deterministic scan."""
    from copy import deepcopy
    scan = deepcopy(review["scan"])
    contextual = review["contextual_review"]
    for row in contextual["finding_reviews"]:
        scan["findings"][row["index"]].update(judgment=row["verdict"], basis=row["basis"], impact=row["impact"], action=row["action"])
    for row in contextual["additional_findings"]:
        scan["findings"].append({**row, "file": row.get("file", row.get("path")), "judgment": row["verdict"], "rule": row.get("rule", "local.contextual-review"), "evidence": row.get("evidence", row.get("category", "Contextual finding"))})
    html = render({"runs": [scan], "generated_at": scan["finished_at"]}, local=True)
    details = "<section><h2>Local contextual review</h2><p>" + escape(contextual["receipt_status"]) + " · " + escape(contextual["disposition"]) + "</p><p>" + escape(contextual["summary"]) + "</p><p>Receipt validation does not attest Agent identity.</p><ul>"
    details += "".join("<li>" + escape(row["id"]) + ": " + escape(row["conclusion"]) + " — " + escape(row["evidence"]) + "</li>" for row in contextual["semantic_reviews"])
    details += "".join("<li>Limitation: " + escape(item) + "</li>" for item in contextual["limitations"])
    return html.replace("</main>", details + "</ul></section></main>")
