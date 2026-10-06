"""One consolidated report over every repository below an audit root.

`fleet` is the single closing step of a fleet audit: given a root that contains
`<Organization>/<Repository>` checkouts with saved local scans, it triages each
repository in-process - deterministically, without a model - and writes one
report: projects grouped by organization on the left, the selected project's
real matches on the right.

The report is deliberately unredacted: the audited repositories are the owner's
public repositories, and a report the owner cannot read has no value. That is
why the output must not live inside a Git working tree, and why the command
refuses such a destination.

This module aggregates, ranks and labels. It never judges privacy, and it never
calls a model.
"""

from __future__ import annotations

import html
import json
import math
import os
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .local_store import LocalStore
from .triage import render_triage, triage

SCHEMA = "general-auditor-fleet-report"

TLDS = frozenset(
    "com org net edu gov int io ai dev app cloud co uk de fr jp cn ru br in au ca nl se fi dk it es ch at be pl cz "
    "pt gr ie il kr sg hk tw mx ar cl za nz tr ua vn th id my ph info biz xyz online site tech store blog wiki news "
    "live life world space fun team group digital network systems software tools works zone land page host website "
    "press art media studio design email chat social community academy school institute foundation sh cc tv me gg to "
    "ly rs".split())
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,60}$")
MEMBER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)+$")
EXPRESSION = re.compile(r"""[(){}\[\]'"=;,:\s]|::|->""")
HOSTLIKE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,24}$")
HOME = re.compile(r"(?i)(/users/|/home/|c:\\users\\|/var/folders/)([^/\s\"'<>)]+)")
MACHINE_TEMP = re.compile(r"(?i)/var/folders/")
WINDOWS_PATH = re.compile(r"^[A-Za-z]:[\\/]")
GENERIC = frozenset(
    "app apps node nodejs root user users runner builder build ci jenkins github gitlab www www-data nginx docker "
    "postgres mysql redis admin administrator service svc guest test tester developer dev sandbox container worker "
    "vscode".split())

# Rules that key on field and identifier names rather than stored literals.
METADATA_RULES = frozenset({"privacy.backend.metadata", "privacy.personal.record-field"})

MACHINE_SHAPES = frozenset({"home-path", "machine-temp"})

REMEDY_LABELS = {
    "DETECTOR-FIX": "规则过宽，改检测器",
    "EXACT-EXCEPTION": "可加精确例外",
    "REAL-FIX": "真实数据，必须修",
    "DECIDE": "需人工判断",
}


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum((n / len(text)) * math.log2(n / len(text)) for n in counts.values())


def shape(value: str) -> str:
    """The deterministic value shape a remedy recommendation is derived from."""
    text = value.strip()
    if not text:
        return "empty"
    home = HOME.search(text)
    if home and MACHINE_TEMP.search(text):
        return "machine-temp"
    if home and home.group(2).lower() not in GENERIC:
        return "home-path"
    if "://" in text:
        return "url"
    if IDENTIFIER.match(text):
        return "identifier"
    if MEMBER.match(text) and text.rsplit(".", 1)[-1].lower() not in TLDS:
        return "dotted-code-name"
    if HOSTLIKE.match(text):
        return "host"
    if text.startswith("/") or WINDOWS_PATH.match(text):
        return "path"
    if EXPRESSION.search(text):
        return "expression"
    if text.isdigit():
        return "digits"
    if len(text) >= 20 and entropy(text) >= 3.3:
        return "high-entropy"
    return "other"


def remedy_for(rule: str, shapes: Counter) -> tuple[str, str]:
    """Recommend a fix from the value shapes a rule fired on, never from a model."""
    shapes = Counter(shapes)
    total = sum(shapes.values()) or 1
    codeish = (shapes["identifier"] + shapes["expression"] + shapes["dotted-code-name"]) / total
    if rule in METADATA_RULES and codeish >= 0.7:
        return "DETECTOR-FIX", "该规则在字段名和标识符上命中，应限定为真实字面值。"
    if rule.startswith("privacy.endpoint") and codeish >= 0.7:
        return "DETECTOR-FIX", "点号代码名被当成主机名，应要求 scheme 或已注册顶级域。"
    if rule.startswith("privacy.credential") and codeish >= 0.5:
        return "DETECTOR-FIX", "凭据规则命中了标识符和类型表达式，应要求字面赋值或熵阈值。"
    if shapes["home-path"] or shapes["machine-temp"]:
        return "REAL-FIX", "机器特有数据，必须从仓库删除，不能进白名单。"
    if (shapes["host"] + shapes["url"]) / total >= 0.7:
        return "EXACT-EXCEPTION", "具名公开引用，可精确例外或集中扩充公开主机集。"
    return "DECIDE", "形态混杂，需要人工决定。"


def discover(root: str) -> list[dict]:
    """Find every repository below the root that has a saved local scan."""
    found = []
    for organization in sorted(os.listdir(root)):
        organization_dir = os.path.join(root, organization)
        if not os.path.isdir(organization_dir):
            continue
        for repository in sorted(os.listdir(organization_dir)):
            repository_dir = os.path.join(organization_dir, repository)
            scan = os.path.join(repository_dir, ".general-auditor", "local", "scan.json")
            if os.path.isfile(scan):
                found.append({"repository": f"{organization}/{repository}", "directory": repository_dir, "scan": scan})
    return found


def _decision_payload(report: dict) -> list[dict]:
    """Every detail row of one repository, decisions only, ordered by volume."""
    groups = []
    for group in report["groups"]:
        if group["disposition"] != "decision":
            continue
        rows = []
        for value in group["values"]:
            location = value["locations"][0] if value["locations"] else {}
            rows.append({
                "n": value["occurrences"],
                "m": value["matched"],
                "f": location.get("file") or "",
                "l": location.get("line"),
                "s": value["source_line"],
            })
        groups.append({
            "rule": group["rule"],
            "reason": group["reason_text"],
            "path_class": group["path_class"],
            "count": group["count"],
            "distinct": group["distinct"],
            "rows": rows,
        })
    groups.sort(key=lambda item: -item["count"])
    return groups


def build(reports: dict) -> dict:
    """Aggregate per-repository triage results, keeping every decision detail row."""
    per_rule = defaultdict(lambda: {"count": 0, "distinct": 0, "repos": Counter(), "shapes": Counter()})
    totals = Counter()
    projects = []
    for name, report in sorted(reports.items()):
        totals.update(report["totals"])
        groups = _decision_payload(report)
        for group in groups:
            row = per_rule[group["rule"]]
            row["count"] += group["count"]
            row["distinct"] += group["distinct"]
            row["repos"][name] += group["count"]
            for item in group["rows"]:
                for value in item["m"]:
                    row["shapes"][shape(value)] += 1
        projects.append({
            "repository": name,
            "organization": name.split("/", 1)[0],
            "name": name.split("/", 1)[1],
            "scope": report["scope"],
            "head": (report["head"] or "")[:12],
            "findings": report["totals"]["findings"],
            "decisions": report["totals"]["decisions"],
            "contracts": report["totals"]["contracts"],
            "cleared": report["totals"]["cleared"],
            "groups": groups,
        })
    projects.sort(key=lambda item: (-item["decisions"], item["repository"]))
    rules = []
    for rule, row in per_rule.items():
        remedy, note = remedy_for(rule, row["shapes"])
        rules.append({"rule": rule, "count": row["count"], "distinct": row["distinct"],
                      "repositories": len(row["repos"]), "remedy": remedy, "note": note,
                      "shapes": dict(row["shapes"].most_common(4))})
    rules.sort(key=lambda item: -item["count"])
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "totals": dict(totals),
        "remedies": rules,
        "projects": projects,
    }


_SCRIPT = """
const DATA = JSON.parse(document.getElementById('fleet-data').textContent);
const panel = document.getElementById('panel');
const REMEDY = DATA.remedies.reduce((acc, r) => (acc[r.rule] = r, acc), {});
const LABEL = {DETECTOR_FIX: '规则过宽', EXACT_EXCEPTION: '可加例外', REAL_FIX: '必须修', DECIDE: '需判断'};
let current = null;

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderSidebar() {
  const nav = document.getElementById('nav');
  const byOrg = {};
  for (const project of DATA.projects) (byOrg[project.organization] ||= []).push(project);
  for (const organization of Object.keys(byOrg).sort()) {
    const box = el('div', 'org');
    box.appendChild(el('h3', null, organization));
    for (const project of byOrg[organization]) {
      const button = el('button');
      button.type = 'button';
      button.dataset.repo = project.repository;
      button.appendChild(el('span', null, project.name));
      button.appendChild(el('small', null, project.decisions.toLocaleString() + ' 条待决策 · ' + project.groups.length + ' 组'));
      button.addEventListener('click', () => select(project.repository));
      box.appendChild(button);
    }
    nav.appendChild(box);
  }
}

function select(repository) {
  current = DATA.projects.find((p) => p.repository === repository);
  for (const button of document.querySelectorAll('#nav button')) {
    button.setAttribute('aria-pressed', String(button.dataset.repo === repository));
  }
  draw();
}

function draw() {
  const filter = (document.getElementById('rowfilter').value || '').toLowerCase();
  panel.textContent = '';
  const head = el('div', 'head');
  head.appendChild(el('h2', null, current.repository));
  head.appendChild(el('p', 'muted', '范围 ' + current.scope + ' · HEAD ' + current.head + ' · 命中 ' +
    current.findings.toLocaleString() + ' · 待决策 ' + current.decisions.toLocaleString() + ' · 已由规则解释 ' +
    current.cleared.toLocaleString() + ' · 契约 ' + current.contracts.toLocaleString()));
  panel.appendChild(head);
  for (const group of current.groups) {
    const remedy = REMEDY[group.rule] || {};
    const section = el('section');
    const title = el('h3');
    title.appendChild(el('code', null, group.rule));
    const tag = el('span', 'tag ' + (remedy.remedy || 'DECIDE'), LABEL[(remedy.remedy || 'DECIDE').replace('-', '_')] || remedy.remedy);
    if (remedy.note) tag.title = remedy.note;
    title.appendChild(tag);
    title.appendChild(el('small', 'muted', group.count.toLocaleString() + ' 条 · ' + group.distinct.toLocaleString() + ' 个不同取值 · ' + group.path_class));
    section.appendChild(title);
    const table = el('table');
    const thead = el('thead');
    const headRow = el('tr');
    for (const label of ['次数', '命中原文', '位置', '源码行']) headRow.appendChild(el('th', null, label));
    thead.appendChild(headRow);
    table.appendChild(thead);
    const tbody = el('tbody');
    for (const row of group.rows) {
      const haystack = (row.m.join(' ') + ' ' + row.f + ' ' + group.rule).toLowerCase();
      if (filter && !haystack.includes(filter)) continue;
      const tr = el('tr');
      tr.appendChild(el('td', 'num', row.n.toLocaleString()));
      const values = el('td');
      for (const value of row.m) values.appendChild(el('code', null, value));
      tr.appendChild(values);
      tr.appendChild(el('td', 'loc', row.f + (row.l ? ':' + row.l : '')));
      tr.appendChild(el('td', 'src', row.s));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    section.appendChild(table);
    panel.appendChild(section);
  }
}

document.getElementById('rowfilter').addEventListener('input', () => { if (current) draw(); });
document.getElementById('projectfilter').addEventListener('input', (event) => {
  const needle = event.target.value.toLowerCase();
  for (const button of document.querySelectorAll('#nav button')) {
    const show = button.dataset.repo.toLowerCase().includes(needle);
    button.hidden = !show;
  }
});
renderSidebar();
const first = DATA.projects.find((p) => p.decisions > 0) || DATA.projects[0];
if (first) select(first.repository);
"""


def render(result: dict) -> str:
    """Render the one closing report: projects on the left, real matches on the right."""
    payload = json.dumps({
        "generated_at": result["generated_at"],
        "remedies": result["remedies"],
        "projects": result["projects"],
    }, ensure_ascii=True, separators=(",", ":"))
    payload = payload.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    projects = len(result["projects"])
    decisions = result["totals"].get("decisions", 0)
    return "\n".join([
        "<!doctype html>",
        '<html lang="zh"><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta name="referrer" content="no-referrer">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; script-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
        "<title>General-Auditor · 收口报告</title>",
        "<style>",
        ":root{color-scheme:light dark;font-family:system-ui,-apple-system,'PingFang SC',sans-serif;background:#0f141a;color:#e8edf3}",
        "*{box-sizing:border-box}body{margin:0;height:100vh;display:flex;overflow:hidden}",
        "aside{width:290px;flex:none;border-right:1px solid #2c3b4c;padding:14px;overflow:auto;background:#131b24}",
        "aside h1{font-size:.95rem;margin:0 0 4px;font-weight:600}aside p{margin:0 0 10px;font-size:.72rem;color:#aab7c5}",
        "input{width:100%;padding:7px 9px;font:inherit;font-size:.8rem;background:#0d1219;color:inherit;border:1px solid #3a4b5e;border-radius:6px}",
        ".org{margin-top:12px}.org h3{font-size:.7rem;letter-spacing:.06em;text-transform:uppercase;color:#8fa2b6;margin:0 0 5px}",
        ".org button{display:block;width:100%;text-align:left;margin:3px 0;padding:7px 9px;font:inherit;font-size:.82rem;color:inherit;background:#18222d;border:1px solid #2f3f50;border-radius:6px;cursor:pointer}",
        ".org button span{display:block}.org button small{display:block;color:#8fa2b6;font-size:.68rem}",
        ".org button[aria-pressed=true]{border-color:#87c9ff;background:#20374d}",
        "main{flex:1;overflow:auto;padding:0 20px 20px}",
        ".toolbar{position:sticky;top:0;z-index:3;background:#0f141a;padding:14px 0 10px;border-bottom:1px solid #2c3b4c}",
        ".toolbar input{max-width:420px}",
        ".head{padding:12px 0 10px}",
        ".head h2{margin:0 0 2px;font-size:1.05rem}.head p{margin:0;font-size:.75rem}",
        ".muted{color:#aab7c5}",
        "section{margin:16px 0 22px}section h3{margin:0 0 6px;font-size:.86rem;display:flex;align-items:center;gap:8px;flex-wrap:wrap}",
        ".tag{font-size:.68rem;padding:2px 7px;border-radius:999px;border:1px solid}",
        ".tag.DETECTOR-FIX{color:#ffcf8a;border-color:#8a5a2b;background:#241d15}",
        ".tag.EXACT-EXCEPTION{color:#9fe3b0;border-color:#2f6b45;background:#16241b}",
        ".tag.REAL-FIX{color:#ffb3ae;border-color:#7d3a37;background:#2a1a19}",
        ".tag.DECIDE{color:#bcd0e6;border-color:#3a4b5e;background:#1a232d}",
        "table{border-collapse:collapse;width:100%;font-size:12.5px;table-layout:fixed}",
        "th,td{padding:5px 7px;text-align:left;vertical-align:top;border-bottom:1px solid #24313e;overflow-wrap:anywhere}",
        "th{background:#17212c;position:sticky;top:0;font-weight:600;font-size:.72rem;color:#aab7c5}",
        "td:first-child,th:first-child{width:62px;text-align:right;color:#8fa2b6}",
        "td:nth-child(2),th:nth-child(2){width:38%}",
        "td:nth-child(3),th:nth-child(3){width:24%}",
        "code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#ffd9a0}td:nth-child(2) code{display:block}",
        ".loc{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:#9db4c9}",
        ".src{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:#c8d4e0}",
        "footer{padding:10px 20px;border-top:1px solid #2c3b4c;font-size:.7rem;color:#8fa2b6}",
        "</style>",
        "<body>",
        '<aside><h1>General-Auditor 收口报告</h1>',
        '<p>' + str(projects) + " 个项目 · " + f"{decisions:,}" + ' 条待决策 · 未脱敏，仅本机</p>',
        '<input id="projectfilter" type="search" placeholder="过滤项目" autocomplete="off">',
        '<nav id="nav"></nav></aside>',
        '<main><div class="toolbar"><input id="rowfilter" type="search" placeholder="过滤命中原文 / 文件 / 规则" autocomplete="off"></div><div id="panel"></div></main>',
        '<script id="fleet-data" type="application/json">' + payload + "</script>",
        "<script>" + _SCRIPT + "</script>",
        "</body></html>",
    ])


def _outside_worktree(path: str) -> bool:
    """A closing report must not be written inside a Git working tree."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    result = subprocess.run(["git", "-C", directory, "rev-parse", "--show-toplevel"],
                            capture_output=True, text=True)
    return result.returncode != 0


def run(root: str, output: str | None = None) -> dict:
    """Triage every repository below the root, then write the single report."""
    entries = discover(root)
    if not entries:
        raise ValueError("No repository with a saved local scan was found below the root")
    reports = {}
    for entry in entries:
        store = LocalStore(entry["directory"])
        with store.locked():
            result = triage(store.read_json("scan.json", None))
            store.write_json("triage.json", result)
            store.write_text("triage.html", render_triage(result))
        reports[entry["repository"]] = result
    aggregate = build(reports)
    target = output or os.path.join(os.path.abspath(root), "fleet-report.html")
    if not _outside_worktree(target):
        raise ValueError("The fleet report contains unredacted text and must stay outside a Git working tree")
    with open(target, "w", encoding="utf-8") as stream:
        stream.write(render(aggregate))
    aggregate["report"] = target
    return aggregate
