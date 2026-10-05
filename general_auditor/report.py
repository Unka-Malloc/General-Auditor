"""Single rolling HTML report, backed by a 30-day JSON ledger."""

from datetime import datetime, timedelta, timezone
from html import escape
import json
from pathlib import Path
import tempfile
from urllib.parse import quote

from .config import repository_name
from .gitdata import SHA


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


def location(run, item):
    if item.get("source") == "github-settings":
        return '<a href="https://github.com/' + escape(run["repository"], quote=True) + '/settings">GitHub repository settings</a>'
    path = escape(item["file"])
    line = item.get("line")
    label = path + (":" + str(line) if line else "")
    revision = item.get("commit", run["head"])
    if "[redacted" in item["file"] or not revision or not SHA.fullmatch(revision):
        return label
    url = "https://github.com/" + quote(run["repository"], safe="/") + "/blob/" + revision + "/" + quote(item["file"], safe="/")
    if line:
        url += "#L" + str(line)
    return '<a rel="noreferrer" href="' + escape(url, quote=True) + '">' + label + "</a>"


def render(ledger, inventory=(), *, local=False):
    runs = ledger["runs"]
    repositories = sorted(set(inventory) | {row["repository"] for row in runs})
    warnings = sum(len(row["findings"]) for row in runs)
    failures = sum(row["status"] == "incomplete" for row in runs)
    latest = runs[0]["finished_at"] if runs else "Not yet audited"
    e = escape
    sections = []
    histories = {repository: [] for repository in repositories}
    for row in runs:
        histories[row["repository"]].append(row)
    for repository in repositories:
        history = histories[repository]
        body = []
        for index, run in enumerate(history):
            rows = []
            for item in run["findings"]:
                rows.append("<tr><td>" + location(run, item) + "<br><small>" + e((item["commit"] or "")[:12]) + "</small></td><td>" + e(item["rule"]) + "</td><td>" + e(item["evidence"]) + "</td><td><b>" + e(item["judgment"]) + "</b><br>" + e(item["basis"]) + "</td><td>" + e(item["impact"]) + "<br><br>" + e(item["action"]) + "</td></tr>")
            findings = ('<div class="scroll"><table><thead><tr><th>File / line / commit</th><th>Rule</th><th>Redacted evidence / category</th><th>Judgment and basis</th><th>Impact and action</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>") if rows else '<p>No pattern warnings in the inspected scope. This is not a privacy clearance.</p>'
            excluded = "".join("<li>" + location(run, item) + " — " + e(item["reason"]) + "</li>" for item in run["coverage"]["excluded"])
            coverage = run["coverage"]
            body.append('<details class="run"' + (" open" if index == 0 else "") + "><summary>" + e(run["finished_at"]) + " · " + e(run["status"]) + " · " + str(len(rows)) + " warnings</summary><p>Commit <code>" + e((run["head"] or "unavailable")[:12]) + "</code> · " + e(run["scope"]) + " · " + e(run["trigger"]) + " · " + str(coverage["text_versions"]) + " text versions / " + str(coverage["commits"]) + " commits</p>" + ('<p class="error">Infrastructure failure: ' + e(run["error"]) + ". This scan is incomplete and will be retried by discovery.</p>" if run.get("error") else "") + findings + ('<details><summary>Coverage exclusions (' + str(len(coverage["excluded"])) + ")</summary><ul>" + excluded + "</ul></details>" if excluded else "") + '<details><summary>Repository-specific local Agent review</summary><ul>' + "".join("<li>" + e(task) + "</li>" for task in run["local_review"]) + "</ul></details></details>")
        sections.append('<section data-repository="' + e(repository, quote=True) + '"><h2>' + e(repository) + "</h2>" + ("".join(body) if body else "<p>No retained scan in the last 30 days.</p>") + "</section>")
    notice = "Local audit report. No result is published by this command." if local else "Rolling 30-day public audit report."
    retention = "" if local else " The current report and JSON ledger expire entries after 30 days; Git history and external copies are not erased."
    return '''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>General-Auditor · rolling audit report</title>
<style>
:root{color-scheme:light dark;font-family:system-ui,sans-serif;background:#10151b;color:#e8edf3}body{max-width:1500px;margin:auto;padding:36px 24px}h1{font-size:2rem;margin-bottom:8px}h2{font-size:1.25rem}p,li{line-height:1.6}a{color:#87c9ff}small{color:#aab7c5}.muted{color:#aab7c5}.stats{display:flex;flex-wrap:wrap;gap:12px;margin:24px 0}.stats span{border:1px solid #354557;padding:12px 18px;border-radius:8px}input{font:inherit;padding:12px;width:min(90%,520px);background:#19232f;color:inherit;border:1px solid #526477;border-radius:6px}section{margin:28px 0;padding:20px;background:#17212c;border:1px solid #354557;border-radius:10px}.run{border-top:1px solid #354557;padding:14px 0}summary{cursor:pointer;font-weight:600;line-height:1.6}.scroll{overflow:auto;margin:16px 0}table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:12px;text-align:left;vertical-align:top;border:1px solid #354557;min-width:155px;overflow-wrap:anywhere}th{background:#233141}code{overflow-wrap:anywhere}.error{color:#ffb3ae}[hidden]{display:none}footer{margin-top:36px;font-size:.9rem;color:#aab7c5}
</style>
<header><p class="muted">COMMON POLICY + REPOSITORY POLICY</p><h1>General-Auditor</h1>
<p>''' + notice + ''' Pattern signals are advisory. No cloud Agent runs here; all contextual judgments remain pending local review.</p>
<p class="muted">Last audit: ''' + e(latest) + " · Report refreshed: " + e(ledger["generated_at"]) + '''</p></header>
<div class="stats"><span>''' + str(len(repositories)) + " repositories</span><span>" + str(len(runs)) + " retained runs</span><span>" + str(warnings) + " warnings</span><span>" + str(failures) + ''' incomplete scans</span></div>
<label for="filter">Filter repositories</label><br><input id="filter" type="search" placeholder="Organization or repository name" autocomplete="off">
<main>''' + "".join(sections) + '''</main>
<footer>Source values, PR bodies and runtime logs are never copied into this report. Binary files, large text files, submodules and LFS payloads are listed as exclusions.''' + retention + '''</footer>
<script>document.getElementById('filter').addEventListener('input',function(){const q=this.value.toLowerCase();document.querySelectorAll('section[data-repository]').forEach(s=>s.hidden=!s.dataset.repository.toLowerCase().includes(q));});</script></html>
'''


def publish(root, results, *, inventory=None, now=None):
    root = Path(root)
    ledger = merge(read_json(root / "data.json", {"runs": []}), results, now=now, public_repositories=inventory)
    root.mkdir(parents=True, exist_ok=True)
    write_json(root / "data.json", ledger)
    write_text(root / "index.html", render(ledger, inventory or ()))
    return ledger
