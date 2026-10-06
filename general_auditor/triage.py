"""Deterministic triage of one private local scan.

Triage answers the question a reader actually has - what in this scan needs a
decision, and what does a stated rule already explain - without calling a model
and without judging privacy. Every finding receives exactly one deterministic
class. Classification is deliberately conservative: a finding is reported as a
decision unless a specific, auditable rule explains it.

Triage never replaces contextual review and never declares a repository safe.
It bounds review: `decision` groups are what a reviewer or maintainer must read,
and `cleared` groups carry the rule that explained them so the explanation
itself can be challenged.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from html import escape

SCHEMA = "general-auditor-local-triage"

# Rule families whose findings locate a declared contract rather than a value.
CONTRACT_PREFIXES = ("repository.", "workflow.", "contribution.", "governance.", "extension.")

REASONS = {
    # Cleared: a stated deterministic rule explains the finding.
    "cleared-license-text": "The file is part of the project's license or notice text.",
    "cleared-placeholder": "Every matched value is an explicit placeholder or a generator template.",
    "cleared-reserved-reference": "Every matched host or address is reserved for documentation, testing or loopback use.",
    "cleared-public-reference": "Every matched value is a well-known public standards, vendor or documentation reference.",
    "cleared-repository-identity": "The matched value carries the repository's or organization's own published identity.",
    "cleared-escape-artifact": "The matched text is a backslash-escaped code fragment, not a literal path or address.",
    "cleared-checksum-fragment": "The matched digits are a fragment of a longer checksum or object identifier on the same line.",
    "cleared-system-path": "The matched path is a standard system location with no personal account component.",
    "cleared-container-account": "The matched account is a container or service account declared by the repository.",
    "cleared-scratch-path": "The matched path is a build, cache or scratch location with no personal account component.",
    "cleared-synthetic-literal": "The matched value is repeated-byte or low-entropy synthetic content.",
    # Decisions: report with the actual values so a reader can judge them.
    "decision-home-path": "An absolute path contains a user home directory with a personal account name.",
    "decision-machine-temp": "The matched value identifies a specific machine's temporary directory.",
    "decision-credential": "A credential, key or token rule matched a value that is not an explicit placeholder.",
    "decision-endpoint": "An endpoint rule matched a host that is not reserved or a known public reference.",
    "decision-personal-or-backend": "A personal-data or backend-data rule matched a literal value.",
    "decision-unclassified": "No deterministic rule explains this finding; it needs a contextual verdict.",
    "contract-declared": "A declared repository, workflow or contribution contract finding with no matched literal.",
}

STRUCTURAL_CATEGORIES = frozenset({
    "Repository contract",
    "Documentation governance",
    "Workflow governance",
    "Repository hygiene",
    "Data-file policy",
    "Branch metadata",
    "Dependency governance",
    "License evidence",
    "CI gate contract",
})

PLACEHOLDER = re.compile(
    r"(?i)(example|sample|dummy|placeholder|redacted|secret[-_ ]?here|your[-_ ]|change[-_ ]?me|"
    r"fake|synthetic|todo|fixme|xxxxxxxx|<[^<>\s]{1,40}>|\{\{?[a-z_][a-z0-9_]{1,30}\}?\}|"
    r"\b(test|dummy)[-_ ]?(value|key|token|user|pass|secret)\b|^[-\s]*$|^(n/?a|none|null|undefined)$)"
)

LICENSE_NAMES = re.compile(r"(?i)^(licen[cs]e|copying|notice|unlicense|authors|contributors)(\..*)?$")

RESERVED_HOSTS = re.compile(
    r"(?i)(^|\.)(example\.(com|org|net)|example|invalid|test|localhost|local|"
    r"host\.docker\.internal|acme|contoso|foobar)$"
)

PUBLIC_REFERENCE_HOSTS = frozenset({
    "gnu.org", "fsf.org", "w3.org", "ietf.org", "rfc-editor.org", "json-schema.org",
    "opensource.org", "creativecommons.org", "apache.org", "python.org", "nodejs.org",
    "npmjs.com", "github.com", "gitlab.com", "developer.mozilla.org", "learn.microsoft.com",
    "kernel.org", "debian.org", "ubuntu.com", "docker.com", "go.dev", "rust-lang.org",
    "crates.io", "pub.dev", "flutter.dev", "dart.dev", "apple.com", "swift.org",
    "kotlinlang.org", "gradle.org", "sqlite.org", "postgresql.org", "mysql.com",
    "redis.io", "mongodb.com", "nginx.org", "cloudflare.com", "schema.org", "unicode.org",
    "iana.org", "iso.org", "ieee.org", "acm.org", "doi.org", "orcid.org", "zenodo.org",
    "arxiv.org", "opencontainers.org", "spdx.org", "semver.org", "keepachangelog.com",
})

DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
))

SYSTEM_ROOTS = ("/usr/", "/etc/", "/var/", "/opt/", "/bin/", "/sbin/", "/lib/", "/lib64/",
                "/proc/", "/sys/", "/dev/", "/run/", "/srv/", "/root/", "c:\\windows\\",
                "c:\\program files", "c:\\programdata\\")

SCRATCH_ROOTS = ("/tmp/", "/var/tmp/", "/private/tmp/", "/build/", "/workspace/",
                 "/app/", "/home/app/", "./build/", "./target/", "./dist/", "./.cache/")

GENERIC_ACCOUNTS = frozenset({
    "app", "apps", "node", "nodejs", "root", "user", "users", "runner", "builder", "build",
    "ci", "jenkins", "github", "gitlab", "www", "www-data", "nginx", "docker", "postgres",
    "mysql", "redis", "admin", "administrator", "service", "svc", "guest", "test", "tester",
    "developer", "dev", "sandbox", "container", "worker", "guest-user", "vscode",
})

HOME_ROOTS = re.compile(r"(?i)(^|[\s\"'=(])((/users/|/home/|c:\\users\\|/var/folders/)([^/\s\"'<>)]+))")

CREDENTIAL_FAMILY = ("credential", "key.", "key-", "token", "jose")
ENDPOINT_FAMILY = ("endpoint", "host-binding", "uri-userinfo", "domain")
PERSONAL_FAMILY = ("personal", "business", "backend", "local.", "runtime")

HEX_RUN = re.compile(r"[0-9a-fA-F]{32,}")
ESCAPED_FRAGMENT = re.compile(r"\\[/.\\]")
LOW_ENTROPY = re.compile(r"^(.)\1{3,}$|^[0-9]{1,}$|^[a-zA-Z]{1,3}$")

LINE_WINDOW = 240


def _rule_family(rule: str) -> str:
    if rule.startswith(CONTRACT_PREFIXES):
        return "contract"
    if any(part in rule for part in CREDENTIAL_FAMILY):
        return "credential"
    if any(part in rule for part in ENDPOINT_FAMILY):
        return "endpoint"
    if any(part in rule for part in PERSONAL_FAMILY):
        return "record"
    return "other"


def _path_class(path: str) -> str:
    lowered = (path or "").lower()
    name = os.path.basename(lowered)
    if LICENSE_NAMES.match(name) or lowered.startswith(("licenses/", "license/")):
        return "license"
    if lowered.startswith((".github/", ".gitlab/", ".circleci/")) or "workflow" in lowered:
        return "ci"
    if lowered.startswith(("docs/", "doc/")) or lowered.endswith((".md", ".rst")):
        return "docs"
    if any(part in lowered for part in ("test", "fixture", "spec/", "specs/", "vector", "conformance", "golden")):
        return "test"
    if lowered.endswith((".json", ".yaml", ".yml", ".toml", ".ini", ".env", ".cddl", ".schema")):
        return "data"
    if lowered.endswith((".lock",)) or "node_modules/" in lowered or "vendor/" in lowered or "third_party/" in lowered:
        return "vendor"
    if any(part in lowered for part in ("generated", "dist/", "build/", "_book/", ".min.")):
        return "generated"
    return "source"


def _matched_values(finding: dict) -> list[str]:
    evidence = finding.get("source_evidence")
    if not isinstance(evidence, dict):
        return []
    spans = evidence.get("value_spans")
    values: list[str] = []
    if isinstance(spans, list):
        for span in spans:
            if isinstance(span, dict) and isinstance(span.get("text"), str) and span["text"].strip():
                values.append(span["text"])
    if not values and isinstance(evidence.get("matched_text"), str) and evidence["matched_text"].strip():
        values.append(evidence["matched_text"])
    return values


def _line_text(finding: dict) -> str:
    evidence = finding.get("source_evidence")
    if not isinstance(evidence, dict):
        return ""
    context = evidence.get("context")
    if not isinstance(context, dict) or not isinstance(context.get("text"), str):
        return ""
    start_line = context.get("start_line")
    line = finding.get("line")
    text = context["text"]
    if isinstance(start_line, int) and isinstance(line, int):
        rows = text.split("\n")
        offset = line - start_line
        if 0 <= offset < len(rows):
            text = rows[offset]
    collapsed = re.sub(r"\s+", " ", text).strip()
    if len(collapsed) <= LINE_WINDOW:
        return collapsed
    column = finding.get("column") or 1
    start = max(0, column - LINE_WINDOW // 3)
    end = min(len(collapsed), start + LINE_WINDOW)
    return ("…" if start else "") + collapsed[start:end] + ("…" if end < len(collapsed) else "")


def _host_of(value: str) -> str | None:
    match = re.match(r"(?i)^[a-z][a-z0-9+.-]*://([^/?#\s]+)", value)
    authority = match.group(1) if match else None
    if authority is None and re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value):
        authority = value
    if authority is None:
        return None
    authority = authority.rsplit("@", 1)[-1]
    host = authority.rsplit(":", 1)[0] if ":" in authority and not authority.count(":") > 1 else authority
    return host.strip("[]").lower() or None


def _reserved_host(host: str) -> bool:
    """Reserved or loopback naming only; public references are a separate reason."""
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return True
    return bool(RESERVED_HOSTS.search(host))


def _public_reference_host(host: str | None) -> bool:
    if not isinstance(host, str) or not host:
        return False
    return host in PUBLIC_REFERENCE_HOSTS or host.endswith(tuple("." + known for known in PUBLIC_REFERENCE_HOSTS))


def _reserved_address(value: str) -> bool | None:
    candidate = value.strip().strip("[]")
    if not candidate or not re.fullmatch(r"[0-9a-fA-F:.]{3,45}", candidate):
        return None
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified or address.is_link_local:
        return True
    return any(address in network for network in DOCUMENTATION_NETWORKS if address.version == network.version)


def _identity_tokens(repository: str) -> set[str]:
    organization, _, name = repository.partition("/")
    tokens = set()
    for raw in (organization, name):
        token = re.sub(r"[^a-z0-9]", "", raw.lower())
        if len(token) >= 4:
            tokens.add(token)
    return tokens


def _classify(finding: dict, repository: str, values: list[str], identity: set[str]) -> tuple[str, str]:
    rule = finding.get("rule") or ""
    family = _rule_family(rule)
    if family == "contract":
        return "contract", "contract-declared"
    path = finding.get("file") or finding.get("path") or ""
    path_class = _path_class(path)
    line = _line_text(finding)
    joined = " ".join(values)

    if path_class == "license":
        return "cleared", "cleared-license-text"
    if values and all(_reserved_address(value) is True or _reserved_host(_host_of(value) or value) for value in values):
        return "cleared", "cleared-reserved-reference"
    if values and all(_public_reference_host(_host_of(value)) for value in values):
        return "cleared", "cleared-public-reference"
    tokens = [re.sub(r"[^a-z0-9]", "", _host_of(value) or value.lower()) for value in values]
    if tokens and identity and all(any(token in candidate for token in identity) for candidate in tokens):
        return "cleared", "cleared-repository-identity"
    if values and all(PLACEHOLDER.search(value) for value in values):
        return "cleared", "cleared-placeholder"
    if ESCAPED_FRAGMENT.search(joined):
        return "cleared", "cleared-escape-artifact"
    if values and all(re.fullmatch(r"[0-9a-f]{6,40}", value.strip(), re.IGNORECASE) for value in values):
        runs = HEX_RUN.findall(line)
        if any(any(value.strip().lower() in run.lower() for run in runs) for value in values):
            return "cleared", "cleared-checksum-fragment"
    lowered = joined.lower()
    home = HOME_ROOTS.search(lowered)
    if home and home.group(4).lower() not in GENERIC_ACCOUNTS:
        if "/var/folders/" in lowered:
            return "decision", "decision-machine-temp"
        return "decision", "decision-home-path"
    if any(root in lowered for root in SYSTEM_ROOTS) and "/users/" not in lowered and "/home/" not in lowered:
        return "cleared", "cleared-system-path"
    if re.search(r"(?i)/home/([^/\s\"'<>)]+)", lowered):
        account = re.search(r"(?i)/home/([^/\s\"'<>)]+)", lowered).group(1)
        if account in GENERIC_ACCOUNTS:
            return "cleared", "cleared-container-account"
        return "decision", "decision-home-path"
    if any(root in lowered for root in SCRATCH_ROOTS):
        return "cleared", "cleared-scratch-path"
    if values and all(LOW_ENTROPY.match(value.strip()) for value in values):
        return "cleared", "cleared-synthetic-literal"

    if family == "credential":
        return "decision", "decision-credential"
    if family == "endpoint":
        return "decision", "decision-endpoint"
    if family == "record":
        return "decision", "decision-personal-or-backend"
    return "decision", "decision-unclassified"


def triage(scan: dict) -> dict:
    """Classify every finding of one saved scan. Pure function, no model, no I/O."""
    if not isinstance(scan, dict) or not isinstance(scan.get("findings"), list):
        raise ValueError("A saved local scan is required")
    repository = scan.get("repository") or ""
    identity = _identity_tokens(repository)
    groups: dict[tuple, dict] = {}
    for index, finding in enumerate(scan["findings"]):
        values = _matched_values(finding)
        disposition, reason = _classify(finding, repository, values, identity)
        path = finding.get("file") or finding.get("path") or ""
        key = (disposition, reason, finding.get("rule") or "", _path_class(path))
        group = groups.setdefault(key, {
            "disposition": disposition,
            "reason": reason,
            "reason_text": REASONS.get(reason, ""),
            "rule": finding.get("rule") or "",
            "category": finding.get("category") or "",
            "path_class": _path_class(path),
            "count": 0,
            "files": set(),
            "samples": [],
        })
        group["count"] += 1
        group["files"].add(path)
        if disposition != "cleared" or len(group["samples"]) < 5:
            group["samples"].append({
                "index": index,
                "file": path,
                "line": finding.get("line"),
                "commit": (finding.get("commit") or "")[:12],
                "matched": [value[:200] for value in values],
                "source_line": _line_text(finding),
            })
    ordered = sorted(groups.values(), key=lambda row: (
        {"decision": 0, "contract": 1, "cleared": 2}[row["disposition"]], -row["count"], row["rule"]))
    for row in ordered:
        row["files"] = len(row["files"])
    totals = {
        "findings": len(scan["findings"]),
        "decisions": sum(row["count"] for row in ordered if row["disposition"] == "decision"),
        "contracts": sum(row["count"] for row in ordered if row["disposition"] == "contract"),
        "cleared": sum(row["count"] for row in ordered if row["disposition"] == "cleared"),
        "groups": len(ordered),
        "decision_groups": sum(1 for row in ordered if row["disposition"] == "decision"),
    }
    return {
        "schema": SCHEMA,
        "repository": repository,
        "scan_id": scan.get("id"),
        "scope": scan.get("scope"),
        "status": scan.get("status"),
        "head": scan.get("head"),
        "coverage": {
            "commits": (scan.get("coverage") or {}).get("commits"),
            "text_versions": (scan.get("coverage") or {}).get("text_versions"),
            "excluded": len((scan.get("coverage") or {}).get("excluded") or []),
        },
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "totals": totals,
        "groups": ordered,
    }


def _rows(group: dict) -> str:
    rows = []
    for sample in group["samples"]:
        location = escape(str(sample["file"])) + ("" if sample["line"] is None else ":" + str(sample["line"]))
        matched = "<br>".join("<code>" + escape(value) + "</code>" for value in sample["matched"]) or "<span class='muted'>structural finding: no matched literal</span>"
        rows.append(
            "<tr><td>" + location + "</td><td>" + escape(sample["commit"]) + "</td><td>"
            + matched + "</td><td><code>" + escape(sample["source_line"]) + "</code></td></tr>")
    return "".join(rows)


def render_triage(result: dict) -> str:
    """Render the deterministic triage as a self-contained private page."""
    totals = result["totals"]
    notice = ("Private local triage. Contains original source values; do not upload, commit or share this file. "
              "Triage does not judge privacy and does not prove a repository safe.")
    sections = []
    for title, disposition, hint in (
        ("Decision required", "decision", "No deterministic rule explains these findings. Read the matched text and decide."),
        ("Declared contract findings", "contract", "Repository, workflow and contribution contracts. These are policy gaps, not disclosures."),
        ("Explained by a deterministic rule", "cleared", "A stated rule covers these findings. The rule, not a model, is the reason."),
    ):
        groups = [row for row in result["groups"] if row["disposition"] == disposition]
        if not groups:
            continue
        body = []
        for row in groups:
            body.append(
                "<details" + (" open" if disposition != "cleared" else "") + "><summary><strong>"
                + escape(row["rule"]) + "</strong> · " + str(row["count"]) + " findings · "
                + str(row["files"]) + " files · " + escape(row["reason"]) + "</summary>"
                + "<p>" + escape(row["reason_text"]) + "</p>"
                + "<div class='scroll'><table><caption>" + escape(row["category"]) + " · path class "
                + escape(row["path_class"]) + "</caption><thead><tr><th>Location</th><th>Commit</th>"
                + "<th>Matched value</th><th>Source line</th></tr></thead><tbody>"
                + _rows(row) + "</tbody></table></div></details>")
        sections.append("<section><h2>" + escape(title) + " · " + str(sum(row["count"] for row in groups))
                        + "</h2><p class='muted'>" + escape(hint) + "</p>" + "".join(body) + "</section>")
    reason_table = "<div class='scroll'><table><thead><tr><th>Disposition</th><th>Rule</th><th>Path class</th>" \
                   "<th>Reason</th><th>Findings</th><th>Files</th></tr></thead><tbody>" + "".join(
        "<tr><td>" + escape(row["disposition"]) + "</td><td>" + escape(row["rule"]) + "</td><td>"
        + escape(row["path_class"]) + "</td><td>" + escape(row["reason"]) + "</td><td>" + str(row["count"])
        + "</td><td>" + str(row["files"]) + "</td></tr>" for row in result["groups"]) + "</tbody></table></div>"
    return """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>General-Auditor · deterministic triage</title>
<style>
:root{color-scheme:light dark;font-family:system-ui,sans-serif;background:#10151b;color:#e8edf3}
body{max-width:1400px;margin:auto;padding:36px 24px}h1{font-size:1.9rem}h2{font-size:1.2rem}
p,li,td,th{line-height:1.55}.muted,footer{color:#aab7c5}
.stats{display:flex;flex-wrap:wrap;gap:12px;margin:20px 0}.stats span{border:1px solid #354557;padding:10px 16px;border-radius:8px}
section{margin:26px 0;padding:18px;background:#17212c;border:1px solid #354557;border-radius:10px}
details{margin:10px 0;border:1px solid #2c3b4c;border-radius:8px;padding:10px}summary{cursor:pointer;font-weight:600}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:10px;text-align:left;vertical-align:top;border:1px solid #354557;overflow-wrap:anywhere}
th{background:#233141}code{overflow-wrap:anywhere}.scroll{overflow:auto;margin:10px 0}
footer{margin-top:32px;font-size:.9rem}
</style>
<header><p class="muted">DETERMINISTIC TRIAGE · NO MODEL, NO VERDICT</p><h1>""" + escape(result["repository"]) + """</h1>
<p>""" + escape(notice) + """</p>
<p>Scope <strong>""" + escape(str(result["scope"])) + """</strong> · head <code>""" + escape((result["head"] or "")[:12]) + """</code> · scan status <strong>""" + escape(str(result["status"])) + """</strong> · commits """ + escape(str(result["coverage"]["commits"])) + """ · text versions """ + escape(str(result["coverage"]["text_versions"])) + """ · excluded objects """ + escape(str(result["coverage"]["excluded"])) + """ · triaged """ + escape(result["generated_at"]) + """</p></header>
<div class="stats"><span>""" + str(totals["findings"]) + """ findings</span><span>""" + str(totals["decisions"]) + """ need a decision</span><span>""" + str(totals["contracts"]) + """ contract findings</span><span>""" + str(totals["cleared"]) + """ explained by rule</span><span>""" + str(totals["decision_groups"]) + """ decision groups</span></div>
<main>""" + "".join(sections) + """<section><h2>All groups</h2>""" + reason_table + """</section></main>
<footer>Matched values and locations are retained only in this private local file. Triage groups detector output deterministically; a cleared group means a stated rule applied, not that the underlying content was reviewed.</footer></html>
"""
