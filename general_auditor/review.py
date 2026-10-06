"""Local, scan-bound contextual review receipts.

This module validates review content supplied by a local workflow. It cannot
attest who wrote a receipt or whether an Agent actually ran, and private local receipts may retain exact source evidence. CI remains source-free and unreviewed.
"""

from __future__ import annotations

import json
from pathlib import PurePosixPath
import re
from copy import deepcopy
from typing import Any


VERDICTS = frozenset({"confirmed", "false_positive", "uncertain"})
FINDING_IDENTITY_FIELDS = (
    "file", "path", "line", "column", "end_line", "end_column", "commit",
    "rule", "rule_id", "category", "severity", "evidence_class", "start", "end",
    "evidence", "judgment", "basis", "impact", "action", "source_evidence",
)
FINDING_DISPLAY_FIELDS = FINDING_IDENTITY_FIELDS
_PROFILE_ID_PART = re.compile(r"[^A-Za-z0-9_.-]+")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# Retain the eight effective Lico-Auditor contextual review domains. These are
# review prompts, never executable rules or automated verdicts.
REVIEW_TOPICS: tuple[dict[str, str], ...] = (
    {
        "id": "agent-business",
        "title": "Customers, accounts, tenants, and business relationships",
        "prompt": (
            "Review actual customer identity, contact details, and real links between "
            "customers or tenants and projects or accounts. Treat field names as search "
            "cues only. Distinguish domain models, schemas, synthetic fixtures, public "
            "facts, and actual customer records."
        ),
    },
    {
        "id": "agent-contracts",
        "title": "Contracts, sales, billing, and revenue",
        "prompt": (
            "Look for nonpublic contract terms, quotes, deal conditions, invoices, "
            "payments, billing, and revenue records. Words such as contract, sales, "
            "invoice, and revenue only help locate context; explain why a concrete fact "
            "is private business information. A field name or feature description alone "
            "does not establish disclosure."
        ),
    },
    {
        "id": "agent-runtime",
        "title": "User records, sessions, and backend runtime data",
        "prompt": (
            "Inspect the actual contents and provenance of structured data, exports, "
            "logs, and database files in the selected Git scope. Distinguish migrations, "
            "schemas, public configuration, deliberately synthetic data, and real user "
            "or backend records. Do not infer leakage from a filename, extension, or "
            "number of user-like fields. State when a selected binary cannot be reviewed."
        ),
    },
    {
        "id": "agent-infrastructure",
        "title": "Private endpoints, deployments, and cloud resources",
        "prompt": (
            "Check endpoint references including URLs, bare hosts, SSH commands, "
            "configuration reference chains, and constructed addresses. Review whether "
            "an actual instance, storage resource, region, cluster, account, or deployment "
            "is nonpublic. A hostname, UUID, bucket term, cluster term, or public IP alone "
            "does not prove private infrastructure; establish ownership and publication "
            "context without testing credentials or contacting services."
        ),
    },
    {
        "id": "agent-machine",
        "title": "User, workspace, volume, and deployment paths",
        "prompt": (
            "Review concrete macOS, Linux, and Windows account paths, arbitrary working "
            "directories, private or shared volumes, temporary identities, and nonpublic "
            "deployment paths. Distinguish standard system prefixes from private path "
            "components. Do not treat common directory words as proof and do not inspect "
            "the reviewing machine to discover identity data."
        ),
    },
    {
        "id": "agent-product-data",
        "title": "Product data directories and stored content",
        "prompt": (
            "Derive the product data-directory convention from the implementation and "
            "its documented overrides. Distinguish a public path contract from actual "
            "databases, credentials, sessions, runtime records, and user files. Do not "
            "enumerate or read private local data outside the selected repository scope."
        ),
    },
    {
        "id": "agent-devices",
        "title": "Device, host, and hardware identities",
        "prompt": (
            "Check actual serial numbers, UDID or ECID values, ADB device selections, "
            "hostnames, and their links to identifiable devices. A field name or a "
            "nonempty identifier-shaped string alone is not evidence of a real identity. "
            "Distinguish captured identifiers, synthetic tests, and public product IDs."
        ),
    },
    {
        "id": "agent-unstructured-credentials",
        "title": "Credentials outside recognized patterns",
        "prompt": (
            "Review literal assignments and use chains for generic credential fields, "
            "aliases, vendor values, multiline or dynamically assembled values, escaped "
            "or encoded material, serialized JWTs, authentication cookies, SSH "
            "certificates, OpenPGP, DER or PKCS#12 material, and private-key fragments. "
            "Distinguish environment references, public verification keys or signatures, "
            "and real signing or symmetric secrets. Do not invent validation for unknown "
            "formats or test credentials against a service."
        ),
    },
)


REVIEW_INSTRUCTIONS = """Review only the repository and immutable scope identified in the request. Inspect outgoing content in each selected commit, including content removed by a later selected commit, and enough surrounding implementation and documentation to establish context. Do not widen the scan to other repositories, local directories, online services, or backend runtime data.

Automated findings are advisory signals, not leak verdicts. A match can be public protocol material, a schema, a reference, a synthetic fixture, or actual protected information. A scan with no findings is not proof of safety. Review the listed findings exactly once, complete every semantic task, add any contextual findings, and identify concrete unreadable or unresolved items as limitations. Consider authorization, input trust, execution authority, persistence, recovery, dependency provenance and license obligations where the change touches them.

This receipt is a private local file. Retain exact original source evidence and necessary reasoning here only; never copy its sensitive content into chat, logs, CI, uploads or public reports. Use repository-relative locations and bind each observation to actual captured source/version. Do not invent source excerpts or a confirmed verdict from a pattern alone. Do not run untrusted repository scripts, contact endpoints, or validate a credential online. A false-positive judgment applies only to the exact finding and scan identity in this receipt; it does not create a rule, path, or value exception.

Receipt validation checks scope and completeness only. It does not attest Agent identity or prove that every private review duty was performed. CI keeps its own result marked unreviewed."""


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or _CONTROL.search(value):
        raise ValueError(f"Invalid review field: {field}")
    return value.strip()


def _receipt_text(value: Any, field: str) -> str:
    _required_text(value, field)
    return value


def _validate_repository(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise ValueError("Invalid scan repository identity")
    if any(part in {".", ".."} for part in value.split("/")):
        raise ValueError("Invalid scan repository identity")
    return value


def _binding(scan: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(scan, dict):
        raise ValueError("Invalid scan record")
    scan_id = _required_text(scan.get("id"), "scan id")
    repository = _validate_repository(scan.get("repository"))
    scope = _required_text(scan.get("scope"), "scan scope")
    profile_source = _required_text(scan.get("profile_source"), "profile source")
    status = _required_text(scan.get("status"), "scan status")
    head = scan.get("head")
    base = scan.get("base")
    if head is not None and (not isinstance(head, str) or not head.strip()):
        raise ValueError("Invalid scan head")
    if base is not None and (not isinstance(base, str) or not base.strip()):
        raise ValueError("Invalid scan base")
    rule_ids = scan.get("rule_ids", [])
    if not isinstance(rule_ids, list) or any(not isinstance(item, str) or not item for item in rule_ids):
        raise ValueError("Invalid scan rules")
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError("Duplicate scan rules")
    coverage = scan.get("coverage", {})
    if not isinstance(coverage, dict):
        raise ValueError("Invalid scan coverage")
    commit_ids = coverage.get("commit_ids", [head] if head else [])
    if not isinstance(commit_ids, list) or any(not isinstance(item, str) or not item for item in commit_ids):
        raise ValueError("Invalid scan commit scope")
    if len(commit_ids) != len(set(commit_ids)):
        raise ValueError("Duplicate scan commits")
    return {
        "id": scan_id,
        "repository": repository,
        "head": head,
        "base": base,
        "scope": scope,
        "profile_source": profile_source,
        "status": status,
        "rule_ids": list(rule_ids),
        "commit_ids": list(commit_ids),
    }


def _finding_identity(finding: Any) -> dict[str, Any]:
    if not isinstance(finding, dict):
        raise ValueError("Invalid scan finding")
    identity = {key: finding[key] for key in FINDING_IDENTITY_FIELDS if key in finding}
    path = identity.get("file") or identity.get("path")
    if not isinstance(path, str) or not path:
        raise ValueError("Scan finding has no repository-relative location")
    if identity.get("file") and identity.get("path") and identity["file"] != identity["path"]:
        raise ValueError("Scan finding contains conflicting paths")
    if not (identity.get("rule") or identity.get("rule_id")):
        raise ValueError("Scan finding has no rule identity")
    if identity.get("rule") and identity.get("rule_id") and identity["rule"] != identity["rule_id"]:
        raise ValueError("Scan finding contains conflicting rule identities")
    for key, value in identity.items():
        if key == "source_evidence":
            if not isinstance(value, dict) or value.get("kind") not in {"literal_match", "derived"}:
                raise ValueError("Invalid source evidence identity")
            if value["kind"] == "literal_match":
                matched = value.get("matched_text")
                span = value.get("span", {})
                context = value.get("context", {})
                if (not isinstance(matched, str) or not isinstance(span, dict)
                        or type(span.get("start")) is not int or type(span.get("end")) is not int
                        or span["start"] < 0 or span["end"] - span["start"] != len(matched)
                        or span.get("unit") != "unicode_codepoint"
                        or not isinstance(context, dict) or not isinstance(context.get("text"), str)
                        or matched not in context["text"]):
                    raise ValueError("Invalid literal source evidence")
            if not isinstance(value.get("provenance"), dict) or value["provenance"].get("commit") != finding.get("commit"):
                raise ValueError("Source evidence does not match its finding version")
        elif key in {"line", "column", "end_line", "end_column", "start", "end"}:
            if value is not None and type(value) is not int:
                raise ValueError("Invalid scan finding location")
            if value is not None and value < (0 if key in {"start", "end"} else 1):
                raise ValueError("Invalid scan finding location")
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            raise ValueError("Invalid scan finding metadata")
    if identity.get("start") is not None and identity.get("end") is not None and identity["end"] < identity["start"]:
        raise ValueError("Invalid scan finding span")
    if identity.get("line") is not None and identity.get("end_line") is not None and identity["end_line"] < identity["line"]:
        raise ValueError("Invalid scan finding line range")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")):
        raise ValueError("Scan finding location must be repository relative")
    return deepcopy(identity)


def _tasks(scan: dict[str, Any]) -> list[dict[str, str]]:
    tasks = [dict(task) for task in REVIEW_TOPICS]
    detector_tasks = scan.get("semantic_review", [])
    if not isinstance(detector_tasks, list):
        raise ValueError("Invalid detector review tasks")
    for task in detector_tasks:
        if not isinstance(task, dict) or set(task) != {"id", "title", "prompt"}:
            raise ValueError("Detector review tasks require id, title, and prompt")
        item = {key: _required_text(task.get(key), f"semantic task {key}") for key in ("id", "title", "prompt")}
        tasks.append(item)
    profile_tasks = scan.get("local_review", [])
    if not isinstance(profile_tasks, list):
        raise ValueError("Invalid repository review requirements")
    repository = _validate_repository(scan.get("repository"))
    repository_key = _PROFILE_ID_PART.sub("-", repository).strip("-.")
    for index, prompt in enumerate(profile_tasks):
        prompt = _required_text(prompt, "repository review requirement")
        tasks.append({
            "id": f"profile:{repository_key}:{index}",
            "title": f"Repository review requirement {index + 1}",
            "prompt": prompt,
        })
    ids = [item["id"] for item in tasks]
    if len(ids) != len(set(ids)):
        raise ValueError("Review task identities must be unique")
    return tasks


def _scan_findings(scan: dict[str, Any]) -> list[dict[str, Any]]:
    findings = scan.get("findings")
    if not isinstance(findings, list):
        raise ValueError("Invalid scan findings")
    result = []
    for index, finding in enumerate(findings):
        identity = _finding_identity(finding)
        display = {key: finding[key] for key in FINDING_DISPLAY_FIELDS if key in finding}
        result.append({"index": index, "identity": identity, "signal": display})
    return result


def _review_files(scan: dict[str, Any]) -> list[dict[str, Any]]:
    files = scan.get("local_review_files", [])
    if not isinstance(files, list):
        raise ValueError("Invalid local review file manifest")
    binding = _binding(scan)
    selected_commits = set(binding["commit_ids"])
    permits_uncommitted = binding["scope"] in {"staged", "worktree"}
    result = []
    seen = set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "commits", "states"}:
            raise ValueError("Local review files require path, commits, and states")
        path = _required_text(item.get("path"), "review file path")
        parsed = PurePosixPath(path)
        if parsed.is_absolute() or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")):
            raise ValueError("Review file path must be repository relative")
        if path in seen:
            raise ValueError("Local review file paths must be unique")
        seen.add(path)
        commits = item.get("commits")
        if (not isinstance(commits, list)
                or (not commits and not permits_uncommitted)
                or any(not isinstance(value, str) or value not in selected_commits for value in commits)):
            raise ValueError("Review file commits must belong to the selected scan scope")
        if len(commits) != len(set(commits)):
            raise ValueError("Duplicate file-scope commits")
        states = item.get("states")
        if not isinstance(states, dict) or any(
            not isinstance(key, str) or type(count) is not int or count < 0
            for key, count in states.items()
        ):
            raise ValueError("Invalid local review file coverage states")
        if not states or not any(states.values()):
            raise ValueError("Review file coverage must identify an inspected version")
        result.append({"path": parsed.as_posix(), "commits": list(commits), "states": dict(states)})
    return result


def _safe_scan_copy(scan: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "visibility", "started_at", "finished_at", "trigger", "agent_review",
        "status", "coverage", "local_review", "semantic_review", "source_mode",
    )
    result = _binding(scan)
    result.update({key: deepcopy(scan[key]) for key in fields if key in scan})
    result["findings"] = [item["signal"] | item["identity"] for item in _scan_findings(scan)]
    return result


def create_review_request(scan: dict[str, Any]) -> dict[str, Any]:
    """Build the private local Agent handoff from one actual scan result."""
    tasks = _tasks(scan)
    binding = _binding(scan)
    # Bind receipts to the exact centrally selected semantic duties as well as
    # the scan head/range. A changed profile prompt cannot reuse an old review.
    binding["review_tasks"] = tasks
    request = {
        "schema": "general-auditor-local-review",
        "binding": binding,
        "instructions": REVIEW_INSTRUCTIONS,
        "tasks": tasks,
        "findings": _scan_findings(scan),
        "coverage": deepcopy(scan.get("coverage", {})),
        "files": _review_files(scan),
    }
    return request


def render_review_template(request: dict[str, Any]) -> str:
    """Render an editable JSON receipt scaffold without adding source content."""
    if not isinstance(request, dict) or request.get("schema") != "general-auditor-local-review":
        raise ValueError("Invalid review request")
    binding = request.get("binding")
    tasks = request.get("tasks")
    findings = request.get("findings")
    if not isinstance(binding, dict) or not isinstance(tasks, list) or not isinstance(findings, list):
        raise ValueError("Invalid review request")
    scaffold = {
        "schema": "general-auditor-local-review-receipt",
        "binding": binding,
        "summary": "",
        "finding_reviews": [
            {
                "index": item["index"],
                "identity": item["identity"],
                "verdict": "",
                "basis": "",
                "impact": "",
                "action": "",
            }
            for item in findings
        ],
        "semantic_reviews": [
            {"id": task["id"], "conclusion": "", "evidence": ""}
            for task in tasks
        ],
        "additional_findings": [],
        "limitations": [],
    }
    packet = {
        "schema": "general-auditor-review-handoff",
        "instructions": request.get("instructions", REVIEW_INSTRUCTIONS),
        "request": {
            "binding": binding,
            "coverage": request.get("coverage", {}),
            "files": request.get("files", []),
            "tasks": tasks,
            "findings": findings,
        },
        "receipt_template": scaffold,
    }
    return json.dumps(packet, ensure_ascii=False, indent=2) + "\n"


def _validate_additional(item: Any) -> dict[str, Any]:
    fields = {"path", "line", "commit", "category", "rule", "verdict", "basis", "impact", "action"}
    if not isinstance(item, dict) or set(item) != fields:
        raise ValueError("Invalid additional finding; include location and judgment fields only")
    path = _required_text(item.get("path"), "additional finding path")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")):
        raise ValueError("Additional finding path must be repository relative")
    if type(item.get("line")) is not int or item["line"] < 1:
        raise ValueError("Additional finding requires a positive source line")
    commit_id = item.get("commit")
    if commit_id is not None and (not isinstance(commit_id, str) or not commit_id.strip()):
        raise ValueError("Invalid additional finding commit")
    if not isinstance(item.get("verdict"), str) or item["verdict"] not in VERDICTS:
        raise ValueError("Invalid additional finding verdict")
    return {
        "path": parsed.as_posix(),
        "line": item["line"],
        "commit": commit_id.strip() if isinstance(commit_id, str) else None,
        "category": _receipt_text(item.get("category"), "additional finding category"),
        "rule": _receipt_text(item.get("rule"), "additional finding rule"),
        "verdict": item["verdict"],
        "basis": _receipt_text(item.get("basis"), "additional finding basis"),
        "impact": _receipt_text(item.get("impact"), "additional finding impact"),
        "action": _receipt_text(item.get("action"), "additional finding action"),
    }


def validate_review(scan: dict[str, Any], review: dict[str, Any]) -> None:
    """Reject stale, incomplete or differently bound local review receipts."""
    request = create_review_request(scan)
    if not isinstance(review, dict):
        raise ValueError("Invalid local review receipt")
    allowed = {
        "schema", "binding", "summary", "finding_reviews", "semantic_reviews",
        "additional_findings", "limitations",
    }
    if set(review) != allowed or review.get("schema") != "general-auditor-local-review-receipt":
        raise ValueError("Invalid local review receipt fields")
    if review.get("binding") != request["binding"]:
        raise ValueError("Review receipt belongs to a different scan identity or scope")
    _receipt_text(review.get("summary"), "summary")

    expected_findings = request["findings"]
    entries = review.get("finding_reviews")
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        raise ValueError("Invalid finding judgments")
    expected_indexes = list(range(len(expected_findings)))
    indexes = [item.get("index") for item in entries]
    if any(type(index) is not int for index in indexes) or sorted(indexes) != expected_indexes:
        raise ValueError("Every scan finding must have exactly one judgment")
    for item in entries:
        if set(item) != {"index", "identity", "verdict", "basis", "impact", "action"}:
            raise ValueError("Finding judgment contains invalid fields")
        expected = expected_findings[item["index"]]
        if item.get("identity") != expected["identity"]:
            raise ValueError("Finding judgment is bound to a different location or rule")
        if not isinstance(item.get("verdict"), str) or item["verdict"] not in VERDICTS:
            raise ValueError("Finding judgment needs a contextual verdict")
        for field in ("basis", "impact", "action"):
            _receipt_text(item.get(field), f"finding {field}")

    expected_tasks = request["tasks"]
    semantic = review.get("semantic_reviews")
    if not isinstance(semantic, list) or any(not isinstance(item, dict) for item in semantic):
        raise ValueError("Invalid semantic review records")
    expected_ids = [task["id"] for task in expected_tasks]
    ids = [item.get("id") for item in semantic]
    if any(not isinstance(task_id, str) for task_id in ids) or len(ids) != len(expected_ids) or set(ids) != set(expected_ids):
        raise ValueError("Every common and repository-specific review task must be completed exactly once")
    for item in semantic:
        if set(item) != {"id", "conclusion", "evidence"}:
            raise ValueError("Semantic review contains invalid fields")
        _receipt_text(item.get("conclusion"), "semantic conclusion")
        _receipt_text(item.get("evidence"), "semantic evidence")

    additional = review.get("additional_findings")
    if not isinstance(additional, list):
        raise ValueError("Invalid additional findings")
    for item in additional:
        normalized = _validate_additional(item)
        commit_id = normalized["commit"]
        if commit_id is None and request["binding"]["scope"] not in {"staged", "worktree"}:
            raise ValueError("An additional finding without a commit must belong to staged or worktree scope")
        if commit_id is not None and commit_id not in request["binding"]["commit_ids"]:
            raise ValueError("Additional finding commit is outside the selected scan scope")
    limitations = review.get("limitations")
    if not isinstance(limitations, list):
        raise ValueError("Limitations must identify unresolved or unreadable scope")
    for item in limitations:
        _receipt_text(item, "limitation")


def complete_review(scan: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    """Return a local-only reviewed copy while preserving the unreviewed scan."""
    request = create_review_request(scan)
    validate_review(scan, review)
    finding_reviews = sorted(review["finding_reviews"], key=lambda item: item["index"])
    semantic_reviews = sorted(review["semantic_reviews"], key=lambda item: item["id"])
    additional = [_validate_additional(item) for item in review["additional_findings"]]
    limitations = list(review["limitations"])
    counts = {verdict: 0 for verdict in sorted(VERDICTS)}
    for item in [*finding_reviews, *additional]:
        counts[item["verdict"]] += 1
    scan_complete = scan.get("status") in {"completed", "completed_with_warnings", "policy_failure"} and not scan.get("coverage", {}).get("excluded") and not scan.get("coverage", {}).get("policy", {}).get("incomplete")
    local_scan = _safe_scan_copy(scan)
    return {
        "schema": "general-auditor-local-review-report",
        "publication": "local_only",
        "scan": local_scan,
        "contextual_review": {
            "receipt_status": "complete" if scan_complete and not limitations else "incomplete",
            "disposition": "action_required" if counts["confirmed"] or counts["uncertain"] else "no_confirmed_finding",
            "source": "local_receipt",
            "identity_attested": False,
            "binding": request["binding"],
            "review_files": deepcopy(request["files"]),
            "summary": review["summary"].strip(),
            "finding_reviews": deepcopy(finding_reviews),
            "semantic_reviews": deepcopy(semantic_reviews),
            "additional_findings": additional,
            "limitations": limitations,
            "counts": counts,
        },
    }


def write_local_receipt(root, scan: dict[str, Any], receipt: dict[str, Any]) -> None:
    """Validate and save a receipt only through the fixed private local store."""
    from .local_store import LocalStore
    validate_review(scan, receipt)
    LocalStore(root).write_json("review-receipt.json", receipt)
