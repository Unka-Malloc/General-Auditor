"""Deterministic advisory scanning. Source values never enter result records."""

from datetime import datetime, timezone
from pathlib import PurePosixPath
import re
from uuid import uuid4

from .config import load_profile, repository_name, validate_profile
from .gitdata import BlobReader, MAX_TEXT_BYTES, commit, git, tree
from .rules import CODE_SUFFIXES, COMPILED, matches, selected_rules


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_path(path):
    # Paths remain useful locations, while common sensitive path components are masked.
    value = re.sub(r"[\x00-\x1f\x7f]", "_", path)
    value = re.sub(r"[^/\s]+@[^/\s]+\.[^/\s]+", "[redacted-email]", value)
    for rule, pattern in COMPILED:
        if rule.group == "common":
            value = pattern.sub("[redacted]", value)
    return value


def applies(rule, path):
    suffix = PurePosixPath(path).suffix.lower()
    if rule.group == "code":
        return suffix in CODE_SUFFIXES
    if rule.group == "workflows":
        return path.startswith(".github/workflows/") and suffix in {".yml", ".yaml"}
    return True


def finding(path, line, revision, rule, *, basis=None):
    return {
        "file": safe_path(path), "line": line, "commit": revision,
        "rule": rule.id, "category": rule.category, "severity": "warning",
        "evidence": "[source value withheld] " + rule.description,
        "judgment": "unreviewed", "basis": basis or "Pattern match only; source context requires local Agent or maintainer review.",
        "impact": "Potential exposure or policy risk if contextual review confirms it.",
        "action": rule.action,
    }


def scan(root, repository, *, head="HEAD", base=None, policy_root=".", profile=None, visibility="private", trigger="local"):
    repository_name(repository)
    if visibility not in {"public", "private"}:
        raise ValueError("Invalid visibility")
    if profile is None:
        profile, profile_source = load_profile(policy_root, repository)
    else:
        profile = validate_profile(profile, repository)
        profile_source = "explicit"
    head = commit(root, head)
    base = commit(root, base) if base else None
    scope = "snapshot"
    revisions = [head]
    if base:
        if git(root, "merge-base", "--is-ancestor", base, head, check=False).returncode:
            common = git(root, "merge-base", base, head, check=False)
            if common.returncode == 0:
                base = common.stdout.decode().strip()
                scope = "commit-range-after-divergence"
            else:
                scope = "snapshot-after-unrelated-history"
        if scope != "snapshot-after-unrelated-history":
            if scope == "snapshot":
                scope = "commit-range"
            revisions = git(root, "rev-list", "--reverse", base + ".." + head).stdout.decode().splitlines()
    if base and git(root, "rev-parse", "--is-shallow-repository").stdout.strip() == b"true":
        raise ValueError("A commit-range audit requires complete ancestry")
    rules = selected_rules(profile.get("additional_rule_groups", []))
    result = {
        "id": str(uuid4()), "repository": repository, "visibility": visibility,
        "started_at": utc_now(), "finished_at": None, "head": head, "base": base,
        "trigger": trigger, "scope": scope, "profile_source": profile_source,
        "rule_ids": [rule.id for rule, _ in rules], "local_review": profile.get("local_review", []),
        "agent_review": "not_performed", "status": "completed", "findings": [],
        "coverage": {"commits": len(revisions), "text_versions": 0, "bytes": 0, "excluded": []},
    }
    seen = set()
    # A range scans changed file versions in every outgoing commit, including content
    # subsequently deleted. A first-parent comparison includes merge resolutions.
    with BlobReader(root) as blobs:
        for revision in revisions:
            changed = None
            if base:
                if scope.startswith("commit-range"):
                    parent = git(root, "rev-parse", revision + "^", check=False)
                    if parent.returncode == 0:
                        changed = set(git(root, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z", parent.stdout.decode().strip(), revision).stdout.decode("utf-8", "replace").split("\0"))
            for path, mode, kind, oid, size in tree(root, revision):
                if (changed is not None and path not in changed) or (path, oid) in seen:
                    continue
                seen.add((path, oid))
                reason = None
                if kind != "blob":
                    reason = "external submodule content"
                elif mode == "120000":
                    reason = "symbolic link (not followed)"
                elif size > MAX_TEXT_BYTES:
                    reason = "file exceeds 2 MiB text limit"
                if reason:
                    result["coverage"]["excluded"].append({"file": safe_path(path), "commit": revision, "reason": reason})
                    continue
                data = blobs.read(oid)
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    text = None
                if text is None or "\0" in text:
                    reason = "binary or non-UTF-8 content"
                elif text.startswith("version https://git-lfs.github.com/spec/v1\n"):
                    reason = "Git LFS object (pointer only)"
                if reason:
                    result["coverage"]["excluded"].append({"file": safe_path(path), "commit": revision, "reason": reason})
                    continue
                result["coverage"]["text_versions"] += 1
                result["coverage"]["bytes"] += size
                applicable = [(rule, regex) for rule, regex in rules if applies(rule, path)]
                for line, content in enumerate(text.splitlines(), 1):
                    for rule, regex in applicable:
                        if next(matches(rule, regex, content), None) is not None:
                            result["findings"].append(finding(path, line, revision, rule))
    paths = {row[0] for row in tree(root, head)}
    for required in profile.get("required_paths", []):
        if not any(path == required or path.startswith(required.rstrip("/") + "/") for path in paths):
            result["findings"].append({
                "file": safe_path(required), "line": None, "commit": head,
                "rule": "repository.required-path", "category": "Repository contract", "severity": "warning",
                "evidence": "Declared repository path is absent", "judgment": "unreviewed",
                "basis": "This path is explicitly declared by this repository profile; no global layout is required.",
                "impact": "A repository-specific documented asset may be missing.",
                "action": "Confirm the contract or update the repository-specific profile.",
            })
    result["status"] = "completed_with_warnings" if result["findings"] else "completed"
    result["finished_at"] = utc_now()
    return result


def failed_result(repository, head, trigger, category="scan_unavailable"):
    return {"id": str(uuid4()), "repository": repository, "visibility": "public",
            "head": head, "base": None, "trigger": trigger, "scope": "unavailable",
            "started_at": utc_now(), "finished_at": utc_now(), "status": "incomplete",
            "agent_review": "not_performed", "profile_source": "unavailable", "rule_ids": [],
            "local_review": [], "findings": [], "coverage": {"commits": 0, "text_versions": 0, "bytes": 0, "excluded": []},
            "error": category}
