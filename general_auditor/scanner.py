"""Deterministic advisory scanning. Source values never enter result records."""

from datetime import datetime, timezone
from contextlib import nullcontext
from functools import lru_cache
from pathlib import PurePosixPath
import re
from uuid import uuid4

from .config import load_profile, repository_name, validate_profile
from .gitdata import BlobReader, commit, git, tree, index_tree, worktree_tree
from .detection import scan_text, rule_catalog, redact_path
from .repository_policy import evaluate
from copy import deepcopy
import os
import stat
from .rules import CODE_SUFFIXES, COMPILED, matches, selected_rules


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_path(path):
    return redact_path(path)


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


class BlobAnalysis:
    """Bounded per-repository LRU of redacted analysis, shared across branch scans."""

    def __init__(self, root, rules, profile=None):
        self.root, self.rules, self.profile = root, rules, profile or {}
        self.inspect = lru_cache(maxsize=4096)(self._inspect)

    def __enter__(self):
        self.blobs = BlobReader(self.root)
        return self

    def __exit__(self, *_):
        self.inspect.cache_clear()
        self.blobs.close()

    def _inspect(self, path, mode, kind, oid, size):
        if kind != "blob":
            return "external submodule content", 0, ()
        if mode == "120000":
            return "symbolic link (not followed)", 0, ()
        data = self.blobs.read(oid)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text is None or "\0" in text:
            return "binary or non-UTF-8 content", 0, ()
        if text.startswith("version https://git-lfs.github.com/spec/v1\n"):
            return "Git LFS object (pointer only)", 0, ()
        return self.inspect_text(path, text, size)

    def inspect_text(self, path, text, size):
        detected = scan_text(text, path, profile=self.profile)
        hits = detected["findings"]
        for rule, regex in self.rules:
            if not applies(rule, path):
                continue
            for match in matches(rule, regex, text):
                hits.append(finding(path, text.count("\n", 0, match.start()) + 1, None, rule))
        return None, size, detected


def _worktree_read(root, raw_path):
    # Open each path component relative to a directory descriptor. No symlink,
    # including a replaced parent directory, can escape the selected repository.
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = raw_path.split(b"/")
        if any(part in {b"", b".", b".."} for part in parts):
            raise ValueError("Invalid repository path")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(leaf, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError("Not a regular repository file")
            return source.read()
    finally:
        os.close(fd)


def _decode(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\0" in text or text.startswith("version https://git-lfs.github.com/spec/v1\n"):
        return None
    return text


def scan(root, repository, *, head="HEAD", base=None, policy_root=".", profile=None,
         visibility="private", trigger="local", analysis=None, scope=None, event=None):
    repository_name(repository)
    if visibility not in {"public", "private"}:
        raise ValueError("Invalid visibility")
    if profile is None:
        profile, profile_source = load_profile(policy_root, repository)
    else:
        profile = validate_profile(profile, repository)
        profile_source = "explicit"
    selected_scope = scope or ("range" if base else "snapshot")
    if selected_scope not in {"snapshot", "range", "history", "staged", "worktree"}:
        raise ValueError("Invalid scan scope")
    if selected_scope == "range" and not base:
        raise ValueError("A range requires a base commit")
    if base and selected_scope != "range":
        raise ValueError("A base applies only to range scans")
    head = commit(root, head)
    base = commit(root, base) if base else None
    scope = "commit-range" if selected_scope == "range" else selected_scope
    revisions = [head]
    if selected_scope in {"range", "history"}:
        if git(root, "rev-parse", "--is-shallow-repository").stdout.strip() == b"true":
            raise ValueError("History audits require complete ancestry")
        if base and git(root, "merge-base", "--is-ancestor", base, head, check=False).returncode:
            common = git(root, "merge-base", base, head, check=False)
            if common.returncode:
                raise ValueError("A range requires shared ancestry")
            base = common.stdout.decode().strip()
            scope = "commit-range-after-divergence"
        revisions = git(root, "rev-list", "--reverse", base + ".." + head if base else head).stdout.decode().splitlines()
    rules = selected_rules(profile.get("additional_rule_groups", []))
    result = {
        "id": str(uuid4()), "repository": repository, "visibility": visibility,
        "started_at": utc_now(), "finished_at": None, "head": head, "base": base,
        "trigger": trigger, "scope": scope, "profile_source": profile_source,
        "rule_ids": [rule.id for rule in rule_catalog()] + [rule.id for rule, _ in rules],
        "local_review": profile.get("local_review", []), "semantic_review": [],
        "local_review_files": [], "agent_review": "not_performed", "status": "completed", "findings": [],
        "coverage": {"commits": len(revisions), "commit_ids": revisions, "text_versions": 0, "bytes": 0, "excluded": [],
                     "privacy": {"evaluated_rule_ids": [rule.id for rule in rule_catalog()], "exempted": [], "finding_counts": []}},
    }
    metadata = dict(event or {})
    metadata.update(head=head, trigger=trigger)
    if "branch_refs" not in metadata:
        refs = git(root, "for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes").stdout.decode("utf-8", "replace").splitlines()
        metadata["branch_refs"] = sorted(set(ref if ref.startswith("refs/heads/") else "refs/heads/" + ref.split("/", 3)[-1] for ref in refs if not ref.endswith("/HEAD")))
    metadata["commit_metadata"] = []
    with BlobReader(root) as commits:
        for revision in revisions:
            kind, raw = commits.read_object(revision)
            if kind != "commit":
                raise ValueError("Commit metadata unavailable")
            headers, _, message = raw.decode("utf-8", "replace").partition("\n\n")
            record = {"trailers": [line for line in message.splitlines() if re.match(r"(?i)^(?:co-authored-by|signed-off-by|reviewed-by|committed-by):", line)]}
            for key in ("author", "committer"):
                match = re.search(r"(?m)^" + key + r" (.*?) <", headers)
                record[key + "_name"] = match.group(1) if match else ""
            metadata["commit_metadata"].append(record)
    seen, topics, review_files = set(), {}, {}
    local_rows = list(index_tree(root)) if selected_scope == "staged" else list(worktree_tree(root)) if selected_scope == "worktree" else None
    candidates = list(tree(root, head)) if local_rows is None else local_rows
    with (nullcontext(analysis) if analysis is not None else BlobAnalysis(root, rules, profile)) as analyzer:
        for revision in revisions:
            changed = None
            if selected_scope == "range":
                parent = git(root, "rev-parse", revision + "^", check=False)
                if parent.returncode == 0:
                    changed = set(git(root, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z", parent.stdout.decode().strip(), revision).stdout.decode("utf-8", "replace").split("\0"))
            rows = local_rows if local_rows is not None else tree(root, revision)
            for row in rows:
                path, mode, kind, oid, size = row[:5]
                if (changed is not None and path not in changed) or (path, oid) in seen:
                    continue
                seen.add((path, oid))
                if selected_scope == "worktree":
                    text = _decode(_worktree_read(root, row[5])) if mode != "120000" and kind == "blob" else None
                    reason, inspected_bytes, detected = analyzer.inspect_text(path, text, len(text.encode("utf-8"))) if text is not None else ("symbolic link, external submodule or non-text content", 0, {})
                else:
                    reason, inspected_bytes, detected = analyzer.inspect(path, mode, kind, oid, size)
                location = {"file": safe_path(path), "commit": revision, "object": oid, "mode": mode}
                review_file = review_files.setdefault(safe_path(path), {"path": safe_path(path), "commits": [], "states": {}})
                if revision not in review_file["commits"]:
                    review_file["commits"].append(revision)
                state = "excluded" if reason else "inspected"
                review_file["states"][state] = review_file["states"].get(state, 0) + 1
                if reason:
                    result["coverage"]["excluded"].append({**location, "reason": reason})
                    continue
                result["coverage"]["text_versions"] += 1
                result["coverage"]["bytes"] += inspected_bytes
                for item in detected["findings"]:
                    located = {**deepcopy(item), "commit": revision}
                    if "span" in located:
                        located.update(located.pop("span"))
                    result["findings"].append(located)
                result["coverage"]["privacy"]["finding_counts"].extend({**item, "file": safe_path(path), "commit": revision} for item in detected["coverage"]["finding_counts"])
                result["coverage"]["privacy"]["exempted"].extend({**item, "file": safe_path(path), "commit": revision} for item in detected["coverage"]["exempted"])
                topics.update({topic["id"]: topic for topic in detected["semantic_review"]})
        rows_by_path = {row[0]: row for row in candidates}
        def read_text(path):
            row = rows_by_path[path]
            if row[1] == "120000" or row[2] != "blob":
                return None
            return _decode(_worktree_read(root, row[5]) if selected_scope == "worktree" else analyzer.blobs.read(row[3]))
        policy = evaluate(repository, profile, [dict(zip(("path", "mode", "kind", "oid", "size"), row[:5])) for row in candidates], read_text, metadata)
    for item in policy["findings"]:
        item["file"] = safe_path(item["file"])
    for item in policy["coverage"].get("incomplete", []):
        if "path" in item:
            item["path"] = safe_path(item["path"])
    result["findings"].extend(policy["findings"])
    result["coverage"]["policy"] = policy["coverage"]
    result["rule_ids"] = list(dict.fromkeys(result["rule_ids"] + policy["coverage"]["evaluated"]))
    result["local_review"] = policy["review_tasks"]
    result["semantic_review"] = list(topics.values())
    result["local_review_files"] = list(review_files.values())
    result["status"] = ("incomplete" if policy["coverage"]["incomplete"] else "policy_failure" if policy["coverage"]["blocking"]
                        else "completed_with_warnings" if result["findings"] else "completed")
    result["finished_at"] = utc_now()
    return result


def failed_result(repository, head, trigger, category="scan_unavailable"):
    return {"id": str(uuid4()), "repository": repository, "visibility": "public",
            "head": head, "base": None, "trigger": trigger, "scope": "unavailable",
            "started_at": utc_now(), "finished_at": utc_now(), "status": "incomplete",
            "agent_review": "not_performed", "profile_source": "unavailable", "rule_ids": [],
            "local_review": [], "findings": [], "coverage": {"commits": 0, "text_versions": 0, "bytes": 0, "excluded": []},
            "error": category}
