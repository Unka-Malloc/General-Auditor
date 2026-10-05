"""Public inventory, repository-isolated scheduling and report persistence."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime, timezone

from .config import MAINTAINER_CATEGORIES, OWNERS, initialize, load_profile, repository_name
from .github import APIError, GitHub
from .gitdata import GitError, public_repository
from .report import publish, read_json, write_json
from .scanner import BlobAnalysis, failed_result, scan, utc_now
from .rules import selected_rules
from .detection import rule_catalog
from .repository_policy import evaluate
from .governance import finding as governance_finding


def plan(candidates, observations, *, force=False):
    jobs = {}
    for candidate in candidates:
        previous = observations.get(candidate["key"])
        if not force and candidate["key"] in observations and previous == candidate["head"]:
            continue
        base = candidate["base"] if force else (previous or candidate["base"])
        identity = (candidate["repository"], candidate["head"], base, candidate.get("head_ref"), candidate.get("base_ref"))
        if identity not in jobs:
            jobs[identity] = {**candidate, "base": base, "keys": []}
        jobs[identity]["keys"].append(candidate["key"])
    return list(jobs.values())


def execute(job, root, *, checkout=None, analysis=None):
    try:
        if job["head"] is None and job["trigger"] == "empty_repository":
            profile, source = load_profile(root, job["repository"])
            result = failed_result(job["repository"], None, "empty_repository")
            result.pop("error")
            result.update(status="completed", scope="empty-repository", profile_source=source,
                          local_review=profile.get("local_review", []),
                          rule_ids=[rule.id for rule in rule_catalog()] + [rule.id for rule, _ in selected_rules(profile.get("additional_rule_groups", []))])
            policy = evaluate(job["repository"], profile, [], lambda path: None,
                              {"trigger": "empty_repository", "branch_refs": [], "commit_metadata": []})
            result["findings"] = policy["findings"]
            result["coverage"]["policy"] = policy["coverage"]
            result["local_review"] = policy["review_tasks"]
            result["status"] = "incomplete" if policy["coverage"]["incomplete"] else "policy_failure" if policy["coverage"]["blocking"] else "completed_with_warnings" if result["findings"] else "completed"
            return result
        return scan(checkout, job["repository"], head=job["head"], base=job["base"],
                    policy_root=root, visibility="public", trigger=job["trigger"], analysis=analysis, event=job)
    except (GitError, ValueError, OSError):
        return failed_result(job["repository"], job["head"], job["trigger"])


def audit_repository(root, row, observations, *, force, api):
    """Discover, fetch and inspect one repository independently of every other one."""
    name = row["repository"]
    previous = {key: head for key, head in observations.items() if key.startswith(name + ":")}
    try:
        candidates = api.candidates(name, row["default_branch"])
    except APIError:
        return [failed_result(name, None, "discovery", "metadata_unavailable")], previous
    current = {item["key"] for item in candidates}
    updated = {key: head for key, head in previous.items() if key in current}
    jobs = plan(candidates, previous, force=force)
    if not jobs:
        return [], updated
    try:
        initialize(root, name, profile_only=True)
        profile, _ = load_profile(root, name)
    except (ValueError, OSError):
        return [failed_result(name, None, "configuration", "invalid_repository_profile")], updated
    issues = []
    if profile.get("category") in MAINTAINER_CATEGORIES:
        try:
            issues = api.access_policy(name)
        except APIError:
            issues = [("governance.verification-unavailable", "GitHub access-policy metadata could not be verified.")]
    results = []
    if all(job["head"] is None for job in jobs):
        results = [execute(job, root) for job in jobs]
    else:
        try:
            with public_repository(name, jobs) as checkout, BlobAnalysis(checkout, selected_rules(profile.get("additional_rule_groups", [])), profile) as analysis:
                results = [execute(job, root, checkout=checkout, analysis=analysis) for job in jobs]
        except (GitError, OSError):
            results = [failed_result(name, job["head"], job["trigger"]) for job in jobs]
    for job, result in zip(jobs, results):
        for rule, description in issues:
            item = governance_finding(rule, description, result["head"])
            if rule in {"governance.verification-unavailable", "governance.bypass-visibility"}:
                item.update(judgment="unverified", basis=description, impact="The caller cannot verify the full access-policy configuration.")
            result["findings"].append(item)
        if result["findings"] and result["status"] == "completed":
            result["status"] = "completed_with_warnings"
        if result["status"] != "incomplete":
            updated.update({key: job["head"] for key in job["keys"]})
    return results, updated


def run(root, *, repository=None, watch=False, workers=8, api=None, on_repository=None):
    root = Path(root)
    api = api or GitHub()
    if not watch and not repository:
        raise ValueError("Explicitly select a repository or 'all' for a manual scan")
    if repository and repository != "all":
        repository_name(repository)
        if repository.split("/")[0] not in OWNERS:
            raise ValueError("Repository is outside the configured public organizations")
    inventory = api.repositories()
    public = {row["repository"] for row in inventory}
    if repository and repository != "all" and repository not in public:
        raise ValueError("Selected repository is not in the public inventory")
    state = read_json(root / "reports/state.json", {"schema_version": 1, "observations": {}, "updated_at": {}})
    observations = {key: head for key, head in state["observations"].items() if key.split(":", 1)[0] in public}
    updated_at = {name: value for name, value in state.get("updated_at", {}).items() if name in public}
    selected = [row for row in inventory if repository in {None, "all", row["repository"]}]
    results = []
    ledger = publish(root / "reports", [], inventory=public)
    write_json(root / "reports/inventory.json", {"schema_version": 1, "repositories": inventory})
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = {pool.submit(audit_repository, root, row, observations.copy(), force=not watch, api=api): row for row in selected}
        for future in as_completed(pending):
            row = pending[future]
            name = row["repository"]
            completed, updates = future.result()
            observations = {key: head for key, head in observations.items() if not key.startswith(name + ":")}
            observations.update(updates)
            updated_at[name] = datetime.now(timezone.utc).isoformat()
            # Persist each completed repository while independent workers continue.
            ledger = publish(root / "reports", completed, inventory=public)
            write_json(root / "reports/state.json", {"schema_version": 1, "observed_at": utc_now(), "observations": observations, "updated_at": updated_at})
            results.extend(completed)
            if on_repository is not None:
                on_repository(root, name, completed)
            print(name + ": " + str(len(completed)) + " scans completed", flush=True)
    return {"repositories": len(selected), "scans": len(results), "warnings": sum(len(row["findings"]) for row in results),
            "incomplete": sum(row["status"] == "incomplete" for row in results), "policy_failures": sum(row["status"] == "policy_failure" for row in results), "retained_runs": len(ledger["runs"])}
