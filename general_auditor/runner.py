"""Public inventory, repository-isolated scheduling and report persistence."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .config import OWNERS, initialize, load_profile, repository_name
from .github import APIError, GitHub
from .gitdata import GitError, public_clone
from .report import publish, read_json, write_json
from .scanner import failed_result, scan, utc_now
from .rules import selected_rules


def plan(candidates, observations, *, force=False):
    jobs = {}
    for candidate in candidates:
        previous = observations.get(candidate["key"])
        if not force and candidate["key"] in observations and previous == candidate["head"]:
            continue
        base = candidate["base"] if force else (previous or candidate["base"])
        identity = (candidate["repository"], candidate["head"], base)
        if identity not in jobs:
            jobs[identity] = {**candidate, "base": base, "keys": []}
        jobs[identity]["keys"].append(candidate["key"])
    return list(jobs.values())


def execute(job, root):
    try:
        if job["head"] is None and job["trigger"] == "empty_repository":
            profile, source = load_profile(root, job["repository"])
            result = failed_result(job["repository"], None, "empty_repository")
            result.pop("error")
            result.update(status="completed", scope="empty-repository", profile_source=source,
                          local_review=profile.get("local_review", []),
                          rule_ids=[rule.id for rule, _ in selected_rules(profile.get("additional_rule_groups", []))])
            return result
        with public_clone(job["repository"], job["head"], job["base"]) as checkout:
            return scan(checkout, job["repository"], head=job["head"], base=job["base"],
                        policy_root=root, visibility="public", trigger=job["trigger"])
    except (GitError, ValueError, OSError):
        # Keep individual failures visible and let independent repositories finish.
        return failed_result(job["repository"], job["head"], job["trigger"])


def run(root, *, repository=None, watch=False, workers=4, api=None):
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
    state = read_json(root / "reports/state.json", {"schema_version": 1, "observations": {}})
    observations = {key: head for key, head in state["observations"].items() if key.split(":", 1)[0] in public}
    results = []
    candidates = []
    seen_keys = set()
    selected = [row for row in inventory if watch or repository == "all" or repository == row["repository"]]
    for row in selected:
        try:
            discovered = api.candidates(row["repository"], row["default_branch"])
            candidates.extend(discovered)
            seen_keys.update(item["key"] for item in discovered)
            # Remove disappeared branches/closed PRs only after successful discovery.
            prefix = row["repository"] + ":"
            observations = {key: head for key, head in observations.items() if not key.startswith(prefix) or key in seen_keys}
        except APIError:
            results.append(failed_result(row["repository"], None, "discovery", "metadata_unavailable"))
    jobs = plan(candidates, observations, force=not watch)
    invalid = set()
    for name in sorted({job["repository"] for job in jobs}):
        try:
            initialize(root, name, profile_only=True)
        except (ValueError, OSError):
            invalid.add(name)
            results.append(failed_result(name, None, "configuration", "invalid_repository_profile"))
    jobs = [job for job in jobs if job["repository"] not in invalid]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = {pool.submit(execute, job, root): job for job in jobs}
        for future in as_completed(pending):
            job = pending[future]
            result = future.result()
            results.append(result)
            if result["status"] != "incomplete":
                for key in job["keys"]:
                    observations[key] = job["head"]
            print(job["repository"] + ": " + result["status"] + ", " + str(len(result["findings"])) + " advisory signals", flush=True)
    # Public inventory is authoritative: a repository that becomes private is removed.
    ledger = publish(root / "reports", results, inventory=public)
    write_json(root / "reports/inventory.json", {"schema_version": 1, "repositories": inventory})
    write_json(root / "reports/state.json", {"schema_version": 1, "observed_at": utc_now(), "observations": observations})
    return {"repositories": len(selected), "scans": len(results), "warnings": sum(len(row["findings"]) for row in results),
            "incomplete": sum(row["status"] == "incomplete" for row in results), "retained_runs": len(ledger["runs"])}
