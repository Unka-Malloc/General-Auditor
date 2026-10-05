"""Explicit maintainer operation; inspect by default, mutate only with --apply."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from general_auditor.config import MAINTAINER_CATEGORIES, validate_profile
from general_auditor.governance import RULESET_NAME, expected_ruleset, violations


def api(path, method="GET", payload=None):
    command = ["gh", "api", path, "--method", method]
    if payload is not None:
        command += ["--input", "-"]
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError("GitHub settings operation failed; response content withheld")
    return json.loads(result.stdout) if result.stdout else None


def configure(repository, apply=False):
    prefix = "repos/" + repository
    metadata = api(prefix)
    if not metadata.get("permissions", {}).get("admin"):
        raise RuntimeError("Repository administration permission is required")
    existing = [row for row in api(prefix + "/rulesets") if row["name"] == RULESET_NAME]
    if len(existing) > 1:
        raise RuntimeError("Ambiguous managed Ruleset identity")
    ruleset = api(prefix + "/rulesets/" + str(existing[0]["id"])) if existing else None
    if apply:
        if metadata.get("pull_request_creation_policy") != "collaborators_only" or metadata.get("has_pull_requests") is not True:
            api(prefix, "PATCH", {"has_pull_requests": True, "pull_request_creation_policy": "collaborators_only"})
        if ruleset is None:
            ruleset = api(prefix + "/rulesets", "POST", expected_ruleset())
        elif violations({"has_pull_requests": True, "pull_request_creation_policy": "collaborators_only"}, ruleset):
            ruleset = api(prefix + "/rulesets/" + str(ruleset["id"]), "PUT", expected_ruleset())
        metadata = api(prefix)
        ruleset = api(prefix + "/rulesets/" + str(ruleset["id"]))
    issues = violations(metadata, ruleset)
    return {"repository": repository, "status": "compliant" if not issues else "changes_required",
            "pull_request_creation_policy": metadata.get("pull_request_creation_policy"),
            "ruleset_id": ruleset["id"] if ruleset else None, "issues": [rule for rule, _ in issues]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--repository", help="Select one declared maintainer-owned repository")
    args = parser.parse_args()
    selected = []
    for path in sorted((ROOT / "profiles").glob("*/*.json")):
        data = json.loads(path.read_text())
        validate_profile(data, path.relative_to(ROOT / "profiles").as_posix()[:-5])
        if data.get("category") in MAINTAINER_CATEGORIES and (not args.repository or args.repository == data["repository"]):
            selected.append(data["repository"])
    if not selected:
        parser.error("No matching maintainer-owned publishing repository")
    failed = False
    for repository in selected:
        try:
            result = configure(repository, args.apply)
        except (RuntimeError, ValueError, OSError):
            result = {"repository": repository, "status": "unverified"}
        print(json.dumps(result), flush=True)
        failed |= result["status"] != "compliant"
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
