"""Inspect or explicitly apply this repository's maintained GitHub policy."""

import argparse
import json
from pathlib import Path

from configure_access import api

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "Unka-Malloc/General-Auditor"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    prefix = "repos/" + REPOSITORY
    settings = {"default_branch": "only", "has_pull_requests": True, "pull_request_creation_policy": "collaborators_only", "delete_branch_on_merge": True, "allow_squash_merge": True, "allow_merge_commit": False, "allow_rebase_merge": False, "allow_auto_merge": True}
    if args.apply:
        api(prefix, "PATCH", settings)
    actual = api(prefix)
    problems = [key for key, value in settings.items() if actual.get(key) != value]
    known = {row["name"]: row["id"] for row in api(prefix + "/rulesets")}
    for path in sorted((ROOT / ".github/rulesets").glob("auditor-*.json")):
        expected = json.loads(path.read_text())
        identity = known.get(expected["name"])
        if args.apply:
            result = api(prefix + "/rulesets" + ("/" + str(identity) if identity else ""), "PUT" if identity else "POST", expected)
            identity = result["id"]
        observed = api(prefix + "/rulesets/" + str(identity)) if identity else {}
        # API responses add default fields to individual rule parameters.
        def contains(wanted, seen):
            if isinstance(wanted, dict):
                return isinstance(seen, dict) and all(key in seen and contains(value, seen[key]) for key, value in wanted.items())
            if isinstance(wanted, list):
                return isinstance(seen, list) and len(wanted) == len(seen) and all(any(contains(item, candidate) for candidate in seen) for item in wanted)
            return wanted == seen
        compliant = contains(expected, observed)
        print(json.dumps({"ruleset": expected["name"], "id": identity, "compliant": compliant}))
        if not compliant:
            problems.append(expected["name"])
    print(json.dumps({"repository": REPOSITORY, "settings_issues": problems}))
    return bool(problems)


if __name__ == "__main__":
    raise SystemExit(main())
