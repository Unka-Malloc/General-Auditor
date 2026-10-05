"""Validate General-Auditor's maintainer-owned temporary-branch PR contract."""

import json
import os
import re
from pathlib import Path
import sys


def validate(event, maintainers):
    pull = event.get("pull_request")
    if pull is None:
        return
    repository = event["repository"]["full_name"]
    if pull["base"]["ref"] != "only":
        raise ValueError("The only supported PR destination is only")
    if not re.fullmatch(r"work/[A-Za-z0-9._-]+", pull["head"]["ref"]) or (pull["head"].get("repo") or {}).get("full_name") != repository:
        raise ValueError("Contributions require a temporary work/ branch in this repository")
    if pull["user"]["login"].lower() not in {name.lower() for name in maintainers}:
        raise ValueError("The PR author is not a designated Auditor maintainer")


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    try:
        validate(json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()), json.loads((root / ".github/maintainers.json").read_text()))
    except (ValueError, KeyError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
    print("PASS Auditor contribution policy")
