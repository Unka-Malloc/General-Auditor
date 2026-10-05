"""Single verification entry point; collect independent failures in one run."""

import ast
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from general_auditor.config import validate_profile
from general_auditor.rules import COMPILED


def source_and_profiles():
    for directory in ("general_auditor", "tests", "tools"):
        for path in (ROOT / directory).rglob("*.py"):
            ast.parse(path.read_text(), filename=str(path.relative_to(ROOT)))
    for path in (ROOT / "profiles").glob("*/*.json"):
        repository = path.relative_to(ROOT / "profiles").as_posix()[:-5]
        profile = validate_profile(json.loads(path.read_text()), repository)
        if len(profile.get("local_review", [])) < 3:
            raise ValueError("Repository-specific Agent review requirements are missing")
    ids = [rule.id for rule, _ in COMPILED]
    if len(ids) != len(set(ids)):
        raise ValueError("Rule identities must be unique")
    for required in ("README.md", "docs/README.md", "action.yml", ".github/workflows/audit.yml", ".github/workflows/verify.yml"):
        if not (ROOT / required).is_file():
            raise ValueError("Required auditor delivery asset is missing")


failed = []
try:
    source_and_profiles()
    print("PASS source syntax, rule identities and repository profiles", flush=True)
except (ValueError, SyntaxError, OSError) as error:
    failed.append("source and profile contracts")
    print("FAIL source and profile contracts: " + type(error).__name__, flush=True)
result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT)
if result.returncode:
    failed.append("deterministic integration tests")
print("Verification " + ("failed: " + ", ".join(failed) if failed else "passed"))
raise SystemExit(bool(failed))
