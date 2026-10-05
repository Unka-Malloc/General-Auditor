"""Path-independent initialization and repository-scoped policy selection."""

import json
from importlib.resources import files
from pathlib import Path
import re

from .repository_policy import validate_policy_profile


OWNERS = ("SymPolicy", "Meshrix-Platform", "LicoLand")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
GROUPS = {"code", "dependencies", "workflows"}
CATEGORIES = {"unclassified", "software", "tooling", "protocol", "website", "documentation", "benchmark", "organization-profile"}
MAINTAINER_CATEGORIES = {"website", "documentation", "benchmark", "organization-profile"}


def repository_name(value):
    if not isinstance(value, str) or not REPOSITORY.fullmatch(value) or any(part in {".", ".."} for part in value.split("/")):
        raise ValueError("Expected an owner/repository identity")
    return value


def default_profile(repository):
    repository_name(repository)
    return {
        "schema_version": 1,
        "repository": repository,
        "category": "unclassified",
        "additional_rule_groups": ["code", "dependencies", "workflows"],
        "required_paths": [],
        "repository_policy": {},
        "privacy_policy": {},
        "privacy_exceptions": [],
        "local_review": [
            "Review privacy and credential findings in context before the first push.",
            "Review every outgoing commit, not only the final working tree.",
            "Assess project-specific authority, data lifecycle and dependency usage boundaries.",
        ],
    }


def validate_profile(data, repository):
    allowed = {
        "schema_version", "repository", "category", "additional_rule_groups", "required_paths",
        "local_review", "repository_policy", "privacy_policy", "privacy_exceptions",
    }
    if not isinstance(data, dict) or set(data) - allowed:
        raise ValueError("Invalid profile fields")
    if data.get("schema_version") != 1 or data.get("repository") != repository:
        raise ValueError("Profile identity or schema does not match")
    if not isinstance(data.get("category", "unclassified"), str) or data.get("category", "unclassified") not in CATEGORIES:
        raise ValueError("Invalid repository category")
    groups = data.get("additional_rule_groups", [])
    if not isinstance(groups, list) or any(not isinstance(x, str) or x not in GROUPS for x in groups):
        raise ValueError("Invalid additional rule groups")
    for key in ("required_paths", "local_review"):
        if not isinstance(data.get(key, []), list) or any(not isinstance(x, str) or not x for x in data.get(key, [])):
            raise ValueError("Invalid profile list")
    for path in data.get("required_paths", []):
        if Path(path).is_absolute() or ".." in Path(path).parts or "\\" in path or path.startswith("/"):
            raise ValueError("Required paths must be repository relative")
    validate_policy_profile(data)
    return data


def load_profile(root, repository):
    repository_name(repository)
    owner, name = repository.split("/", 1)
    path = Path(root) / "profiles" / owner / (name + ".json")
    if path.exists():
        return validate_profile(json.loads(path.read_text()), repository), "repository"
    return default_profile(repository), "template"


def initialize(root, repository, *, profile_only=False, with_workflow=False):
    """Create missing files only. No required source/docs layout, no overwrites."""
    root = Path(root)
    owner, name = repository.split("/", 1)
    destination = root / ("profiles/" + owner + "/" + name + ".json" if profile_only else ".general-auditor/config.json")
    repository_name(repository)
    created = []
    if destination.exists():
        validate_profile(json.loads(destination.read_text()), repository)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(default_profile(repository), indent=2) + "\n")
        created.append(destination.relative_to(root).as_posix())
    if not profile_only:
        guide = destination.parent / "README.md"
        if not guide.exists():
            guide.write_text(files("general_auditor").joinpath("templates/LOCAL-REVIEW.md").read_text())
            created.append(guide.relative_to(root).as_posix())
        if with_workflow:
            workflow = root / ".github/workflows/general-auditor.yml"
            if not workflow.exists():
                workflow.parent.mkdir(parents=True, exist_ok=True)
                workflow.write_text(files("general_auditor").joinpath("templates/workflow.yml").read_text())
                created.append(workflow.relative_to(root).as_posix())
    return created
