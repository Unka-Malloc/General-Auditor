"""Maintainer-owned publishing policy and read-only drift detection."""

RULESET_NAME = "Maintainer-owned publishing"


def expected_ruleset():
    # GitHub role IDs are not ordered by privilege: maintain=2, write=4, admin=5.
    # See integrations/terraform-provider-github repository_ruleset documentation.
    return {
        "name": RULESET_NAME, "target": "branch", "enforcement": "active",
        "bypass_actors": [
            {"actor_type": "OrganizationAdmin", "bypass_mode": "always"},
            {"actor_type": "RepositoryRole", "actor_id": 2, "bypass_mode": "always"},
            {"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"},
        ],
        "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
        "rules": [{"type": "creation"}, {"type": "update", "parameters": {"update_allows_fetch_and_merge": False}}, {"type": "deletion"}],
    }


def actors(rows):
    return {(row["actor_type"], None if row["actor_type"] == "OrganizationAdmin" else row.get("actor_id"), row.get("bypass_mode", "always")) for row in rows}


def violations(metadata, ruleset):
    issues = []
    if metadata.get("has_pull_requests") is not True or metadata.get("pull_request_creation_policy") != "collaborators_only":
        issues.append(("governance.pull-request-access", "Pull requests must be enabled for collaborators only."))
    expected = expected_ruleset()
    if not ruleset or any(ruleset.get(key) != expected[key] for key in ("target", "enforcement", "conditions")):
        issues.append(("governance.maintainer-branches", "An active maintainer-only Ruleset must cover every branch without exclusions."))
    else:
        rules = {row["type"]: row for row in ruleset.get("rules", [])}
        if set(rules) != {"creation", "update", "deletion"} or rules.get("update", {}).get("parameters", {}).get("update_allows_fetch_and_merge", False):
            issues.append(("governance.maintainer-branches", "Branch creation, updates and deletion must be restricted without an upstream synchronization exception."))
        if "bypass_actors" not in ruleset:
            issues.append(("governance.bypass-visibility", "GitHub hides bypass identities from this read-only caller; an administrator must verify the maintain/admin role restriction."))
        elif actors(ruleset["bypass_actors"]) != actors(expected["bypass_actors"]):
            issues.append(("governance.maintainer-branches", "Only organization administrators and repository maintain/admin roles may bypass this Ruleset."))
    return issues


def finding(rule, description, head):
    return {"file": "GitHub repository settings", "line": None, "commit": head,
            "source": "github-settings", "rule": rule, "category": "Contribution governance",
            "severity": "warning", "evidence": description, "judgment": "configuration_drift",
            "basis": "The observed GitHub setting differs from the repository category's declared policy.",
            "impact": "Unprivileged contributions or non-maintainer branch changes may be admitted.",
            "action": "A repository administrator should reconcile the declared access policy; CI never changes permissions."}


def check_repository(repository, profile, head, *, api=None):
    """Inspect only the selected repository's declared contribution controls.

    Return source-free findings; unavailable metadata remains explicitly unverified.
    Local source scans do not call this network-backed CI check implicitly.
    """
    from .config import MAINTAINER_CATEGORIES, repository_name
    from .github import APIError, GitHub

    repository_name(repository)
    if profile.get("category") not in MAINTAINER_CATEGORIES:
        return []
    try:
        issues = (api or GitHub()).access_policy(repository)
    except APIError:
        issues = [("governance.verification-unavailable", "GitHub access-policy metadata could not be verified.")]
    findings = []
    for rule, description in issues:
        item = finding(rule, description, head)
        if rule in {"governance.verification-unavailable", "governance.bypass-visibility"}:
            item.update(judgment="unverified", basis=description,
                        impact="The caller cannot verify the full access-policy configuration.")
        findings.append(item)
    return findings
