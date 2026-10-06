# Maintainer-owned publishing access

The [common policy](common-policy.md#maintainer-owned-publishing) defines the requirement. Repository categories in `profiles/` select its scope; the [grouped inventory](repositories.md) is the human-readable projection.

## Native GitHub controls

| Control | Required setting | Effect |
| --- | --- | --- |
| Pull request feature | Enabled; `collaborators_only` creation policy | Unprivileged external users cannot create a new PR. Users with write, maintain or admin access may propose changes. |
| Branch Ruleset | `Maintainer-owned publishing`, active, every branch | Branch creation, updates and deletion require bypass permission. |
| Bypass roles | Organization administrators; repository maintain and admin | Ordinary repository write access does not permit changing protected branches. |
| Other Rulesets | Preserved | Existing review, status-check and history restrictions continue to apply. |

This governs the upstream repository. Public source can still be read or forked. Existing PR history is not deleted by changing creation access. No automated PR comments or external messages are sent.

GitHub repository role IDs are not sequential by privilege: maintain is `2`, write is `4`, and admin is `5`. The managed Ruleset deliberately excludes the write role. Its bypass permission applies only to this specific Ruleset and does not bypass independent existing rules.

## Administrator operation

```sh
# Read-only inspection of all declared publishing repositories.
python3 tools/configure_access.py

# Explicitly reconcile one authorized repository.
python3 tools/configure_access.py --repository ExampleOrg/ExampleRepo --apply

# Explicitly reconcile all declared publishing repositories.
python3 tools/configure_access.py --apply
```

The command uses the operator's existing authenticated `gh` session without extracting or publishing credentials. It creates or updates only the named managed Ruleset, preserves unrelated Rulesets, and reads back the resulting settings. It does not add collaborators, grant new roles, change visibility, or delete PRs. New publishing repositories must be classified in their profile before this administration operation applies to them.

## Read-only observation

Access-policy inspection is separate from local report generation and CI content
checks. GitHub can withhold `bypass_actors` from read-only callers; that information
must remain **unverified**, not compliant or misconfigured. The administrator
command checks complete policy using authorized access. It does not require a
central scheduled audit or public reporting service.

## References

- [GitHub PR access settings](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/disabling-pull-requests)
- [GitHub repository Rulesets API and bypass visibility](https://docs.github.com/en/rest/repos/rules)
- [GitHub Terraform provider: repository role identifiers](https://github.com/integrations/terraform-provider-github/blob/main/docs/resources/repository_ruleset.md)
