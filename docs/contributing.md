# Maintaining General-Auditor

General-Auditor accepts contributions only from its designated maintainers,
currently `Unka-Malloc`. The list is maintained in `.github/maintainers.json` and
ownership is recorded in `.github/CODEOWNERS`. This personal repository's owner
holds its administrator role; ordinary collaborator write access does not grant
authority to update its branches or merge changes.

## Branch and merge contract

`only` is the sole permanent branch. Each change uses a temporary `work/*` branch
in this repository and a PR targeting `only`. GitHub deletes merged temporary
branches automatically. External PR creation is disabled through the native
collaborator-only setting. The contribution check rejects fork sources,
non-maintainer authors and other branch routes.

| Ruleset | Scope | Requirement |
| --- | --- | --- |
| Auditor maintainer authority | All branches | Only the repository administrator role can create, update or delete branches. |
| Auditor branch lifecycle | Everything except `only` and `work/*` | Branch creation is prohibited, with no bypass actors. |
| Auditor contribution gate | `only` | PR required, `verify` required from GitHub Actions (implementation and contribution checks), current base required, conversations resolved, squash-only linear history, no deletion or force push. |

The contribution gate has **no bypass actors**. Administrator bypass of the
separate authority Ruleset does not bypass the PR or check requirements. There
is no report-bot exception. Zero mandatory third-party approvals permits the sole
designated maintainer to submit and merge their own PR after the required checks;
it does not permit a direct push.

The maintained declarations are in `.github/rulesets/`. Use
`python3 tools/configure_auditor.py` to inspect the live configuration and add
`--apply` only for an authorized reconciliation. The command preserves unrelated
Rulesets. Adding a maintainer requires reviewing both the declared identity and
the repository's actual role/Ruleset configuration; changing the list alone does
not grant GitHub permissions.

## Verification and publication

Run `python3 tools/verify.py` after source review and scoped fixes. Required checks
cover the actual implementation and contribution route. Pattern warnings in
audited repositories remain advisory.

Audit results are repository-owned Actions artifacts and one Pages HTML report.
They are not source commits. Scanner and publisher tokens have read-only source
access. The dispatcher starts repository workers, and a separate notification
job requests publication after each scan. The notification job has only Actions
write permission and executes no target source. Pages publication uses its own
deployment permissions. Source changes are always delivered through PRs.

## Consolidated sources

The contribution gate adopts Lico-Auditor's `only` branch, PR-only history,
linear history, resolved discussions and required self-tests. It adopts
styio-audit's promotion-check principle and binds checks to the GitHub Actions
application. Styio's multiple release channels and Lico's project-specific
version checks are not copied: General-Auditor has one maintained branch and
functional workflow names. See [policy sources](policy-sources.md).
