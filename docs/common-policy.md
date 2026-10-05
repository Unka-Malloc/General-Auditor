# Common policy

This baseline applies to every repository, independently of language, directory structure, branch naming or repository-specific policy. Repository policy adds requirements; it cannot exempt a repository from this baseline.

## Contextual Agent review

The contributor's local Agent is responsible for contextual review before publication. CI does not host an Agent, certify that a local Agent ran, or claim that a repository is privacy-safe. A contributor can bypass local tooling; responsibility for disclosure remains with the contributor.

1. Inspect every outgoing commit, including content removed in later commits, and the relevant surrounding implementation and documentation.
2. Keep credentials, private keys, sensitive ciphertext, personal or machine information, nonpublic endpoints, user content and backend runtime data out of published source, examples, test fixtures, reports and logs. Use synthetic data and portable placeholders.
3. Evaluate whether each signal represents actual protected information, a public protocol fact, a schema, a reference, a synthetic fixture or a detector implementation. A hardcoded word or format alone is not a violation.
4. Review authentication, authorization, input trust, execution authority, persistence and recovery where the change touches those boundaries. Do not execute untrusted repository content merely to collect evidence.
5. Review dependency provenance, license obligations and actual usage scope. No single license or release-branch convention is imposed on unrelated projects.
6. Preserve documented publication and support boundaries. Correct unpublished project-owned mistakes consistently across producers, consumers, tests and documentation. Do not infer a support obligation from a development commit alone.
7. Keep repository-triggered review scoped to that repository and the common baseline. Repository-specific findings must not trigger audits of unrelated repositories.

## Maintainer-owned publishing

Official websites, standalone public documentation, benchmark repositories and organization presentation repositories do not accept pull requests from unprivileged external contributors. Their repository settings must enable pull requests for **collaborators only**. GitHub defines collaborators as users with write, maintain or admin access; organization membership alone is not sufficient.

An active `Maintainer-owned publishing` branch Ruleset covers every branch and restricts creation, updates and deletion to organization administrators and repository maintain/admin roles. Repository writers may propose a PR through the collaborator-only entry point, but cannot change these protected branches. Existing review, status-check and history-protection Rulesets continue to apply independently. This policy governs changes to the upstream repository; it does not prevent reading or forking public source.

The repository category in each central profile selects this policy. Protocol definitions and software implementations retain their existing contribution policy unless explicitly classified otherwise. Use `tools/configure_access.py` for administrator-side verification and explicit configuration. CI only observes settings and reports drift; it never grants access or weakens a Ruleset. GitHub omits bypass identities from read-only API responses, so central CI marks that portion unverified rather than inventing a pass or a violation.

General-Auditor itself uses the stricter [maintainer contribution contract](contributing.md): one permanent `only` branch, temporary upstream `work/*` PRs, required checks and no direct source pushes. Reports are published through Actions artifacts and Pages without modifying source branches.

## Workflow and documentation identity

First-party workflows, action entry points, files and documentation use stable functional names. Do not introduce version-named workflow copies or use Auditor version tags as workflow identities. General-Auditor's maintained entry point is `only`; callers can pin a reviewed commit when their update policy requires it. External action dependencies remain pinned to immutable commits. Package metadata and published protocol identities do not create permission for version-named development boundaries.

The default root `README.md` is written in English. Chinese documentation belongs in a separate linked document. Both language entries describe the current maintained implementation.

## Evidence and judgments

Each privacy finding must identify the file, line and commit when available, rule, redacted content category, judgment and basis, impact, and handling recommendation or result. Never copy the sensitive value into the report. Review the original content locally when context is needed.

Automated records use `warning` and `unreviewed`. They do not assert `confirmed leak` or `false positive`. The local Agent's review must explain that distinction using evidence. A report with no matches is not proof of safety. Missing coverage and failed scans must remain visible.

The local `review-request` and `review-complete` commands can bind a redacted receipt to the exact scan, tasks and findings. A receipt records submitted review content only; it does not attest Agent identity or completion of a real conversation. Keep the request, receipt and reviewed report out of CI artifacts and the shared Pages report. See the [local review template](../general_auditor/templates/LOCAL-REVIEW.md) and [audit coverage ledger](audit-coverage.md).

## Enforcement

Pattern matches are advisory. The `scan` exit contract is:

| Exit | Scan state | Meaning |
| --- | --- | --- |
| `0` | `completed` or `completed_with_warnings` | Scanning completed; privacy warnings still require contextual review. |
| `2` | `policy_failure` | A declared deterministic repository contract failed. |
| `1` | `incomplete` or execution error | Required input or execution was unavailable; coverage is not complete. |

A `review-complete` command can successfully validate a receipt that records limitations; command success does not certify complete review or privacy safety. Structural checks include declared paths, admitted data formats, documentation structure and CI evidence. Keyword matches inside those surfaces remain advisory. Common deterministic rules are always selected; repository profiles can only add optional rule groups, declared paths and local review requirements. Profile requirements are reviewed by maintainers of General-Auditor; a PR cannot weaken policy by supplying executable rules or a replacement profile inside its target repository.
