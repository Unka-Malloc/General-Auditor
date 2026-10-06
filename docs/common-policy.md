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

The repository category in each central profile selects this policy. Protocol definitions and software implementations retain their existing contribution policy unless explicitly classified otherwise. Use `tools/configure_access.py` for administrator-side verification and explicit configuration. Read-only access inspection never grants access or weakens a Ruleset. GitHub can omit bypass identities from read-only API responses; unavailable evidence must remain unverified rather than becoming a pass or violation.

General-Auditor itself uses the stricter [maintainer contribution contract](contributing.md): one permanent `only` branch, temporary upstream `work/*` PRs, required checks and no direct source pushes. Detailed reports remain in ignored local files; CI returns only a safe summary and does not publish reports.

## Workflow and documentation identity

First-party workflows, action entry points, files and documentation use stable functional names. Do not introduce version-named workflow copies or use Auditor version tags as workflow identities. General-Auditor's maintained entry point is `only`; callers can pin a reviewed commit when their update policy requires it. External action dependencies remain pinned to immutable commits. Package metadata and published protocol identities do not create permission for version-named development boundaries.

The default root `README.md` is written in English. Chinese documentation belongs in a separate linked document. Both language entries describe the current maintained implementation.

## Evidence and judgments

Each detailed local finding identifies file, line, commit when available, actual matched source and context, rule explanation, judgment and basis, impact and handling. Preserve original source spelling in the private report. Structural findings with no source literal say so. Missing source must not be invented or reconstructed from a redacted archive.

Exact content is authorized only inside the repository's ignored `.general-auditor/local/` files. CI summaries, terminal output, conversation, PRs and cloud artifacts must not contain these values. A report is private data even when its scanned repository is public. The `check` command produces no report; local scan and review commands refuse CI execution.

Automated records use `warning` and `unreviewed`. They do not assert a confirmed issue or false positive. Contextual judgments must be supported by the selected source: `false_positive`, `confirmed`, or `uncertain` with a concrete missing fact. A report with no matches is not proof of safety. Missing coverage and failed scans remain visible.

Local review requests and receipts are bound to one exact scan, its tasks and findings. They may retain the actual evidence in the same private directory. A receipt does not attest Agent identity, prove a conversation occurred, or create a reusable exception. See the [local review guide](../general_auditor/templates/LOCAL-REVIEW.md).

## Enforcement

Pattern matches are advisory. The `scan` and summary-only `check` exit contract is:

| Exit | Scan state | Meaning |
| --- | --- | --- |
| `0` | `completed` or `completed_with_warnings` | Scanning completed; privacy warnings still require contextual review. |
| `2` | `policy_failure` | A declared deterministic repository contract failed. |
| `1` | `incomplete` or execution error | Required input or execution was unavailable; coverage is not complete. |

A `review-complete` command can successfully validate a receipt that records limitations; command success does not certify complete review or privacy safety. Structural checks include declared paths, admitted data formats, documentation structure and CI evidence. Keyword matches inside those surfaces remain advisory. Common deterministic rules are always selected; repository profiles can only add optional rule groups, declared paths and local review requirements. Profile requirements are reviewed by maintainers of General-Auditor; a PR cannot weaken policy by supplying executable rules or a replacement profile inside its target repository.
