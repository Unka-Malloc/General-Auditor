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

## Evidence and judgments

Each privacy finding must identify the file, line and commit when available, rule, redacted content category, judgment and basis, impact, and handling recommendation or result. Never copy the sensitive value into the report. Review the original content locally when context is needed.

Automated records use `warning` and `unreviewed`. They do not assert `confirmed leak` or `false positive`. The local Agent's review must explain that distinction using evidence. A report with no matches is not proof of safety. Missing coverage and failed scans must remain visible.

## Enforcement

Pattern matches are advisory and return a successful scanner exit status. Invalid configuration, unavailable Git objects or failed infrastructure return a nonzero status. Common deterministic rules are always selected; repository profiles can only add optional rule groups, declared paths and local review requirements. Profile requirements are reviewed by maintainers of General-Auditor; a PR cannot weaken policy by supplying executable rules or a replacement profile inside its target repository.
