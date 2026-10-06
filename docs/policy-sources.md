# Policy sources and consolidation

The [audit coverage ledger](audit-coverage.md) maps each retained check family
to its General-Auditor implementation, tests, or explicit requirement-backed
replacement. This document records source lineage and scoped attribution.

| Source | Policy material used | General-Auditor treatment |
| --- | --- | --- |
| [Lico-Auditor](https://github.com/LicoLand/Lico-Auditor) | First-party privacy, documentation, contribution, repository-profile and contextual-review policy | Owner-authorized policy data and review intent are represented in the common detector, central profiles, repository policy checks and local review. No Lico-Auditor package is imported or executed. |
| [styio-audit](https://github.com/SymPolicy/styio-audit) | Public common checks and repository-specific resource, dependency, license and CI contract inventories | Selected policy data is adapted into central repository profiles and the policy evaluator. The evaluator consumes the adapted declarations; no styio-audit package is imported or executed. |

The detector and policy evaluator use Python's standard library. Source-derived
policy data does not create a runtime dependency on either former auditor.

Styio's selected policy data remains subject to its Apache-2.0 terms. The scoped
attribution is in the repository-root [`NOTICE`](../NOTICE), and the unmodified
license text is preserved in [`LICENSES/APACHE-2.0.txt`](../LICENSES/APACHE-2.0.txt).
The source repository's [license policy](https://github.com/SymPolicy/styio-audit/blob/main/LICENSE-POLICY.md)
and [Apache license](https://github.com/SymPolicy/styio-audit/blob/main/LICENSE)
are the source references. The scoped notice does not set a license for
General-Auditor as a whole.

Lico-Auditor's first-party policy reuse was directly authorized by its owner.
No third-party source code is imported as a dependency. This document does not
copy private operational records, local machine details, exact detector values,
or private source content.

## Deliberate policy boundaries

- Every repository receives the mandatory common baseline. A trusted central
  profile can add its repository-specific data, structural contracts and local
  semantic tasks; it cannot disable common rules or execute target code.
- Privacy and keyword signals remain advisory. A pattern, field name, IP shape,
  token shape or commercial term does not itself establish a violation. Local
  contextual review remains separate from CI results.
- CI preserves applicable deterministic repository contracts such as file
  admission, resource-scope presence, dependency/license evidence, publishing
  access, documentation structure, and declared workflow requirements. Missing
  evidence or an applicable contract failure is not converted into a privacy
  verdict; incomplete input is reported separately.
- No single release-branch chain, source layout, license, CI suite or package
  framework is imposed on unrelated repositories. Obsolete multi-channel
  promotion workflows are not recreated as a universal policy.
- A local false-positive judgment applies only to its exact scan and finding.
  It does not create a lasting path/value exception. Exact source evidence and receipt reasoning remain in ignored local files.
  CI emits only a safe status/count summary and produces no shared report.

## Source repository retirement

Both Lico-Auditor and styio-audit are private and archived, as verified after
retirement. Their dedicated active profiles have been removed; valid shared
checks, consumer-specific policy and source/license provenance remain maintained
in General-Auditor. Historical source links may require access to the archives.

The old local checkouts, linked worktrees and dedicated skill routing were
removed after preserving independent assets and unpublished work privately.
Private backup locations and contents are not part of this public record.

Consumer adoption is a separate state: 38 draft PRs across maintained upstream
branch targets remain open and unmerged. Archival does not mean that every
consumer default branch has switched its workflow.
Active consumer branches may still contain references to the retired auditors
until the migration PRs and required promotions land. Public unauthenticated
fetches of those now-private repositories can fail; this record does not claim
that legacy CI remains operational after archival.
