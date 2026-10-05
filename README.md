# General-Auditor

[简体中文](docs/README.zh-CN.md) · [Documentation](docs/README.md) · [Audit coverage and parity](docs/audit-coverage.md) · [Repository inventory](docs/repositories.md)

General-Auditor provides mandatory common policy, repository-specific review requirements, and a single rolling audit report for every public repository in **SymPolicy**, **Meshrix-Platform**, and **LicoLand**.

[Audit report](https://unka-malloc.github.io/General-Auditor/) · [Report artifacts](https://github.com/Unka-Malloc/General-Auditor/actions/workflows/publish-report.yml) · [Audit workflow runs](https://github.com/Unka-Malloc/General-Auditor/actions/workflows/audit.yml)

Contextual privacy judgments belong to the contributor's local Agent before publication. CI collects deterministic advisory signals without invoking a paid Agent, validating credentials, or executing audited repositories. Pattern matches produce warnings and do not fail CI. Declared structural repository-contract violations fail the policy check; unavailable input, configuration and infrastructure failures are reported separately.

## Repository scope

| Organization | Continuing public repositories | Pending auditor retirement | Maintainer-owned publishing repositories |
| --- | ---: | ---: | ---: |
| SymPolicy | 17 | 1 | 6 |
| Meshrix-Platform | 4 | 0 | 2 |
| LicoLand | 9 | 1 | 4 |

The [grouped inventory](docs/repositories.md) lists 30 continuing repositories and the two still-public auditors pending retirement. Migration changes are prepared for review; an open PR does not establish deployment. Websites, standalone documentation, benchmarks and organization presentation repositories accept collaborator PRs only. An additional Ruleset restricts all branch changes to organization administrators and repository maintain/admin roles. Existing review and status-check rules continue to apply.

## Implemented behavior

- [Common policy](docs/common-policy.md) always applies. Each [repository profile](profiles/) adds its own review requirements; missing profiles use the same initialization defaults.
- The [audit coverage ledger](docs/audit-coverage.md) maps retained Lico-Auditor and styio-audit check families to their General-Auditor rules, policy checks, tests, and deliberate replacements.
- No fixed source, documentation, instruction-file or branch layout is required. Required paths are explicit repository-specific declarations.
- Central CI discovers public branch and open-PR changes concurrently every 15 minutes. Each changed repository gets an independent workflow; slow repositories do not delay other scans or their saved results. A manual run selects one repository or explicitly selects `all`.
- Initial branch scans inspect current snapshots. Subsequent scans inspect changed file versions in every outgoing commit, including content removed before the final head.
- Each repository saves its result artifact on completion. A separate publisher merges durable results into one Pages HTML document and an Actions checkpoint, retaining the latest 30 days. A daily refresh expires old entries even without source changes. Reports do not create source commits.
- Report rows contain locations, rules, redacted categories, judgments and their basis, impact and recommendations. No source values or backend runtime records are copied into the report.
- Publishing-category scans observe GitHub PR access and branch restrictions. Bypass identities hidden by GitHub's read-only API are marked unverified; administrator-side verification checks the complete configuration.

GitHub schedules and hosted runners are subject to platform availability. CI does not guarantee pre-publication filtering or execution of local hooks. Binary files and other uninspected content are listed explicitly. Text blobs have no fixed scanner size cutoff; repository-specific file-size contracts remain independent. See [coverage and operational boundaries](docs/architecture.md).

## Maintaining the Auditor

`only` is the sole permanent branch. Designated maintainers use temporary `work/*` branches and PRs; direct pushes to `only` are prohibited, including administrator and bot pushes. Required checks, resolved discussions and linear squash history are enforced. External PR creation is disabled. See [contribution governance](docs/contributing.md).

## Local usage

Python 3.11+ and Git are required. The scanner has no third-party runtime dependencies.

```sh
git clone https://github.com/Unka-Malloc/General-Auditor.git
cd General-Auditor
python3 -m general_auditor init --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo
python3 -m general_auditor scan --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo --scope worktree --output out/audit.json
python3 -m general_auditor review-request --scan out/audit.json --output out/review-request.json --template out/review-handoff.json
# Ask your local Agent to fill handoff.receipt_template and save that object as out/review-receipt.json.
python3 -m general_auditor review-complete --scan out/audit.json --receipt out/review-receipt.json --output out/review-report.json --html out/review-report.html
```

`scan` supports `snapshot`, `range`, `history`, `staged`, and `worktree` scopes. A worktree scan reads tracked working files and non-ignored untracked files; a staged scan reads the index. Run both when both views are part of the outgoing change. `history` inspects all commits reachable from the selected head; `range` requires `--base <previous-commit>`. Without an explicit scope, `--base` selects a range and otherwise the scan uses a snapshot. CI uses immutable event commits and never examines a contributor's local files.

`review-request --template` writes a handoff envelope containing `receipt_template`. Complete that object and save it separately as the receipt passed to `review-complete`; do not pass the whole handoff envelope. After local contextual review, `review-complete` validates the receipt and writes a local-only JSON/HTML report. Receipts and reviewed reports stay local; they are not accepted as public CI results. Pattern signals remain `warning / unreviewed` and CI does not call a paid Agent or certify local review. A receipt checks its scan binding and completeness, but cannot prove who wrote it or establish that all sensitive content was removed.

Initialization adds only missing files and preserves repository layout. Add `--with-workflow` for optional immediate repository-local CI. Its maintained first-party action entry is `Unka-Malloc/General-Auditor@only`; workflows use functional names, not version-named copies or Auditor version tags. Every continuing public upstream in the configured organizations must adopt the repository-local General-Auditor workflow. Central discovery can scan common rules without scaffolding, but does not replace that CI requirement. See [initialization](docs/initialization.md).

## Central operations

```sh
# Audit exactly one repository.
gh workflow run audit.yml -R Unka-Malloc/General-Auditor -f repository=LicoLand/LicoArc

# Explicitly audit all configured public repositories.
gh workflow run audit.yml -R Unka-Malloc/General-Auditor -f repository=all -f force=true

# Inspect declared publishing access policy using an administrator's gh session.
python3 tools/configure_access.py
```

Inspect this Auditor’s own governance with `python3 tools/configure_auditor.py`. Both administration tools change settings only when explicitly invoked with `--apply`. Central CI has no cross-repository write credential and never mutates repository access. [Access-policy administration](docs/access-policy.md)

## Verification

```sh
python3 tools/verify.py
```

The verification entry point checks source syntax, rule/profile contracts, and deterministic tests using synthetic Git repositories and mocked GitHub settings. It does not start real Agent conversations.

Policy coverage and source attribution are documented for [Lico-Auditor](https://github.com/LicoLand/Lico-Auditor) and [styio-audit](https://github.com/SymPolicy/styio-audit). Their remote retirement is handled separately from this implementation; see [policy sources](docs/policy-sources.md).
