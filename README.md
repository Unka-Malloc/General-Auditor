# General-Auditor

[简体中文](docs/README.zh-CN.md) · [Documentation](docs/README.md) · [Repository inventory](docs/repositories.md)

General-Auditor provides mandatory common policy, repository-specific review requirements, and a single rolling audit report for every public repository in **SymPolicy**, **Meshrix-Platform**, and **LicoLand**.

[Audit report](https://unka-malloc.github.io/General-Auditor/) · [Report artifacts](https://github.com/Unka-Malloc/General-Auditor/actions/workflows/publish-report.yml) · [Audit workflow runs](https://github.com/Unka-Malloc/General-Auditor/actions/workflows/audit.yml)

Contextual privacy judgments belong to the contributor's local Agent before publication. CI collects deterministic advisory signals without invoking a paid Agent, validating credentials, or executing audited repositories. Pattern matches produce warnings and do not fail CI. Configuration and infrastructure failures remain explicit.

## Repository scope

| Organization | Public repositories | Maintainer-owned publishing repositories |
| --- | ---: | ---: |
| SymPolicy | 18 | 6 |
| Meshrix-Platform | 4 | 2 |
| LicoLand | 10 | 4 |

The [grouped inventory](docs/repositories.md) names every repository and its category. Websites, standalone documentation, benchmarks and organization presentation repositories accept collaborator PRs only. An additional Ruleset restricts all branch changes to organization administrators and repository maintain/admin roles. Existing review and status-check rules continue to apply.

## Implemented behavior

- [Common policy](docs/common-policy.md) always applies. Each [repository profile](profiles/) adds its own review requirements; missing profiles use the same initialization defaults.
- No fixed source, documentation, instruction-file or branch layout is required. Required paths are explicit repository-specific declarations.
- Central CI discovers public branch and open-PR changes concurrently every 15 minutes. Each changed repository gets an independent workflow; slow repositories do not delay other scans or their saved results. A manual run selects one repository or explicitly selects `all`.
- Initial branch scans inspect current snapshots. Subsequent scans inspect changed file versions in every outgoing commit, including content removed before the final head.
- Each repository saves its result artifact on completion. A separate publisher merges durable results into one Pages HTML document and an Actions checkpoint, retaining the latest 30 days. A daily refresh expires old entries even without source changes. Reports do not create source commits.
- Report rows contain locations, rules, redacted categories, judgments and their basis, impact and recommendations. No source values or backend runtime records are copied into the report.
- Publishing-category scans observe GitHub PR access and branch restrictions. Bypass identities hidden by GitHub's read-only API are marked unverified; administrator-side verification checks the complete configuration.

GitHub schedules and hosted runners are subject to platform availability. CI does not guarantee pre-publication filtering or execution of local hooks. Binary files, large text files and other excluded content are listed explicitly. See [coverage and operational boundaries](docs/architecture.md).

## Maintaining the Auditor

`only` is the sole permanent branch. Designated maintainers use temporary `work/*` branches and PRs; direct pushes to `only` are prohibited, including administrator and bot pushes. Required checks, resolved discussions and linear squash history are enforced. External PR creation is disabled. See [contribution governance](docs/contributing.md).

## Local usage

Python 3.11+ and Git are required. The scanner has no third-party runtime dependencies.

```sh
git clone https://github.com/Unka-Malloc/General-Auditor.git
cd General-Auditor
python3 -m general_auditor init --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo
python3 -m general_auditor scan --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo --output out/audit.json --html out/audit.html
```

The scanner reads committed Git content. It does not inspect uncommitted changes. Commit locally, then ask the local Agent to review the common policy, selected profile, findings and original context before the first push. Add `--base <previous-commit>` to inspect a commit range. Local results default to private and are never automatically published.

Initialization adds only missing files and preserves repository layout. Add `--with-workflow` for optional immediate repository-local CI. Its maintained first-party action entry is `Unka-Malloc/General-Auditor@only`; workflows use functional names, not version-named copies or Auditor version tags. The configured public organizations already have central profiles and require no target-repository scaffolding to run common rules. See [initialization](docs/initialization.md).

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

Policy concepts are consolidated from [Lico-Auditor](https://github.com/LicoLand/Lico-Auditor) and [styio-audit](https://github.com/SymPolicy/styio-audit). Both remain independent projects. See [policy sources](docs/policy-sources.md).
