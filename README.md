# General-Auditor

[简体中文](docs/README.zh-CN.md) · [Documentation](docs/README.md) · [Audit coverage](docs/audit-coverage.md) · [Repository inventory](docs/repositories.md)

General-Auditor applies mandatory common policy and repository-specific checks across **SymPolicy**, **Meshrix-Platform**, and **LicoLand**. CI returns a safe status summary. Detailed audit reports are generated locally, with the actual matched source text and context visible to the owner.

Deterministic matches are **unreviewed candidates**, not confirmed disclosures. A contributor's local Agent evaluates their context. Privacy keywords remain advisory; declared structural contract failures and incomplete execution have separate failing statuses. CI does not invoke a paid Agent, validate credentials online, or execute audited source.

## Repository scope

| Organization | Continuing public repositories | Retired private auditors | Maintainer-owned publishing repositories |
| --- | ---: | ---: | ---: |
| SymPolicy | 17 | 1 | 6 |
| Meshrix-Platform | 4 | 0 | 2 |
| LicoLand | 9 | 1 | 4 |

The [grouped inventory](docs/repositories.md) lists all 30 continuing upstreams and two private archives. Websites, standalone documentation, benchmarks and organization presentation repositories have collaborator-only PR creation and maintainer-controlled branch changes. Independent review and status checks remain applicable.

## Local reports

Python 3.11+ and Git are required; there are no third-party runtime dependencies.
Run these commands from a trusted General-Auditor checkout:

```sh
python3 -m general_auditor init --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo
python3 -m general_auditor scan --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo --scope worktree
```

Open `../ExampleRepo/.general-auditor/local/index.html` locally. The output directory is fixed under the target's Git root, even when invoked from a component directory. It contains the local report and its scan/review data and must remain ignored and untracked. Do not move these files into cloud storage, PR attachments, Actions artifacts or public logs.

The self-contained report provides a repository sidebar, selected run/scope history, hit rules, source locations, actual matches and context. Exact values are authorized **inside those private files only**. HTML treats source as text, never executable markup. Previously retained redacted archives cannot supply missing original evidence; a new exact-scope scan is required.

| Scope | Source inspected |
| --- | --- |
| `snapshot` | Selected committed tree |
| `range` | Outgoing commit versions between `--base` and `--head`, including transient content |
| `history` | Every commit reachable from `--head` |
| `staged` | Current Git index |
| `worktree` | Tracked working files and non-ignored untracked files |

Run separate staged and worktree scans when both views matter. Exclusions and incomplete input remain visible; a scan with no matches does not prove safety. Local report/review commands refuse CI environments.

For contextual judgments, follow the [local review guide](general_auditor/templates/LOCAL-REVIEW.md). Receipts remain bound to the selected scan and record evidence-based `false_positive`, `confirmed` or `uncertain` judgments; they do not attest Agent identity or create lasting rule exceptions.

## Repository CI

```sh
python3 -m general_auditor init --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo --with-workflow
```

The maintained action is `Unka-Malloc/General-Auditor@only`. It uses the summary-only `check` path for this repository's immutable candidate and trusted central profile. It writes no report and exposes no matched text. There is no central scheduled audit fanout, Pages report or cloud report upload. See [initialization](docs/initialization.md) for ignore rules and existing tracked-report handling.

No standard source directory or branch layout is required. Common rules always apply; profiles add declared paths, structural contracts and review tasks. Every continuing upstream must adopt General-Auditor CI, preserving its own unrelated checks and branch promotion rules. Prepared migration PRs do not establish that default branches have switched.

## Maintenance

`only` is the sole permanent branch. Designated maintainers submit temporary `work/*` PRs; direct pushes, external PRs and version-named workflow copies are prohibited. See [contribution governance](docs/contributing.md).

```sh
python3 tools/verify.py
python3 tools/configure_auditor.py
python3 tools/configure_access.py
```

Verification uses synthetic data. Administration commands are read-only unless explicitly given `--apply`; this documentation does not authorize remote changes. [Coverage](docs/audit-coverage.md) and [source attribution](docs/policy-sources.md) preserve applicable Lico-Auditor and styio-audit policy, with no runtime dependency on either private archive.
