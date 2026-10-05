# Initialization and repository policy

There is one initialization schema and set of defaults: `general_auditor/config.py`. Both central discovery and local initialization use it. The common privacy detector is maintained in `general_auditor/detection/`; deterministic repository contracts are evaluated from `general_auditor/repository_policy.py`. The mandatory semantic baseline is [common-policy.md](common-policy.md), and check-level provenance is in the [audit coverage ledger](audit-coverage.md).

## Central initialization

```sh
python3 -m general_auditor discover
```

This discovers the configured organizations' public repositories and creates missing `profiles/<owner>/<repository>.json` files. Existing files are validated and never overwritten. An ordinary scheduled or manual batch run creates the same profile in its local workspace before scanning. CI does not commit generated profiles to the protected source branch; maintainers persist repository-specific refinements through a PR. Newly discovered repositories can therefore run all common rules immediately.

Each trusted central profile declares its repository identity, category, additive detector groups, applicable structural contracts, optional required paths and repository-specific local review tasks. Unknown fields, mismatched identities, untrusted policy sources and invalid relative paths fail validation. Profiles cannot disable the mandatory common detectors; applicable structural contracts are declared centrally. `required_paths` is empty by default; the existence of `src/`, `docs/`, root instructions or another particular path is never a universal prerequisite.

Maintain repository-specific requirements in General-Auditor through reviewed changes. A target repository cannot replace the centrally selected profile or weaken common policy. Lico-Auditor and styio-audit are now private archives and are excluded from public discovery. Their dedicated profiles are removed; applicable shared and consumer policy remains in General-Auditor. Consumer migration PRs remain unmerged.

## Local initialization

Run from an installed or cloned General-Auditor:

```sh
python3 -m general_auditor init --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo
```

This adds `.general-auditor/config.json` and `.general-auditor/README.md` only when missing. It preserves existing custom configuration and all source/documentation layout. To use the local profile explicitly:

```sh
python3 -m general_auditor scan \
  --repository ExampleOrg/ExampleRepo \
  --directory ../ExampleRepo \
  --scope worktree \
  --profile ../ExampleRepo/.general-auditor/config.json \
  --output out/audit.json

python3 -m general_auditor review-request \
  --scan out/audit.json \
  --output out/review-request.json \
  --template out/review-handoff.json
```

Have the local Agent read the common policy, selected profile and redacted request, then inspect only the selected source scope locally before a push. `staged` audits the index; `worktree` reads current tracked files and non-ignored untracked files; run both when both views are outgoing. `snapshot` audits the selected committed tree, `range` requires `--base`, and `history` covers all commits reachable from the selected head. A supplied `--base` defaults to a range; without one, the default is a snapshot. Use `review-complete --scan out/audit.json --receipt out/review-receipt.json --output out/review-report.json --html out/review-report.html` after the local review. Receipts and reviewed reports are local-only; they do not prove Agent identity and must not be uploaded or published. Local hooks are optional convenience and do not guarantee review.

## Repository CI

```sh
python3 -m general_auditor init \
  --repository ExampleOrg/ExampleRepo \
  --directory ../ExampleRepo \
  --with-workflow
```

The additional template is packaged at `general_auditor/templates/workflow.yml`. It triggers on pushes and PRs, checks out complete candidate history, then runs the published `Unka-Malloc/General-Auditor@only` action. The action reads only this checkout and its matching central profile. It uses isolated Python imports, so a target repository cannot replace the auditor's modules by placing a same-named Python file in its tree. No target scripts are run.

The `only` reference receives maintained common policy updates. First-party workflow identities follow their function and do not use version tags or version-named copies. Repositories requiring individually approved updates can replace it with a reviewed commit SHA. Public upstream PRs receive no paid Agent token and no cross-repository write credential. Private repositories keep results in their own CI context. The JSON output is redacted and classified private by default; the template does not send it to the public collector. The `general-auditor-report` workflow artifact contains JSON and a local HTML report with a table for every finding, retained for 30 days within the source repository's access boundary. The local CLI can also generate HTML with `--html out/audit.html`.

Every continuing public upstream in SymPolicy, Meshrix-Platform and LicoLand must use this General-Auditor CI entry. The initialization flag remains optional for other local/ad hoc repositories. Central discovery independently observes public heads and updates the shared HTML; it does not replace the required upstream workflow or make polling instantaneous. One repository event only scans that repository and its common/profile rules.
