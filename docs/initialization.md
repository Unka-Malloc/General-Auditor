# Initialization and repository policy

There is one initialization schema and set of defaults: `general_auditor/config.py`. Both central discovery and local initialization use it. The executable common rules live in `general_auditor/rules.py`; the mandatory semantic baseline is [common-policy.md](common-policy.md).

## Central initialization

```sh
python3 -m general_auditor discover
```

This discovers the configured organizations' public repositories and creates missing `profiles/<owner>/<repository>.json` files. Existing files are validated and never overwritten. An ordinary scheduled or manual batch run does the same initialization before scanning. Newly discovered repositories can therefore run all common rules immediately.

Each profile declares its repository identity, additive detector groups, optional required paths and repository-specific local Agent review requirements. Unknown profile fields, mismatched identities and invalid relative paths fail validation. Common detectors cannot be removed by a profile. `required_paths` defaults to an empty list; the existence of `src/`, `docs/`, root instructions or another particular path is never a universal prerequisite.

Maintain repository-specific requirements centrally through normal reviewed changes. Target repository configuration is a proposal for that policy, not an automatic authority to weaken CI. Existing Lico-Auditor and styio-audit assets remain independent; this project does not rewrite or delete them.

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
  --profile ../ExampleRepo/.general-auditor/config.json \
  --output out/audit.json
```

Have the local Agent read the common policy, selected profile and redacted result, then inspect source context locally before any push. Uncommitted edits are outside this Git-content scanner. Local hooks are optional convenience and do not guarantee review.

## Optional immediate CI

```sh
python3 -m general_auditor init \
  --repository ExampleOrg/ExampleRepo \
  --directory ../ExampleRepo \
  --with-workflow
```

The additional template is packaged at `general_auditor/templates/workflow.yml`. It triggers on pushes and PRs, checks out complete candidate history, then runs the published `Unka-Malloc/General-Auditor@main` action. The action reads only this checkout and its matching central profile. It uses isolated Python imports, so a target repository cannot replace the auditor's modules by placing a same-named Python file in its tree. No target scripts are run.

The `main` reference receives maintained common policy updates. First-party workflow identities follow their function and do not use version tags or version-named copies. Repositories requiring individually approved updates can replace it with a reviewed commit SHA. Public upstream PRs receive no paid Agent token and no cross-repository write credential. Private repositories keep results in their own CI context. The JSON output is redacted and classified private by default; the template does not send it to the public collector. The `general-auditor-report` workflow artifact contains JSON and a local HTML report with a table for every finding, retained for 30 days within the source repository's access boundary. The local CLI can also generate HTML with `--html out/audit.html`.

This local CI is optional for the configured public organizations: the central collector independently observes their public heads and updates the shared HTML. Enabling the local template provides immediate feedback and adds a local scan; it does not make central polling instantaneous and does not trigger scans of other repositories.
