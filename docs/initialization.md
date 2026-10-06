# Repository initialization

No conventional source, documentation or branch layout is required. Common rules
apply immediately; profiles add only declared repository-specific requirements.

## Local setup

Run from a trusted General-Auditor checkout:

```sh
python3 -m general_auditor init --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo
```

Initialization preserves existing configuration and layout. The generated
`.general-auditor/config.json` and local guide describe the repository. The
`.general-auditor/local/` directory is reserved for private generated reports and
review sidecars and must be ignored by Git. Existing unrelated ignore rules are
preserved. Initialization must detect already tracked local-report files; adding
an ignore entry cannot remove them from Git history or the index.

For an existing tracked report, inspect the affected paths and use index-only
untracking within the authorized cleanup scope. Preserve the working copy and
independent historical records. Never delete a user's report merely to obtain a
clean Git status. Once values have been published, local untracking does not
retract prior copies.

```sh
python3 -m general_auditor scan --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo --scope worktree
```

The report is always written below the selected repository's Git root at
`.general-auditor/local/`; caller-selected output paths are not supported.
See the [local review guide](../general_auditor/templates/LOCAL-REVIEW.md) for
contextual review and all supported scan scopes. Do not place exact matches in
terminal output or send these local files to CI, chat or external services.

## Repository CI

```sh
python3 -m general_auditor init --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo --with-workflow
```

The template uses `Unka-Malloc/General-Auditor@only`, complete candidate history,
read-only source permissions and isolated Python imports. It invokes the
summary-only `check` path, not local report generation. It creates no audit
artifact, HTML report or cloud upload. It never executes audited repository
scripts. Exact source findings are available only through the owner's local scan.

Every continuing public upstream in the configured organizations requires this
repository-scoped CI entry. Keep unrelated required checks and documented branch
promotion routes. First-party workflow names describe their function; there are
no Auditor version tags or version-named workflow copies. External Actions use
reviewed immutable revisions.

## Profiles

Profiles in General-Auditor are maintained through its protected PR process.
Each declares the repository identity, category, additive detector groups,
structural contracts and local review tasks. Unknown fields, mismatched identities
and invalid paths fail validation. Target configuration cannot disable common
policy or silently replace the trusted CI profile.

The old Lico-Auditor and styio-audit sources are private archives. Their applicable
shared and consumer checks remain here; no active source dependency on their
packages or local clones is needed.
