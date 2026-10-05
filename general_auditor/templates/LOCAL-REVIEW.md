# Local review

Run General-Auditor locally before publishing changes and ask your local Agent
to review the selected source scope. CI does not run an Agent, test credentials,
or decide whether a privacy signal is a real disclosure. Contributors remain
responsible for the content they publish.

## Select the outgoing scope

Run commands from the General-Auditor checkout. Outputs under its ignored `out/`
directory stay with the local review unless you choose to move them.

```sh
# Current index only; use this for staged content.
python3 -m general_auditor scan --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo --scope staged --output out/audit.json

# Current tracked working files and non-ignored untracked files.
python3 -m general_auditor scan --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo --scope worktree --output out/audit.json

# Selected immutable commit range.
python3 -m general_auditor scan --repository ExampleOrg/ExampleRepo --directory ../ExampleRepo --scope range --base <base-commit> --head <candidate-commit> --output out/audit.json
```

`snapshot` audits the selected head tree; `history` audits all commits reachable
from that head. With no explicit scope, a supplied `--base` selects a range and
otherwise the scan uses a snapshot. A worktree scan reads the current filesystem
view; run a separate `staged` scan when the index itself is also part of the
outgoing change. Central CI selects immutable event commits and does not inspect
your local index or working files.

## Ask your local Agent for contextual review

Generate a redacted request and an editable receipt template:

```sh
python3 -m general_auditor review-request --scan out/audit.json --output out/review-request.json --template out/review-handoff.json
```

The template file is a handoff envelope containing `receipt_template`. Give the request and the matching local repository context to your local Agent. Have it save the completed `receipt_template` object alone as `out/review-receipt.json`; the full handoff envelope is not a receipt.
Have it complete every finding and semantic task, add any contextual finding,
and record concrete limitations. Do not include source excerpts, exact matched
values, credentials, personal or machine identifiers, ciphertext, user records,
or backend runtime data in the receipt.

Validate the completed receipt and create a local-only report:

```sh
python3 -m general_auditor review-complete --scan out/audit.json --receipt out/review-receipt.json --output out/review-report.json --html out/review-report.html
```

The receipt is bound to the scan and its exact scope. A false-positive judgment
does not create a reusable exception. The validator checks structure,
completeness, scope and common sensitive-literal patterns; it cannot prove that
all personal data was removed, identify who wrote the receipt, or prove that an
Agent ran. Reviewed reports and receipts stay local. Do not commit, upload to
Actions, or publish them as the shared report.

## Repository-specific requirements

The mandatory common policy applies without `README`, `docs`, `src`, or any
other conventional layout. `required_paths` is empty by default. Central CI
selects trusted repository profiles from General-Auditor; target-repository
configuration cannot disable the baseline. This file is an initialization guide,
not an executable policy or security boundary.

Read the mandatory [common policy](https://github.com/Unka-Malloc/General-Auditor/blob/only/docs/common-policy.md),
the [audit coverage ledger](https://github.com/Unka-Malloc/General-Auditor/blob/only/docs/audit-coverage.md),
and the matching [central repository profile](https://github.com/Unka-Malloc/General-Auditor/tree/only/profiles)
before reviewing changes.
