# Local review

Run General-Auditor before the first push and review its signals with your local
Agent. Contributors are responsible for the privacy of submitted content.
Keywords do not prove disclosure. CI does not call a paid Agent or validate a
local Agent's completion.

Inspect every outgoing commit, necessary surrounding source, documentation,
synthetic fixtures, dependency terms, and the project's public/private boundary.
For each issue record the repository-relative file and line, rule, redacted
category, real-issue/false-positive reasoning, impact and treatment. Never copy
secrets, personal values or backend runtime rows into an issue, log or report.

The common baseline runs without this configuration and without README, docs,
src or any other standard path. `required_paths` is empty by default. Populate
it only for requirements actually owned by this repository.

Repository overrides are maintained in General-Auditor's central `profiles/`
directory. This file is an editable initialization proposal; it cannot disable
the baseline used by central CI. A local hook is optional and is not a security
boundary.

Read the mandatory [common policy](https://github.com/Unka-Malloc/General-Auditor/blob/only/docs/common-policy.md) and the matching [central repository profile](https://github.com/Unka-Malloc/General-Auditor/tree/only/profiles) before contextual review.
