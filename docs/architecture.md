# Architecture and operational boundaries

## Execution paths

General-Auditor uses Python 3.11+ standard-library code and Git reads. Common
privacy detectors and the selected trusted repository profile share one scanner.
Two explicit execution paths have different information boundaries:

| Path | Output | Permitted environment |
| --- | --- | --- |
| `check` / repository CI action | Status and counts only; no report files or matched source | CI or local engineering checks |
| `scan`, local review and HTML | Actual selected source matches, context, locations and judgments in fixed private files | Local use only; CI environments are rejected before source access |

There is no hosted report service, central repository fanout or cloud report
upload. One repository's event checks only that repository. Publishing access
administration remains a distinct authorized operation; it is not a report job.

## Policy and source trust

Common rules cannot be disabled by a target repository. Profiles under
`profiles/<owner>/<repository>.json` add repository-specific contracts, detector
groups and semantic tasks. Missing profiles use layout-independent initialization
defaults. Required paths are explicit profile declarations, never universal
assumptions about `src`, `docs`, README or branch names. A local profile override
is explicit; CI selects policy from its trusted Auditor source.

Audits read source as data. They do not execute target build scripts, hooks,
submodules, templates, Actions or Agent instructions. Git inputs do not gain
execution authority because a local Agent reads them. Keep API credentials and
Git process diagnostics out of finding output.

## Scope and locations

`snapshot` reads the selected committed tree. `range` reads changed versions in
outgoing commits, including content deleted before the final head; it requires a
base and uses the common ancestor when appropriate. Unrelated or shallow history
cannot silently become complete range coverage. `history` reads all commits
reachable from the selected head. Repeated path/blob analyses can be reused, but
every finding retains its actual occurrence location and commit.

`staged` reads the index, independently of unstaged changes. `worktree` reads
tracked working files and non-ignored untracked files. Both support an unborn
branch and use a null commit when no committed version exists. Invoking from a
subdirectory resolves the Git root rather than omitting sibling source.

Text blobs have no fixed scanner size cutoff. Binary/non-UTF-8 files, symlink
targets, submodules and LFS payloads remain explicit uninspected coverage unless
an applicable implementation actually reads them. Source-size contracts are
independent structural checks. Commit attribution policy does not imply general
privacy inspection of every commit message, PR title, issue or external runtime
record. Local review must state any requested coverage gap concretely.

## Exact local evidence

A local finding shows actual matched source from its selected version, its
repository-relative file, line, commit when applicable, context and rule
explanation. Preserve exact spelling and source content. Structural findings
without a source match must say so; do not synthesize an original value.
Unreviewed signals remain candidates until contextual evidence supports a
judgment. Source unavailable from an old redacted archive remains unavailable,
not a reconstructed or supposedly verified original.

HTML escapes source content and uses safe text rendering. The report is
self-contained and keeps organization/repository navigation, run/scope selection,
actual hit rules and per-finding detail. Changing the selected run must not leave
another run's context or judgment visible. Local source excerpts never enter CI
summaries, annotations, public links, PR descriptions or external validation APIs.

## Local persistence and review

The sole generated root is `<Git root>/.general-auditor/local/`, ignored by Git.
`scan.json`, `history.json` and `index.html` hold the latest scan, retained runs
and report. `review-request.json`, `review-handoff.json`, `review-receipt.json`,
`receipt-history.json`, `review.json` and `review.html` hold local review data.
Retained local history is not governed by the retired hosted 30-day expiry job;
cleanup requires an explicit local decision and must preserve user data.

Initialization adds the ignore rule without replacing unrelated ignore content.
Already tracked files remain tracked despite an ignore rule: detect that state,
remove them from the index while preserving working files when authorized, and
never represent `.gitignore` alone as upload prevention. Owned CI workflows must
contain no raw-report producers or upload steps.

The local request and receipt are bound to a scan, its scope, findings and
semantic tasks. Review records source-supported `false_positive`, `confirmed`
and `uncertain` judgments, with concrete evidence, impact and handling. A receipt
checks the binding and completeness; it cannot prove who wrote it, that an Agent
ran, or that all sensitive information has been found. Exact private evidence
may be retained in these local files, but must not be echoed in conversation.

Prior redacted hosted records are independent historical data. Preserve their
existing meaning and limitations locally; do not keep the retired publisher or
claim those records contain source text that was never stored.

## Verification

`python3 tools/verify.py` exercises the implementation with synthetic repositories
and source values. Tests cover local source fidelity, exact locations, selected
scopes, persistence, review binding, safe HTML rendering and summary-only CI.
Real Agent judgments are a separate user-assigned workflow, not a replacement
for engineering checks. Actual upstream CI execution is distinct from an open PR.
