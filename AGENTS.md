# General-Auditor maintenance

Read `docs/contributing.md`, `docs/architecture.md` and `docs/common-policy.md`.

- `only` is the sole permanent branch. Use temporary `work/*` branches and PRs
  after required checks pass. Never directly push to `only`, bypass its gate,
  or create version-named workflow identities.
- Designated maintainers and native Rulesets own contribution authority. Inspect
  settings with `python3 tools/configure_auditor.py`; mutation needs authorization.
- Each CI event checks only its repository's common rules and trusted profile.
  CI uses summary-only `check`; it neither creates nor uploads audit reports.
  Do not restore central fanout, hosted reporting or a report-bot bypass.
- Exact matched source and context belong only in the selected repository's
  Git-ignored `.general-auditor/local/` files. Never print them in terminals,
  chat, workflow logs, annotations, PRs or cloud artifacts. Local report and
  review commands must reject CI execution before reading source.
- Report evidence must come from the actual selected source version. Never
  reconstruct an original value from a redacted archive or fabricate a match.
  Deterministic matches are unreviewed candidates; contextual review supplies
  confirmed, false-positive or concrete uncertain judgments.
- Only the maintained report may be shown to a developer. The single closing
  report is the file that one pass of
  `python3 -m general_auditor fleet --root ROOT` writes over the saved local
  scans; present that file and nothing else. Never hand-assemble, re-render,
  summarise into a substitute file or leave a competing temporary report beside
  it, and never regenerate one by hand to answer a question. If the maintained
  report is missing or stale, re-run that command. Its unredacted content stays
  outside version control.
- Keep English engineering documentation and the separate Chinese overview
  current. Preserve source attribution and independent historical assets.
- Finish scoped fixes and source review, then run `python3 tools/verify.py`.
  Verify source fidelity, locations, scopes, private persistence, safe rendering
  and CI isolation deterministically; do not initiate real Agent acceptance.
