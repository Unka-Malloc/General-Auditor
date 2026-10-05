# General-Auditor maintenance

Read `docs/contributing.md`, `docs/architecture.md` and `docs/common-policy.md` for
the owned contribution, execution and evidence contracts.

- `only` is the sole permanent branch. Work on a temporary `work/*` branch and
  merge through a PR after the required checks pass. Do not directly push to
  `only`, bypass its gate, or create version-named workflow identities.
- Designated maintainers are listed in `.github/maintainers.json`. Keep the
  maintained Ruleset declarations and GitHub settings aligned. Inspect them with
  `python3 tools/configure_auditor.py`; applying settings requires authorization.
- Repository audits are independent. A slow or failed repository must not hold
  another repository's result. Only the shared report writer is serialized.
- CI stores results in Actions artifacts and publishes one HTML document through
  Pages. It has no source-write permission. Never restore report commits or a bot
  exception to branch protection as a publication mechanism.
- Keep deterministic signals advisory and redacted. Source values, credentials,
  private repository data and runtime records must not enter public artifacts.
  Contextual Agent review belongs to the contributor's local workflow.
- Use English for the root README and maintained engineering documentation;
  update the separate Chinese overview when its described behavior changes.
- Finish source review and scoped repairs, then run `python3 tools/verify.py`.
  Exercise concurrency, ordering, persistence and recovery with deterministic
  tests. Cloud execution verifies wiring; it does not replace those tests.
