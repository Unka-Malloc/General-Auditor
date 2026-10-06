# Documentation

- [Maintaining General-Auditor](contributing.md): designated maintainers, temporary branches and required PR checks.
- [Common policy](common-policy.md): mandatory contextual review requirements.
- [Audit coverage and parity](audit-coverage.md): legacy check families, General-Auditor counterparts, tests, and requirement-backed replacements.
- [Architecture and coverage](architecture.md): local evidence, summary-only CI, persistence and limitations.
- [Initialization](initialization.md): path-independent configuration, repository policy and optional CI integration.
- [Policy sources](policy-sources.md): consolidation of Lico-Auditor and styio-audit concepts.
- [Repository inventory](repositories.md): all organizations and repositories grouped by purpose.
- [Access-policy administration](access-policy.md): collaborator-only PRs and maintainer-only branch changes.
- [Chinese overview](README.zh-CN.md).

Executable privacy detectors live in [`general_auditor/detection/`](../general_auditor/detection/); additive pattern rules live in [`general_auditor/rules.py`](../general_auditor/rules.py). Deterministic repository contracts are evaluated by [`repository_policy.py`](../general_auditor/repository_policy.py). Repository policy lives in [`profiles/`](../profiles/). The initialization schema and defaults are owned by [`general_auditor/config.py`](../general_auditor/config.py).
