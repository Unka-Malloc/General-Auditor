# Documentation

- [Common policy](common-policy.md): mandatory contextual review requirements.
- [Architecture and coverage](architecture.md): scheduling, trust boundaries, persistence and limitations.
- [Initialization](initialization.md): path-independent configuration, repository policy and optional CI integration.
- [Policy sources](policy-sources.md): consolidation of Lico-Auditor and styio-audit concepts.

Executable detector definitions live in [`general_auditor/rules.py`](../general_auditor/rules.py). Repository policy lives in [`profiles/`](../profiles/). The initialization schema and defaults are owned by [`general_auditor/config.py`](../general_auditor/config.py).
