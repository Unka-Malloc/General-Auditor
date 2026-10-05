# Policy sources and consolidation

General-Auditor consolidates policy concepts from two independent public projects:

| Source | Adopted concepts | Scope in General-Auditor |
| --- | --- | --- |
| [Lico-Auditor](https://github.com/LicoLand/Lico-Auditor) | Privacy-first evidence, credential and local-information signals, repository profiles, contextual review and developer-facing reports | Common privacy signals, per-finding redaction, additive profiles and local Agent review requirements |
| [styio-audit](https://github.com/SymPolicy/styio-audit) | Common and repository modules, dependency/usage review, lifecycle and workflow review, inventory | Central public inventory, independent profiles, optional code/dependency/workflow signal groups and project-specific review tasks |

The new scanner is a standard-library implementation. Existing source trees, unpublished local modifications, private operational data and protected-name lists are not copied into it. Neither upstream repository is treated as a runtime executable dependency.

General-Auditor adopts its own PR-only `only` branch, linear history, resolved discussions and required verification from the upstream contribution gates, with checks bound to GitHub Actions. See [maintainer governance](contributing.md). Project-specific license choices, multiple release channels, version workflows, directory requirements and downstream fan-out from an older auditor are not universal policy here. Pattern detection never becomes a blocking verdict. General-Auditor adds a single rolling report and schedules each observed repository independently. Local contextual Agent review remains distinct from deterministic CI signal collection.
