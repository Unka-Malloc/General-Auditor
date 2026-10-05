"""Executable rule catalog. Matches are signals, never leak verdicts.

Policy concepts are consolidated from Lico-Auditor and styio-audit. No target
scripts are executed; no credentials are tested against a service.
"""

from dataclasses import asdict, dataclass
import re


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    description: str
    pattern: str
    action: str
    group: str = "common"

    def public(self):
        return asdict(self)


RULES = (
    Rule("security.shell-execution", "Command execution", "Shell execution surface", r"\b(?:shell\s*=\s*True|os\.system\s*\(|child_process\.exec\s*\(|eval\s*\()", "Check input trust, argument handling and the actual execution boundary.", "code"),
    Rule("security.disabled-verification", "Transport and authentication", "Disabled verification indicator", r"(?i)\b(?:verify_signature|rejectUnauthorized|ssl_verify|tls_verify)\s*[=:]\s*false\b|--no-check-certificate\b", "Determine whether this is executable insecure behavior or a negative test.", "code"),
    Rule("dependencies.commercial-term", "Dependency governance", "Dependency usage term needing review", r"(?i)\b(?:commercial license|evaluation only|subscription required|proprietary license)\b", "Review the actual dependency license and usage scope; terminology alone is not a violation.", "dependencies"),
    Rule("workflow.mutable-action", "Workflow governance", "Action reference without a full commit pin", r"(?m)^\s*-?\s*uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@(?!(?:[0-9a-f]{40})\s*(?:#.*)?$)[^\s#]+", "Review third-party action provenance and pin trusted executable dependencies.", "workflows"),
)

COMPILED = tuple((rule, re.compile(rule.pattern)) for rule in RULES)
CODE_SUFFIXES = {".py", ".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx", ".go", ".rs", ".dart", ".cpp", ".cc", ".c", ".h", ".sh", ".java", ".kt", ".swift"}


def selected_rules(groups):
    """Common rules cannot be disabled by a repository profile."""
    return [(rule, pattern) for rule, pattern in COMPILED if rule.group == "common" or rule.group in groups]


def matches(rule, pattern, text):
    yield from pattern.finditer(text)
