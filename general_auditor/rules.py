"""Executable rule catalog. Matches are signals, never leak verdicts.

Policy concepts are consolidated from Lico-Auditor and styio-audit. No target
scripts are executed; no credentials are tested against a service.
"""

from dataclasses import asdict, dataclass
import ipaddress
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
    Rule("privacy.private-key", "Credentials", "Private-key container marker", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", "Review key ownership locally; revoke exposed credentials."),
    Rule("privacy.credential-binding", "Credentials", "Literal credential assignment", r'''(?i)\b(?:[a-z][a-z0-9_]*_)?(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|secret[_-]?key)["']?\s*[:=]\s*["']([^"'\r\n]+)["']''', "Determine whether this is a real credential, reference or synthetic fixture."),
    Rule("privacy.environment-credential", "Credentials", "Unquoted environment credential assignment", r'''(?i)^\s*(?:export\s+)?(?:[a-z][a-z0-9_]*_)?(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|secret[_-]?key)\s*=\s*([^\s"'#]+)''', "Determine whether this value is synthetic, a variable reference or an exposed credential."),
    Rule("privacy.credential-url", "Credentials", "URL with embedded authentication", r"\b[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@", "Use an external secret source for real authentication material."),
    Rule("privacy.token-format", "Credentials", "Recognized token-like format", r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35})\b", "Review provenance locally; a format match does not establish validity."),
    Rule("privacy.home-path", "Local information", "User home-directory reference", r"(?:/Users/|/home/|[A-Za-z]:\\Users\\)[^\s/\\\"'<>]+", "Replace personal machine paths with portable project-relative examples."),
    Rule("privacy.ip-address", "Network information", "Non-loopback IPv4 literal", r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", "Distinguish public protocol examples from private deployment information."),
    Rule("privacy.runtime-record", "Runtime and personal data", "Potential runtime or personal-data field", r'''(?i)["'](?:email|phone|customer_id|tenant_id|session_token|device_id|billing_address)["']\s*:\s*["'][^"'\n]+["']''', "Review provenance; schemas and synthetic fixtures must not be classified as real data solely by field names."),
    Rule("privacy.operational-url", "Backend information", "Operational endpoint reference", r"(?i)\b(?:https?|postgres(?:ql)?|mysql|redis|mongodb(?:\+srv)?|amqp)://[^\s\"'<>]*(?:internal|production|private|admin|backend)[^\s\"'<>]*", "Review whether the endpoint discloses nonpublic infrastructure."),
    Rule("security.shell-execution", "Command execution", "Shell execution surface", r"\b(?:shell\s*=\s*True|os\.system\s*\(|child_process\.exec\s*\(|eval\s*\()", "Check input trust, argument handling and the actual execution boundary.", "code"),
    Rule("security.disabled-verification", "Transport and authentication", "Disabled verification indicator", r"(?i)\b(?:verify_signature|rejectUnauthorized|ssl_verify|tls_verify)\s*[=:]\s*false\b|--no-check-certificate\b", "Determine whether this is executable insecure behavior or a negative test.", "code"),
    Rule("dependencies.commercial-term", "Dependency governance", "Dependency usage term needing review", r"(?i)\b(?:commercial license|evaluation only|subscription required|proprietary license)\b", "Review the actual dependency license and usage scope; terminology alone is not a violation.", "dependencies"),
    Rule("workflow.mutable-action", "Workflow governance", "Action reference without a full commit pin", r"(?m)^\s*-?\s*uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@(?!(?:[0-9a-f]{40})\s*(?:#.*)?$)[^\s#]+", "Review third-party action provenance and pin trusted executable dependencies.", "workflows"),
)

COMPILED = tuple((rule, re.compile(rule.pattern)) for rule in RULES)
PLACEHOLDER = re.compile(r"(?i)^(?:|<[^>]*>|\$.*|\{\{.*|replace[-_].*|your[-_].*|example[-_].*|redacted|changeme|x{3,}|\*+)$")
CODE_SUFFIXES = {".py", ".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx", ".go", ".rs", ".dart", ".cpp", ".cc", ".c", ".h", ".sh", ".java", ".kt", ".swift"}


def selected_rules(groups):
    """Common rules cannot be disabled by a repository profile."""
    return [(rule, pattern) for rule, pattern in COMPILED if rule.group == "common" or rule.group in groups]


def matches(rule, pattern, text):
    for match in pattern.finditer(text):
        if rule.id in {"privacy.credential-binding", "privacy.environment-credential"} and PLACEHOLDER.fullmatch(match.group(1)):
            continue
        if rule.id == "privacy.ip-address":
            try:
                address = ipaddress.ip_address(match.group())
            except ValueError:
                continue
            if address.is_loopback or address.is_unspecified:
                continue
        yield match
