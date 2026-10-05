"""Portable source-free privacy detection shared by local and CI scans.

Every match is an advisory location signal. The detector never validates a
credential against a service and never returns matched text.
"""

from bisect import bisect_right
from collections import Counter
from collections.abc import Mapping, Sequence

from .context import context_rules
from .keys import key_rules
from .paths import redact_path
from .providers import collect_provider_candidates, provider_rules
from .types import Candidate, DetectorRule, RuleMetadata


_ACTIONS = {
    "Credentials": "Review the source and provenance locally; remove real credentials from the outgoing scope and rotate exposed values.",
    "Private key material": "Review key ownership and purpose locally; remove exposed private material and rotate affected keys.",
    "Public key material": "Confirm that the public key is intentional and approved for publication.",
    "Backend information": "Review endpoint ownership and publication context without connecting to the service.",
    "Network information": "Confirm whether this address reveals a nonpublic deployment or is approved public reference data.",
    "Runtime and personal data": "Review whether the value is synthetic, public, or actual protected information; remove real records from the outgoing scope.",
    "Local information": "Replace machine-specific identifiers and paths with portable examples.",
}


def _build_catalog() -> tuple[DetectorRule, ...]:
    definitions = (*provider_rules(), *key_rules(), *context_rules())
    identifiers = [row[0] for row in definitions]
    if len(set(identifiers)) != len(identifiers):
        raise RuntimeError("Privacy rule identifiers must be unique")
    return tuple(
        DetectorRule(
            id=rule_id,
            category=category,
            title=description,
            description=description,
            action=_ACTIONS[category],
            finder=finder,
            group="common",
        )
        for rule_id, category, description, finder in definitions
    )


_DETECTORS: tuple[DetectorRule, ...] = _build_catalog()
RULE_CATALOG: tuple[RuleMetadata, ...] = tuple(rule.public() for rule in _DETECTORS)
_CATALOG_BY_ID = {rule.id: rule for rule in _DETECTORS}
_PROVIDER_RULE_IDS = frozenset(
    rule.id for rule in _DETECTORS
    if rule.id.startswith("privacy.credential.provider.")
    or rule.id == "privacy.credential.binding"
    or rule.id.startswith("privacy.credential.format.")
)


def rule_catalog() -> tuple[RuleMetadata, ...]:
    """Return immutable, source-free public descriptions of all common rules."""
    return RULE_CATALOG


def _profile_exceptions(profile: Mapping[str, object], exceptions: Sequence[Mapping[str, object]] | None):
    if exceptions is not None:
        return exceptions
    values = profile.get("privacy_exceptions", ())
    return values if isinstance(values, (list, tuple)) else ()


def _exact_exception(candidate: Candidate, rule_id: str, path: str, text: str, exceptions) -> bool:
    value_spans = candidate.value_spans or ((candidate.start, candidate.end),)
    values = tuple(text[start:end] for start, end in value_spans)
    normalized_path = path.replace("\\", "/").removeprefix("./")
    for exception in exceptions:
        if not isinstance(exception, Mapping):
            continue
        if exception.get("rule") != rule_id or exception.get("path") != normalized_path:
            continue
        expected = exception.get("value")
        if isinstance(expected, str) and expected and expected in values:
            return True
    return False


def _valid_candidate(candidate: Candidate, text_length: int) -> bool:
    return (
        isinstance(candidate.start, int)
        and isinstance(candidate.end, int)
        and 0 <= candidate.start < candidate.end <= text_length
        and all(0 <= start < end <= text_length for start, end in candidate.value_spans)
    )


SEMANTIC_REVIEW_TOPICS: tuple[dict[str, str], ...] = (
    {
        "id": "privacy-credentials",
        "title": "Credential and authentication context",
        "prompt": (
            "Review credential-like findings in their actual source context. Distinguish literal secrets from placeholders, references, public protocol examples, and synthetic fixtures. "
            "Assess whether real authentication material is included in the outgoing change; do not test it or contact a service."
        ),
    },
    {
        "id": "privacy-key-material",
        "title": "Key and signed-token material",
        "prompt": (
            "Review private-key, public-key, JWK, SSH, and compact-token findings. Establish whether material is private, public, synthetic, or an intentional verification artifact. "
            "Structural matching does not validate cryptographic strength or key validity."
        ),
    },
    {
        "id": "privacy-endpoints",
        "title": "Endpoint and network disclosure",
        "prompt": (
            "Review endpoint, hostname, and IP findings against repository publication context and the approved profile scope. Determine whether they identify nonpublic infrastructure; do not contact endpoints."
        ),
    },
    {
        "id": "privacy-personal-data",
        "title": "Personal, runtime, and machine-local information",
        "prompt": (
            "Review personal-data-shaped fields, identifiers, and local path findings for provenance. Distinguish schemas, synthetic data, public examples, and real user, device, or runtime records without widening beyond the selected repository scope."
        ),
    },
)
_SEMANTIC_BY_CATEGORY = {
    "Credentials": "privacy-credentials",
    "Private key material": "privacy-key-material",
    "Public key material": "privacy-key-material",
    "Backend information": "privacy-endpoints",
    "Network information": "privacy-endpoints",
    "Runtime and personal data": "privacy-personal-data",
    "Local information": "privacy-personal-data",
}
_SEMANTIC_BY_ID = {topic["id"]: topic for topic in SEMANTIC_REVIEW_TOPICS}


def scan_text(
    text: str,
    path: str,
    *,
    profile: Mapping[str, object] | None = None,
    exceptions: Sequence[Mapping[str, object]] | None = None,
) -> dict[str, object]:
    """Scan one decoded text blob and return source-free advisory findings.

    `profile` must be selected by the central trusted policy loader. When
    `exceptions` is omitted, exact exceptions come only from that profile.
    Passing an explicit sequence replaces the profile's exception list for
    focused local use and deterministic tests.
    """
    if not isinstance(text, str):
        raise TypeError("text must be decoded Unicode")
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a nonempty repository-relative string")
    trusted_profile: Mapping[str, object] = profile if isinstance(profile, Mapping) else {}
    scoped_exceptions = _profile_exceptions(trusted_profile, exceptions)
    provider_matches = collect_provider_candidates(text)
    line_starts = [0]
    line_starts.extend(index + 1 for index, character in enumerate(text) if character == "\n")
    findings: list[dict[str, object]] = []
    finding_counts: Counter[str] = Counter()
    exempted_counts: Counter[str] = Counter()
    semantic_ids: set[str] = set()
    path_value = path.replace("\\", "/").removeprefix("./")

    for rule in _DETECTORS:
        candidates = provider_matches.get(rule.id, ()) if rule.id in _PROVIDER_RULE_IDS else rule.finder(text, path, trusted_profile)
        seen_spans: set[tuple[int, int]] = set()
        for candidate in candidates:
            if not isinstance(candidate, Candidate) or not _valid_candidate(candidate, len(text)):
                continue
            span = (candidate.start, candidate.end)
            if span in seen_spans:
                continue
            seen_spans.add(span)
            if _exact_exception(candidate, rule.id, path_value, text, scoped_exceptions):
                exempted_counts[rule.id] += 1
                continue
            line_index = bisect_right(line_starts, candidate.start) - 1
            findings.append({
                "file": redact_path(path),
                "line": line_index + 1,
                "column": candidate.start - line_starts[line_index] + 1,
                "commit": None,
                "rule": rule.id,
                "category": rule.category,
                "severity": "warning",
                "evidence": "[source value withheld] " + rule.description,
                "judgment": "unreviewed",
                "basis": candidate.basis,
                "impact": "Potential exposure or policy risk if contextual review confirms it.",
                "action": rule.action,
                "span": {"start": candidate.start, "end": candidate.end},
            })
            finding_counts[rule.id] += 1
            topic = _SEMANTIC_BY_CATEGORY.get(rule.category)
            if topic:
                semantic_ids.add(topic)

    semantic_review = [
        dict(_SEMANTIC_BY_ID[topic_id])
        for topic_id in sorted(semantic_ids)
    ]
    return {
        "findings": findings,
        "coverage": {
            "evaluated_rule_ids": [rule.id for rule in _DETECTORS],
            "finding_counts": [
                {"rule": rule_id, "count": finding_counts[rule_id]}
                for rule_id in sorted(finding_counts)
            ],
            "exempted": [
                {"rule": rule_id, "count": exempted_counts[rule_id]}
                for rule_id in sorted(exempted_counts)
            ],
        },
        "catalog": RULE_CATALOG,
        "semantic_review": semantic_review,
    }


__all__ = [
    "RULE_CATALOG", "SEMANTIC_REVIEW_TOPICS", "redact_path", "rule_catalog", "scan_text",
]
