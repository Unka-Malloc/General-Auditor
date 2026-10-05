"""Source-free types shared by the deterministic privacy detectors."""

from dataclasses import dataclass
from typing import Callable, Iterable, Mapping


@dataclass(frozen=True, slots=True)
class Candidate:
    """An internal match location; the matched value is never stored here."""

    start: int
    end: int
    basis: str
    value_spans: tuple[tuple[int, int], ...] = ()


Finder = Callable[[str, str, Mapping[str, object]], Iterable[Candidate]]


@dataclass(frozen=True, slots=True)
class DetectorRule:
    id: str
    category: str
    title: str
    description: str
    action: str
    finder: Finder
    group: str = "common"

    def public(self) -> "RuleMetadata":
        return RuleMetadata(
            id=self.id,
            category=self.category,
            title=self.title,
            description=self.description,
            action=self.action,
            group=self.group,
        )


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    """Immutable catalog entry with no compiled patterns or matched values."""

    id: str
    category: str
    title: str
    description: str
    action: str
    group: str

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "action": self.action,
            "group": self.group,
        }
