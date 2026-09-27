"""Group scan findings by root cause.

A finding is a piece of evidence. A group is a bug.

Two findings belong to the same group when they share the same
parameter, the same category, and the same root cause (derived from
finding_type). The group's severity is the highest among its evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# (category, finding_type) -> root_cause.
# Unmapped pairs fall through to finding_type.
_ROOT_CAUSE_MAP: dict[tuple[str, str], str] = {
    ("sqli", "db_error"): "sql_injection",
    ("sqli", "status_change"): "sql_injection",
    ("sqli", "length_anomaly"): "sql_injection",
    ("sqli", "timing_anomaly"): "sql_injection",
    ("traversal", "status_change"): "path_traversal",
    ("traversal", "length_anomaly"): "path_traversal",
    ("cmdi", "timing_anomaly"): "command_injection",
    ("cmdi", "status_change"): "command_injection",
}

# finding_type values that all mean "the endpoint reflected our input".
_REFLECTION_TYPES: frozenset[str] = frozenset(
    {
        "payload_reflected",
        "reflected_xss",
        "reflection_context",
    }
)

# Root causes where the bug is not category-specific: the same
# finding applies regardless of which payload class triggered it.
_CROSS_CATEGORY_ROOTS: frozenset[str] = frozenset({"reflection"})


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def classify_root_cause(category: str, finding_type: str) -> str:
    if finding_type in _REFLECTION_TYPES:
        return "reflection"
    return _ROOT_CAUSE_MAP.get((category, finding_type), finding_type)


@dataclass
class FindingGroup:
    param: str
    category: str
    root_cause: str
    severity: str
    evidence: list = field(default_factory=list)

    def add(self, finding) -> None:
        self.evidence.append(finding)
        if _SEV_ORDER.get(finding.severity, 99) < _SEV_ORDER.get(self.severity, 99):
            self.severity = finding.severity

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)

    @property
    def payload_names(self) -> list[str]:
        seen: list[str] = []
        for e in self.evidence:
            if e.payload_name not in seen:
                seen.append(e.payload_name)
        return seen

    def to_dict(self) -> dict:
        return {
            "param": self.param,
            "category": self.category,
            "root_cause": self.root_cause,
            "severity": self.severity,
            "evidence_count": self.evidence_count,
            "payloads": self.payload_names,
            "evidence": [
                {
                    "payload_name": e.payload_name,
                    "payload_value": e.payload_value,
                    "finding_type": e.finding_type,
                    "severity": e.severity,
                    "detail": e.detail,
                    "response_status": e.response_status,
                }
                for e in self.evidence
            ],
        }


def group_findings(findings: list) -> list[FindingGroup]:
    """Group findings by (param, category, root_cause).

    For cross-category root causes (e.g. reflection), the category is
    dropped from the key so the same bug reported by different payload
    classes collapses into one group.
    """
    groups: dict[tuple[str, str, str], FindingGroup] = {}
    for f in findings:
        root = classify_root_cause(f.category, f.finding_type)
        cat = "" if root in _CROSS_CATEGORY_ROOTS else f.category
        key = (f.param, cat, root)
        g = groups.get(key)
        if g is None:
            g = FindingGroup(
                param=f.param,
                category=cat,
                root_cause=root,
                severity=f.severity,
            )
            groups[key] = g
        g.add(f)
    return list(groups.values())
