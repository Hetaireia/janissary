"""Evidence grading (ADR-033).

Grade answers how strong the evidence is; severity answers how bad the
class is when proven. The two are orthogonal on purpose.

Only rows backed by class-by-class evidence belong in the table. Everything
else falls back by mechanism:

- P3: a confirmer pass - a single-observation in-band oracle.
- P4: unproven, or nothing in the table (the ADR-033 ceiling).

Rows are revised in one place as each class is touched; per-call constants
are not allowed (ADR-033 decision 5).
"""

from __future__ import annotations

# finding_type -> grade. Only rows with evidence belong here.
_GRADES: dict[str, str] = {
    "collaborator_hit": "P1",
    "dns_only_resolution": "P4",
}

DEFAULT_GRADE = "P4"
CONFIRMED_GRADE = "P3"


def grade_for(finding_type: str, verified: bool) -> str:
    """Grade a finding that has no explicit grade set."""
    known = _GRADES.get(finding_type or "")
    if known:
        return known
    return CONFIRMED_GRADE if verified else DEFAULT_GRADE
