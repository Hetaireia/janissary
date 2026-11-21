"""VerificationEngine — the sole emitter of VerifiedFinding (Phase 0.1).

Phase 0.1 (part 2 of N): verify() is implemented with a pluggable
Confirmer list. With no confirmers configured, every well-formed
candidate is promoted to VerifiedFinding with status='unproven' and
reason='no_confirmer_matched' — matching the roadmap's Phase 0.2(b)
"not silently dropped" invariant.

All production emission sites have been rewired through this engine.
It is the sole routing path for verified findings from heuristic,
HTTP differential, WebSocket, GraphQL, IDOR, and specialised
detector paths. Host-bypass observations are retained directly as
candidates per ADR-030 Rule 1 and do not pass through verify().

Current call sites: engine/scanner.py (21), heuristic/engine.py (2),
heuristic/__init__.py (1) -- 24 total.

See docs/ROADMAP.md Phase 0.1 and 0.2(b).
"""

from __future__ import annotations

from dataclasses import asdict

from .confirmers import Confirmer
from .types import (
    CandidateFinding,
    FailedVerification,
    VerificationStatus,
    VerifiedFinding,
)

VerificationResult = VerifiedFinding | FailedVerification

_EVIDENCE_FIELDS = (
    "param",
    "payload_name",
    "payload_value",
    "category",
    "severity",
    "finding_type",
    "detail",
    "response_status",
    "response_length",
    "response_time",
    "reflection_context",
    "response_content_type",
    "url",
    "method",
    "raw_request",
    "raw_response",
    "confidence",
    "evidence_excerpt",
    "evidence_grade",
    "signature_id",
    "observation_count",
    "first_observation_id",
    "last_observation_id",
    "payload_families",
    "contributing_observation_ids",
)


def _promote(
    candidate: CandidateFinding,
    status: VerificationStatus,
    reason: str | None,
) -> VerifiedFinding:
    """Build a VerifiedFinding from a CandidateFinding's evidence fields."""
    source = asdict(candidate)
    evidence = {name: source[name] for name in _EVIDENCE_FIELDS}
    return VerifiedFinding(
        **evidence,
        verification_status=status,
        verification_reason=reason,
    )


class VerificationEngine:
    """Sole producer of VerifiedFinding.

    Contract:
    - Accepts a CandidateFinding.
    - Returns either VerifiedFinding (verification_status='verified' or
      'unproven') or FailedVerification (with a reason code).
    - Never raises on a well-formed candidate; a failed verification
      is a FailedVerification return, not an exception.

    A candidate is promoted to VerifiedFinding with status 'verified'
    only when a Confirmer confirms it. Candidates that pass structural
    checks but no confirmer matched are promoted with status 'unproven'
    and reason='no_confirmer_matched' — they are emitted, but flagged,
    so that Phase 0.2(b)'s "not silently dropped" invariant holds.

    Confirmers are tried in order. The first non-None result wins.
    """

    def __init__(self, confirmers: list[Confirmer] | None = None) -> None:
        self._confirmers = list(confirmers or [])

    def verify(self, candidate: CandidateFinding) -> VerificationResult:
        if not candidate.param or not candidate.category:
            return FailedVerification(
                candidate=candidate,
                reason="malformed",
                detail="candidate missing required field (param or category)",
            )

        for confirmer in self._confirmers:
            result = confirmer.confirm(candidate)
            if result is None:
                continue
            if result.unproven:
                return _promote(candidate, "unproven", result.reason)
            if result.confirmed:
                return _promote(candidate, "verified", result.reason)
            return FailedVerification(
                candidate=candidate,
                reason=result.reason,
                detail=f"rejected by confirmer '{confirmer.name}'",
            )

        return _promote(candidate, "unproven", "no_confirmer_matched")
