"""Verification boundary package (Phase 0.1).

See docs/ROADMAP.md Phase 0.1.
"""

from .confirmers import (
    AnalyzerImplicitConfirmer,
    Confirmation,
    Confirmer,
    CorroboratorConfirmer,
    DnsOnlyOobConfirmer,
    GraphQLReconConfirmer,
    OracleConfirmer,
    WebSocketReconConfirmer,
)
from .engine import VerificationEngine, VerificationResult
from .grading import grade_for
from .types import (
    CandidateFinding,
    FailedVerification,
    VerificationStatus,
    VerifiedFinding,
)

__all__ = [
    "AnalyzerImplicitConfirmer",
    "CandidateFinding",
    "Confirmation",
    "Confirmer",
    "CorroboratorConfirmer",
    "DnsOnlyOobConfirmer",
    "FailedVerification",
    "GraphQLReconConfirmer",
    "OracleConfirmer",
    "VerificationEngine",
    "VerificationResult",
    "VerificationStatus",
    "VerifiedFinding",
    "WebSocketReconConfirmer",
    "grade_for",
]
