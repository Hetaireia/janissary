"""Verification boundary package (Phase 0.1).

See docs/ROADMAP.md Phase 0.1.
"""
from .engine import VerificationEngine, VerificationResult
from .types import (
    CandidateFinding,
    FailedVerification,
    VerificationStatus,
    VerifiedFinding,
)

__all__ = [
    "CandidateFinding",
    "FailedVerification",
    "VerificationEngine",
    "VerificationResult",
    "VerificationStatus",
    "VerifiedFinding",
]