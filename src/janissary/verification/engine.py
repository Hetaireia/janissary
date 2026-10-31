"""VerificationEngine — the sole emitter of VerifiedFinding (Phase 0.1).

Phase 0.1 (part 1 of N): interface only. The implementation — baseline
comparison, delta computation, normalizer invocation — lands in
subsequent commits. Until then, `verify()` raises NotImplementedError
so that no code path can accidentally emit a VerifiedFinding through
an unimplemented engine.

Production code MUST NOT depend on this class until the NotImplementedError
is removed by a later commit. This commit introduces the interface so
subsequent commits can wire emission sites against a stable shape.

See docs/ROADMAP.md Phase 0.1 and 0.2(b).
"""
from __future__ import annotations

from .types import CandidateFinding, FailedVerification, VerifiedFinding


VerificationResult = VerifiedFinding | FailedVerification


class VerificationEngine:
    """Sole producer of VerifiedFinding.

    Contract:
    - Accepts a CandidateFinding.
    - Returns either VerifiedFinding (verification_status='verified' or
      'unproven') or FailedVerification (with a reason code).
    - Never raises on a well-formed candidate; a failed verification
      is a FailedVerification return, not an exception.

    A candidate is promoted to VerifiedFinding with status 'verified'
    only when the engine has evidence (differential delta, oracle
    match, normalizer pass) that the payload caused the observed
    behavior. Candidates that pass structural checks but lack a
    confirmatory signal are promoted with status 'unproven' and a
    verification_reason — they are emitted, but flagged, so that
    Phase 0.2(b)'s "not silently dropped" invariant holds.
    """

    def verify(self, candidate: CandidateFinding) -> VerificationResult:
        raise NotImplementedError(
            "VerificationEngine.verify() is not yet implemented. "
            "Phase 0.1 part 1 introduces the interface; the implementation "
            "and emission-site rewiring are subsequent commits. Do not wire "
            "any production emission path through this engine until this "
            "exception is removed."
        )