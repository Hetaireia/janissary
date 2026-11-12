"""Data model for the verification boundary (Phase 0.1).

Phase 0.1 architectural invariant: the VerificationEngine is the sole
producer of VerifiedFinding. Discovery modules produce CandidateFinding.
The engine either promotes a candidate to VerifiedFinding (with status
'verified' or 'unproven') or returns FailedVerification with a reason code.

See docs/ROADMAP.md Phase 0.1 and 0.2(b).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

VerificationStatus = Literal["verified", "unproven"]


@dataclass(frozen=True)
class CandidateFinding:
    """A finding proposed by a discovery module, prior to verification.

    Mirrors engine.scanner.ScanFinding's shape so that eventual promotion
    is a field copy. Does NOT include `fingerprint` or `verification_status`
    — identity and status are assigned by the engine (ADR-007) so that a
    candidate is not a finding until verification accepts it.
    """

    # Detection evidence
    param: str
    payload_name: str
    payload_value: str
    category: str
    severity: str
    finding_type: str
    detail: str

    # Response observations
    response_status: int | None = None
    response_length: int = 0
    response_time: float | None = None
    reflection_context: str | None = None
    response_content_type: str = ""

    # Wire-level artifacts for reproduction
    url: str = ""
    method: str = "GET"
    raw_request: str | None = None
    raw_response: str | None = None

    # Optional: why this candidate exists (populated by the producer, not
    # the engine — useful for debugging the discovery layer in isolation)
    discovery_reason: str | None = None

    # Heuristic metadata carried through promotion. Populated by the
    # heuristic engine; defaulted to 0.0/"" for Track A candidates.
    # NOTE: confidence is heuristic metadata, not a calibrated probability.
    # NOTE: evidence_excerpt is an internal data-model field and is NOT
    #       currently serialised to JSON/JSONL/SARIF. Its reporting contract
    #       is deferred to a future schema version.
    confidence: float = 0.0
    evidence_excerpt: str = ""


@dataclass(frozen=True)
class VerifiedFinding:
    """A finding that has passed through the verification engine.

    Same shape as engine.scanner.ScanFinding, plus verification metadata.
    The `verification_status` distinguishes proven findings from findings
    the engine accepted as candidates but could not prove (Phase 0.2(b):
    "candidate generated, verification failed because baseline was
    unstable" — not silently dropped).
    """

    # Detection evidence (same as CandidateFinding)
    param: str
    payload_name: str
    payload_value: str
    category: str
    severity: str
    finding_type: str
    detail: str

    # Response observations
    response_status: int | None = None
    response_length: int = 0
    response_time: float | None = None
    reflection_context: str | None = None
    response_content_type: str = ""

    # Wire-level artifacts
    url: str = ""
    method: str = "GET"
    raw_request: str | None = None
    raw_response: str | None = None

    # Identity (ADR-007, populated by the engine)
    fingerprint: str = ""

    # Verification metadata — the whole point of the type
    verification_status: VerificationStatus = "verified"
    verification_reason: str | None = None

    # Heuristic metadata propagated from CandidateFinding. Not serialised;
    # see CandidateFinding for the reporting-contract note.
    confidence: float = 0.0
    evidence_excerpt: str = ""


@dataclass(frozen=True)
class FailedVerification:
    """A candidate the engine could not promote to VerifiedFinding.

    Retained (not dropped) so the scan summary can report
    "N candidates generated, M could not be verified, top reasons: ..."
    This is what Phase 0.2(b) requires for FN-12: the SQLi candidate on
    Juice Shop must be visible as a failed verification with
    reason='baseline_unstable', not silently dropped.
    """

    candidate: CandidateFinding
    reason: str  # short machine-readable code, e.g. "baseline_unstable"
    detail: str = ""  # human-readable explanation
