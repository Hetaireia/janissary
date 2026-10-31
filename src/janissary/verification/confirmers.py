"""Confirmer protocol — pluggable verification rules (Phase 0.1).

A Confirmer examines a CandidateFinding and either confirms it (with a
reason), explicitly rejects it (with a reason), or declines to comment
(returns None). The engine tries confirmers in order and stops at the
first non-None result.

Confirmers are where oracle logic lives — db_error detection, response
reflection detection, timing deltas, union-column inference, etc. The
engine itself does not contain any vulnerability-specific logic.

See docs/ROADMAP.md Phase 0.1 and 0.2(b).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .types import CandidateFinding


@dataclass(frozen=True)
class Confirmation:
    """Result of a Confirmer's examination.

    `unproven=True` takes precedence over `confirmed`: the candidate is
    promoted to VerifiedFinding with verification_status='unproven' and
    verification_reason=reason. Used by Phase 0.2(b) corroborator path:
    the finding is emitted (not silently dropped), but marked as
    unverified because the baseline did not support a confident match.

    `confirmed=True` promotes the candidate to VerifiedFinding with
    verification_status='verified' and verification_reason=reason.
    `confirmed=False` (with unproven=False) produces FailedVerification
    with reason=reason.
    """

    confirmed: bool
    reason: str
    unproven: bool = False


@runtime_checkable
class Confirmer(Protocol):
    """A verification rule.

    Implementations must be stateless (or state must be thread-safe and
    idempotent) — the engine may call confirm() concurrently in future
    sessions.

    Return None to mean "no opinion, try next confirmer".
    Return Confirmation(confirmed=True, reason=...) to verify.
    Return Confirmation(confirmed=False, reason=...) to explicitly reject.
    """

    name: str

    def confirm(self, candidate: CandidateFinding) -> Confirmation | None: ...

class AnalyzerImplicitConfirmer:
    """Implicit confirmation from the analyzer pipeline.

    The DifferentialAnalyzer runs BEFORE any emission site is reached.
    It already filtered CORROBORATOR_ONLY_TYPES and payload_reflected
    candidates. By the time a candidate reaches the emission boundary,
    the analyzer has effectively verified it.

    Findings verified this way carry reason='analyzer:<finding_type>',
    distinguishing them from future confirmer additions (Phase 0.2(b)
    baseline stability check, etc.).
    """

    name = "analyzer_implicit"

    def confirm(self, candidate: CandidateFinding) -> Confirmation | None:
        return Confirmation(
            confirmed=True,
            reason=f"analyzer:{candidate.finding_type or 'unknown'}",
        )

class CorroboratorConfirmer:
    """Marks structural-signal findings as unproven.

    Corroborators (status_change, length_anomaly, length_shrink) are not
    detectors: a 500 or a length delta does not by itself prove a
    vulnerability class. Per Phase 0.2(b), they are emitted as
    verification_status='unproven' rather than silently dropped, so the
    operator can see the structural signal without claiming it verifies
    a specific category. Reason='corroborator_structural' is stable and
    machine-readable.
    """

    name = "corroborator"

    _CORROBORATOR_TYPES = frozenset(
        {"status_change", "length_anomaly", "length_shrink"}
    )

    def confirm(self, candidate: CandidateFinding) -> Confirmation | None:
        if candidate.finding_type in self._CORROBORATOR_TYPES:
            return Confirmation(
                confirmed=True,
                reason="corroborator_structural",
                unproven=True,
            )
        return None