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

    `confirmed=True` promotes the candidate to VerifiedFinding with
    verification_status='verified' and verification_reason=reason.
    `confirmed=False` produces FailedVerification with reason=reason.
    """

    confirmed: bool
    reason: str


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