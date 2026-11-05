"""Tests for IdorConfirmer + _ENGINE registration (M42, ADR-024 D2)."""

from __future__ import annotations

from janissary.engine.scanner import _ENGINE
from janissary.verification.confirmers import Confirmation, IdorConfirmer
from janissary.verification.types import CandidateFinding, VerifiedFinding


def _idor_candidate(**overrides):
    base = dict(
        param="q",
        payload_name="idor",
        payload_value="http://x/orders/42",
        category="idor",
        severity="medium",
        finding_type="idor_candidate",
        detail="cross-identity match",
        discovery_reason="idor:cross_identity_match",
    )
    base.update(overrides)
    return CandidateFinding(**base)


def test_name_is_idor():
    assert IdorConfirmer().name == "idor"


def test_confirm_returns_unproven_for_idor_reason():
    result = IdorConfirmer().confirm(_idor_candidate())
    assert isinstance(result, Confirmation)
    assert result.unproven is True
    assert result.reason == "idor:cross_identity_match"


def test_confirm_returns_none_for_non_idor_reason():
    c = _idor_candidate(discovery_reason="heuristic:HEUR-001")
    assert IdorConfirmer().confirm(c) is None


def test_engine_order_idor_before_analyzer():
    names = [c.name for c in _ENGINE._confirmers]
    assert "idor" in names
    assert names.index("idor") < names.index("analyzer_implicit")


def test_engine_verify_idor_candidate_unproven():
    result = _ENGINE.verify(_idor_candidate())
    assert isinstance(result, VerifiedFinding)
    assert result.verification_status == "unproven"
    assert result.verification_reason == "idor:cross_identity_match"
