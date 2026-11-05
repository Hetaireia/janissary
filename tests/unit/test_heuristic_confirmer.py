"""Tests for HeuristicConfirmer + integration with _ENGINE (M38)."""

from __future__ import annotations

from janissary.engine.scanner import _ENGINE
from janissary.verification.confirmers import Confirmation, HeuristicConfirmer
from janissary.verification.types import CandidateFinding, VerifiedFinding


def _heuristic_candidate(**overrides):
    base = dict(
        param="q",
        payload_name="heuristic",
        payload_value="v",
        category="sqli:error_leak",
        severity="low",
        finding_type="heuristic_sqli_error_leak",
        detail="test",
        discovery_reason="heuristic:HEUR-001",
    )
    base.update(overrides)
    return CandidateFinding(**base)


def _track_a_candidate(**overrides):
    base = dict(
        param="q",
        payload_name="sql_q",
        payload_value="v",
        category="sqli",
        severity="high",
        finding_type="status_change",
        detail="test",
    )
    base.update(overrides)
    return CandidateFinding(**base)


def test_name_is_heuristic():
    assert HeuristicConfirmer().name == "heuristic"


def test_confirm_returns_unproven_for_heuristic_reason():
    c = _heuristic_candidate()
    result = HeuristicConfirmer().confirm(c)
    assert isinstance(result, Confirmation)
    assert result.unproven is True
    assert result.confirmed is True
    assert result.reason == "heuristic:HEUR-001"


def test_confirm_returns_none_when_no_discovery_reason():
    c = _track_a_candidate()
    assert HeuristicConfirmer().confirm(c) is None


def test_confirm_returns_none_when_reason_not_heuristic():
    c = _track_a_candidate(discovery_reason="something:else")
    assert HeuristicConfirmer().confirm(c) is None


def test_engine_order_heuristic_before_analyzer():
    names = [c.name for c in _ENGINE._confirmers]
    assert "heuristic" in names
    assert names.index("heuristic") < names.index("analyzer_implicit")


def test_engine_verify_heuristic_candidate_unproven():
    result = _ENGINE.verify(_heuristic_candidate())
    assert isinstance(result, VerifiedFinding)
    assert result.verification_status == "unproven"


def test_engine_verify_heuristic_candidate_reason_preserved():
    result = _ENGINE.verify(_heuristic_candidate())
    assert result.verification_reason == "heuristic:HEUR-001"


def test_engine_verify_track_a_corroborator_unchanged():
    result = _ENGINE.verify(_track_a_candidate())
    assert result.verification_status == "unproven"
    assert result.verification_reason == "corroborator_structural"


def test_engine_verify_track_a_unmatched_promoted_by_analyzer():
    result = _ENGINE.verify(_track_a_candidate(finding_type="some_new_type"))
    assert result.verification_status == "verified"
    assert result.verification_reason.startswith("analyzer:")


def test_engine_verify_preserves_evidence():
    c = _heuristic_candidate()
    result = _ENGINE.verify(c)
    assert result.param == c.param
    assert result.category == c.category
    assert result.finding_type == c.finding_type
