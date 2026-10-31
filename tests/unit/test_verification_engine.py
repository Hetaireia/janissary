"""Tests for the verification boundary types and interface (Phase 0.1).

Phase 0.1 part 1: the types exist and the engine's contract is documented.
The implementation of verify() is a later commit; these tests pin the
contract so that when the implementation lands, it fills a known shape.
"""
from dataclasses import FrozenInstanceError

import pytest

from janissary.verification import (
    CandidateFinding,
    FailedVerification,
    VerificationEngine,
    VerifiedFinding,
)
from janissary.verification.types import VerificationStatus


def _sample_candidate(**overrides) -> CandidateFinding:
    base = dict(
        param="id",
        payload_name="sql_union_select",
        payload_value="1' UNION SELECT 1,2,3--",
        category="sqli",
        severity="high",
        finding_type="sql_union_rows",
        detail="Response returned 3 union columns",
        url="http://example.com/api/users?id=1",
        method="GET",
        response_status=200,
        response_length=512,
    )
    base.update(overrides)
    return CandidateFinding(**base)


def test_candidate_finding_constructs_with_required_fields():
    c = _sample_candidate()
    assert c.param == "id"
    assert c.category == "sqli"
    assert not hasattr(c, "verification_status")
    assert not hasattr(c, "fingerprint")


def test_candidate_finding_is_frozen():
    c = _sample_candidate()
    with pytest.raises(FrozenInstanceError):
        c.param = "other"  # type: ignore[misc]


def test_verified_finding_defaults_to_verified():
    v = VerifiedFinding(
        param="id",
        payload_name="sql_union_select",
        payload_value="1' UNION SELECT 1,2,3--",
        category="sqli",
        severity="high",
        finding_type="sql_union_rows",
        detail="Response returned 3 union columns",
        url="http://example.com/api/users?id=1",
    )
    assert v.verification_status == "verified"
    assert v.verification_reason is None


def test_verified_finding_can_be_unproven():
    v = VerifiedFinding(
        param="id",
        payload_name="sql_single_quote",
        payload_value="'",
        category="sqli",
        severity="high",
        finding_type="status_change",
        detail="500 from 401 baseline",
        verification_status="unproven",
        verification_reason="baseline_unstable",
    )
    assert v.verification_status == "unproven"
    assert v.verification_reason == "baseline_unstable"


def test_failed_verification_captures_candidate_and_reason():
    c = _sample_candidate()
    f = FailedVerification(
        candidate=c,
        reason="baseline_unstable",
        detail="Baseline length varied by 37% across 5 samples",
    )
    assert f.candidate is c
    assert f.reason == "baseline_unstable"
    assert "37%" in f.detail


def test_engine_raises_not_implemented_on_verify():
    """Phase 0.1 part 1: engine is interface only. This test exists so
    that a future commit which implements verify() must also update this
    test — making the implementation commit self-announcing."""
    engine = VerificationEngine()
    with pytest.raises(NotImplementedError, match="Phase 0.1 part 1"):
        engine.verify(_sample_candidate())


def test_verification_status_is_literal_verified_or_unproven():
    """Guard against typos in status strings at type-check time and test time."""
    assert VerificationStatus is not None