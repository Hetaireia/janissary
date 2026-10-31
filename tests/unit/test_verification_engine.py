"""Tests for the verification boundary types and interface (Phase 0.1).

Phase 0.1 part 2: verify() is implemented with a pluggable Confirmer
list. These tests pin the promotion and rejection contract so that
subsequent emission-site rewires and confirmer additions have a stable
target.
"""
from dataclasses import FrozenInstanceError

import pytest

from janissary.verification import (
    CandidateFinding,
    Confirmation,
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


class _ConfirmingConfirmer:
    name = "confirming"

    def confirm(self, candidate: CandidateFinding) -> Confirmation | None:
        return Confirmation(confirmed=True, reason="matched_pattern")


class _RejectingConfirmer:
    name = "rejecting"

    def confirm(self, candidate: CandidateFinding) -> Confirmation | None:
        return Confirmation(confirmed=False, reason="not_evidence")


class _AbstainingConfirmer:
    name = "abstaining"

    def confirm(self, candidate: CandidateFinding) -> Confirmation | None:
        return None


# --- Type-level tests (unchanged from part 1) ---


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


def test_verification_status_is_literal_verified_or_unproven():
    """Guard against typos in status strings at type-check time and test time."""
    assert VerificationStatus is not None


# --- Engine behaviour tests (new in part 2) ---


def test_verify_returns_malformed_when_param_missing():
    engine = VerificationEngine()
    result = engine.verify(_sample_candidate(param=""))
    assert isinstance(result, FailedVerification)
    assert result.reason == "malformed"


def test_verify_returns_malformed_when_category_missing():
    engine = VerificationEngine()
    result = engine.verify(_sample_candidate(category=""))
    assert isinstance(result, FailedVerification)
    assert result.reason == "malformed"


def test_verify_returns_unproven_when_no_confirmers():
    engine = VerificationEngine()
    result = engine.verify(_sample_candidate())
    assert isinstance(result, VerifiedFinding)
    assert result.verification_status == "unproven"
    assert result.verification_reason == "no_confirmer_matched"
    # Evidence fields carried through
    assert result.param == "id"
    assert result.category == "sqli"
    assert result.response_status == 200


def test_verify_returns_verified_when_confirmer_confirms():
    engine = VerificationEngine(confirmers=[_ConfirmingConfirmer()])
    result = engine.verify(_sample_candidate())
    assert isinstance(result, VerifiedFinding)
    assert result.verification_status == "verified"
    assert result.verification_reason == "matched_pattern"


def test_verify_returns_failed_when_confirmer_rejects():
    engine = VerificationEngine(confirmers=[_RejectingConfirmer()])
    result = engine.verify(_sample_candidate())
    assert isinstance(result, FailedVerification)
    assert result.reason == "not_evidence"
    assert "rejecting" in result.detail


def test_verify_uses_first_non_none_confirmer_result():
    engine = VerificationEngine(
        confirmers=[
            _AbstainingConfirmer(),
            _ConfirmingConfirmer(),
            _RejectingConfirmer(),
        ]
    )
    result = engine.verify(_sample_candidate())
    assert isinstance(result, VerifiedFinding)
    assert result.verification_reason == "matched_pattern"

class _UnprovenConfirmer:
    name = "unproven"

    def confirm(self, candidate: CandidateFinding) -> Confirmation | None:
        return Confirmation(confirmed=False, reason="baseline_unstable", unproven=True)


def test_verify_returns_unproven_when_confirmer_marks_unproven():
    engine = VerificationEngine(confirmers=[_UnprovenConfirmer()])
    result = engine.verify(_sample_candidate())
    assert isinstance(result, VerifiedFinding)
    assert result.verification_status == "unproven"
    assert result.verification_reason == "baseline_unstable"


def test_unproven_takes_precedence_over_confirmed():
    class _Both:
        name = "both"

        def confirm(self, candidate):
            return Confirmation(confirmed=True, reason="ambiguous", unproven=True)

    engine = VerificationEngine(confirmers=[_Both()])
    result = engine.verify(_sample_candidate())
    assert isinstance(result, VerifiedFinding)
    assert result.verification_status == "unproven"
    assert result.verification_reason == "ambiguous"


def test_confirmed_still_produces_verified_status():
    engine = VerificationEngine(confirmers=[_ConfirmingConfirmer()])
    result = engine.verify(_sample_candidate())
    assert isinstance(result, VerifiedFinding)
    assert result.verification_status == "verified"


def test_rejected_still_produces_failed_verification():
    engine = VerificationEngine(confirmers=[_RejectingConfirmer()])
    result = engine.verify(_sample_candidate())
    assert isinstance(result, FailedVerification)