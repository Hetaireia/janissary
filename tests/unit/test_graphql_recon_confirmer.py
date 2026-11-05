"""Tests for GraphQLReconConfirmer (Phase 2.1 + FN-15 part 3a).

The confirmer marks graphql_* candidates as unproven so the engine
does not overclaim. It must fire before AnalyzerImplicitConfirmer
in _ENGINE._confirmers — that ordering is load-bearing.
"""
import pytest

from janissary.engine.scanner import _ENGINE
from janissary.verification import (
    AnalyzerImplicitConfirmer,
    CandidateFinding,
    CorroboratorConfirmer,
    GraphQLReconConfirmer,
    VerifiedFinding,
)


def _graphql_candidate(**kw) -> CandidateFinding:
    base = dict(
        param="introspection_query",
        payload_name="introspection_query",
        payload_value="__schema introspection",
        category="graphql",
        severity="info",
        finding_type="graphql_introspection_enabled",
        detail="Schema introspection enabled (42 types exposed)",
        url="http://x/graphql",
        method="POST",
    )
    base.update(kw)
    return CandidateFinding(**base)


def _non_graphql_candidate(**kw) -> CandidateFinding:
    base = dict(
        param="q",
        payload_name="sql_single_quote",
        payload_value="'",
        category="sqli",
        severity="high",
        finding_type="db_error",
        detail="SQL error observed",
        url="http://x/",
        method="GET",
    )
    base.update(kw)
    return CandidateFinding(**base)


def test_confirmer_fires_on_graphql_prefix():
    confirmer = GraphQLReconConfirmer()
    result = confirmer.confirm(_graphql_candidate())
    assert result is not None
    assert result.confirmed is True
    assert result.unproven is True
    assert result.reason == "graphql_recon"


def test_confirmer_returns_none_on_non_graphql_finding():
    confirmer = GraphQLReconConfirmer()
    result = confirmer.confirm(_non_graphql_candidate())
    assert result is None


def test_confirmer_fires_on_all_graphql_prefixes():
    """Every finding_type in the graphql_ family is caught."""
    confirmer = GraphQLReconConfirmer()
    for ft in [
        "graphql_introspection_enabled",
        "graphql_batching_accepted",
        "graphql_suggestions_enabled",
        "graphql_depth_abuse",
        "graphql_alias_abuse",
        "graphql_argument_fuzz_error",
    ]:
        result = confirmer.confirm(_graphql_candidate(finding_type=ft))
        assert result is not None and result.unproven, f"{ft} not caught"


def test_engine_marks_graphql_candidate_unproven():
    """End-to-end: a graphql candidate through _ENGINE becomes
    VerifiedFinding with status='unproven', reason='graphql_recon'."""
    result = _ENGINE.verify(_graphql_candidate())
    assert isinstance(result, VerifiedFinding)
    assert result.verification_status == "unproven"
    assert result.verification_reason == "graphql_recon"


def test_engine_still_marks_non_graphql_candidate_verified():
    """Regression guard: adding GraphQLReconConfirmer must not change
    behavior for non-graphql candidates. They fall through to
    AnalyzerImplicitConfirmer and get verified."""
    result = _ENGINE.verify(_non_graphql_candidate())
    assert isinstance(result, VerifiedFinding)
    assert result.verification_status == "verified"
    assert result.verification_reason == "analyzer:db_error"


def test_engine_confirmer_order_is_load_bearing():
    """If GraphQLReconConfirmer came after AnalyzerImplicitConfirmer,
    graphql candidates would be marked verified (overclaim). This test
    pins the order."""
    names = [c.name for c in _ENGINE._confirmers]
    assert names == ["corroborator", "websocket_recon", "graphql_recon", "heuristic", "analyzer_implicit"], (
        f"confirmer order changed; got {names}. GraphQLReconConfirmer "
        f"must run BEFORE AnalyzerImplicitConfirmer or graphql candidates "
        f"get marked verified instead of unproven."
    )


def test_verified_finding_preserves_evidence_fields_from_graphql_candidate():
    """Engine round-trip preserves the evidence that discovery attached."""
    c = _graphql_candidate()
    result = _ENGINE.verify(c)
    assert isinstance(result, VerifiedFinding)
    assert result.param == c.param
    assert result.category == "graphql"
    assert result.finding_type == "graphql_introspection_enabled"
    assert result.url == "http://x/graphql"
    assert result.method == "POST"
    assert result.severity == "info"
