"""Tests for Scanner.scan_graphql() (Phase 2.1 + FN-15 part 3b)."""

from unittest.mock import patch

from janissary.engine.scanner import Scanner
from janissary.integrations.graphql import GraphQLProfile
from janissary.verification.types import CandidateFinding


def _scanner(target="http://x/graphql"):
    s = Scanner(target=target, params=["x"], method="GET", detect_waf=False)
    return s


def _reachable_profile(**kw):
    base = {"endpoint": "http://x/graphql", "reachable": True}
    base.update(kw)
    return GraphQLProfile(**base)


def _graphql_candidate(**kw) -> CandidateFinding:
    base = {
        "param": "introspection_query",
        "payload_name": "introspection_query",
        "payload_value": "__schema",
        "category": "graphql",
        "severity": "info",
        "finding_type": "graphql_introspection_enabled",
        "detail": "Introspection enabled",
        "url": "http://x/graphql",
        "method": "POST",
    }
    base.update(kw)
    return CandidateFinding(**base)


def test_preflight_failure_aborts():
    s = _scanner()
    with patch.object(s, "preflight", return_value=(False, "unreachable")):
        summary = s.scan_graphql()
    assert summary.aborted is True
    assert summary.abort_reason == "unreachable"
    assert summary.findings == []


def test_unreachable_graphql_marks_scan_incomplete():
    s = _scanner()
    profile = GraphQLProfile(endpoint="http://x/graphql", reachable=False)
    with patch.object(s, "preflight", return_value=(True, "")):  # noqa: SIM117
        with patch("janissary.engine.scanner.detect", return_value=profile):
            summary = s.scan_graphql()
    assert summary.aborted is False
    assert summary.scan_incomplete is True
    assert "not reachable" in summary.abort_reason


def test_reachable_graphql_produces_findings():
    s = _scanner()
    profile = _reachable_profile(introspection_enabled=True, type_count=42)
    candidates = [_graphql_candidate()]

    with patch.object(s, "preflight", return_value=(True, "")):  # noqa: SIM117
        with patch("janissary.engine.scanner.detect", return_value=profile):
            with patch(
                "janissary.engine.scanner.GraphQLDiscoveryModule.discover",
                return_value=candidates,
            ):
                summary = s.scan_graphql(include_probes=False)
    assert summary.aborted is False
    assert summary.scan_incomplete is False
    assert len(summary.candidates) == 1
    finding = summary.candidates[0]
    assert finding.category == "graphql"
    assert finding.verification_status == "unproven"
    assert finding.verification_reason == "graphql_recon"


def test_graphql_findings_marked_unproven_by_engine():
    """Critical: findings must go through _ENGINE so GraphQLReconConfirmer
    marks them unproven. If wiring is broken they'd be 'verified'."""
    s = _scanner()
    profile = _reachable_profile()
    candidates = [_graphql_candidate()]

    with patch.object(s, "preflight", return_value=(True, "")):  # noqa: SIM117
        with patch("janissary.engine.scanner.detect", return_value=profile):
            with patch(
                "janissary.engine.scanner.GraphQLDiscoveryModule.discover",
                return_value=candidates,
            ):
                summary = s.scan_graphql(include_probes=False)
    assert summary.candidates
    for f in summary.candidates:
        assert f.verification_status == "unproven"
        assert f.verification_reason == "graphql_recon"


def test_multiple_candidates_produce_multiple_findings():
    s = _scanner()
    profile = _reachable_profile()
    candidates = [
        _graphql_candidate(finding_type="graphql_introspection_enabled"),
        _graphql_candidate(finding_type="graphql_batching_accepted"),
        _graphql_candidate(finding_type="graphql_suggestions_enabled"),
    ]

    with patch.object(s, "preflight", return_value=(True, "")):  # noqa: SIM117
        with patch("janissary.engine.scanner.detect", return_value=profile):
            with patch(
                "janissary.engine.scanner.GraphQLDiscoveryModule.discover",
                return_value=candidates,
            ):
                summary = s.scan_graphql(include_probes=False)
    assert len(summary.candidates) == 3


def test_include_fuzz_passed_to_discovery_module():
    """Regression: include_fuzz default must remain False (fuzzing fires
    N HTTP requests per target; opt-in only)."""
    s = _scanner()
    profile = _reachable_profile()
    captured = {}

    def fake_discover(self, include_probes, include_fuzz, max_fuzz_targets):
        captured["include_fuzz"] = include_fuzz
        captured["include_probes"] = include_probes
        captured["max_fuzz_targets"] = max_fuzz_targets
        return []

    with patch.object(s, "preflight", return_value=(True, "")):  # noqa: SIM117
        with patch("janissary.engine.scanner.detect", return_value=profile):
            with patch(
                "janissary.engine.scanner.GraphQLDiscoveryModule.discover",
                fake_discover,
            ):
                s.scan_graphql()
    assert captured["include_fuzz"] is False
    assert captured["include_probes"] is True
    assert captured["max_fuzz_targets"] == 20


def test_summary_target_and_method():
    s = _scanner(target="http://example.test/graphql")
    profile = _reachable_profile(endpoint="http://example.test/graphql")

    with patch.object(s, "preflight", return_value=(True, "")):  # noqa: SIM117
        with patch("janissary.engine.scanner.detect", return_value=profile):
            with patch(
                "janissary.engine.scanner.GraphQLDiscoveryModule.discover",
                return_value=[],
            ):
                summary = s.scan_graphql()
    assert summary.target == "http://example.test/graphql"
    assert summary.method == "POST"


def test_empty_candidates_empty_findings():
    s = _scanner()
    profile = _reachable_profile()

    with patch.object(s, "preflight", return_value=(True, "")):  # noqa: SIM117
        with patch("janissary.engine.scanner.detect", return_value=profile):
            with patch(
                "janissary.engine.scanner.GraphQLDiscoveryModule.discover",
                return_value=[],
            ):
                summary = s.scan_graphql()
    assert summary.findings == []
    assert summary.finding_count == 0
