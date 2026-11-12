"""Tests for M75a routing in cli.py.

After M75a, no unproven finding can enter ScanSummary.findings via any CLI
routing path (cmd_scan heuristic/IDOR, graphql/websocket merge). M75b
enforces the invariant at the collection class; these tests enforce the
CLI's responsibility to route before it gets there.
"""

from types import SimpleNamespace

from janissary.cli import (
    _merge_graphql_into_scan,
    _merge_host_bypass_into_scan,
    _merge_ws_into_scan,
)
from janissary.engine.scanner import ScanSummary, _to_scan_finding
from janissary.verification import VerifiedFinding


def _verified():
    vf = VerifiedFinding(
        param="q",
        payload_name="sql_single_quote",
        payload_value="'",
        category="sqli",
        severity="critical",
        finding_type="db_error",
        detail="SQL error",
        url="http://x/a?q='",
        verification_status="verified",
    )
    return _to_scan_finding(vf)


def _unproven():
    vf = VerifiedFinding(
        param="q",
        payload_name="heuristic",
        payload_value="x",
        category="heuristic",
        severity="info",
        finding_type="heuristic_match",
        detail="heuristic hit",
        url="http://x/a?q=x",
        verification_status="unproven",
        verification_reason="heuristic_discovery",
    )
    return _to_scan_finding(vf)


def _empty():
    return ScanSummary(target="http://x", params=["q"], method="GET")


def _src(**kw):
    base = {
        "findings": [],
        "candidates": [],
        "total_requests": 0,
        "scan_incomplete": False,
        "abort_reason": None,
        "aborted": False,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_merge_graphql_routes_unproven_to_candidates():
    dst = _empty()
    _merge_graphql_into_scan(dst, _src(findings=[_unproven()]))
    assert len(dst.findings) == 0
    assert len(dst.candidates) == 1


def test_merge_graphql_preserves_verified():
    dst = _empty()
    _merge_graphql_into_scan(dst, _src(findings=[_verified()]))
    assert len(dst.findings) == 1
    assert len(dst.candidates) == 0


def test_merge_graphql_drains_src_candidates():
    dst = _empty()
    _merge_graphql_into_scan(dst, _src(candidates=[_unproven()]))
    assert len(dst.candidates) == 1
    assert len(dst.findings) == 0


def test_merge_ws_routes_unproven_to_candidates():
    dst = _empty()
    _merge_ws_into_scan(dst, _src(findings=[_unproven()]))
    assert len(dst.findings) == 0
    assert len(dst.candidates) == 1


def test_merge_ws_preserves_verified():
    dst = _empty()
    _merge_ws_into_scan(dst, _src(findings=[_verified()]))
    assert len(dst.findings) == 1


def test_merge_host_bypass_is_candidate_only():
    dst = _empty()
    _merge_host_bypass_into_scan(dst, _src(candidates=[_unproven()]))
    assert len(dst.candidates) == 1
    assert len(dst.findings) == 0
