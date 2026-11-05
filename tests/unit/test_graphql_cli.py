"""Tests for --graphql CLI flag and _merge_graphql_into_scan (FN-15 3c)."""

import contextlib
from argparse import Namespace
from unittest.mock import MagicMock, patch

from janissary.cli import _merge_graphql_into_scan, cmd_scan
from janissary.engine.scanner import ScanFinding, ScanSummary


def _scan_finding(**kw) -> ScanFinding:
    base = {
        "param": "q",
        "payload_name": "sql_single_quote",
        "payload_value": "'",
        "category": "sqli",
        "severity": "high",
        "finding_type": "db_error",
        "detail": "SQL error",
        "url": "http://x/",
        "method": "GET",
    }
    base.update(kw)
    f = ScanFinding(**base)
    f._engine_emitted = True
    return f


def _graphql_finding(**kw) -> ScanFinding:
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
        "verification_status": "unproven",
        "verification_reason": "graphql_recon",
    }
    base.update(kw)
    f = ScanFinding(**base)
    f._engine_emitted = True
    return f


def _summary(findings=None, **kw):
    s = ScanSummary(
        target=kw.get("target", "http://x/"),
        params=kw.get("params", ["q"]),
        method=kw.get("method", "GET"),
    )
    for f in findings or []:
        s.findings.append(f)
    s.finding_count = len(s.findings)
    s.total_requests = kw.get("total_requests", 10)
    s.aborted = kw.get("aborted", False)
    s.abort_reason = kw.get("abort_reason")
    s.scan_incomplete = kw.get("scan_incomplete", False)
    return s


def test_merge_appends_findings_and_updates_count():
    s = _summary([_scan_finding()])
    gql = _summary(
        [_graphql_finding(), _graphql_finding(finding_type="graphql_batching_accepted")]
    )
    result = _merge_graphql_into_scan(s, gql)
    assert result is s
    assert len(s.findings) == 3
    assert s.finding_count == 3


def test_merge_sums_total_requests():
    s = _summary([], total_requests=20)
    gql = _summary([], total_requests=15)
    _merge_graphql_into_scan(s, gql)
    assert s.total_requests == 35


def test_merge_propagates_scan_incomplete():
    s = _summary([])
    gql = _summary([], scan_incomplete=True, abort_reason="not reachable")
    _merge_graphql_into_scan(s, gql)
    assert s.scan_incomplete is True
    assert "not reachable" in s.abort_reason


def test_merge_does_not_overwrite_existing_abort_reason():
    s = _summary([], scan_incomplete=True, abort_reason="http incomplete")
    gql = _summary([], scan_incomplete=True, abort_reason="graphql incomplete")
    _merge_graphql_into_scan(s, gql)
    assert s.abort_reason == "http incomplete"


def test_merge_propagates_aborted_when_outer_not_aborted():
    s = _summary([])
    gql = _summary([], aborted=True, abort_reason="graphql aborted")
    _merge_graphql_into_scan(s, gql)
    assert s.aborted is True
    assert s.abort_reason == "graphql aborted"


def test_merge_findings_pass_verified_findings_list_assertion():
    """The outer summary.findings is a _VerifiedFindingsList that
    asserts _engine_emitted=True. Merge must not raise."""
    s = _summary([])
    gql = _summary([_graphql_finding()])
    _merge_graphql_into_scan(s, gql)  # would raise AssertionError if marker missing
    assert len(s.findings) == 1


def test_graphql_flag_registered_in_scan_subparser():
    """Argparse must accept --graphql on scan."""
    import sys
    from unittest.mock import patch as _p

    from janissary.cli import main

    test_argv = ["janissary", "scan", "-u", "http://x/", "--graphql", "--json"]
    with _p.object(sys, "argv", test_argv):
        with _p("janissary.cli.Scanner") as MockScanner:
            inst = MockScanner.return_value
            inst.scan.return_value = _summary([])
            inst.scan_graphql.return_value = _summary([])
            with contextlib.suppress(SystemExit):
                main()
    # If argparse rejected --graphql, main would have raised SystemExit(2)
    # before Scanner was instantiated.
    assert MockScanner.called, "--graphql was rejected by argparse"


def test_cmd_scan_calls_scan_graphql_when_flag_set():
    args = Namespace(
        url="http://x/graphql",
        params="q",
        method="GET",
        timeout=10.0,
        baseline_count=10,
        delay=0.0,
        stealth=False,
        no_waf=True,
        inject_in="auto",
        baseline_value="",
        json_template=None,
        quiet=True,
        export=None,
        json=True,
        jsonl=False,
        show_version=False,
        proxy=None,
        graphql=True,
    )
    http_summary = _summary([])
    gql_summary = _summary([_graphql_finding()])
    with patch("janissary.cli.Scanner") as MockScanner:
        inst = MockScanner.return_value
        inst.scan.return_value = http_summary
        inst.scan_graphql.return_value = gql_summary
        with patch("janissary.cli.scope_from_args") as mock_scope:
            mock_scope.return_value.require = MagicMock()
            with contextlib.suppress(SystemExit):
                cmd_scan(args)
    inst.scan_graphql.assert_called_once()
    call_kwargs = inst.scan_graphql.call_args.kwargs
    assert call_kwargs.get("include_probes") is True
    assert call_kwargs.get("include_fuzz") is False


def test_cmd_scan_does_not_call_scan_graphql_when_flag_absent():
    args = Namespace(
        url="http://x/",
        params="q",
        method="GET",
        timeout=10.0,
        baseline_count=10,
        delay=0.0,
        stealth=False,
        no_waf=True,
        inject_in="auto",
        baseline_value="",
        json_template=None,
        quiet=True,
        export=None,
        json=True,
        jsonl=False,
        show_version=False,
        proxy=None,
        graphql=False,
    )
    with patch("janissary.cli.Scanner") as MockScanner:
        inst = MockScanner.return_value
        inst.scan.return_value = _summary([])
        with patch("janissary.cli.scope_from_args") as mock_scope:
            mock_scope.return_value.require = MagicMock()
            with contextlib.suppress(SystemExit):
                cmd_scan(args)
    inst.scan_graphql.assert_not_called()
