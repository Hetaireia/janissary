"""Unit tests for negative-results reporting (M18)."""

from __future__ import annotations

from unittest.mock import MagicMock

from janissary.cli import _print_summary


def _fake_summary(**overrides):
    """ScanSummary stand-in with sane defaults; override per test."""
    s = MagicMock()
    s.target = "http://test/"
    s.params = ["q"]
    s.method = "GET"
    s.total_requests = 10
    s.finding_count = 0
    s.groups = []
    s.aborted = False
    s.abort_reason = None
    s.scan_incomplete = False
    s.baselines = {}
    s.waf = None
    s.pacer = None
    s.findings = []
    for k, v in overrides.items():
        setattr(s, k, v)
    return s


def test_clean_scan_prints_negative_result(capsys):
    _print_summary(_fake_summary())
    out = capsys.readouterr().out
    assert "Negative result" in out
    assert "10 request" in out
    assert "responded normally" in out


def test_clean_scan_reports_correct_request_count(capsys):
    _print_summary(_fake_summary(total_requests=42))
    out = capsys.readouterr().out
    assert "42 request" in out


def test_scan_with_findings_does_not_print_negative_result(capsys):
    # finding_count > 0 exercises the guard. Use empty findings list: a bare
    # MagicMock as a finding would crash the downstream severity-grouping
    # loop (f.severity is a MagicMock, not a string).
    _print_summary(_fake_summary(finding_count=1))
    out = capsys.readouterr().out
    assert "Negative result" not in out
    assert "Findings:        1" in out


def test_aborted_scan_does_not_print_negative_result(capsys):
    _print_summary(
        _fake_summary(aborted=True, abort_reason="network error")
    )
    out = capsys.readouterr().out
    assert "Negative result" not in out
    assert "ABORTED" in out


def test_incomplete_scan_does_not_print_negative_result(capsys):
    _print_summary(_fake_summary(scan_incomplete=True))
    out = capsys.readouterr().out
    assert "Negative result" not in out
    assert "INCOMPLETE" in out


def test_clean_scan_still_shows_findings_line(capsys):
    _print_summary(_fake_summary())
    out = capsys.readouterr().out
    # The "Findings: 0" line must remain - negative result is additional
    assert "Findings:        0" in out