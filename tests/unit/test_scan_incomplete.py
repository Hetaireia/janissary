"""Tests for ScanSummary.scan_incomplete (Phase 0.2(c)).

The flag distinguishes "scan never started" (preflight abort, 0 findings
is correct) from "scan started but stopped early" (auth expired mid-scan,
findings are partial). CI needs the distinction; exit code 2 alone cannot
express it.
"""
from unittest.mock import MagicMock

from janissary.engine.scanner import ScanSummary


def test_scan_incomplete_defaults_false():
    s = ScanSummary(target="http://x/", params=["q"], method="GET")
    assert s.scan_incomplete is False


def test_preflight_abort_does_not_set_scan_incomplete(monkeypatch):
    """Preflight failure: scan never ran, findings are not partial."""
    from janissary.engine import scanner as scanner_mod

    def fake_preflight(self):
        return (False, "target unreachable")

    monkeypatch.setattr(scanner_mod.Scanner, "preflight", fake_preflight)
    s = scanner_mod.Scanner(target="http://x/", params=["q"], method="GET")
    summary = s.scan(quiet=True)
    assert summary.aborted is True
    assert summary.abort_reason == "target unreachable"
    assert summary.scan_incomplete is False

def test_scan_incomplete_true_emits_in_json_summary():
    """JSON envelope carries scan_incomplete so CI can gate on it."""
    from janissary.cli import _summary_to_dict

    s = ScanSummary(target="http://x/", params=["q"], method="GET", scan_incomplete=True)
    d = _summary_to_dict(s)
    assert d["scan_incomplete"] is True


def test_scan_incomplete_false_emits_in_json_summary():
    from janissary.cli import _summary_to_dict

    s = ScanSummary(target="http://x/", params=["q"], method="GET")
    d = _summary_to_dict(s)
    assert d["scan_incomplete"] is False


def test_scan_incomplete_prints_incomplete_line(capsys):
    """Human summary prints INCOMPLETE when flag set, not otherwise."""
    from janissary.cli import _print_summary

    s = ScanSummary(target="http://x/", params=["q"], method="GET", scan_incomplete=True)
    _print_summary(s)
    out = capsys.readouterr().out
    assert "INCOMPLETE" in out


def test_source_marks_scan_incomplete_at_abort_site():
    """Source-level tripwire: mid-scan abort must set scan_incomplete=True."""
    from pathlib import Path

    src = Path("src/janissary/engine/scanner.py").read_text(encoding="utf-8")
    assert "summary.scan_incomplete = True" in src, (
        "scanner no longer sets scan_incomplete=True at the mid-scan abort site"
    )