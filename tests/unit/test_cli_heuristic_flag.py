"""CLI tests for --heuristic flag (M38)."""

from __future__ import annotations

from janissary.cli import build_parser
from janissary.engine.scanner import Scanner
from janissary.heuristic.types import Observation


def test_heuristic_flag_defaults_false():
    args = build_parser().parse_args(["scan", "--url", "http://x/"])
    assert args.heuristic is False


def test_heuristic_flag_sets_true():
    args = build_parser().parse_args(["scan", "--url", "http://x/", "--heuristic"])
    assert args.heuristic is True


def test_scanner_collect_observations_default_false():
    s = Scanner(target="http://x/", params=["q"])
    assert s._collect_observations is False
    assert s._observations == []


def test_scanner_collect_observations_true():
    s = Scanner(target="http://x/", params=["q"], collect_observations=True)
    assert s._collect_observations is True


def test_scanner_get_observations_returns_copy():
    s = Scanner(target="http://x/", params=["q"], collect_observations=True)
    s._observations = [Observation(url="u", body="b")]
    copy = s.get_observations()
    assert copy == s._observations
    copy.append(Observation(url="new", body="x"))
    assert len(s._observations) == 1


def test_scanner_run_heuristic_empty():
    s = Scanner(target="http://x/", params=["q"], collect_observations=True)
    assert s.run_heuristic() == []


def test_scanner_run_heuristic_returns_unproven_findings():
    s = Scanner(target="http://x/", params=["q"], collect_observations=True)
    s._observations = [
        Observation(
            url="http://x/",
            body="You have an error in your SQL syntax near MySQL",
            param="q",
            payload_name="sql_q",
            payload_value="v",
        )
    ]
    findings = s.run_heuristic()
    assert len(findings) == 1
    assert findings[0].verification_status == "unproven"
    assert findings[0].verification_reason == "heuristic:HEUR-001"
    assert getattr(findings[0], "_engine_emitted", False) is True


def test_scan_help_mentions_heuristic():
    p = build_parser()
    scan_parser = None
    for action in p._subparsers._group_actions:
        if hasattr(action, "choices") and "scan" in action.choices:
            scan_parser = action.choices["scan"]
            break
    assert scan_parser is not None
    h = next(
        (a for a in scan_parser._actions if "--heuristic" in a.option_strings), None
    )
    assert h is not None
    assert "heuristic" in (h.help or "").lower()
