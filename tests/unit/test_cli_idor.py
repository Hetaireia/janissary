"""CLI validation tests for --idor flag (M42, ADR-024 D3)."""

from __future__ import annotations

from types import SimpleNamespace

from janissary.cli import _parse_signals, build_parser, cmd_scan


def _args(**kw):
    base = {
        "show_version": False,
        "url": "http://x/",
        "sessions": None,
        "cookie": None,
        "bearer": None,
        "cookie_alt": None,
        "bearer_alt": None,
        "idor": False,
        "params": None,
        "quiet": True,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_idor_flag_defaults_false():
    args = build_parser().parse_args(["scan", "--url", "http://x/"])
    assert args.idor is False


def test_idor_flag_sets_true():
    args = build_parser().parse_args(["scan", "--url", "http://x/", "--idor"])
    assert args.idor is True


def test_idor_without_any_identity_rejects(capsys):
    rc = cmd_scan(_args(idor=True))
    assert rc == 64
    err = capsys.readouterr().err
    assert "primary identity missing" in err


def test_idor_primary_missing_when_only_alt(capsys):
    rc = cmd_scan(_args(idor=True, cookie_alt="b=2"))
    assert rc == 64
    err = capsys.readouterr().err
    assert "primary identity missing" in err


def test_idor_alt_missing_when_only_primary(capsys):
    rc = cmd_scan(_args(idor=True, cookie="a=1"))
    assert rc == 64
    err = capsys.readouterr().err
    assert "alternate identity missing" in err


def test_idor_sessions_plus_alt_exclusive(capsys):
    rc = cmd_scan(_args(idor=True, sessions="s.json", cookie_alt="b=2"))
    assert rc == 64
    err = capsys.readouterr().err
    assert "mutually exclusive" in err


def test_parse_signals_idor_prefix():
    assert _parse_signals("idor:cross_identity_match") == ["idor_cross_identity_match"]


def test_parse_signals_heuristic_prefix_preserved():
    assert _parse_signals("heuristic:HEUR-001") == ["HEUR-001"]
    assert _parse_signals("heuristic:HEUR-001+HEUR-002") == ["HEUR-001", "HEUR-002"]
    assert _parse_signals("corroborator_structural") == []
    assert _parse_signals(None) == []
