"""cmd_scan validation for --sessions (M41, ADR-023 D4)."""

from __future__ import annotations

from types import SimpleNamespace

from janissary.cli import cmd_scan


def _args(**kw):
    base = dict(
        show_version=False,
        url="http://x/",
        sessions=None,
        cookie=None,
        bearer=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_sessions_mutually_exclusive_with_cookie(capsys):
    rc = cmd_scan(_args(sessions="s.json", cookie="c=1"))
    assert rc == 64
    err = capsys.readouterr().err
    assert "mutually exclusive" in err


def test_sessions_mutually_exclusive_with_bearer(capsys):
    rc = cmd_scan(_args(sessions="s.json", bearer="tok"))
    assert rc == 64
    err = capsys.readouterr().err
    assert "mutually exclusive" in err
