"""ADR-030 Stage 6: --openapi --dry-run enumeration.

The dry-run path is the integration test's entry point: it exercises
parse_spec -> build_scan_targets -> rendering with no Scanner, no network,
and no preflight.
"""

import argparse

import pytest

from janissary.cli import _cmd_scan_openapi_dry_run


def _args(openapi, dry_run=True):
    return argparse.Namespace(openapi=str(openapi), dry_run=dry_run)


def _petstore_2_0():
    from pathlib import Path

    return (
        Path(__file__).resolve().parents[2]
        / "tests"
        / "fixtures"
        / "openapi"
        / "petstore-2.0.json"
    )


def test_dry_run_reports_swagger_2_0(capsys):
    rc = _cmd_scan_openapi_dry_run(_args(_petstore_2_0()))
    out = capsys.readouterr().out
    assert rc == 0
    assert "swagger 2.0" in out
    assert "20 imported" in out


def test_dry_run_reports_targets(capsys):
    rc = _cmd_scan_openapi_dry_run(_args(_petstore_2_0()))
    out = capsys.readouterr().out
    assert rc == 0
    assert "Total targets:" in out
    assert "inject=path" in out
    assert "inject=query" in out


def test_dry_run_body_target_carries_note(capsys):
    rc = _cmd_scan_openapi_dry_run(_args(_petstore_2_0()))
    out = capsys.readouterr().out
    assert rc == 0
    assert "body parameters are not injected by name" in out


def test_dry_run_missing_spec_returns_64(capsys):
    rc = _cmd_scan_openapi_dry_run(_args("/nonexistent/spec.json"))
    captured = capsys.readouterr()
    assert rc == 64
    assert "[!] --openapi:" in captured.err


def test_dry_run_invalid_json_returns_64(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    rc = _cmd_scan_openapi_dry_run(_args(bad))
    captured = capsys.readouterr()
    assert rc == 64
    assert "[!] --openapi:" in captured.err


def test_openapi_and_dry_run_flags_registered():
    from janissary.cli import build_parser

    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "--openapi"])
    ns = parser.parse_args(["scan", "--openapi", "s.json", "--dry-run"])
    assert ns.openapi == "s.json"
    assert ns.dry_run is True
