"""ADR-030 Stage 6d: _run_openapi_scan loop integration tests.

Covers the orchestration layer: dependency resolution, spec parse,
per-target scanner construction, merge, and emit. Each test exercises
one of those guarantees against mocks so the loop's plumbing is verified
without any network or real target.

What this file does NOT re-test (see the referenced files):
  * parse_spec behavior                 -- test_openapi_import.py
  * build_scan_targets output shape     -- test_openapi_dispatch.py
  * Scanner construction per target     -- test_openapi_dispatch_consumption.py
  * _cmd_scan_openapi_dry_run rendering -- test_openapi_dry_run.py

The only thing tested here is the loop that joins them.
"""

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from janissary.cli import _run_openapi_scan, cmd_scan
from janissary.engine.scanner import ScanSummary
from janissary.importers.dispatch import build_scan_targets
from janissary.importers.openapi import (
    OpenAPIImportError,
    ParseResult,
    parse_spec,
)

PETSTORE = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "openapi"
    / "petstore-3.0.json"
)


def _args(openapi, quiet=True, dry_run=False):
    return argparse.Namespace(
        openapi=str(openapi),
        quiet=quiet,
        dry_run=dry_run,
    )


def _mock_scanner():
    s = MagicMock()
    s.scan.return_value = ScanSummary(target="http://x/", params=[], method="GET")
    return s


def _expected_target_count(path):
    result = parse_spec(path)
    return sum(len(build_scan_targets(op)) for op in result.imported)


def test_loop_builds_one_scanner_per_target_and_emits_merged():
    """No silent drops: every build_scan_targets output becomes a scanner."""
    expected = _expected_target_count(PETSTORE)
    assert expected > 0, "fixture must yield at least one target"

    with (
        patch("janissary.cli._resolve_scan_deps", return_value=MagicMock()),
        patch(
            "janissary.cli._build_scanner", return_value=_mock_scanner()
        ) as mock_build,
        patch("janissary.cli._emit_scan_result", return_value=0) as mock_emit,
    ):
        rc = _run_openapi_scan(_args(PETSTORE))

    assert rc == 0
    assert mock_build.call_count == expected
    assert mock_emit.call_count == 1
    merged = mock_emit.call_args[0][1]
    assert isinstance(merged, ScanSummary)


def test_empty_spec_emits_empty_summary():
    """parse_spec returning zero imported operations must not crash."""
    empty = ParseResult(source="test", imported=[], skipped=[], notes=[])
    with (
        patch("janissary.cli._resolve_scan_deps", return_value=MagicMock()),
        patch("janissary.importers.openapi.parse_spec", return_value=empty),
        patch("janissary.cli._build_scanner") as mock_build,
        patch("janissary.cli._emit_scan_result", return_value=0) as mock_emit,
    ):
        rc = _run_openapi_scan(_args(PETSTORE))

    assert rc == 0
    assert mock_build.call_count == 0
    assert mock_emit.call_count == 1
    merged = mock_emit.call_args[0][1]
    assert merged.finding_count == 0
    assert merged.aborted is False


def test_deps_none_returns_64_without_parsing():
    """Dependency resolution failure aborts before touching the spec."""
    with (
        patch("janissary.cli._resolve_scan_deps", return_value=None),
        patch("janissary.importers.openapi.parse_spec") as mock_parse,
    ):
        rc = _run_openapi_scan(_args(PETSTORE))

    assert rc == 64
    mock_parse.assert_not_called()


def test_import_error_returns_64_no_scanners_built():
    """Spec parse failure returns 64 without ever constructing a scanner."""
    with (
        patch("janissary.cli._resolve_scan_deps", return_value=MagicMock()),
        patch(
            "janissary.importers.openapi.parse_spec",
            side_effect=OpenAPIImportError("bad spec"),
        ),
        patch("janissary.cli._build_scanner") as mock_build,
        patch("janissary.cli._emit_scan_result") as mock_emit,
    ):
        rc = _run_openapi_scan(_args(PETSTORE))

    assert rc == 64
    assert mock_build.call_count == 0
    assert mock_emit.call_count == 0


def test_one_target_failure_does_not_abort_loop():
    """Per-target try/except continues past a raising scanner build."""
    expected = _expected_target_count(PETSTORE)
    if expected < 2:
        pytest.skip("fixture has too few targets for partial-failure test")

    calls = {"n": 0}

    def build_or_raise(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("simulated target failure")
        return _mock_scanner()

    with (
        patch("janissary.cli._resolve_scan_deps", return_value=MagicMock()),
        patch("janissary.cli._build_scanner", side_effect=build_or_raise),
        patch("janissary.cli._emit_scan_result", return_value=0) as mock_emit,
    ):
        rc = _run_openapi_scan(_args(PETSTORE))

    assert rc == 0
    assert mock_emit.call_count == 1
    assert calls["n"] == expected


@pytest.mark.parametrize(
    "dry_run,target_helper",
    [
        (True, "_cmd_scan_openapi_dry_run"),
        (False, "_run_openapi_scan"),
    ],
)
def test_cmd_scan_dispatches_openapi(dry_run, target_helper):
    """--openapi dispatches to dry-run or loop based on --dry-run."""
    args = argparse.Namespace(
        show_version=False,
        openapi="spec.json",
        dry_run=dry_run,
    )
    patch_target = f"janissary.cli.{target_helper}"
    with patch(patch_target, return_value=42) as m:
        assert cmd_scan(args) == 42
    m.assert_called_once_with(args)
