"""M83 Stage 2: Scanner recording integration tests.

Verifies the scanner-side wiring for per-case path-traversal recording:
parameter acceptance, lazy recorder construction, call-site wrap,
status-write behavior, and failure isolation.
"""

import json
from unittest.mock import MagicMock

import pytest

from janissary.engine.scanner import Scanner


def test_no_recorder_when_case_dir_none():
    s = Scanner("http://example.test/x", ["p"])
    assert s._recorder is None
    assert s._record_case_dir is None


def test_recorder_constructed_from_case_dir(tmp_path):
    case_dir = tmp_path / "case1"
    case_dir.mkdir()
    s = Scanner("http://example.test/x", ["p"], record_case_dir=case_dir)
    assert s._recorder is not None
    assert s._recorder.case_id == "case1"
    assert s._record_case_dir == case_dir


def test_recorder_rejects_unsanitized_case_dir_name(tmp_path):
    case_dir = tmp_path / "test.case"
    case_dir.mkdir()
    with pytest.raises(ValueError):
        Scanner("http://example.test/x", ["p"], record_case_dir=case_dir)


def test_maybe_record_observation_noop_when_no_recorder():
    s = Scanner("http://example.test/x", ["p"])
    s._maybe_record_observation(
        url="http://x/y",
        param="p",
        baseline=None,
        snapshot_exists=None,
        snapshot_noexist=None,
        payload_exists="pe",
        payload_noexist="pn",
        oracle_result=[],
    )


def test_maybe_record_observation_invokes_recorder(tmp_path):
    case_dir = tmp_path / "case1"
    case_dir.mkdir()
    s = Scanner("http://example.test/x", ["p"], record_case_dir=case_dir)
    s._recorder = MagicMock()
    baseline = object()
    snap_e = object()
    snap_n = object()
    oracle = [{"detail": "test"}]
    s._maybe_record_observation(
        url="http://x/y",
        param="p",
        baseline=baseline,
        snapshot_exists=snap_e,
        snapshot_noexist=snap_n,
        payload_exists="pe",
        payload_noexist="pn",
        oracle_result=oracle,
    )
    s._recorder.record.assert_called_once_with(
        url="http://x/y",
        param="p",
        baseline=baseline,
        snapshot_exists=snap_e,
        snapshot_noexist=snap_n,
        payload_exists="pe",
        payload_noexist="pn",
        oracle_result=oracle,
    )


def test_maybe_record_observation_swallows_recorder_exception(tmp_path):
    case_dir = tmp_path / "case1"
    case_dir.mkdir()
    s = Scanner("http://example.test/x", ["p"], record_case_dir=case_dir)
    s._recorder = MagicMock()
    s._recorder.record.side_effect = RuntimeError("simulated")
    s._maybe_record_observation(
        url="http://x/y",
        param="p",
        baseline=None,
        snapshot_exists=None,
        snapshot_noexist=None,
        payload_exists="pe",
        payload_noexist="pn",
        oracle_result=[],
    )


def test_write_recording_status_noop_when_no_recorder():
    s = Scanner("http://example.test/x", ["p"])
    s._write_recording_status()


def test_write_recording_status_writes_file(tmp_path):
    case_dir = tmp_path / "case1"
    case_dir.mkdir()
    s = Scanner("http://example.test/x", ["p"], record_case_dir=case_dir)
    s._write_recording_status()
    status_path = case_dir / "recording_status.json"
    assert status_path.exists()
    payload = json.loads(status_path.read_text())
    assert payload["recording_enabled"] is True
    assert payload["recorder_constructed"] is True
    assert payload["records_attempted"] == 0
    assert payload["records_written"] == 0
    assert payload["failures_total"] == 0
    assert payload["failure_log_written"] is False
    assert "scanner_version" in payload
    assert "completed_at" in payload


def test_write_recording_status_after_recording(tmp_path):
    case_dir = tmp_path / "case1"
    case_dir.mkdir()
    s = Scanner("http://example.test/x", ["p"], record_case_dir=case_dir)
    s._recorder._diagnostics.records_attempted = 2
    s._recorder._diagnostics.records_written = 1
    s._recorder._diagnostics.failures_total = 1
    s._recorder._diagnostics.failure_log_written = True
    s._write_recording_status()
    payload = json.loads((case_dir / "recording_status.json").read_text())
    assert payload["records_attempted"] == 2
    assert payload["records_written"] == 1
    assert payload["failures_total"] == 1
    assert payload["failure_log_written"] is True


def test_write_recording_status_swallows_write_exception(tmp_path):
    case_dir = tmp_path / "case1"
    case_dir.mkdir()
    s = Scanner("http://example.test/x", ["p"], record_case_dir=case_dir)
    status_path = case_dir / "recording_status.json"
    status_path.mkdir()
    s._write_recording_status()
