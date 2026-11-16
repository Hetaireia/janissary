import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests

from janissary.auth import SessionSpec
from janissary.engine.scanner import Scanner


def _assert_status_files(case_dir):
    recording = case_dir / "recording_status.json"
    probe_evidence = case_dir / "probe_evidence_status.json"
    assert recording.is_file()
    assert probe_evidence.is_file()
    assert json.loads(recording.read_text())["recording_enabled"] is True
    assert json.loads(probe_evidence.read_text())["recording_enabled"] is True


def _track_status_writers(scanner, monkeypatch):
    attempted = []
    recording_writer = scanner._write_recording_status
    probe_writer = scanner._write_probe_evidence_status

    def write_recording_status():
        attempted.append("recording")
        recording_writer()

    def write_probe_evidence_status():
        attempted.append("probe_evidence")
        probe_writer()

    monkeypatch.setattr(scanner, "_write_recording_status", write_recording_status)
    monkeypatch.setattr(
        scanner, "_write_probe_evidence_status", write_probe_evidence_status
    )
    return attempted


def test_preflight_abort_attempts_and_writes_both_status_files(tmp_path, monkeypatch):
    case_dir = tmp_path / "case1"
    case_dir.mkdir()
    scanner = Scanner("http://example.test/x", ["p"], record_case_dir=case_dir)
    monkeypatch.setattr(scanner, "preflight", lambda: (False, "empty body"))
    attempted = _track_status_writers(scanner, monkeypatch)

    summary = scanner.scan()

    assert summary.aborted is True
    assert attempted == ["recording", "probe_evidence"]
    _assert_status_files(case_dir)


def test_normal_scan_completion_writes_both_status_files(tmp_path, monkeypatch):
    case_dir = tmp_path / "case1"
    case_dir.mkdir()
    scanner = Scanner(
        "http://example.test/x", [], record_case_dir=case_dir, detect_waf=False
    )
    monkeypatch.setattr(scanner, "preflight", lambda: (True, ""))
    attempted = _track_status_writers(scanner, monkeypatch)

    summary = scanner.scan()

    assert summary.aborted is False
    assert attempted == ["recording", "probe_evidence"]
    _assert_status_files(case_dir)


def test_missing_xpathi_prerequisite_records_indeterminate_oracle(
    tmp_path, monkeypatch
):
    from unittest.mock import MagicMock

    case_dir = tmp_path / "case1"
    case_dir.mkdir()
    scanner = Scanner(
        "http://example.test/x",
        ["p"],
        record_case_dir=case_dir,
        detect_waf=False,
    )
    monkeypatch.setattr(scanner, "preflight", lambda: (True, ""))

    def fake_paced_request(url, param, value):
        if value == "'":
            return None
        response = MagicMock()
        response.status_code = 200
        response.content = b"ok"
        response.text = "ok"
        response.headers = {}
        response.elapsed = None
        response.request = None
        return response

    monkeypatch.setattr(scanner, "_paced_request", fake_paced_request)

    scanner.scan(quiet=True)

    events = [
        json.loads(line)
        for line in (case_dir / "probe_evidence.jsonl").read_text().splitlines()
        if line.strip()
    ]
    quote_attempt = next(
        event
        for event in events
        if event.get("event_type") == "probe_attempt"
        and event.get("payload_name") == "sql_single_quote"
    )
    oracle_event = next(
        event
        for event in events
        if event.get("event_type") == "oracle_evaluation"
        and event.get("oracle_id") == "xpath_error_oracle"
    )

    assert quote_attempt["request_outcome"] == "none_response"
    assert oracle_event["oracle_evaluated"] is False
    assert oracle_event["oracle_result"] == "indeterminate"
    assert "sql_single_quote snapshot" in oracle_event["indeterminate_reason"]
    assert (
        oracle_event["prerequisite_event_ids"]["sql_single_quote"]
        == quote_attempt["event_id"]
    )
    assert oracle_event["prerequisite_event_ids"]["sql_or_1eq1"] is not None


@pytest.mark.parametrize(
    ("retry_outcome", "snapshot_captured"),
    [
        ("response", True),
        ("exception", False),
        ("none_response", False),
    ],
)
def test_auth_retry_evidence_links_attempts_and_snapshot_source(
    tmp_path, monkeypatch, retry_outcome, snapshot_captured
):
    case_dir = tmp_path / "case1"
    case_dir.mkdir()
    scanner = Scanner(
        "http://example.test/x",
        ["p"],
        auth_configured=True,
        auth_sessions=[
            SessionSpec(cookie="first=1"),
            SessionSpec(cookie="second=2"),
        ],
        record_case_dir=case_dir,
    )

    initial_response = MagicMock()
    initial_response.status_code = 401

    if retry_outcome == "response":
        retry_result = MagicMock()
        retry_result.status_code = 200
        monkeypatch.setattr(scanner, "_paced_request", lambda *args: retry_result)
    elif retry_outcome == "exception":

        def raise_request_exception(*args):
            raise requests.RequestException("simulated retry failure")

        monkeypatch.setattr(scanner, "_paced_request", raise_request_exception)
    else:
        monkeypatch.setattr(scanner, "_paced_request", lambda *args: None)

    summary = SimpleNamespace(total_requests=0)
    result = scanner._try_rotate_on_401(initial_response, "p", "payload", summary)
    retry_evidence = scanner._last_auth_retry_evidence

    assert retry_evidence["request_outcome"] == retry_outcome
    assert (result.status_code == 200) is (retry_outcome == "response")

    returned_event_id = scanner._record_xpath_probe_attempts(
        param="p",
        payload_name="sql_single_quote",
        payload_value="'",
        initial_response=initial_response,
        retry_evidence=retry_evidence,
        snapshot_captured=snapshot_captured,
    )

    events = [
        json.loads(line)
        for line in (case_dir / "probe_evidence.jsonl").read_text().splitlines()
        if line.strip()
    ]
    initial_event, retry_event = events

    assert initial_event["request_outcome"] == "response"
    assert initial_event["response_status"] == 401
    assert initial_event["snapshot_captured"] is False
    assert initial_event["used_for_snapshot"] is False

    assert retry_event["request_outcome"] == retry_outcome
    assert retry_event["attempt_role"] == "auth_retry"
    assert retry_event["parent_event_id"] == initial_event["event_id"]
    assert retry_event["snapshot_captured"] is snapshot_captured
    assert retry_event["used_for_snapshot"] is snapshot_captured

    expected_returned_id = (
        retry_event["event_id"]
        if retry_outcome == "response"
        else initial_event["event_id"]
    )
    assert returned_event_id == expected_returned_id
