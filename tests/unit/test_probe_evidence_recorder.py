"""Unit tests for the family-neutral probe evidence recorder."""

import json

import pytest

from janissary.harness.probe_evidence import ProbeEvidenceRecorder


def make_recorder(tmp_path):
    return ProbeEvidenceRecorder(
        case_id="case1",
        raw_path=tmp_path / "probe_evidence.jsonl",
        failure_path=tmp_path / "probe_evidence_failures.jsonl",
    )


def read_events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_records_probe_attempt_with_expected_schema(tmp_path):
    recorder = make_recorder(tmp_path)

    event_id = recorder.record_probe_attempt(
        param="username",
        payload_name="sql_single_quote",
        payload_value="'",
        request_outcome="response",
        response_status=500,
        snapshot_captured=True,
        used_for_snapshot=True,
    )

    event = read_events(tmp_path / "probe_evidence.jsonl")[0]
    assert event["event_id"] == event_id
    assert event["schema_version"] == 1
    assert event["event_type"] == "probe_attempt"
    assert event["case_id"] == "case1"
    assert event["param"] == "username"
    assert event["payload_name"] == "sql_single_quote"
    assert event["request_attempted"] is True
    assert event["request_outcome"] == "response"
    assert event["response_received"] is True
    assert event["response_status"] == 500
    assert event["snapshot_captured"] is True
    assert event["used_for_snapshot"] is True
    assert "payload_value" not in event
    assert len(event["payload_sha256"]) == 64
    assert recorder.diagnostics.records_attempted == 1
    assert recorder.diagnostics.records_written == 1
    assert recorder.diagnostics.failures_total == 0


def test_probe_identity_is_stable_for_same_logical_probe(tmp_path):
    first = make_recorder(tmp_path / "first")
    second = make_recorder(tmp_path / "second")

    first.record_probe_attempt(
        param="username",
        payload_name="sql_single_quote",
        payload_value="'",
        request_outcome="response",
        response_status=500,
    )
    second.record_probe_attempt(
        param="username",
        payload_name="sql_single_quote",
        payload_value="'",
        request_outcome="response",
        response_status=500,
    )

    first_event = read_events(tmp_path / "first/probe_evidence.jsonl")[0]
    second_event = read_events(tmp_path / "second/probe_evidence.jsonl")[0]
    assert first_event["probe_id"] == second_event["probe_id"]
    assert first_event["attempt_id"] != second_event["attempt_id"]


def test_distinct_payloads_have_distinct_probe_ids(tmp_path):
    recorder = make_recorder(tmp_path)

    recorder.record_probe_attempt(
        param="username",
        payload_name="sql_single_quote",
        payload_value="'",
        request_outcome="response",
        response_status=500,
    )
    recorder.record_probe_attempt(
        param="username",
        payload_name="sql_single_quote",
        payload_value='"',
        request_outcome="response",
        response_status=500,
    )

    events = read_events(tmp_path / "probe_evidence.jsonl")
    assert events[0]["probe_id"] != events[1]["probe_id"]


@pytest.mark.parametrize(
    ("outcome", "attempted", "response_received"),
    [
        ("response", True, True),
        ("exception", True, False),
        ("none_response", True, False),
        ("not_attempted", False, False),
    ],
)
def test_records_request_outcomes(
    tmp_path,
    outcome,
    attempted,
    response_received,
):
    recorder = make_recorder(tmp_path)

    recorder.record_probe_attempt(
        param="p",
        payload_name="probe",
        payload_value="value",
        request_outcome=outcome,
        request_attempted=attempted,
        response_status=200 if outcome == "response" else None,
        failure_reason="simulated" if outcome == "exception" else None,
    )

    event = read_events(tmp_path / "probe_evidence.jsonl")[0]
    assert event["request_outcome"] == outcome
    assert event["request_attempted"] is attempted
    assert event["response_received"] is response_received
    assert event["response_status"] == (200 if response_received else None)


def test_records_auth_retry_relationship(tmp_path):
    recorder = make_recorder(tmp_path)

    original_event_id = recorder.record_probe_attempt(
        param="p",
        payload_name="sql_single_quote",
        payload_value="'",
        request_outcome="response",
        response_status=401,
    )
    retry_event_id = recorder.record_probe_attempt(
        param="p",
        payload_name="sql_single_quote",
        payload_value="'",
        request_outcome="response",
        response_status=200,
        parent_event_id=original_event_id,
        attempt_role="auth_retry",
        snapshot_captured=True,
        used_for_snapshot=True,
    )

    original, retry = read_events(tmp_path / "probe_evidence.jsonl")
    assert original["event_id"] == original_event_id
    assert retry["event_id"] == retry_event_id
    assert retry["parent_event_id"] == original_event_id
    assert retry["attempt_role"] == "auth_retry"
    assert original["probe_id"] == retry["probe_id"]
    assert original["attempt_id"] != retry["attempt_id"]


def test_records_oracle_evaluation_and_prerequisites(tmp_path):
    recorder = make_recorder(tmp_path)
    prerequisites = {
        "sql_single_quote": "evt_quote",
        "sql_or_1eq1": "evt_or",
    }

    event_id = recorder.record_oracle_evaluation(
        oracle_id="xpath_error_oracle",
        param="username",
        prerequisite_event_ids=prerequisites,
        oracle_evaluated=True,
        oracle_result="no_finding",
    )

    event = read_events(tmp_path / "probe_evidence.jsonl")[0]
    assert event["event_id"] == event_id
    assert event["event_type"] == "oracle_evaluation"
    assert event["oracle_id"] == "xpath_error_oracle"
    assert event["oracle_evaluated"] is True
    assert event["oracle_result"] == "no_finding"
    assert event["prerequisite_event_ids"] == prerequisites


def test_indeterminate_oracle_requires_reason(tmp_path):
    recorder = make_recorder(tmp_path)

    event_id = recorder.record_oracle_evaluation(
        oracle_id="xpath_error_oracle",
        param="username",
        prerequisite_event_ids={
            "sql_single_quote": None,
            "sql_or_1eq1": "evt_or",
        },
        oracle_evaluated=False,
        oracle_result="indeterminate",
        indeterminate_reason="quote probe did not return a response",
    )

    event = read_events(tmp_path / "probe_evidence.jsonl")[0]
    assert event["event_id"] == event_id
    assert event["oracle_result"] == "indeterminate"
    assert event["oracle_evaluated"] is False
    assert event["indeterminate_reason"]


def test_rejects_inconsistent_request_outcome(tmp_path):
    recorder = make_recorder(tmp_path)

    with pytest.raises(ValueError):
        recorder.record_probe_attempt(
            param="p",
            payload_name="probe",
            payload_value="value",
            request_outcome="not_attempted",
            request_attempted=True,
        )


@pytest.mark.parametrize(
    ("outcome", "attempted"),
    [
        ("exception", True),
        ("none_response", True),
        ("not_attempted", False),
    ],
)
def test_rejects_snapshot_without_response(tmp_path, outcome, attempted):
    recorder = make_recorder(tmp_path)

    with pytest.raises(ValueError, match="snapshot cannot be captured"):
        recorder.record_probe_attempt(
            param="p",
            payload_name="probe",
            payload_value="value",
            request_outcome=outcome,
            request_attempted=attempted,
            snapshot_captured=True,
        )


def test_rejects_snapshot_use_without_capture(tmp_path):
    recorder = make_recorder(tmp_path)

    with pytest.raises(ValueError, match="snapshot cannot be used"):
        recorder.record_probe_attempt(
            param="p",
            payload_name="probe",
            payload_value="value",
            request_outcome="response",
            response_status=200,
            snapshot_captured=False,
            used_for_snapshot=True,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_attempted", 1),
        ("snapshot_captured", 1),
        ("used_for_snapshot", 1),
    ],
)
def test_rejects_non_boolean_attempt_flags(tmp_path, field, value):
    recorder = make_recorder(tmp_path)
    kwargs = {
        "param": "p",
        "payload_name": "probe",
        "payload_value": "value",
        "request_outcome": "response",
        "response_status": 200,
        field: value,
    }

    with pytest.raises(TypeError, match=f"{field} must be a boolean"):
        recorder.record_probe_attempt(**kwargs)


def test_rejects_inconsistent_oracle_result(tmp_path):
    recorder = make_recorder(tmp_path)

    with pytest.raises(ValueError):
        recorder.record_oracle_evaluation(
            oracle_id="xpath_error_oracle",
            param="p",
            prerequisite_event_ids={},
            oracle_evaluated=False,
            oracle_result="no_finding",
        )


def test_append_failure_is_counted_and_does_not_raise(tmp_path, monkeypatch):
    recorder = make_recorder(tmp_path)
    raw_path = tmp_path / "probe_evidence.jsonl"

    def fail_open(*args, **kwargs):
        raise OSError("simulated raw write failure")

    original_open = type(raw_path).open

    def fail_raw_open(path, *args, **kwargs):
        if path == raw_path:
            raise OSError("simulated raw write failure")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(type(raw_path), "open", fail_raw_open)

    event_id = recorder.record_probe_attempt(
        param="p",
        payload_name="probe",
        payload_value="value",
        request_outcome="response",
        response_status=200,
    )

    diagnostics = recorder.diagnostics
    assert event_id is None
    assert diagnostics.records_attempted == 1
    assert diagnostics.records_written == 0
    assert diagnostics.failures_total == 1
    assert diagnostics.records_attempted == (
        diagnostics.records_written + diagnostics.failures_total
    )
    assert diagnostics.failure_log_written is True
    failure = read_events(tmp_path / "probe_evidence_failures.jsonl")[0]
    assert failure["event_id"].startswith("evt_")
    assert failure["failure_type"] == "OSError"


def test_failure_log_failure_is_also_contained(tmp_path, monkeypatch):
    recorder = make_recorder(tmp_path)

    def fail_open(*args, **kwargs):
        raise OSError("simulated write failure")

    monkeypatch.setattr(type(recorder.raw_path), "open", fail_open)
    monkeypatch.setattr(type(recorder.failure_path), "open", fail_open)

    recorder.record_probe_attempt(
        param="p",
        payload_name="probe",
        payload_value="value",
        request_outcome="response",
        response_status=200,
    )

    diagnostics = recorder.diagnostics
    assert diagnostics.records_attempted == 1
    assert diagnostics.records_written == 0
    assert diagnostics.failures_total == 1
    assert diagnostics.failure_log_written is False
    assert diagnostics.failure_log_broken is True


def test_oracle_recording_does_not_mutate_prerequisite_mapping(tmp_path):
    recorder = make_recorder(tmp_path)
    prerequisites = {"quote": "evt_quote", "or": None}
    original = dict(prerequisites)

    recorder.record_oracle_evaluation(
        oracle_id="xpath_error_oracle",
        param="p",
        prerequisite_event_ids=prerequisites,
        oracle_evaluated=False,
        oracle_result="indeterminate",
        indeterminate_reason="missing prerequisite",
    )

    assert prerequisites == original


def test_rejects_unsanitized_case_id(tmp_path):
    with pytest.raises(ValueError):
        ProbeEvidenceRecorder(
            case_id="case.invalid",
            raw_path=tmp_path / "raw.jsonl",
            failure_path=tmp_path / "failures.jsonl",
        )
