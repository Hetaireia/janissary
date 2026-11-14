"""M83 Stage 1: recorder tests.

Covers criterion 1 (persisted observations), criterion 2 (record schema),
criterion 6a (failure isolation — no exceptions escape record()),
and criterion 11 (truncation metadata).

Full 6a (byte-identical scan with flag) is deferred to Stage 3 CLI
integration tests.
"""

import json

from janissary.detection import Baseline, ResponseSnapshot
from janissary.harness.pathtraver import (
    BODY_STORE_LIMIT,
    PathtraverRecorder,
)


class FakeResponse:
    def __init__(self, status=200, text="", content_type="text/html", elapsed=0.1):
        self.status_code = status
        self.text = text
        self.headers = {"content-type": content_type}
        self._elapsed = elapsed

    @property
    def elapsed(self):
        outer = self

        class Elapsed:
            def total_seconds(self):
                return outer._elapsed

        return Elapsed()


def snap(**kwargs):
    return ResponseSnapshot.from_response(FakeResponse(**kwargs))


def make_baseline(bodies):
    b = Baseline()
    for body in bodies:
        b.add(snap(text=body))
    return b


BENIGN = "Access to file: created."
EXISTS_BODY = "Access to file: passwd created. And file already exists."
NOEXIST_BODY = "Access to file: passwd_noexist created. But file doesn't exist yet."
PAYLOAD_EXISTS = "../../../etc/passwd"
PAYLOAD_NOEXIST = "../../../etc/passwd_janissary_noexist_abc123"


def _recorder(tmp_path):
    return PathtraverRecorder(
        case_id="testcase",
        raw_path=tmp_path / "raw.jsonl",
        failure_path=tmp_path / "fail.jsonl",
    )


def _call(recorder, *, baseline=None, snap_e=None, snap_n=None, oracle_result=None):
    if baseline is None:
        baseline = make_baseline([BENIGN])
    if snap_e is None:
        snap_e = snap(text=EXISTS_BODY)
    if snap_n is None:
        snap_n = snap(text=NOEXIST_BODY)
    if oracle_result is None:
        oracle_result = [{"detail": "divergence"}]
    return recorder.record(
        url="http://x/y",
        param="p",
        baseline=baseline,
        snapshot_exists=snap_e,
        snapshot_noexist=snap_n,
        payload_exists=PAYLOAD_EXISTS,
        payload_noexist=PAYLOAD_NOEXIST,
        oracle_result=oracle_result,
    )


def test_record_writes_one_line(tmp_path):
    recorder = _recorder(tmp_path)
    _call(recorder)
    lines = (tmp_path / "raw.jsonl").read_text().strip().split("\n")
    assert len(lines) == 1


def test_record_schema_top_level_fields(tmp_path):
    recorder = _recorder(tmp_path)
    _call(recorder)
    record = json.loads((tmp_path / "raw.jsonl").read_text().strip())
    assert record["observation_id"] == "testcase_obs0001"
    assert record["case_id"] == "testcase"
    assert record["url"] == "http://x/y"
    assert record["param"] == "p"
    assert "delivery" in record
    assert "probes" in record
    assert "comparison" in record
    assert "classification" in record
    assert "classification_reason" in record
    assert "oracle_fired" in record


def test_record_schema_probe_fields(tmp_path):
    recorder = _recorder(tmp_path)
    _call(recorder)
    record = json.loads((tmp_path / "raw.jsonl").read_text().strip())
    for probe in ("exists", "noexist"):
        p = record["probes"][probe]
        assert "status" in p
        assert "content_type" in p
        assert "evidence_hash" in p
        assert "structural_signature" in p
        assert "body_truncated" in p
        assert "body_original_length" in p
        assert "body_stored" in p


def test_multiple_observations_per_case(tmp_path):
    recorder = _recorder(tmp_path)
    _call(recorder)
    _call(recorder)
    lines = (tmp_path / "raw.jsonl").read_text().strip().split("\n")
    assert len(lines) == 2
    r1 = json.loads(lines[0])
    r2 = json.loads(lines[1])
    assert r1["case_id"] == r2["case_id"] == "testcase"
    assert r1["observation_id"] == "testcase_obs0001"
    assert r2["observation_id"] == "testcase_obs0002"
    assert r1["observation_id"] != r2["observation_id"]


def test_truncation_metadata_long_body(tmp_path):
    long_body = "x" * (BODY_STORE_LIMIT + 500)
    recorder = _recorder(tmp_path)
    _call(recorder, snap_e=snap(text=long_body))
    record = json.loads((tmp_path / "raw.jsonl").read_text().strip())
    p = record["probes"]["exists"]
    assert p["body_truncated"] is True
    assert p["body_original_length"] == BODY_STORE_LIMIT + 500
    assert len(p["body_stored"]) == BODY_STORE_LIMIT


def test_truncation_metadata_short_body(tmp_path):
    short_body = "short"
    recorder = _recorder(tmp_path)
    _call(recorder, snap_e=snap(text=short_body))
    record = json.loads((tmp_path / "raw.jsonl").read_text().strip())
    p = record["probes"]["exists"]
    assert p["body_truncated"] is False
    assert p["body_original_length"] == len(short_body)
    assert p["body_stored"] == short_body


def test_diagnostics_after_success(tmp_path):
    recorder = _recorder(tmp_path)
    _call(recorder)
    d = recorder.diagnostics
    assert d.records_attempted == 1
    assert d.records_written == 1
    assert d.failures_total == 0
    assert d.failure_log_broken is False


def test_recorder_does_not_raise_on_both_write_failures(tmp_path):
    recorder = PathtraverRecorder(
        case_id="c",
        raw_path=tmp_path / "nonexistent" / "raw.jsonl",
        failure_path=tmp_path / "nonexistent" / "fail.jsonl",
    )
    _call(recorder)
    d = recorder.diagnostics
    assert d.records_attempted == 1
    assert d.records_written == 0
    assert d.failures_total >= 1
    assert d.failure_log_broken is True


def test_failure_log_succeeds_when_raw_fails(tmp_path):
    recorder = PathtraverRecorder(
        case_id="c",
        raw_path=tmp_path / "nonexistent" / "raw.jsonl",
        failure_path=tmp_path / "fail.jsonl",
    )
    _call(recorder)
    d = recorder.diagnostics
    assert d.failures_total >= 1
    assert d.failure_log_broken is False
    assert (tmp_path / "fail.jsonl").exists()


def test_input_immutability(tmp_path):
    baseline = make_baseline([BENIGN])
    snap_e = snap(text=EXISTS_BODY)
    snap_n = snap(text=NOEXIST_BODY)
    oracle_result = [{"detail": "divergence"}]

    snap_e_body_before = snap_e.body
    snap_n_body_before = snap_n.body
    oracle_result_len_before = len(oracle_result)

    recorder = _recorder(tmp_path)
    _call(
        recorder,
        baseline=baseline,
        snap_e=snap_e,
        snap_n=snap_n,
        oracle_result=oracle_result,
    )

    assert snap_e.body == snap_e_body_before
    assert snap_n.body == snap_n_body_before
    assert len(oracle_result) == oracle_result_len_before


def test_record_build_failure_increments_failures(tmp_path, monkeypatch):
    recorder = _recorder(tmp_path)

    def boom(*args, **kwargs):
        raise RuntimeError("simulated _build_record failure")

    monkeypatch.setattr(PathtraverRecorder, "_build_record", boom)
    _call(recorder)
    d = recorder.diagnostics
    assert d.records_attempted == 1
    assert d.records_written == 0
    assert d.failures_total == 1
    assert d.failure_log_written is True


def test_record_build_failure_does_not_raise(tmp_path, monkeypatch):
    recorder = _recorder(tmp_path)

    def boom(*args, **kwargs):
        raise RuntimeError("simulated")

    monkeypatch.setattr(PathtraverRecorder, "_build_record", boom)
    _call(recorder)


def test_record_serialization_failure_increments_failures(tmp_path, monkeypatch):
    recorder = _recorder(tmp_path)

    def fake_build(*args, **kwargs):
        return {"not_serializable": object()}

    monkeypatch.setattr(PathtraverRecorder, "_build_record", fake_build)
    _call(recorder)
    d = recorder.diagnostics
    assert d.records_attempted == 1
    assert d.records_written == 0
    assert d.failures_total == 1


def test_record_build_failure_and_failure_log_both_fail(tmp_path, monkeypatch):
    recorder = PathtraverRecorder(
        case_id="c",
        raw_path=tmp_path / "nonexistent" / "raw.jsonl",
        failure_path=tmp_path / "nonexistent" / "fail.jsonl",
    )

    def boom(*args, **kwargs):
        raise RuntimeError("simulated")

    monkeypatch.setattr(PathtraverRecorder, "_build_record", boom)
    _call(recorder)
    d = recorder.diagnostics
    assert d.records_attempted == 1
    assert d.records_written == 0
    assert d.failures_total == 1
    assert d.failure_log_broken is True


def test_diagnostics_invariant_after_mixed_calls(tmp_path, monkeypatch):
    recorder = _recorder(tmp_path)
    _call(recorder)
    _call(recorder)
    _call(recorder)

    def boom(*args, **kwargs):
        raise RuntimeError("simulated")

    monkeypatch.setattr(PathtraverRecorder, "_build_record", boom)
    _call(recorder)
    _call(recorder)

    d = recorder.diagnostics
    assert d.records_attempted == 5
    assert d.records_written == 3
    assert d.failures_total == 2
    assert d.records_attempted == d.records_written + d.failures_total


def test_recorder_init_rejects_unsanitized_case_id(tmp_path):
    import pytest

    with pytest.raises(ValueError):
        PathtraverRecorder(
            case_id="path/to",
            raw_path=tmp_path / "raw.jsonl",
            failure_path=tmp_path / "fail.jsonl",
        )
