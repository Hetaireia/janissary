"""M83 Stage 4: runner integration tests.

Tests run_janissary's per-case recording orchestration with the subprocess
layer mocked. Verifies capability probe handling, case-directory creation,
per-case status classification, enrichment, and coverage accounting.
"""

import json
from pathlib import Path

import pytest

from benchmark.track_a import runner


def _cases(n=2, prefix="T"):
    return [
        {
            "testname": f"{prefix}{i}",
            "mode": "query",
            "param": "p",
            "method": "GET",
            "path": f"/x/{i}",
            "vulnerable": "true",
        }
        for i in range(n)
    ]


def _env():
    return {"JANISSARY_BIN": "/fake/janissary", "JANISSARY_TIMEOUT": "5"}


@pytest.fixture
def mocked(monkeypatch, tmp_path):
    captured = {"scan_cmds": [], "case_statuses": {}}

    def fake_probe(cmd_prefix, timeout=10.0):
        return True, "--record-case-dir" + "\n" * 200

    def fake_run(cmd, timeout):
        if "--record-case-dir" in cmd:
            idx = cmd.index("--record-case-dir")
            cdir = Path(cmd[idx + 1])
            captured["scan_cmds"].append(cmd)
            cdir.mkdir(parents=True, exist_ok=True)
            status = captured["case_statuses"].get(cdir.name)
            if status is not None:
                (cdir / "recording_status.json").write_text(
                    json.dumps(status), encoding="utf-8"
                )
                if status.get("records_written", 0) > 0:
                    (cdir / "case_records_raw.jsonl").write_text(
                        json.dumps(
                            {
                                "observation_id": cdir.name + "_obs0001",
                                "case_id": cdir.name,
                                "url": "http://x/",
                                "classification": "existence_divergence",
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )
            return (0, "", "", False)
        # Non-recording scan (probe/help already mocked; shouldn't reach here
        # for scan if recording_enabled; only when disabled)
        captured["scan_cmds"].append(cmd)
        return (0, "", "", False)

    monkeypatch.setattr(runner, "_probe_record_case_dir_support", fake_probe)
    monkeypatch.setattr(runner, "_run_subprocess_tree", fake_run)
    monkeypatch.setattr(runner, "_dispatch", lambda c: ("query", "p", "GET"))
    monkeypatch.setattr(runner, "case_url", lambda base, c: f"{base}/{c['testname']}")
    return captured


def _valid_status(written=0, failures=0):
    return {
        "recording_enabled": True,
        "recorder_constructed": True,
        "records_attempted": written + failures,
        "records_written": written,
        "failures_total": failures,
        "failure_log_written": bool(failures),
        "scanner_version": "test",
        "completed_at": "2026-11-14T00:00:00+00:00",
    }


def test_capability_supported_records_run_level_enabled(tmp_path, mocked):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    runner.run_janissary(run_dir, _cases(2), "http://x", _env())
    status = json.loads((run_dir / "recording_status.json").read_text())
    assert status["recording_enabled"] is True


def test_capability_unsupported_records_reason(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    def fake_probe(cmd_prefix, timeout=10.0):
        return False, "output without the flag"

    monkeypatch.setattr(runner, "_probe_record_case_dir_support", fake_probe)
    monkeypatch.setattr(
        runner, "_run_subprocess_tree", lambda cmd, t: (0, "", "", False)
    )
    monkeypatch.setattr(runner, "_dispatch", lambda c: ("query", "p", "GET"))
    monkeypatch.setattr(runner, "case_url", lambda base, c: f"{base}/{c['testname']}")

    runner.run_janissary(run_dir, _cases(2), "http://x", _env())
    status = json.loads((run_dir / "recording_status.json").read_text())
    assert status["recording_enabled"] is False
    assert "reason" in status


def test_no_record_case_dir_in_cmd_when_unsupported(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    captured = []

    def fake_run(cmd, timeout):
        captured.append(cmd)
        return (0, "", "", False)

    monkeypatch.setattr(
        runner,
        "_probe_record_case_dir_support",
        lambda cp, timeout=10.0: (False, "no flag"),
    )
    monkeypatch.setattr(runner, "_run_subprocess_tree", fake_run)
    monkeypatch.setattr(runner, "_dispatch", lambda c: ("query", "p", "GET"))
    monkeypatch.setattr(runner, "case_url", lambda base, c: f"{base}/{c['testname']}")

    runner.run_janissary(run_dir, _cases(2), "http://x", _env())
    for cmd in captured:
        assert "--record-case-dir" not in cmd


def test_record_case_dir_in_cmd_when_supported(tmp_path, mocked):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    mocked["case_statuses"]["T0"] = _valid_status(written=1)
    mocked["case_statuses"]["T1"] = _valid_status(written=0)
    runner.run_janissary(run_dir, _cases(2), "http://x", _env())
    assert len(mocked["scan_cmds"]) == 2
    for cmd in mocked["scan_cmds"]:
        assert "--record-case-dir" in cmd


def test_collision_returns_2_before_any_scan(tmp_path, mocked):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cases = [
        {
            "testname": "T.a",
            "mode": "query",
            "param": "p",
            "method": "GET",
            "path": "/x",
            "vulnerable": "true",
        },
        {
            "testname": "T_a",
            "mode": "query",
            "param": "p",
            "method": "GET",
            "path": "/x",
            "vulnerable": "true",
        },
    ]
    rc = runner.run_janissary(run_dir, cases, "http://x", _env())
    assert rc == 2
    assert len(mocked["scan_cmds"]) == 0


def test_case_selection_written(tmp_path, mocked):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    mocked["case_statuses"]["T0"] = _valid_status(written=1)
    mocked["case_statuses"]["T1"] = _valid_status(written=1)
    runner.run_janissary(run_dir, _cases(2), "http://x", _env())
    selection = json.loads((run_dir / "case_selection.json").read_text())
    assert "T0" in selection and "T1" in selection
    assert selection["T0"]["testname"] == "T0"


def test_attempts_bookkeeping(tmp_path, mocked):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    mocked["case_statuses"]["T0"] = _valid_status(written=1)
    runner.run_janissary(run_dir, _cases(1), "http://x", _env())
    lines = (run_dir / "case_attempts.jsonl").read_text().strip().split("\n")
    events = [json.loads(line) for line in lines if line.strip()]
    assert any(e["event"] == "attempt_started" for e in events)
    assert any(e["event"] == "attempt_finished" for e in events)


def test_classification_has_observations(tmp_path, mocked):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    mocked["case_statuses"]["T0"] = _valid_status(written=1)
    runner.run_janissary(run_dir, _cases(1), "http://x", _env())
    summary = json.loads((run_dir / "recording_summary.json").read_text())
    assert summary["primary_dispositions"]["has_observations"] == 1
    records = (run_dir / "case_records.jsonl").read_text().strip().split("\n")
    assert len([r for r in records if r.strip()]) == 1


def test_classification_zero_observations(tmp_path, mocked):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    mocked["case_statuses"]["T0"] = _valid_status(written=0, failures=0)
    runner.run_janissary(run_dir, _cases(1), "http://x", _env())
    summary = json.loads((run_dir / "recording_summary.json").read_text())
    assert summary["primary_dispositions"]["zero_observations"] == 1
    zf = (run_dir / "case_zero_observations.jsonl").read_text().strip()
    assert zf


def test_classification_recording_failed(tmp_path, mocked):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    mocked["case_statuses"]["T0"] = _valid_status(written=0, failures=1)
    runner.run_janissary(run_dir, _cases(1), "http://x", _env())
    summary = json.loads((run_dir / "recording_summary.json").read_text())
    assert summary["primary_dispositions"]["recording_failed"] == 1


def test_classification_recording_indeterminate_when_status_missing(tmp_path, mocked):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    # No case_statuses entry → subprocess returns rc=0 but doesn't write status
    runner.run_janissary(run_dir, _cases(1), "http://x", _env())
    summary = json.loads((run_dir / "recording_summary.json").read_text())
    assert summary["primary_dispositions"]["recording_indeterminate"] == 1


def test_classification_recording_disabled(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    monkeypatch.setattr(
        runner,
        "_probe_record_case_dir_support",
        lambda cp, timeout=10.0: (False, "no flag"),
    )
    monkeypatch.setattr(
        runner, "_run_subprocess_tree", lambda cmd, t: (0, "", "", False)
    )
    monkeypatch.setattr(runner, "_dispatch", lambda c: ("query", "p", "GET"))
    monkeypatch.setattr(runner, "case_url", lambda base, c: f"{base}/{c['testname']}")
    runner.run_janissary(run_dir, _cases(2), "http://x", _env())
    summary = json.loads((run_dir / "recording_summary.json").read_text())
    assert summary["primary_dispositions"]["recording_disabled"] == 2


def test_recording_summary_invariants(tmp_path, mocked):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    mocked["case_statuses"]["T0"] = _valid_status(written=1)
    mocked["case_statuses"]["T1"] = _valid_status(written=0)
    runner.run_janissary(run_dir, _cases(2), "http://x", _env())
    summary = json.loads((run_dir / "recording_summary.json").read_text())
    assert summary["accounting_valid"] is True
    assert summary["primary_dispositions_sum"] == 2
    assert (
        summary["missing_breakdown_sum"] == summary["primary_dispositions"]["missing"]
    )


def test_unmatched_observation_preserved(tmp_path, mocked):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    mocked["case_statuses"]["T0"] = _valid_status(written=1)
    runner.run_janissary(run_dir, _cases(1), "http://x", _env())
    # Manually add an unmatched case dir (simulating a prior run's leftover)
    stray = run_dir / "case_raw" / "STRAY"
    stray.mkdir(parents=True)
    (stray / "case_records_raw.jsonl").write_text(
        json.dumps({"observation_id": "s1", "case_id": "STRAY"}) + "\n",
        encoding="utf-8",
    )
    runner._enrich_and_write(
        run_dir,
        _cases(1),
        {"T0": {"testname": "T0", "mode": "query", "url": "http://x/T0"}},
        True,
    )
    summary = json.loads((run_dir / "recording_summary.json").read_text())
    assert summary["unmatched_observations"] >= 1
    records = [
        json.loads(line)
        for line in (run_dir / "case_records.jsonl").read_text().splitlines()
        if line.strip()
    ]
    unenriched = [r for r in records if r.get("enriched") is False]
    assert len(unenriched) >= 1


def test_status_invalid_fields_indeterminate(tmp_path, mocked):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    invalid = _valid_status(written=1)
    invalid["records_written"] = 5  # > records_attempted
    mocked["case_statuses"]["T0"] = invalid
    runner.run_janissary(run_dir, _cases(1), "http://x", _env())
    summary = json.loads((run_dir / "recording_summary.json").read_text())
    assert summary["primary_dispositions"]["recording_indeterminate"] == 1


def test_mkdir_failure_aborts_before_scan(tmp_path, monkeypatch, capsys):
    """Fail-closed: per-case mkdir failure aborts the run before any scan."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    scan_calls: list = []

    def fake_probe(cmd_prefix, timeout=10.0):
        return True, "--record-case-dir" + "\n" * 200

    def fake_run(cmd, timeout):
        scan_calls.append(cmd)
        return (0, "", "", False)

    monkeypatch.setattr(runner, "_probe_record_case_dir_support", fake_probe)
    monkeypatch.setattr(runner, "_run_subprocess_tree", fake_run)
    monkeypatch.setattr(runner, "_dispatch", lambda c: ("query", "p", "GET"))
    monkeypatch.setattr(runner, "case_url", lambda base, c: f"{base}/{c['testname']}")

    original_mkdir = Path.mkdir

    def failing_mkdir(self, *args, **kwargs):
        # Only fail per-case directories under case_raw/; allow case_raw/ itself
        if self.parent.name == "case_raw":
            raise OSError("simulated mkdir failure")
        return original_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", failing_mkdir)

    rc = runner.run_janissary(run_dir, _cases(2), "http://x", _env())
    captured = capsys.readouterr()

    # 1. Runner returned failure code
    assert rc == 2
    # 2. No scan subprocess was launched
    assert scan_calls == []
    # 3. Directory-creation failure was reported on stderr
    assert "cannot create case directory" in captured.err
