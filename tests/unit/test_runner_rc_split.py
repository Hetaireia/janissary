"""Tests for the rc=2 safe-case abort split in run_janissary."""

from __future__ import annotations

from benchmark.track_a import runner


def _cases(vulnerable: str):
    return [
        {
            "testname": "BenchmarkTest00001",
            "mode": "param",
            "vulnerable": vulnerable,
            "category": "sqli-00",
        }
    ]


def _stub_helpers(monkeypatch, rc: int):
    monkeypatch.setattr(
        runner, "_probe_record_case_dir_support", lambda *a, **k: (False, "")
    )
    monkeypatch.setattr(runner, "_dispatch", lambda c: ("query", "q", "GET"))
    monkeypatch.setattr(runner, "case_url", lambda base, c: "http://x/")
    monkeypatch.setattr(runner, "_enrich_and_write", lambda *a, **k: None)
    monkeypatch.setattr(
        runner, "_run_subprocess_tree", lambda cmd, timeout: (rc, "", "", False)
    )


def test_rc2_on_safe_case_does_not_force_exit_1(tmp_path, monkeypatch):
    _stub_helpers(monkeypatch, rc=2)
    rc = runner.run_janissary(tmp_path, _cases("false"), "http://x", {})
    assert rc == 0


def test_rc2_on_vulnerable_case_forces_exit_1(tmp_path, monkeypatch):
    _stub_helpers(monkeypatch, rc=2)
    rc = runner.run_janissary(tmp_path, _cases("true"), "http://x", {})
    assert rc == 1


def test_rc0_does_not_force_exit_1(tmp_path, monkeypatch):
    _stub_helpers(monkeypatch, rc=0)
    assert runner.run_janissary(tmp_path, _cases("false"), "http://x", {}) == 0
    assert runner.run_janissary(tmp_path, _cases("true"), "http://x", {}) == 0


def test_rc1_does_not_force_exit_1(tmp_path, monkeypatch):
    _stub_helpers(monkeypatch, rc=1)
    assert runner.run_janissary(tmp_path, _cases("false"), "http://x", {}) == 0
    assert runner.run_janissary(tmp_path, _cases("true"), "http://x", {}) == 0


def test_rc3_forces_exit_1(tmp_path, monkeypatch):
    _stub_helpers(monkeypatch, rc=3)
    assert runner.run_janissary(tmp_path, _cases("false"), "http://x", {}) == 1
    assert runner.run_janissary(tmp_path, _cases("true"), "http://x", {}) == 1


def test_rc2_with_missing_vulnerable_field_defaults_to_safe(tmp_path, monkeypatch):
    _stub_helpers(monkeypatch, rc=2)
    cases = [{"testname": "BenchmarkTest00001", "mode": "param"}]
    rc = runner.run_janissary(tmp_path, cases, "http://x", {})
    assert rc == 0
