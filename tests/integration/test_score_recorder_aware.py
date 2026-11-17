"""Fixture-based tests for score_recorder_aware."""

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from benchmark.track_a.score_recorder_aware import diagnose  # noqa: E402


def _j(path, rows):
    path.write_text(
        "\n".join(json.dumps(r) for r in rows) + ("\n" if rows else ""),
        encoding="utf-8",
    )


def _jd(path, doc):
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def _mk(
    base,
    *,
    cases,
    records,
    findings,
    indeterminate=None,
    summary_over=None,
    dirs=None,
    skip_raw=None,
):
    csv_path = base / "cases.csv"
    lines = ["testname,category,urlpath,mode,header_name,vulnerable"]
    for c in cases:
        lines.append(
            f"{c['testname']},{c['category']},{c['urlpath']},param,,{c['vulnerable']}"
        )
    csv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    run = base / "run"
    run.mkdir()
    _jd(run / "manifest.json", {"cases_csv": str(csv_path)})
    _jd(run / "case_selection.json", {c["testname"]: {} for c in cases})
    _j(run / "case_records.jsonl", records)
    _j(run / "findings.jsonl", findings)
    _j(run / "case_recording_indeterminate.jsonl", indeterminate or [])
    _j(run / "case_zero_observations.jsonl", [])
    _j(run / "case_recording_failed.jsonl", [])
    _j(run / "case_missing.jsonl", [])
    dirs = dirs if dirs is not None else [c["testname"] for c in cases]
    skip = set(skip_raw or [])
    for cid in dirs:
        cd = run / "case_raw" / cid
        cd.mkdir(parents=True)
        if cid not in skip:
            _j(cd / "case_records_raw.jsonl", [{"case_id": cid}])
    s = {
        "recording_enabled": True,
        "cases_total": len(cases),
        "primary_dispositions": {"recording_indeterminate": len(indeterminate or [])},
        "primary_dispositions_sum": len(cases),
        "accounting_valid": True,
    }
    if summary_over:
        s.update(summary_over)
    _jd(run / "recording_summary.json", s)
    return run, csv_path


def _case_id(name, category="xss-01", vuln="false"):
    return {
        "testname": name,
        "category": category,
        "urlpath": f"/{category}/{name}",
        "vulnerable": vuln,
    }


def _obs(cid, cls="no_observable_divergence", fired=False):
    return {
        "case_id": cid,
        "observation_id": f"{cid}_obs0001",
        "classification": cls,
        "oracle_fired": fired,
        "url": f"http://x/benchmark/xss-01/{cid}",
    }


def _finding(name, cls="xss", category="xss-01"):
    return {"class": cls, "url": f"http://x/benchmark/{category}/{name}"}


def _bands(rep):
    return [o["diagnostic_band"] for c in rep["per_case"] for o in c["observations"]]


def test_agree_clean(tmp_path):
    c = [_case_id("A")]
    rep = diagnose(*_mk(tmp_path, cases=c, records=[_obs("A")], findings=[]))
    assert _bands(rep) == ["agree_clean"]


def test_agree_detected(tmp_path):
    c = [_case_id("A")]
    rep = diagnose(
        *_mk(
            tmp_path,
            cases=c,
            records=[_obs("A", "delivered", True)],
            findings=[_finding("A")],
        )
    )
    assert _bands(rep) == ["agree_detected"]


def test_recorder_signal_no_finding(tmp_path):
    c = [_case_id("A")]
    rep = diagnose(
        *_mk(tmp_path, cases=c, records=[_obs("A", "delivered", True)], findings=[])
    )
    assert _bands(rep) == ["recorder_signal_no_finding"]


def test_scorer_finding_no_recorder(tmp_path):
    c = [_case_id("A")]
    rep = diagnose(
        *_mk(tmp_path, cases=c, records=[_obs("A")], findings=[_finding("A")])
    )
    assert _bands(rep) == ["scorer_finding_no_recorder"]


def test_recorder_inconclusive(tmp_path):
    c = [_case_id("A")]
    rep = diagnose(
        *_mk(tmp_path, cases=c, records=[_obs("A", "inconclusive")], findings=[])
    )
    assert _bands(rep) == ["recorder_inconclusive"]


def test_recorder_inconclusive_with_raw_finding(tmp_path):
    c = [_case_id("A")]
    rep = diagnose(
        *_mk(
            tmp_path,
            cases=c,
            records=[_obs("A", "inconclusive")],
            findings=[_finding("A")],
        )
    )
    assert _bands(rep) == ["recorder_inconclusive"]
    assert rep["per_case"][0]["effective_scored"] is True


def test_orphan_finding(tmp_path):
    c = [_case_id("A")]
    rep = diagnose(
        *_mk(
            tmp_path,
            cases=c,
            records=[_obs("A")],
            findings=[_finding("NOPE", "xss", "xss-99")],
        )
    )
    assert len(rep["orphan_findings"]) == 1
    assert _bands(rep) == ["agree_clean"]


def test_out_of_scope_finding(tmp_path):
    c = [_case_id("A")]
    rep = diagnose(
        *_mk(
            tmp_path,
            cases=c,
            records=[_obs("A", "inconclusive")],
            findings=[_finding("A", "ssrf", "xss-01")],
        )
    )
    assert _bands(rep) == ["recorder_inconclusive"]
    case = rep["per_case"][0]
    assert case["raw_findings"][0]["reason"] == "out_of_scope"
    assert case["effective_scored"] is False


def test_multiple_observations(tmp_path):
    c = [_case_id("A")]
    obs = [
        _obs("A", "inconclusive"),
        {
            "case_id": "A",
            "observation_id": "A_obs0002",
            "classification": "no_observable_divergence",
            "oracle_fired": False,
            "url": "http://x/benchmark/xss-01/A",
        },
    ]
    rep = diagnose(*_mk(tmp_path, cases=c, records=obs, findings=[]))
    assert len(rep["per_case"][0]["observations"]) == 2


def test_unrecognised_classification(tmp_path):
    c = [_case_id("A")]
    rep = diagnose(*_mk(tmp_path, cases=c, records=[_obs("A", "weird")], findings=[]))
    assert _bands(rep) == ["unrecognised_classification"]


def test_recording_anomaly_and_indeterminate(tmp_path):
    c = [_case_id("A"), _case_id("B"), _case_id("C")]
    ind = [{"case_id": "B", "reason": "status_file_missing"}]
    recs = [_obs("A")]
    rep = diagnose(
        *_mk(
            tmp_path,
            cases=c,
            records=recs,
            findings=[],
            indeterminate=ind,
            skip_raw=["B", "C"],
        )
    )
    bands = _bands(rep)
    assert "agree_clean" in bands
    assert "recorder_indeterminate" in bands
    assert "recording_anomaly" in bands
    assert any(a["kind"] == "no_records_not_indeterminate" for a in rep["anomalies"])


def test_accounting_mismatch(tmp_path):
    c = [_case_id("A")]
    rep = diagnose(
        *_mk(
            tmp_path,
            cases=c,
            records=[_obs("A")],
            findings=[],
            summary_over={"primary_dispositions_sum": 999},
        )
    )
    assert any(a["kind"] == "accounting_mismatch" for a in rep["anomalies"])


@pytest.mark.skipif(
    not (REPO / "benchmark/track_a/runs/20261115T083529Z-janissary-r1").exists(),
    reason="B2 r1 not present",
)
def test_b2_r1_smoke():
    rep = diagnose(REPO / "benchmark/track_a/runs/20261115T083529Z-janissary-r1")
    assert rep["total_cases"] == 30
    ind_count = len(
        [
            ln
            for ln in (
                REPO
                / "benchmark/track_a/runs/20261115T083529Z-janissary-r1"
                / "case_recording_indeterminate.jsonl"
            )
            .read_text(encoding="utf-8")
            .splitlines()
            if ln.strip()
        ]
    )
    assert rep["band_counts"].get("recorder_indeterminate", 0) == ind_count
