"""Tests for two-run SARIF emission (M40, ADR-019 D1).

ADR-019 D1: single SARIF file, two runs. runs[0] = verified
(properties.track="verified"), runs[1] = discovery
(properties.track="discovery"). Both always emitted, even if empty.

ADR-019 D2: each result has partialFingerprints.finding/v1 AND
partialFingerprints.verification_status/v1.

ADR-019 D3: discovery results carry properties.signals (list of
heuristic signature IDs). Verified-track heuristic findings do NOT
carry signals (they would only reach the verified track if promoted
by the engine — signals field is not preserved through promotion).
"""

from __future__ import annotations

import json
from pathlib import Path

from janissary.cli import _parse_signals, _write_sarif
from janissary.engine.scanner import ScanFinding, ScanSummary


def _finding(
    *,
    verification_status: str = "verified",
    verification_reason: str | None = None,
    category: str = "sqli",
    finding_type: str = "db_error",
    severity: str = "high",
    payload_name: str = "sql_q",
    param: str = "q",
) -> ScanFinding:
    f = ScanFinding(
        param=param,
        payload_name=payload_name,
        payload_value="v",
        category=category,
        severity=severity,
        finding_type=finding_type,
        detail="test detail",
        url="http://x/",
        verification_status=verification_status,
        verification_reason=verification_reason,
    )
    f._engine_emitted = True
    return f


def _summary(*findings: ScanFinding) -> ScanSummary:
    s = ScanSummary(target="http://x/", params=["q"], method="GET")
    for f in findings:
        if f.verification_status == "unproven":
            s.candidates.append(f)
        else:
            s.findings.append(f)
    s.finding_count = len(s.findings)
    return s


def _read(tmp_path: Path, summary) -> dict:
    path = tmp_path / "out.sarif"
    _write_sarif(summary, str(path))
    return json.loads(path.read_text(encoding="utf-8"))


# --- _parse_signals unit coverage -------------------------------------


def test_parse_signals_heuristic_single():
    assert _parse_signals("heuristic:HEUR-001") == ["HEUR-001"]


def test_parse_signals_heuristic_multiple():
    assert _parse_signals("heuristic:HEUR-001+HEUR-002") == ["HEUR-001", "HEUR-002"]


def test_parse_signals_non_heuristic():
    assert _parse_signals("corroborator_structural") == []


def test_parse_signals_none():
    assert _parse_signals(None) == []


# --- two-run structure ------------------------------------------------


def test_verified_only_summary_emits_two_runs(tmp_path):
    doc = _read(tmp_path, _summary(_finding(verification_status="verified")))
    assert len(doc["runs"]) == 2


def test_discovery_only_summary_emits_two_runs(tmp_path):
    doc = _read(
        tmp_path,
        _summary(
            _finding(
                verification_status="unproven",
                verification_reason="heuristic:HEUR-001",
                category="sqli:error_leak",
                finding_type="heuristic_sqli_error_leak",
                severity="low",
            )
        ),
    )
    assert len(doc["runs"]) == 2


def test_empty_summary_emits_two_empty_runs(tmp_path):
    doc = _read(tmp_path, _summary())
    assert len(doc["runs"]) == 2
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][1]["results"] == []


def test_run_track_labels(tmp_path):
    doc = _read(tmp_path, _summary())
    assert doc["runs"][0]["properties"]["track"] == "verified"
    assert doc["runs"][1]["properties"]["track"] == "discovery"


def test_mixed_summary_partitioned_by_status(tmp_path):
    """M75c safeguard: candidates remain distinguishable from verified
    findings in the emitted SARIF. The verified run contains only
    verified results; the discovery run contains only unproven
    results. No candidate is represented as verified."""
    doc = _read(
        tmp_path,
        _summary(
            _finding(verification_status="verified", finding_type="db_error"),
            _finding(
                verification_status="unproven",
                verification_reason="heuristic:HEUR-001",
                category="sqli:error_leak",
                finding_type="heuristic_sqli_error_leak",
                severity="low",
            ),
        ),
    )
    assert len(doc["runs"][0]["results"]) == 1
    assert len(doc["runs"][1]["results"]) == 1
    assert doc["runs"][0]["results"][0]["ruleId"] == "sqli:db_error"
    assert (
        doc["runs"][1]["results"][0]["ruleId"]
        == "sqli:error_leak:heuristic_sqli_error_leak"
    )
    # Explicit distinction check: verified run has no unproven results
    for r in doc["runs"][0]["results"]:
        assert r["properties"]["verification_status"] == "verified"
        assert r["partialFingerprints"]["verification_status/v1"] == "verified"
    # Discovery run has no verified results
    for r in doc["runs"][1]["results"]:
        assert r["properties"]["verification_status"] == "unproven"
        assert r["partialFingerprints"]["verification_status/v1"] == "unproven"


# --- partialFingerprints (ADR-019 D2) ---------------------------------


def test_verified_track_has_verification_status_fingerprint(tmp_path):
    doc = _read(tmp_path, _summary(_finding(verification_status="verified")))
    fps = doc["runs"][0]["results"][0]["partialFingerprints"]
    assert "finding/v1" in fps
    assert fps["verification_status/v1"] == "verified"


def test_discovery_track_has_unproven_fingerprint(tmp_path):
    doc = _read(
        tmp_path,
        _summary(
            _finding(
                verification_status="unproven",
                verification_reason="heuristic:HEUR-001",
                category="sqli:error_leak",
                finding_type="heuristic_sqli_error_leak",
                severity="low",
            )
        ),
    )
    fps = doc["runs"][1]["results"][0]["partialFingerprints"]
    assert "finding/v1" in fps
    assert fps["verification_status/v1"] == "unproven"


# --- properties.signals (ADR-019 D3) ----------------------------------


def test_signals_present_on_heuristic_finding(tmp_path):
    doc = _read(
        tmp_path,
        _summary(
            _finding(
                verification_status="unproven",
                verification_reason="heuristic:HEUR-001",
                category="sqli:error_leak",
                finding_type="heuristic_sqli_error_leak",
                severity="low",
            )
        ),
    )
    props = doc["runs"][1]["results"][0]["properties"]
    assert props["signals"] == ["HEUR-001"]


def test_signals_multi_parsed(tmp_path):
    doc = _read(
        tmp_path,
        _summary(
            _finding(
                verification_status="unproven",
                verification_reason="heuristic:HEUR-001+HEUR-002",
                category="sqli:error_leak",
                finding_type="heuristic_sqli_error_leak",
                severity="low",
            )
        ),
    )
    props = doc["runs"][1]["results"][0]["properties"]
    assert props["signals"] == ["HEUR-001", "HEUR-002"]


def test_signals_absent_on_non_heuristic_unproven(tmp_path):
    # A Track A finding with unproven status (e.g. corroborator) routes
    # to discovery but has no heuristic signals.
    doc = _read(
        tmp_path,
        _summary(
            _finding(
                verification_status="unproven",
                verification_reason="corroborator_structural",
                finding_type="status_change",
            )
        ),
    )
    props = doc["runs"][1]["results"][0]["properties"]
    assert "signals" not in props


# --- per-run findingCount ---------------------------------------------


def test_finding_count_is_per_run_not_total(tmp_path):
    # This test verifies SARIF `findingCount` semantics (per-run vs. total),
    # not dedup behavior. Phase 1 dedup would collapse the two verified
    # db_error findings because they share a fingerprint (differ only by
    # payload_name, which is not an ADR-007 fingerprint input). Force
    # distinct fingerprints so the test's scenario — two surviving
    # findings in run 0 — is preserved.
    f1 = _finding(verification_status="verified", finding_type="db_error")
    f2 = _finding(
        verification_status="verified",
        finding_type="db_error",
        payload_name="p2",
    )
    f2.fingerprint = f1.fingerprint + "-run0-second"
    doc = _read(
        tmp_path,
        _summary(
            f1,
            f2,
            _finding(
                verification_status="unproven",
                verification_reason="heuristic:HEUR-001",
                category="sqli:error_leak",
                finding_type="heuristic_sqli_error_leak",
                severity="low",
            ),
        ),
    )
    assert doc["runs"][0]["invocations"][0]["properties"]["findingCount"] == 2
    assert doc["runs"][1]["invocations"][0]["properties"]["findingCount"] == 1
