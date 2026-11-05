"""Tests for the Phase 0.1 runtime invariant on ScanSummary.findings.

The invariant: ScanSummary.findings is a _VerifiedFindingsList, which
only accepts findings produced by VerificationEngine.verify() ->
_to_scan_finding(). These tests pin both the mechanism and the
source-level wiring, so a future edit that removes either fails here.
"""

from dataclasses import asdict
from pathlib import Path

import pytest

from janissary.engine.scanner import (
    _ENGINE,
    ScanFinding,
    ScanSummary,
    _to_scan_finding,
    _VerifiedFindingsList,
)
from janissary.verification import CandidateFinding


def _candidate(**kw) -> CandidateFinding:
    base = {
        "param": "q",
        "payload_name": "sql_single_quote",
        "payload_value": "'",
        "category": "sqli",
        "severity": "critical",
        "finding_type": "db_error",
        "detail": "SQL error observed",
        "url": "http://x/a?q='",
    }
    base.update(kw)
    return CandidateFinding(**base)


def _engine_emitted_finding() -> ScanFinding:
    return _to_scan_finding(_ENGINE.verify(_candidate()))


def _raw_scan_finding() -> ScanFinding:
    return ScanFinding(
        param="q",
        payload_name="sql_single_quote",
        payload_value="'",
        category="sqli",
        severity="critical",
        finding_type="db_error",
        detail="SQL error observed",
        url="http://x/a?q='",
    )


def test_verified_findings_list_accepts_engine_emitted_finding():
    lst = _VerifiedFindingsList()
    f = _engine_emitted_finding()
    lst.append(f)
    assert len(lst) == 1
    assert lst[0] is f


def test_verified_findings_list_rejects_raw_scan_finding():
    lst = _VerifiedFindingsList()
    with pytest.raises(AssertionError, match="Phase 0.1 invariant"):
        lst.append(_raw_scan_finding())
    assert len(lst) == 0


def test_verified_findings_list_extend_rejects_raw_finding():
    lst = _VerifiedFindingsList()
    good = _engine_emitted_finding()
    raw = _raw_scan_finding()
    with pytest.raises(AssertionError, match="Phase 0.1 invariant"):
        lst.extend([good, raw])


def test_to_scan_finding_sets_engine_emitted_marker():
    f = _engine_emitted_finding()
    assert getattr(f, "_engine_emitted", False) is True


def test_raw_scan_finding_has_no_marker():
    f = _raw_scan_finding()
    assert not getattr(f, "_engine_emitted", False)


def test_asdict_does_not_leak_engine_emitted():
    """The marker is a non-dataclass attribute. asdict() walks fields only,
    so JSON/SARIF output is unaffected by its presence."""
    f = _engine_emitted_finding()
    d = asdict(f)
    assert "_engine_emitted" not in d
    assert d["param"] == "q"
    assert d["category"] == "sqli"


def test_scan_summary_findings_is_verified_findings_list():
    summary = ScanSummary(target="http://x", params=["q"], method="GET")
    assert isinstance(summary.findings, _VerifiedFindingsList)


def test_source_uses_verified_findings_list_and_marker():
    """Source-level tripwire: removing the invariant from scanner.py
    must fail this test even if the 670 behavior tests still pass."""
    src = Path("src/janissary/engine/scanner.py").read_text(encoding="utf-8")
    assert (
        "findings: list[ScanFinding] = field(default_factory=_VerifiedFindingsList)"
        in src
    ), "ScanSummary.findings no longer uses _VerifiedFindingsList default factory"
    assert "finding._engine_emitted = True" in src, (
        "_to_scan_finding no longer sets _engine_emitted marker"
    )
    assert "class _VerifiedFindingsList(list):" in src, (
        "_VerifiedFindingsList class definition removed"
    )
