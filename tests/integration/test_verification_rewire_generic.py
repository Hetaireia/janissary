"""Integration test: the differential emission site routes through the engine.

Pins three properties of the rewire:
1. The module-level _ENGINE is a VerificationEngine configured with
   AnalyzerImplicitConfirmer.
2. The exact call chain used at the emission site — _ENGINE.verify(candidate)
   then _to_scan_finding(result) — produces a ScanFinding with
   verification_status='verified' and an analyzer-prefixed reason.
3. The scanner.py source still contains the wired call (source-level
   tripwire; a future edit reverting to inline ScanFinding() will fail
   this even if behavior is unchanged).
"""

from pathlib import Path

from janissary.engine.scanner import _ENGINE, _to_scan_finding
from janissary.verification import (
    CandidateFinding,
    VerificationEngine,
    VerifiedFinding,
)


def _candidate(**overrides) -> CandidateFinding:
    base = {
        "param": "id",
        "payload_name": "sql_union_select",
        "payload_value": "1' UNION SELECT 1,2,3--",
        "category": "sqli",
        "severity": "high",
        "finding_type": "sql_union_rows",
        "detail": "Response returned 3 union columns",
        "url": "http://example.com/api/users?id=1",
        "method": "GET",
        "response_status": 200,
        "response_length": 512,
        "response_time": 0.42,
        "response_content_type": "application/json",
        "raw_request": "GET /api/users?id=1 HTTP/1.1",
        "raw_response": "HTTP/1.1 200 OK",
    }
    base.update(overrides)
    return CandidateFinding(**base)


def test_module_engine_is_verification_engine():
    assert isinstance(_ENGINE, VerificationEngine)


def test_module_engine_uses_analyzer_implicit_confirmer():
    # Access the private list; it is the only way to assert configuration
    # without exposing internals through a public API on VerificationEngine.
    confirmers = getattr(_ENGINE, "_confirmers", [])
    names = [getattr(c, "name", None) for c in confirmers]
    assert "analyzer_implicit" in names


def test_verify_then_convert_produces_scan_finding_with_verification_metadata():
    """The exact call chain at the emission site."""
    candidate = _candidate()
    result = _ENGINE.verify(candidate)
    assert isinstance(result, VerifiedFinding)
    assert result.verification_status == "verified"
    assert result.verification_reason == "analyzer:sql_union_rows"

    finding = _to_scan_finding(result)
    # Evidence fields preserved
    assert finding.param == "id"
    assert finding.category == "sqli"
    assert finding.finding_type == "sql_union_rows"
    assert finding.response_status == 200
    assert finding.raw_request == "GET /api/users?id=1 HTTP/1.1"
    # Verification metadata preserved
    assert finding.verification_status == "verified"
    assert finding.verification_reason == "analyzer:sql_union_rows"
    # Fingerprint computed by __post_init__ (not passed through)
    assert finding.fingerprint != ""


def test_emission_site_source_uses_engine_call_chain():
    """Source-level tripwire: reverting the site to inline ScanFinding()
    must fail this test even though behavior is unchanged."""
    src = Path("src/janissary/engine/scanner.py").read_text(encoding="utf-8")
    assert "_ENGINE.verify(candidate)" in src, (
        "differential emission site no longer calls _ENGINE.verify(candidate)"
    )
    assert "finding = _to_scan_finding(result)" in src, (
        "differential emission site no longer converts via _to_scan_finding()"
    )
