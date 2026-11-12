"""Schema compatibility tests for M80 additions."""

from janissary.engine.scanner import _to_scan_finding
from janissary.heuristic.types import Observation
from janissary.verification.engine import VerificationEngine
from janissary.verification.types import CandidateFinding, VerifiedFinding


def _candidate(**kw):
    base = {
        "param": "q",
        "payload_name": "p",
        "payload_value": "v",
        "category": "sqli",
        "severity": "high",
        "finding_type": "db_error",
        "detail": "d",
        "url": "http://x/a?q=v",
    }
    base.update(kw)
    return CandidateFinding(**base)


def test_observation_backward_compatible():
    o = Observation(url="http://x/", body="b")
    assert o.source_id == ""
    assert o.observation_id == ""
    assert o.method == "GET"
    assert o.headers == {}


def test_candidate_finding_confidence_defaults_zero():
    c = _candidate()
    assert c.confidence == 0.0
    assert c.evidence_excerpt == ""


def test_verification_preserves_confidence_and_excerpt():
    c = _candidate(confidence=0.45, evidence_excerpt="SQL syntax near ''")
    engine = VerificationEngine()
    vf = engine.verify(c)
    assert isinstance(vf, VerifiedFinding)
    assert vf.confidence == 0.45
    assert vf.evidence_excerpt == "SQL syntax near ''"


def test_scan_finding_carries_confidence_and_excerpt():
    vf = VerifiedFinding(
        param="q",
        payload_name="p",
        payload_value="v",
        category="sqli",
        severity="high",
        finding_type="db_error",
        detail="d",
        url="http://x/a?q=v",
        verification_status="verified",
        confidence=0.45,
        evidence_excerpt="excerpt",
    )
    sf = _to_scan_finding(vf)
    assert sf.confidence == 0.45
    assert sf.evidence_excerpt == "excerpt"


def test_confidence_does_not_affect_verification_status():
    engine = VerificationEngine()
    lo = _candidate(confidence=0.1)
    hi = _candidate(confidence=0.9, payload_value="w")
    vlo = engine.verify(lo)
    vhi = engine.verify(hi)
    assert vlo.verification_status == vhi.verification_status == "unproven"
