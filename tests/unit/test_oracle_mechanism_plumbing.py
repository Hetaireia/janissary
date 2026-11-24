"""Plumbing for the oracle_mechanism field (ADR-036 Phase 5).

The field carries per-oracle attribution from candidate through promotion
and ScanFinding conversion to serialized output. It is deliberately not
part of the finding identity, so attribution can never split a finding.
Every pre-ADR-036 emission site leaves it empty, and an empty value must
stay out of serialized output so existing findings stay byte-identical.
"""

from janissary.engine.scanner import ScanFinding, _to_scan_finding
from janissary.output.emitter import _normalize_finding
from janissary.verification.engine import _promote
from janissary.verification.types import CandidateFinding


def _candidate(**over):
    base = {
        "param": "file",
        "payload_name": "traversal_passwd",
        "payload_value": "../../etc/passwd",
        "category": "traversal",
        "severity": "critical",
        "finding_type": "pathtraver_existence_oracle",
        "detail": "d",
    }
    base.update(over)
    return CandidateFinding(**base)


def _verified(mechanism):
    return _promote(_candidate(oracle_mechanism=mechanism), "verified", None)


def test_candidate_defaults_to_empty_mechanism():
    assert _candidate().oracle_mechanism == ""


def test_promotion_carries_mechanism():
    assert _verified("root_clamp_convergence").oracle_mechanism == (
        "root_clamp_convergence"
    )


def test_scan_finding_carries_mechanism():
    assert _to_scan_finding(_verified("root_clamp_convergence")).oracle_mechanism == (
        "root_clamp_convergence"
    )


def test_scan_finding_defaults_to_empty_mechanism():
    assert (
        ScanFinding(
            param="file",
            payload_name="p",
            payload_value="v",
            category="traversal",
            severity="critical",
            finding_type="pathtraver_existence_oracle",
            detail="d",
        ).oracle_mechanism
        == ""
    )


def test_emitter_includes_mechanism_when_set():
    finding = _to_scan_finding(_verified("self_referential_normalization"))
    assert (
        _normalize_finding(finding)["oracle_mechanism"]
        == "self_referential_normalization"
    )


def test_emitter_omits_mechanism_when_empty():
    assert "oracle_mechanism" not in _normalize_finding(_to_scan_finding(_verified("")))


def test_mechanism_does_not_change_fingerprint():
    plain = _to_scan_finding(_verified(""))
    tagged = _to_scan_finding(_verified("content_signature"))
    assert plain.fingerprint == tagged.fingerprint
