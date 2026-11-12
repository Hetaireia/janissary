"""M82a: aggregation schema + propagation. No aggregation logic."""

import json

from janissary.engine.scanner import ScanFinding, _to_scan_finding
from janissary.output.emitter import _normalize_finding
from janissary.verification.engine import _EVIDENCE_FIELDS, _promote
from janissary.verification.types import CandidateFinding, VerifiedFinding


def _candidate(**overrides):
    base = {
        "param": "q",
        "payload_name": "sql_quote",
        "payload_value": "'",
        "category": "sqli",
        "severity": "high",
        "finding_type": "db_error",
        "detail": "d",
        "url": "http://x/a?q=%27",
        "method": "GET",
    }
    base.update(overrides)
    return CandidateFinding(**base)


def _verified(**overrides):
    base = {
        "param": "q",
        "payload_name": "sql_quote",
        "payload_value": "'",
        "category": "sqli",
        "severity": "high",
        "finding_type": "db_error",
        "detail": "d",
        "url": "http://x/a?q=%27",
        "method": "GET",
        "verification_status": "verified",
    }
    base.update(overrides)
    return VerifiedFinding(**base)


def _scan(**overrides):
    base = {
        "param": "q",
        "payload_name": "sql_quote",
        "payload_value": "'",
        "category": "sqli",
        "severity": "high",
        "finding_type": "db_error",
        "detail": "d",
        "url": "http://x/a?q=%27",
        "method": "GET",
    }
    base.update(overrides)
    return ScanFinding(**base)


def test_candidate_defaults():
    c = _candidate()
    assert c.signature_id == ""
    assert c.observation_count == 1
    assert c.first_observation_id == ""
    assert c.last_observation_id == ""
    assert c.payload_families == ()
    assert c.contributing_observation_ids == ()


def test_verified_defaults():
    v = _verified()
    assert v.signature_id == ""
    assert v.observation_count == 1
    assert v.first_observation_id == ""
    assert v.last_observation_id == ""
    assert v.payload_families == ()
    assert v.contributing_observation_ids == ()


def test_scan_defaults():
    s = _scan()
    assert s.signature_id == ""
    assert s.observation_count == 1
    assert s.first_observation_id == ""
    assert s.last_observation_id == ""
    assert s.payload_families == ()
    assert s.contributing_observation_ids == ()


def test_promote_carries_all_six():
    c = _candidate(
        signature_id="sql_error_probe",
        observation_count=7,
        first_observation_id="a" * 64,
        last_observation_id="b" * 64,
        payload_families=("sql_quote", "sql_union"),
        contributing_observation_ids=("a" * 64, "b" * 64),
    )
    v = _promote(c, "verified", None)
    assert v.signature_id == "sql_error_probe"
    assert v.observation_count == 7
    assert v.first_observation_id == "a" * 64
    assert v.last_observation_id == "b" * 64
    assert v.payload_families == ("sql_quote", "sql_union")
    assert v.contributing_observation_ids == ("a" * 64, "b" * 64)


def test_to_scan_finding_carries_all_six():
    v = _verified(
        signature_id="sql_error_probe",
        observation_count=7,
        first_observation_id="a" * 64,
        last_observation_id="b" * 64,
        payload_families=("sql_quote", "sql_union"),
        contributing_observation_ids=("a" * 64, "b" * 64),
    )
    s = _to_scan_finding(v)
    assert s.signature_id == "sql_error_probe"
    assert s.observation_count == 7
    assert s.first_observation_id == "a" * 64
    assert s.last_observation_id == "b" * 64
    assert s.payload_families == ("sql_quote", "sql_union")
    assert s.contributing_observation_ids == ("a" * 64, "b" * 64)


def test_track_a_scan_finding_defaults_unchanged():
    s = _scan()
    assert s.signature_id == ""
    assert s.observation_count == 1
    assert s.payload_families == ()
    assert s.fingerprint != ""


def test_normalize_finding_omits_new_fields():
    s = _scan(
        signature_id="sig_a",
        observation_count=42,
        first_observation_id="a" * 64,
        last_observation_id="b" * 64,
        payload_families=("p1", "p2"),
        contributing_observation_ids=("a" * 64,),
    )
    out = _normalize_finding(s)
    forbidden = {
        "signature_id",
        "observation_count",
        "first_observation_id",
        "last_observation_id",
        "payload_families",
        "contributing_observation_ids",
    }
    assert not (forbidden & set(out.keys()))


def test_json_serialization_roundtrip_excludes_new_fields():
    s = _scan(signature_id="sig_a", observation_count=42)
    out = _normalize_finding(s)
    serialized = json.dumps(out)
    for name in ("signature_id", "observation_count", "payload_families"):
        assert name not in serialized


def test_evidence_fields_includes_all_six():
    required = {
        "signature_id",
        "observation_count",
        "first_observation_id",
        "last_observation_id",
        "payload_families",
        "contributing_observation_ids",
    }
    assert required.issubset(set(_EVIDENCE_FIELDS))
