"""M78a: --jsonl emits candidates as distinct records after verified."""

import io
import json

from janissary.engine.scanner import ScanFinding
from janissary.output.emitter import OutputEmitter, OutputFormat


def _vf():
    f = ScanFinding(
        param="q",
        payload_name="p",
        payload_value="v",
        category="sqli",
        severity="high",
        finding_type="db_error",
        detail="SQL error",
        url="http://x/a?q=v",
        method="GET",
        verification_status="verified",
    )
    f._engine_emitted = True
    return f


def _cand():
    f = ScanFinding(
        param="q",
        payload_name="heuristic",
        payload_value="x",
        category="heuristic",
        severity="info",
        finding_type="heur",
        detail="h",
        url="http://x/a?q=x",
        method="GET",
        verification_status="unproven",
        verification_reason="heuristic_discovery",
    )
    f._engine_emitted = True
    return f


def _emit(payload):
    buf = io.StringIO()
    OutputEmitter(OutputFormat.JSONL, stdout=buf).emit(payload, {})
    return buf.getvalue()


def test_jsonl_emits_verified_then_candidates():
    out = _emit({"findings": [_vf()], "candidates": [_cand(), _cand()]})
    lines = [json.loads(line) for line in out.strip().split("\n")]
    assert len(lines) == 3
    assert lines[0]["record_type"] == "verified"
    assert lines[1]["record_type"] == "candidate"
    assert lines[2]["record_type"] == "candidate"
    assert lines[0]["verification_status"] == "verified"
    assert lines[1]["verification_status"] == "unproven"


def test_jsonl_candidates_only():
    out = _emit({"findings": [], "candidates": [_cand()]})
    lines = [json.loads(line) for line in out.strip().split("\n")]
    assert len(lines) == 1
    assert lines[0]["record_type"] == "candidate"
    # ScanFinding ids come from the ADR-007 fingerprint, not the
    # F-/C- fallback. record_type is the authoritative stream marker.
    assert lines[0]["id"]


def test_jsonl_empty_produces_no_lines():
    out = _emit({"findings": [], "candidates": []})
    assert out.strip() == ""


def test_jsonl_record_type_does_not_override_verification_status():
    cand = _cand()
    assert cand.verification_status == "unproven"
    out = _emit({"findings": [], "candidates": [cand]})
    rec = json.loads(out.strip())
    assert rec["record_type"] == "candidate"
    assert rec["verification_status"] == "unproven"
