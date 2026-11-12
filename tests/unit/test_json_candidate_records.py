"""M78a: --json emits candidates top-level with full shape."""

import io
import json

from janissary.engine.scanner import ScanFinding, ScanSummary
from janissary.output.emitter import SCHEMA_VERSION, OutputEmitter, OutputFormat


def _vf(**kw):
    base = {
        "param": "q",
        "payload_name": "p",
        "payload_value": "v",
        "category": "sqli",
        "severity": "high",
        "finding_type": "db_error",
        "detail": "SQL error",
        "url": "http://x/a?q=v",
        "method": "GET",
        "verification_status": "verified",
    }
    base.update(kw)
    f = ScanFinding(**base)
    f._engine_emitted = True
    return f


def _cand(**kw):
    base = {
        "param": "q",
        "payload_name": "heuristic",
        "payload_value": "x",
        "category": "heuristic",
        "severity": "info",
        "finding_type": "heur",
        "detail": "h",
        "url": "http://x/a?q=x",
        "method": "GET",
        "verification_status": "unproven",
        "verification_reason": "heuristic_discovery",
    }
    base.update(kw)
    f = ScanFinding(**base)
    f._engine_emitted = True
    return f


def _emit(fmt, payload, meta=None):
    buf = io.StringIO()
    OutputEmitter(fmt, stdout=buf).emit(payload, meta or {})
    return buf.getvalue()


def test_json_has_top_level_candidates():
    doc = json.loads(
        _emit(OutputFormat.JSON, {"findings": [_vf()], "candidates": [_cand()]})
    )
    assert "findings" in doc
    assert "candidates" in doc
    assert len(doc["findings"]) == 1
    assert len(doc["candidates"]) == 1
    assert doc["finding_count"] == 1
    assert doc["candidate_count"] == 1
    assert doc["schema_version"] == SCHEMA_VERSION == "1.1"


def test_json_record_type_marks_stream():
    doc = json.loads(
        _emit(OutputFormat.JSON, {"findings": [_vf()], "candidates": [_cand()]})
    )
    assert doc["findings"][0]["record_type"] == "verified"
    assert doc["candidates"][0]["record_type"] == "candidate"
    assert doc["findings"][0]["verification_status"] == "verified"
    assert doc["candidates"][0]["verification_status"] == "unproven"


def test_json_finding_shape_matches_candidate_shape():
    doc = json.loads(
        _emit(OutputFormat.JSON, {"findings": [_vf()], "candidates": [_cand()]})
    )
    required = {
        "id",
        "class",
        "fingerprint",
        "severity",
        "url",
        "method",
        "parameter",
        "payload",
        "record_type",
        "verification_status",
        "timestamp",
    }
    fkeys = set(doc["findings"][0].keys())
    ckeys = set(doc["candidates"][0].keys())
    assert required.issubset(fkeys)
    assert required.issubset(ckeys)
    # Shapes are equivalent: the only field that may differ is
    # verification_reason, which is None on verified findings (and
    # therefore omitted by _normalize_finding) and set on candidates.
    assert fkeys - ckeys <= {"verification_reason"}
    assert ckeys - fkeys <= {"verification_reason"}


def test_json_scan_meta_does_not_duplicate_candidates():
    doc = json.loads(
        _emit(
            OutputFormat.JSON,
            {"findings": [], "candidates": [_cand()]},
            {"candidates": [{"stale": True}], "candidate_count": 999},
        )
    )
    assert "candidates" not in doc["scan"]
    assert "candidate_count" not in doc["scan"]
    assert doc["candidate_count"] == 1


def test_export_and_stdout_json_shapes_match():
    """--export json (via _summary_to_dict) and --json (via OutputEmitter)
    produce equivalent finding/candidate record shapes."""
    from janissary.cli import _summary_to_dict

    summary = ScanSummary(target="http://x/", params=["q"], method="GET")
    summary.record(_vf())
    summary.candidates.append(_cand())

    export_payload = _summary_to_dict(summary)
    stdout_doc = json.loads(
        _emit(
            OutputFormat.JSON,
            {"findings": summary.findings, "candidates": summary.candidates},
        )
    )

    assert len(export_payload["findings"]) == len(stdout_doc["findings"]) == 1
    assert len(export_payload["candidates"]) == len(stdout_doc["candidates"]) == 1
    assert set(export_payload["findings"][0].keys()) == set(
        stdout_doc["findings"][0].keys()
    )
    assert set(export_payload["candidates"][0].keys()) == set(
        stdout_doc["candidates"][0].keys()
    )
    assert (
        export_payload["findings"][0]["record_type"]
        == stdout_doc["findings"][0]["record_type"]
        == "verified"
    )
    assert (
        export_payload["candidates"][0]["record_type"]
        == stdout_doc["candidates"][0]["record_type"]
        == "candidate"
    )
