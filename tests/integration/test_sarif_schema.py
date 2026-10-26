"""Validate _write_sarif output against the official SARIF 2.1.0 JSON schema.

Phase 0.3c follow-on (handover Option 1). Catches shape drift in real time.
No network: schema is vendored at tests/fixtures/sarif/sarif-schema-2.1.0.json
(SHA-256 C3B4BB2D6093897483348925AAA73AF03B3E3F4BD4CA38CEF26DCB4212A2682E,
fetched from OASIS errata01 on 2026-10-26).

Complements tests/integration/test_sarif_output.py, which asserts on our own
expectations; this file asserts on the spec.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from janissary.cli import _write_sarif
from janissary.engine.scanner import ScanFinding, ScanSummary

SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "sarif"
    / "sarif-schema-2.1.0.json"
)


@pytest.fixture(scope="module")
def sarif_schema() -> dict:
    if not SCHEMA_PATH.exists():
        pytest.skip(
            f"schema fixture missing at {SCHEMA_PATH}; vendor it to enable this test"
        )
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _finding(**kw) -> ScanFinding:
    base = {
        "param": "q",
        "payload_name": "sqli-basic",
        "payload_value": "' OR 1=1--",
        "category": "sqli",
        "severity": "high",
        "finding_type": "error_based",
        "detail": "SQL error signature observed",
        "url": "https://example.test/search?q=1",
    }
    base.update(kw)
    return ScanFinding(**base)


def _summary(
    findings: list[ScanFinding], target: str = "https://example.test"
) -> ScanSummary:
    return ScanSummary(target=target, params=["q"], method="GET", findings=findings)


def _write_and_load(
    tmp_path: Path, summary: ScanSummary, name: str = "out.sarif"
) -> dict:
    out = tmp_path / name
    _write_sarif(summary, str(out))
    return json.loads(out.read_text(encoding="utf-8"))


def _assert_schema_valid(schema: dict, doc: dict) -> None:
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    errors = sorted(cls(schema).iter_errors(doc), key=lambda e: list(e.path))
    assert not errors, "SARIF schema violations:\n" + "\n".join(
        f"  {list(e.path)}: {e.message}" for e in errors
    )


def test_write_sarif_output_validates_against_official_schema(tmp_path, sarif_schema):
    summary = _summary(
        [
            _finding(),
            _finding(
                category="xss",
                finding_type="reflected",
                severity="medium",
                url="https://example.test/greet?name=x",
                param="name",
            ),
            _finding(
                category="traversal",
                finding_type="path",
                severity="critical",
                url="https://example.test/file?name=../../etc/passwd",
                param="name",
            ),
            _finding(
                category="weakrand",
                finding_type="predictable",
                severity="low",
                url="https://example.test/token",
                param="token",
            ),
        ]
    )
    _assert_schema_valid(sarif_schema, _write_and_load(tmp_path, summary))


def test_write_sarif_empty_findings_still_schema_valid(tmp_path, sarif_schema):
    doc = _write_and_load(tmp_path, _summary([]), "empty.sarif")
    _assert_schema_valid(sarif_schema, doc)
    run = doc["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["name"]


def test_write_sarif_uncataloged_type_falls_back_and_validates(tmp_path, sarif_schema):
    f = _finding(
        category="misc", finding_type="totally_uncataloged_type", severity="medium"
    )
    doc = _write_and_load(tmp_path, _summary([f]), "fallback.sarif")
    _assert_schema_valid(sarif_schema, doc)
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule.get("id")


def test_write_sarif_rule_index_and_fingerprint_present(tmp_path, sarif_schema):
    summary = _summary(
        [
            _finding(category="sqli", finding_type="error_based"),
            _finding(
                category="sqli",
                finding_type="error_based",
                url="https://example.test/other?q=2",
            ),
            _finding(category="xss", finding_type="reflected", severity="medium"),
        ]
    )
    doc = _write_and_load(tmp_path, summary, "idx.sarif")
    _assert_schema_valid(sarif_schema, doc)
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]

    assert len(results) == 3
    for r in results:
        assert isinstance(r["ruleIndex"], int)
        assert 0 <= r["ruleIndex"] < len(rules)
        assert "finding/v1" in r.get("partialFingerprints", {})
        assert r["level"] in {"error", "warning", "note", "none"}

    assert len(rules) == 2
    assert results[0]["ruleIndex"] == results[1]["ruleIndex"]
    assert results[2]["ruleIndex"] != results[0]["ruleIndex"]

    for rule in rules:
        ss = rule.get("properties", {}).get("security-severity")
        assert ss is not None
        assert 0.0 <= float(ss) <= 10.0


def test_write_sarif_security_severity_is_schema_valid_string(tmp_path, sarif_schema):
    summary = _summary(
        [_finding(severity=s) for s in ("critical", "high", "medium", "low", "info")]
    )
    doc = _write_and_load(tmp_path, summary, "sev.sarif")
    _assert_schema_valid(sarif_schema, doc)
    for r in doc["runs"][0]["results"]:
        sev = r["properties"]["security-severity"]
        assert isinstance(sev, str)
        assert 0.0 <= float(sev) <= 10.0
