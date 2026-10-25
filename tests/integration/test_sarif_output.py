"""Integration tests for SARIF output (ADR-008 0.3c-b)."""

from __future__ import annotations

import json
from pathlib import Path

from janissary.cli import _write_sarif
from janissary.engine.scanner import ScanFinding, ScanSummary


def _summary(
    target: str = "http://x/a", params: list[str] | None = None
) -> ScanSummary:
    return ScanSummary(
        target=target,
        params=params or ["q"],
        method="GET",
        total_requests=10,
    )


def _finding(
    category: str = "sqli",
    finding_type: str = "db_error",
    severity: str = "critical",
    param: str = "q",
    url: str = "http://x/a?q='",
    detail: str = "SQL error observed",
) -> ScanFinding:
    return ScanFinding(
        param=param,
        payload_name="sql_single_quote",
        payload_value="'",
        category=category,
        severity=severity,
        finding_type=finding_type,
        detail=detail,
        url=url,
    )


def _read_sarif(tmp_path: Path, summary: ScanSummary) -> dict:
    path = tmp_path / "out.sarif"
    _write_sarif(summary, str(path))
    return json.loads(path.read_text(encoding="utf-8"))


def test_sarif_full_document_shape(tmp_path):
    summary = _summary()
    summary.findings.append(_finding())
    doc = _read_sarif(tmp_path, summary)

    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert doc["version"] == "2.1.0"
    assert isinstance(doc["runs"], list)
    assert len(doc["runs"]) == 1

    run = doc["runs"][0]
    assert "tool" in run
    assert "driver" in run["tool"]
    assert run["tool"]["driver"]["name"] == "JANISSARY"
    assert "version" in run["tool"]["driver"]
    assert "rules" in run["tool"]["driver"]
    assert isinstance(run["tool"]["driver"]["rules"], list)
    assert "invocations" in run
    assert "taxonomies" in run
    assert "results" in run


def test_sarif_rules_dedup(tmp_path):
    """Two findings same (cat, ft) -> one rule, two results."""
    summary = _summary()
    summary.findings.append(_finding(param="q"))
    summary.findings.append(_finding(param="search"))
    doc = _read_sarif(tmp_path, summary)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    results = doc["runs"][0]["results"]
    assert len(rules) == 1
    assert len(results) == 2
    assert rules[0]["id"] == "sqli:db_error"
    assert results[0]["ruleIndex"] == 0
    assert results[1]["ruleIndex"] == 0


def test_sarif_distinct_rules(tmp_path):
    summary = _summary()
    summary.findings.append(_finding(category="sqli", finding_type="db_error"))
    summary.findings.append(_finding(category="xss", finding_type="reflected_xss"))
    doc = _read_sarif(tmp_path, summary)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    results = doc["runs"][0]["results"]
    assert len(rules) == 2
    assert len(results) == 2
    assert rules[0]["id"] == "sqli:db_error"
    assert rules[1]["id"] == "xss:reflected_xss"
    assert results[0]["ruleIndex"] == 0
    assert results[1]["ruleIndex"] == 1


def test_sarif_partial_fingerprints_on_every_result(tmp_path):
    summary = _summary()
    summary.findings.append(_finding(param="q"))
    summary.findings.append(_finding(param="s"))
    doc = _read_sarif(tmp_path, summary)
    for r in doc["runs"][0]["results"]:
        assert "partialFingerprints" in r
        assert "finding/v1" in r["partialFingerprints"]
        assert r["partialFingerprints"]["finding/v1"].startswith("jfv1:")


def test_sarif_artifact_uri_uses_finding_url(tmp_path):
    summary = _summary(target="http://x/a")
    summary.findings.append(_finding(url="http://x/a?q=' OR 1=1"))
    doc = _read_sarif(tmp_path, summary)
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "http://x/a?q=' OR 1=1"


def test_sarif_artifact_uri_falls_back_to_target(tmp_path):
    summary = _summary(target="http://x/a")
    summary.findings.append(_finding(url=""))
    doc = _read_sarif(tmp_path, summary)
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "http://x/a"


def test_sarif_per_result_security_severity_overrides_rule_default(tmp_path):
    """Rule default for sqli is 9.5; this finding is severity=medium."""
    summary = _summary()
    summary.findings.append(
        _finding(category="sqli", finding_type="db_error", severity="medium")
    )
    doc = _read_sarif(tmp_path, summary)
    rule_sev = doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"][
        "security-severity"
    ]
    result_sev = doc["runs"][0]["results"][0]["properties"]["security-severity"]
    assert rule_sev == "9.5"
    assert result_sev == "5.5"


def test_sarif_aborted_scan_invocation(tmp_path):
    summary = _summary()
    summary.aborted = True
    summary.abort_reason = "HTTP 500"
    doc = _read_sarif(tmp_path, summary)
    inv = doc["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False
    assert "toolExecutionNotifications" in inv
    assert len(inv["toolExecutionNotifications"]) == 1
    assert "HTTP 500" in inv["toolExecutionNotifications"][0]["message"]["text"]


def test_sarif_empty_findings(tmp_path):
    summary = _summary()
    doc = _read_sarif(tmp_path, summary)
    run = doc["runs"][0]
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is True
    assert "taxonomies" in run


def test_sarif_taxonomies_present(tmp_path):
    summary = _summary()
    summary.findings.append(_finding())
    doc = _read_sarif(tmp_path, summary)
    taxonomies = doc["runs"][0]["taxonomies"]
    assert len(taxonomies) == 1
    assert taxonomies[0]["name"] == "CWE"
    ids = {entry["id"] for entry in taxonomies[0]["taxa"]}
    assert "cwe-89" in ids
