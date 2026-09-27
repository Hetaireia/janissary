"""Tests for janissary.engine.grouping."""

from __future__ import annotations

from janissary.engine.grouping import (
    FindingGroup,
    classify_root_cause,
    group_findings,
)


class _F:
    """Minimal stand-in for ScanFinding."""

    def __init__(
        self,
        param: str,
        category: str,
        severity: str,
        finding_type: str,
        payload_name: str = "p",
        payload_value: str = "v",
        detail: str = "",
        response_status: int | None = None,
    ) -> None:
        self.param = param
        self.category = category
        self.severity = severity
        self.finding_type = finding_type
        self.payload_name = payload_name
        self.payload_value = payload_value
        self.detail = detail
        self.response_status = response_status


def test_classify_known_pair():
    assert classify_root_cause("sqli", "db_error") == "sql_injection"
    assert classify_root_cause("sqli", "status_change") == "sql_injection"


def test_classify_reflection_canonicalises():
    assert classify_root_cause("sqli", "payload_reflected") == "reflection"
    assert classify_root_cause("xss", "payload_reflected") == "reflection"
    assert classify_root_cause("xss", "reflected_xss") == "reflection"
    assert classify_root_cause("traversal", "payload_reflected") == "reflection"


def test_classify_falls_through():
    assert classify_root_cause("weird", "mystery") == "mystery"


def test_same_root_cause_groups():
    findings = [
        _F("q", "sqli", "high", "status_change", payload_name="a"),
        _F("q", "sqli", "critical", "db_error", payload_name="b"),
        _F("q", "sqli", "medium", "length_anomaly", payload_name="c"),
    ]
    groups = group_findings(findings)
    assert len(groups) == 1
    assert groups[0].evidence_count == 3
    assert groups[0].severity == "critical"


def test_different_root_cause_splits():
    findings = [
        _F("q", "sqli", "critical", "db_error"),
        _F("q", "sqli", "low", "payload_reflected"),
    ]
    groups = group_findings(findings)
    assert len(groups) == 2
    by_root = {g.root_cause: g for g in groups}
    assert set(by_root) == {"sql_injection", "reflection"}


def test_different_param_splits():
    findings = [
        _F("q", "sqli", "high", "db_error"),
        _F("id", "sqli", "high", "db_error"),
    ]
    groups = group_findings(findings)
    assert len(groups) == 2


def test_severity_escalates():
    g = FindingGroup(
        param="q", category="sqli", root_cause="sql_injection", severity="low"
    )
    g.add(_F("q", "sqli", "high", "db_error"))
    g.add(_F("q", "sqli", "critical", "status_change"))
    g.add(_F("q", "sqli", "medium", "length_anomaly"))
    assert g.severity == "critical"


def test_payload_names_dedup_preserves_order():
    g = FindingGroup(
        param="q", category="sqli", root_cause="sql_injection", severity="low"
    )
    g.add(_F("q", "sqli", "high", "db_error", payload_name="a"))
    g.add(_F("q", "sqli", "high", "status_change", payload_name="b"))
    g.add(_F("q", "sqli", "high", "length_anomaly", payload_name="a"))
    assert g.payload_names == ["a", "b"]


def test_group_to_dict_roundtrip():
    findings = [
        _F("q", "sqli", "high", "db_error", payload_name="a", detail="d1"),
        _F("q", "sqli", "critical", "status_change", payload_name="b", detail="d2"),
    ]
    g = group_findings(findings)[0]
    d = g.to_dict()
    assert d["param"] == "q"
    assert d["category"] == "sqli"
    assert d["root_cause"] == "sql_injection"
    assert d["severity"] == "critical"
    assert d["evidence_count"] == 2
    assert d["payloads"] == ["a", "b"]
    assert len(d["evidence"]) == 2
    assert d["evidence"][0]["payload_name"] == "a"


def test_empty_input():
    assert group_findings([]) == []


def test_reflection_collapses_across_categories():
    findings = [
        _F("q", "sqli", "low", "payload_reflected"),
        _F("q", "xss", "high", "reflected_xss"),
        _F("q", "traversal", "low", "payload_reflected"),
        _F("q", "cmdi", "low", "payload_reflected"),
    ]
    groups = group_findings(findings)
    assert len(groups) == 1
    assert groups[0].root_cause == "reflection"
    assert groups[0].severity == "high"
    assert groups[0].evidence_count == 4
