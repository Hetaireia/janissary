"""Unit tests for the SARIF rule catalog."""

from __future__ import annotations

import pytest

from janissary.sarif_rules import (
    TOOL_URI,
    RuleMeta,
    all_rule_ids,
    cwe_tag,
    cwe_taxonomy,
    rule_for,
    sarif_level,
    security_severity,
)

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity,expected",
    [
        ("critical", "error"),
        ("high", "error"),
        ("medium", "warning"),
        ("low", "note"),
        ("info", "note"),
    ],
)
def test_sarif_level_known_severities(severity, expected):
    assert sarif_level(severity) == expected


def test_sarif_level_unknown_severity_defaults_note():
    assert sarif_level("bizarre") == "note"
    assert sarif_level("") == "note"
    assert sarif_level(None) == "note"


def test_sarif_level_case_insensitive():
    assert sarif_level("HIGH") == "error"
    assert sarif_level("Critical") == "error"


@pytest.mark.parametrize(
    "severity,expected",
    [
        ("critical", 9.5),
        ("high", 7.5),
        ("medium", 5.5),
        ("low", 3.5),
        ("info", 0.1),
    ],
)
def test_security_severity_known(severity, expected):
    assert security_severity(severity) == expected


def test_security_severity_unknown_defaults_low():
    assert security_severity("bizarre") == 0.1
    assert security_severity("") == 0.1
    assert security_severity(None) == 0.1


# ---------------------------------------------------------------------------
# CWE tag
# ---------------------------------------------------------------------------


def test_cwe_tag_format():
    assert cwe_tag(89) == "external/cwe/cwe-89"
    assert cwe_tag(22) == "external/cwe/cwe-22"
    assert cwe_tag(643) == "external/cwe/cwe-643"


# ---------------------------------------------------------------------------
# Catalog lookup
# ---------------------------------------------------------------------------


def test_rule_for_returns_catalog_entry():
    meta = rule_for("sqli", "db_error")
    assert meta.rule_id == "sqli:db_error"
    assert meta.short_description == "SQL Injection"
    assert 89 in meta.cwes
    assert meta.default_severity == "critical"


def test_rule_for_traversal_collapse():
    meta = rule_for("traversal", "traversal_collapse")
    assert meta.rule_id == "traversal:traversal_collapse"
    assert 22 in meta.cwes


def test_rule_for_fallback_for_unknown():
    meta = rule_for("unmapped_category", "unmapped_type")
    assert meta.rule_id == "unmapped_category:unmapped_type"
    assert meta.short_description == "Unmapped Type"
    assert meta.cwes == ()
    assert meta.default_severity == "medium"


def test_rule_for_fallback_handles_empty_inputs():
    meta = rule_for("", "")
    assert meta.rule_id == "unknown:unknown"


# ---------------------------------------------------------------------------
# RuleMeta.to_sarif shape
# ---------------------------------------------------------------------------


def test_rule_meta_to_sarif_shape():
    meta = rule_for("sqli", "db_error")
    sarif = meta.to_sarif()
    assert sarif["id"] == "sqli:db_error"
    assert sarif["shortDescription"]["text"] == "SQL Injection"
    assert sarif["helpUri"] == TOOL_URI
    assert "properties" in sarif


def test_rule_meta_to_sarif_security_severity_is_string():
    meta = rule_for("sqli", "db_error")
    sarif = meta.to_sarif()
    sev = sarif["properties"]["security-severity"]
    assert isinstance(sev, str)
    assert sev == "9.5"


def test_rule_meta_to_sarif_includes_cwe_tags():
    meta = rule_for("sqli", "db_error")
    sarif = meta.to_sarif()
    assert "tags" in sarif["properties"]
    assert "external/cwe/cwe-89" in sarif["properties"]["tags"]


def test_rule_meta_to_sarif_omits_tags_when_no_cwe():
    meta = RuleMeta(
        category="custom",
        finding_type="no_cwe",
        short_description="No CWE",
        cwes=(),
    )
    sarif = meta.to_sarif()
    assert "tags" not in sarif["properties"]


# ---------------------------------------------------------------------------
# Catalog integrity
# ---------------------------------------------------------------------------


def test_all_rule_ids_unique_and_sorted():
    ids = all_rule_ids()
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))


def test_all_rule_ids_expected_members():
    ids = set(all_rule_ids())
    expected = {
        "sqli:db_error",
        "sqli:sqli_quote_oracle",
        "sqli:sql_result_rows",
        "traversal:traversal_collapse",
        "traversal:pathtraver_existence_oracle",
        "cmdi:command_output",
        "cmdi:output_region",
        "ldapi:ldap_injection",
        "xpathi:xpathi_error_oracle",
        "xpathi:xpath_result_rows",
        "xss:payload_reflected",
        "xss:reflected_xss",
        "xss:reflection_context",
        "trustbound:trustbound_session_oracle",
        "securecookie:securecookie_flag_oracle",
        "weakrand:weakrand_rng_oracle",
    }
    assert expected.issubset(ids), f"missing from catalog: {expected - ids}"


# ---------------------------------------------------------------------------
# CWE taxonomy
# ---------------------------------------------------------------------------


def test_cwe_taxonomy_shape():
    tax = cwe_taxonomy()
    assert tax["name"] == "CWE"
    assert tax["organization"] == "MITRE"
    assert "taxa" in tax
    assert isinstance(tax["taxa"], list)


def test_cwe_taxonomy_includes_expected_cwes():
    tax = cwe_taxonomy()
    ids = {entry["id"] for entry in tax["taxa"]}
    for expected in ("cwe-89", "cwe-22", "cwe-78", "cwe-79"):
        assert expected in ids, f"missing {expected}"


def test_cwe_taxonomy_entries_have_required_fields():
    tax = cwe_taxonomy()
    for entry in tax["taxa"]:
        assert "id" in entry
        assert "name" in entry
        assert "shortDescription" in entry
        assert entry["helpUri"].startswith("https://cwe.mitre.org/data/definitions/")
