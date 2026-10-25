"""Integration tests for 0.3b fingerprint wiring (ADR-007).

Covers: ScanFinding.fingerprint populated via __post_init__;
agent.Finding.fingerprint populated and dedup_key delegating to it;
from_dict legacy migration; store dedup on stable identity; SARIF
partialFingerprints; emitter fingerprint output.
"""

from __future__ import annotations

from pathlib import Path

from janissary.agent.finding_store import Finding, FindingStore
from janissary.engine.scanner import ScanFinding, ScanSummary


def test_scan_finding_fingerprint_populated():
    f = ScanFinding(
        param="q",
        payload_name="sql_single_quote",
        payload_value="'",
        category="sqli",
        severity="high",
        finding_type="db_error",
        detail="sql error",
        url="http://x/a?q='",
    )
    assert f.fingerprint.startswith("jfv1:")
    assert len(f.fingerprint) == len("jfv1:") + 32


def test_scan_finding_fingerprint_stable_across_payloads():
    f1 = ScanFinding(
        param="q",
        payload_name="sql_single_quote",
        payload_value="'",
        category="sqli",
        severity="high",
        finding_type="db_error",
        detail="d1",
        url="http://x/a?q='",
    )
    f2 = ScanFinding(
        param="q",
        payload_name="sql_or_1eq1",
        payload_value="' OR '1'='1",
        category="sqli",
        severity="critical",
        finding_type="db_error",
        detail="d2",
        url="http://x/a?q=' OR '1'='1",
    )
    assert f1.fingerprint == f2.fingerprint


def test_scan_finding_fingerprint_overridable():
    f = ScanFinding(
        param="q",
        payload_name="p",
        payload_value="'",
        category="sqli",
        severity="high",
        finding_type="db_error",
        detail="",
        url="http://x/a",
        fingerprint="jfv1:explicit",
    )
    assert f.fingerprint == "jfv1:explicit"


def test_agent_finding_fingerprint_populated():
    f = Finding(
        target="http://x/a",
        category="sqli",
        severity="high",
        finding_type="db_error",
        discriminator="q",
    )
    assert f.fingerprint.startswith("jfv1:")


def test_agent_finding_dedup_key_returns_fingerprint():
    f = Finding(
        target="http://x/a",
        category="sqli",
        severity="high",
        finding_type="db_error",
        discriminator="q",
    )
    assert f.dedup_key() == f.fingerprint


def test_agent_finding_roundtrip():
    f = Finding(
        target="http://x/a",
        category="sqli",
        severity="high",
        finding_type="db_error",
        discriminator="q",
    )
    fp = f.fingerprint
    d = f.to_dict()
    assert d["fingerprint"] == fp
    f2 = Finding.from_dict(d)
    assert f2.fingerprint == fp


def test_agent_finding_legacy_dict_computes_fingerprint():
    legacy = {
        "target": "http://x/a",
        "category": "sqli",
        "severity": "high",
        "finding_type": "db_error",
        "discriminator": "q",
        "detail": "",
        "payload": "",
        "response_status": 500,
        "recorded_at": "2026-01-01T00:00:00+00:00",
    }
    f = Finding.from_dict(legacy)
    assert f.fingerprint.startswith("jfv1:")
    assert f.dedup_key() == f.fingerprint


def test_finding_store_dedup_on_stable_identity(tmp_path: Path):
    store = FindingStore(str(tmp_path / "findings.json"))
    f1 = Finding(
        target="http://x/a?sessionid=abc",
        category="sqli",
        severity="high",
        finding_type="db_error",
        discriminator="q",
    )
    f2 = Finding(
        target="http://x/a?sessionid=xyz",
        category="sqli",
        severity="high",
        finding_type="db_error",
        discriminator="q",
    )
    assert store.add(f1) is True
    assert store.add(f2) is False
    assert store.count() == 1


def test_finding_store_persists_fingerprint(tmp_path: Path):
    path = tmp_path / "findings.json"
    store = FindingStore(str(path))
    f = Finding(
        target="http://x/a",
        category="sqli",
        severity="high",
        finding_type="db_error",
        discriminator="q",
    )
    fp = f.fingerprint
    store.add(f)
    store.save()
    store2 = FindingStore(str(path))
    store2.load()
    assert store2.count() == 1
    assert store2.all()[0].fingerprint == fp


def test_write_sarif_includes_partial_fingerprints(tmp_path: Path):
    from janissary.cli import _write_sarif

    f = ScanFinding(
        param="q",
        payload_name="p",
        payload_value="'",
        category="sqli",
        severity="high",
        finding_type="db_error",
        detail="sql error",
        url="http://x/a?q='",
    )
    summary = ScanSummary(target="http://x/a", params=["q"], method="GET")
    summary.findings.append(f)

    path = tmp_path / "out.sarif"
    _write_sarif(summary, str(path))
    content = path.read_text(encoding="utf-8")
    assert '"partialFingerprints"' in content
    assert f.fingerprint in content


def test_emitter_normalize_finding_has_fingerprint():
    from janissary.output.emitter import _normalize_finding

    f = ScanFinding(
        param="q",
        payload_name="p",
        payload_value="'",
        category="sqli",
        severity="high",
        finding_type="db_error",
        detail="sql error",
        url="http://x/a?q='",
    )
    normalized = _normalize_finding(f)
    assert "fingerprint" in normalized
    assert normalized["fingerprint"] == f.fingerprint
    assert normalized["id"] == f.fingerprint
