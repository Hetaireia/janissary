"""Unit tests for the findings store."""

from __future__ import annotations

import json
from pathlib import Path

from janissary.agent.finding_store import Finding, FindingStore


def _finding(**kwargs) -> Finding:
    base = {
        "target": "http://t/",
        "category": "sqli",
        "severity": "high",
        "finding_type": "error",
        "discriminator": "q",
    }
    base.update(kwargs)
    return Finding(**base)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


def test_finding_sets_recorded_at():
    f = _finding()
    assert f.recorded_at
    assert "T" in f.recorded_at


def test_dedup_key_stable():
    a = _finding()
    b = _finding()
    assert a.dedup_key() == b.dedup_key()


def test_dedup_key_differs_by_discriminator():
    a = _finding(discriminator="q")
    b = _finding(discriminator="id")
    assert a.dedup_key() != b.dedup_key()


def test_to_dict_flattens_extra():
    f = _finding(extra={"cve": "CVE-2021-1234"})
    d = f.to_dict()
    assert d["cve"] == "CVE-2021-1234"
    assert "extra" not in d


def test_from_dict_roundtrip():
    f = _finding(extra={"cve": "CVE-2021-1234"})
    d = f.to_dict()
    g = Finding.from_dict(d)
    assert g.target == f.target
    assert g.extra.get("cve") == "CVE-2021-1234"


def test_from_dict_backfills_missing():
    g = Finding.from_dict({"target": "http://x/"})
    assert g.target == "http://x/"
    assert g.severity == "info"
    assert g.finding_type == "unknown"


# ---------------------------------------------------------------------------
# Store basics
# ---------------------------------------------------------------------------


def test_add_returns_true_then_false_on_duplicate():
    s = FindingStore(":memory:")
    assert s.add(_finding()) is True
    assert s.add(_finding()) is False
    assert s.count() == 1


def test_extend_counts_new_only():
    s = FindingStore(":memory:")
    n = s.extend([_finding(), _finding(), _finding(discriminator="id")])
    assert n == 2
    assert s.count() == 2


def test_by_target():
    s = FindingStore(":memory:")
    s.add(_finding(target="http://a/"))
    s.add(_finding(target="http://b/"))
    assert len(s.by_target("http://a/")) == 1


def test_by_severity():
    s = FindingStore(":memory:")
    s.add(_finding(severity="high"))
    s.add(_finding(severity="low", discriminator="x"))
    assert len(s.by_severity("high")) == 1


def test_by_category():
    s = FindingStore(":memory:")
    s.add(_finding(category="sqli"))
    s.add(_finding(category="xss", discriminator="x"))
    assert len(s.by_category("xss")) == 1


def test_len_matches_count():
    s = FindingStore(":memory:")
    s.add(_finding())
    s.add(_finding(discriminator="id"))
    assert len(s) == 2


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_save_and_load(tmp_path: Path):
    p = tmp_path / "findings.json"
    s = FindingStore(p)
    s.add(_finding())
    s.add(_finding(discriminator="id"))
    s.save()

    s2 = FindingStore(p)
    n = s2.load()
    assert n == 2
    assert len(s2.all()) == 2


def test_save_is_atomic_no_tmp_left(tmp_path: Path):
    p = tmp_path / "findings.json"
    s = FindingStore(p)
    s.add(_finding())
    s.save()
    leftovers = [f for f in tmp_path.iterdir() if f.suffix == ".tmp"]
    assert leftovers == []


def test_load_missing_file_returns_zero(tmp_path: Path):
    s = FindingStore(tmp_path / "nope.json")
    assert s.load() == 0


def test_load_corrupt_file_returns_zero(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text("not json", encoding="utf-8")
    s = FindingStore(p)
    assert s.load() == 0


def test_load_ignores_non_dict_entries(tmp_path: Path):
    p = tmp_path / "mixed.json"
    p.write_text(
        json.dumps({"version": 1, "findings": [{"target": "http://a/"}, "junk"]}),
        encoding="utf-8",
    )
    s = FindingStore(p)
    assert s.load() == 1


def test_clear_empties_store():
    s = FindingStore(":memory:")
    s.add(_finding())
    s.clear()
    assert s.count() == 0


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def test_summary_counts():
    s = FindingStore(":memory:")
    s.add(_finding(severity="high", category="sqli"))
    s.add(_finding(severity="low", category="xss", discriminator="x"))
    s.add(_finding(severity="high", category="sqli", discriminator="y"))
    summ = s.summary()
    assert summ["total"] == 3
    assert summ["by_severity"]["high"] == 2
    assert summ["by_category"]["sqli"] == 2
    assert "http://t/" in summ["targets"]
