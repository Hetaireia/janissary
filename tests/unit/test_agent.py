"""Unit tests for the agent orchestrator."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from janissary.agent import Agent, Finding, FindingStore


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


@dataclass
class FakeFP:
    cms: str | None = None
    waf: object = None


class FakeWAF:
    def __init__(self, vendor: str) -> None:
        self.vendor = vendor


def _store() -> FindingStore:
    return FindingStore(":memory:")


def _adapter_returning(findings):
    def fn(target, context):
        return list(findings)

    return fn


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_register_adapter():
    a = Agent(_store())
    a.register_adapter("scan", _adapter_returning([]))
    assert "scan" in a.adapters


def test_known_platforms_passthrough():
    assert "wordpress" in Agent.known_platforms()


# ---------------------------------------------------------------------------
# Fingerprint handling
# ---------------------------------------------------------------------------


def test_run_no_fingerprinter_no_adapters_aborts():
    a = Agent(_store())
    result = a.run("http://t/")
    assert result.aborted is True
    assert "no modules" in result.abort_reason.lower()


def test_run_fingerprint_identifies_cms():
    a = Agent(
        _store(),
        adapters={"scan": _adapter_returning([])},
        fingerprinter=lambda target: FakeFP(cms="wordpress"),
    )
    result = a.run("http://t/")
    assert "wordpress" in result.platforms
    assert "scan" in result.plan


def test_run_waf_string_reported():
    a = Agent(
        _store(),
        adapters={"scan": _adapter_returning([])},
        fingerprinter=lambda target: FakeFP(cms="wordpress", waf="cloudflare"),
    )
    result = a.run("http://t/")
    assert result.waf == "cloudflare"


def test_run_waf_object_reported():
    a = Agent(
        _store(),
        adapters={"scan": _adapter_returning([])},
        fingerprinter=lambda target: FakeFP(cms="wordpress", waf=FakeWAF("sucuri")),
    )
    result = a.run("http://t/")
    assert result.waf == "sucuri"


def test_allowed_platforms_filters():
    a = Agent(
        _store(),
        adapters={"scan": _adapter_returning([])},
        fingerprinter=lambda target: FakeFP(cms="wordpress"),
        allowed_platforms=["drupal"],
    )
    result = a.run("http://t/")
    assert "wordpress" not in result.platforms


def test_extra_platforms_merged():
    a = Agent(
        _store(),
        adapters={"scan": _adapter_returning([]), "graphql": _adapter_returning([])},
        fingerprinter=lambda target: FakeFP(cms="wordpress"),
    )
    result = a.run("http://t/", extra_platforms=["graphql"])
    assert "graphql" in result.platforms
    assert "graphql" in result.plan


# ---------------------------------------------------------------------------
# Module dispatch
# ---------------------------------------------------------------------------


def test_adapters_are_invoked_and_findings_recorded():
    store = _store()
    f1 = _finding(discriminator="q")
    f2 = _finding(discriminator="id")
    a = Agent(
        store,
        adapters={
            "scan": _adapter_returning([f1]),
            "admin": _adapter_returning([f2]),
        },
        fingerprinter=lambda target: FakeFP(cms="wordpress"),
    )
    result = a.run("http://t/")
    assert result.new_findings == 2
    assert "scan" in result.modules_run
    assert "admin" in result.modules_run
    assert store.count() == 2


def test_missing_adapter_is_skipped():
    a = Agent(
        _store(),
        adapters={},
        fingerprinter=lambda target: FakeFP(cms="wordpress"),
    )
    result = a.run("http://t/")
    assert "scan" in result.modules_skipped or not result.plan


def test_adapter_exception_recorded_not_fatal():
    def bad(target, context):
        raise RuntimeError("boom")

    a = Agent(
        _store(),
        adapters={
            "scan": bad,
            "admin": _adapter_returning([_finding(discriminator="id")]),
        },
        fingerprinter=lambda target: FakeFP(cms="wordpress"),
    )
    result = a.run("http://t/")
    assert "scan" in result.modules_skipped
    assert "admin" in result.modules_run
    assert result.new_findings == 1


def test_duplicate_findings_not_double_counted():
    store = _store()
    a = Agent(
        store,
        adapters={"scan": _adapter_returning([_finding()])},
        fingerprinter=lambda target: FakeFP(cms="wordpress"),
    )
    a.run("http://t/")
    a.run("http://t/")
    assert store.count() == 1


def test_max_modules_limits_plan():
    a = Agent(
        _store(),
        adapters={
            "scan": _adapter_returning([]),
            "xmlrpc": _adapter_returning([]),
            "admin": _adapter_returning([]),
        },
        fingerprinter=lambda target: FakeFP(cms="wordpress"),
        max_modules=1,
    )
    result = a.run("http://t/")
    assert len(result.plan) == 1


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def test_run_to_dict_roundtrip():
    a = Agent(
        _store(),
        adapters={"scan": _adapter_returning([_finding()])},
        fingerprinter=lambda target: FakeFP(cms="wordpress"),
    )
    result = a.run("http://t/")
    d = result.to_dict()
    assert d["target"] == "http://t/"
    assert d["new_findings"] == 1
    assert "plan" in d
    assert "modules_run" in d


# ---------------------------------------------------------------------------
# Persistence integration
# ---------------------------------------------------------------------------


def test_run_writes_through_to_disk(tmp_path: Path):
    p = tmp_path / "findings.json"
    store = FindingStore(p)
    a = Agent(
        store,
        adapters={"scan": _adapter_returning([_finding()])},
        fingerprinter=lambda target: FakeFP(cms="wordpress"),
    )
    a.run("http://t/")
    store.save()

    store2 = FindingStore(p)
    assert store2.load() == 1
