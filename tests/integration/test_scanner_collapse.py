"""Integration tests for collapse oracle wiring in Scanner (ADR-006)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from janissary.engine import scanner as scanner_mod
from janissary.engine.baseline_struct import ArmingReason, BaselineArmingState
from janissary.engine.dom_hash import fingerprint
from janissary.engine.scanner import Scanner

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
REAL_FORM = (FIXTURES / "real_html_form.html").read_text(encoding="utf-8")
PASSWD = (FIXTURES / "etc_passwd.txt").read_text(encoding="utf-8")


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/html"}
        self.elapsed = timedelta(seconds=0.01)
        self.cookies = {}


class FakeSession:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        return self.handler(url)

    def close(self):
        pass


def _handler(url: str):
    u = url.lower()
    if "noexist" in u:
        return FakeResponse(200, REAL_FORM, {"content-type": "text/html"})
    if "passwd" in u:
        return FakeResponse(200, PASSWD, {"content-type": "text/plain"})
    return FakeResponse(200, REAL_FORM, {"content-type": "text/html"})


def _make_scanner() -> Scanner:
    return Scanner(
        target="http://t/search?q=test",
        params=["q"],
        baseline_count=3,
        session=FakeSession(_handler),
        delay=0.0,
        detect_waf=False,
    )


def _force_armed(monkeypatch):
    fp_vals = (fingerprint(REAL_FORM).value,) * 3

    def fake_arming(baseline):
        return BaselineArmingState(
            armed=True,
            reason=ArmingReason.ARMED,
            fingerprints=fp_vals,
            root_signature=None,
            sample_count=3,
            hamming_max=0,
        )

    monkeypatch.setattr(scanner_mod, "compute_arming_state", fake_arming)


def _force_unarmed(monkeypatch):
    def fake_arming(baseline):
        return BaselineArmingState(
            armed=False,
            reason=ArmingReason.UNARMED_DISPERSION,
            fingerprints=(),
            root_signature=None,
            sample_count=0,
            hamming_max=0,
        )

    monkeypatch.setattr(scanner_mod, "compute_arming_state", fake_arming)


def _collapse_count(summary):
    return sum(1 for f in summary.findings if f.finding_type == "traversal_collapse")


def test_armed_emits_collapse(monkeypatch):
    _force_armed(monkeypatch)
    summary = _make_scanner().scan(quiet=True)
    assert _collapse_count(summary) >= 1
    first = next(f for f in summary.findings if f.finding_type == "traversal_collapse")
    assert first.category == "traversal"
    assert first.severity == "critical"
    arming = summary.baselines["q"]["arming"]
    assert arming["armed"] is True
    assert arming["emitted_count"] >= 1


def test_unarmed_passes_through(monkeypatch):
    _force_unarmed(monkeypatch)
    summary = _make_scanner().scan(quiet=True)
    assert _collapse_count(summary) == 0


def test_armed_with_root_signature_none_still_emits(monkeypatch):
    """ADR-006 D7: collapse path does not consult root_signature."""
    _force_armed(monkeypatch)
    summary = _make_scanner().scan(quiet=True)
    assert _collapse_count(summary) >= 1
