# JANISSARY-FN-4
"""FN-4: agent falls back to a scan adapter when fingerprinting yields no plan."""
from __future__ import annotations

import janissary.agent.adapters as A
import janissary.engine.scanner as S


class _FakeScanFinding:
    param = "id"
    payload_name = "sqli"
    payload_value = "' OR 1=1"
    category = "sqli"
    severity = "high"
    finding_type = "error-based"
    detail = "sql syntax error"
    response_status = 500
    response_length = 42
    response_time = 0.1
    reflection_context = None
    response_content_type = "text/html"
    fingerprint = "abc123"
    url = "http://x/y?id=1"


class _FakeSummary:
    aborted = False
    abort_reason = ""
    findings = [_FakeScanFinding()]


def test_scan_adapter_is_registered():
    assert "scan" in A.default_adapters()


def test_scan_adapter_maps_scanfindings_to_agent_findings(monkeypatch):
    class _FakeScanner:
        def __init__(self, **kw): self.kw = kw
        def scan(self): return _FakeSummary()

    monkeypatch.setattr(S, "Scanner", _FakeScanner)
    out = A.scan_adapter("http://x/y?id=1", {"session": None})
    assert len(out) == 1
    f = out[0]
    assert f.category == "sqli"
    assert f.severity == "high"
    assert f.discriminator == "id:sqli"
    assert f.payload == "' OR 1=1"
    assert f.response_status == 500


def test_scan_adapter_returns_empty_on_abort(monkeypatch):
    class _FakeScanner:
        def __init__(self, **kw): pass
        def scan(self):
            s = _FakeSummary()
            s.aborted = True
            s.abort_reason = "test"
            return s

    monkeypatch.setattr(S, "Scanner", _FakeScanner)
    out = A.scan_adapter("http://x/y?id=1", {"session": None})
    assert out == []
