"""Unit tests for SSRF collaborator client (ADR-012)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from janissary.integrations.collaborator import (
    CollaboratorClient,
    CollaboratorError,
    SsrfPayload,
)


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.url = ""
        self.request = None

    def json(self):
        import json

        return json.loads(self.text)


def _collab_session(responses):
    s = MagicMock()
    s.get.side_effect = list(responses)
    s.close = MagicMock()
    return s


def test_client_new_unique_id_format():
    """Uniq format is 'jns-' + 16 hex, distinct across calls."""
    c = CollaboratorClient("http://collab.example.com", session=_collab_session([]))
    u1 = c.new_unique_id()
    u2 = c.new_unique_id()
    assert u1.startswith("jns-")
    assert len(u1) == 20
    assert u1 != u2


def test_client_payload_for_renders_url():
    """Template substitution fills {uniq} and {collab}."""
    c = CollaboratorClient("http://collab.example.com", session=_collab_session([]))
    payload = SsrfPayload("test", "http://{uniq}.{collab}/")
    url = c.payload_for(payload, "jns-abc123")
    assert "jns-abc123" in url
    assert "collab.example.com" in url


def test_client_poll_empty_body_returns_empty():
    """204 No Content -> empty list, no exception."""
    c = CollaboratorClient(
        "http://collab.example.com",
        session=_collab_session([FakeResp(status=204, text="")]),
    )
    assert c.poll("jns-abc") == []


def test_client_poll_transport_error_raises():
    """Transport failure surfaces as CollaboratorError."""
    s = MagicMock()
    s.get.side_effect = requests.RequestException("boom")
    c = CollaboratorClient("http://collab.example.com", session=s)
    with pytest.raises(CollaboratorError):
        c.poll("jns-abc")


# ---------------------------------------------------------------------------
# Scanner._ssrf_phase integration (ADR-012 D3-D5)
# ---------------------------------------------------------------------------


def _scanner_with_collab(collab_mock, session_mock, **kwargs):
    """Build a Scanner pre-configured for SSRF phase testing (no sleeps)."""
    from janissary.engine.scanner import Scanner

    s = Scanner(
        target="http://target.example/",
        params=["q"],
        session=session_mock,
        detect_waf=False,
        collaborator=collab_mock,
        **kwargs,
    )
    s._ssrf_poll_delays = [0.001, 0.001, 0.001]
    return s


def _ok_response():
    return FakeResp(status=200, text="ok", headers={"content-type": "text/html"})


def test_scanner_ssrf_hit_http_emits_finding():
    """HTTP collaborator hit -> critical finding with collaborator_hit type."""
    from janissary.engine.scanner import ScanSummary
    from janissary.integrations.collaborator import SsrfHit

    session = MagicMock()
    session.get.return_value = _ok_response()

    collab = MagicMock()
    collab.new_unique_id.side_effect = [f"jns-u{i}" for i in range(5)]
    collab.payload_for.side_effect = lambda p, u: f"http://{u}.collab.example.com/"
    target_hit = SsrfHit(
        protocol="http",
        payload_name="ssrf_http",
        subdomain="jns-u0",
        source_ip="1.2.3.4",
        timestamp="2026-10-28T00:00:00Z",
    )
    collab.poll.side_effect = lambda u: [target_hit] if u == "jns-u0" else []

    scanner = _scanner_with_collab(collab, session)
    summary = ScanSummary(target="http://target.example/", params=["q"], method="GET")
    scanner._ssrf_phase("q", summary, quiet=True)

    ssrf = [f for f in summary.findings if f.category == "ssrf"]
    assert len(ssrf) == 1
    assert ssrf[0].severity == "critical"
    assert ssrf[0].finding_type == "collaborator_hit"
    assert "1.2.3.4" in ssrf[0].detail


def test_scanner_ssrf_dns_only_emits_info():
    """DNS-only hit -> info finding, not critical."""
    from janissary.engine.scanner import ScanSummary
    from janissary.integrations.collaborator import SsrfHit

    session = MagicMock()
    session.get.return_value = _ok_response()

    collab = MagicMock()
    collab.new_unique_id.side_effect = [f"jns-d{i}" for i in range(5)]
    collab.payload_for.side_effect = lambda p, u: f"http://{u}.collab.example.com:9/"
    target_hit = SsrfHit(
        protocol="dns",
        payload_name="ssrf_dns_only",
        subdomain="jns-d0",
        source_ip="5.6.7.8",
    )
    collab.poll.side_effect = lambda u: [target_hit] if u == "jns-d0" else []

    scanner = _scanner_with_collab(collab, session)
    summary = ScanSummary(target="http://target.example/", params=["q"], method="GET")
    scanner._ssrf_phase("q", summary, quiet=True)

    ssrf = [f for f in summary.findings if f.category == "ssrf"]
    assert len(ssrf) == 1
    assert ssrf[0].severity == "info"
    assert ssrf[0].finding_type == "dns_only_resolution"


def test_scanner_ssrf_collaborator_unreachable_skips_phase():
    """CollaboratorError during poll -> phase continues, no findings, no crash."""
    from janissary.engine.scanner import ScanSummary
    from janissary.integrations.collaborator import CollaboratorError

    session = MagicMock()
    session.get.return_value = _ok_response()

    collab = MagicMock()
    collab.new_unique_id.return_value = "jns-down"
    collab.payload_for.return_value = "http://jns-down.collab.example.com/"
    collab.poll.side_effect = CollaboratorError("unreachable")

    scanner = _scanner_with_collab(collab, session)
    summary = ScanSummary(target="http://target.example/", params=["q"], method="GET")
    scanner._ssrf_phase("q", summary, quiet=True)

    ssrf = [f for f in summary.findings if f.category == "ssrf"]
    assert ssrf == []


def test_scanner_ssrf_no_collaborator_no_ssrf_findings():
    """Without collaborator, _ssrf_phase is a no-op (benchmark neutral)."""
    from janissary.engine.scanner import ScanSummary

    session = MagicMock()
    session.get.return_value = _ok_response()

    from janissary.engine.scanner import Scanner

    scanner = Scanner(
        target="http://target.example/",
        params=["q"],
        session=session,
        detect_waf=False,
        collaborator=None,
    )
    summary = ScanSummary(target="http://target.example/", params=["q"], method="GET")
    before = summary.total_requests
    scanner._ssrf_phase("q", summary, quiet=True)
    assert summary.total_requests == before  # no requests made
    assert [f for f in summary.findings if f.category == "ssrf"] == []
