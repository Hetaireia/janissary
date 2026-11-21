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
    assert ssrf[0].evidence_grade == "P1"
    assert "1.2.3.4" in ssrf[0].detail


def test_scanner_ssrf_dns_only_emits_candidate():
    """ADR-034 D3/D5: DNS-only -> candidates, unproven, P4."""
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

    assert [f for f in summary.findings if f.category == "ssrf"] == []
    ssrf_cand = [f for f in summary.candidates if f.category == "ssrf"]
    assert len(ssrf_cand) == 1
    assert ssrf_cand[0].severity == "info"
    assert ssrf_cand[0].finding_type == "dns_only_resolution"
    assert ssrf_cand[0].evidence_grade == "P4"
    assert ssrf_cand[0].verification_status == "unproven"
    assert "oob_dns_only_no_http" in (ssrf_cand[0].verification_reason or "")
    assert "5.6.7.8" in ssrf_cand[0].detail


def test_scanner_ssrf_http_suppresses_dns_on_same_param():
    """ADR-034 D2: HTTP fetch present -> DNS-only suppressed entirely."""
    from janissary.engine.scanner import ScanSummary
    from janissary.integrations.collaborator import SsrfHit

    session = MagicMock()
    session.get.return_value = _ok_response()

    collab = MagicMock()
    collab.new_unique_id.side_effect = [f"jns-m{i}" for i in range(5)]
    collab.payload_for.side_effect = lambda p, u: f"http://{u}.collab.example.com/"
    http_hit = SsrfHit(
        protocol="http",
        payload_name="ssrf_http",
        subdomain="jns-m0",
        source_ip="1.2.3.4",
        timestamp="2026-10-28T00:00:00Z",
    )
    dns_hit = SsrfHit(
        protocol="dns",
        payload_name="ssrf_dns_only",
        subdomain="jns-m1",
        source_ip="5.6.7.8",
    )
    collab.poll.side_effect = lambda u: {"jns-m0": [http_hit], "jns-m1": [dns_hit]}.get(
        u, []
    )

    scanner = _scanner_with_collab(collab, session)
    summary = ScanSummary(target="http://target.example/", params=["q"], method="GET")
    scanner._ssrf_phase("q", summary, quiet=True)

    ssrf = [f for f in summary.findings if f.category == "ssrf"]
    assert len(ssrf) == 1
    assert ssrf[0].finding_type == "collaborator_hit"
    assert ssrf[0].evidence_grade == "P1"
    assert [f for f in summary.candidates if f.category == "ssrf"] == []


def test_scanner_ssrf_http_after_dns_upgrades_to_collaborator_hit():
    """ADR-034 D1: delayed HTTP hit on same uniq overrides earlier DNS."""
    from janissary.engine.scanner import ScanSummary
    from janissary.integrations.collaborator import SsrfHit

    session = MagicMock()
    session.get.return_value = _ok_response()

    collab = MagicMock()
    collab.new_unique_id.side_effect = [f"jns-l{i}" for i in range(5)]
    collab.payload_for.side_effect = lambda p, u: f"http://{u}.collab.example.com/"
    dns_hit = SsrfHit(
        protocol="dns",
        payload_name="ssrf_dns_only",
        subdomain="jns-l0",
        source_ip="5.6.7.8",
    )
    http_hit = SsrfHit(
        protocol="http",
        payload_name="ssrf_http",
        subdomain="jns-l0",
        source_ip="1.2.3.4",
        timestamp="2026-10-28T00:00:00Z",
    )
    poll_calls = []

    def _poll(u):
        if u != "jns-l0":
            return []
        if len(poll_calls) == 0:
            poll_calls.append(1)
            return [dns_hit]
        return [http_hit]

    collab.poll.side_effect = _poll

    scanner = _scanner_with_collab(collab, session)
    summary = ScanSummary(target="http://target.example/", params=["q"], method="GET")
    scanner._ssrf_phase("q", summary, quiet=True)

    ssrf = [f for f in summary.findings if f.category == "ssrf"]
    assert len(ssrf) == 1
    assert ssrf[0].finding_type == "collaborator_hit"
    assert ssrf[0].evidence_grade == "P1"
    assert [f for f in summary.candidates if f.category == "ssrf"] == []


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
