"""Tests for SSRF redirect-chain OOB payloads (ADR-028 BL-1b)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from janissary.engine.scanner import ScanSummary, Scanner


def _make_collab() -> MagicMock:
    """Collaborator stub that records calls and returns no hits."""
    collab = MagicMock()
    collab.new_unique_id.side_effect = lambda name: f"u_{name}"
    collab.payload_for.side_effect = (
        lambda p, u: p.url_template.format(uniq=u, collab="collab.example.com")
    )
    collab.poll.return_value = []
    return collab


def _summary() -> ScanSummary:
    return ScanSummary(target="http://example.com/x", params=["q"], method="GET")


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Skip the ssrf poll delays so tests run in milliseconds, not 10s each."""
    import janissary.engine.scanner as _sc
    monkeypatch.setattr(_sc.time, "sleep", lambda _s: None)


def test_redirect_oob_payloads_issued_when_flag_set():
    """With --ssrf-redirector, new_unique_id is called for both OOB redirect payloads."""
    collab = _make_collab()
    s = Scanner(
        target="http://example.com/x",
        params=["q"],
        ssrf_redirector="https://redir.example.com/r",
        collaborator=collab,
    )
    s._ssrf_phase("q", _summary(), quiet=True)
    called = [c.args[0] for c in collab.new_unique_id.call_args_list]
    assert "ssrf_redirect_oob_http" in called
    assert "ssrf_redirect_oob_https" in called


def test_redirect_oob_payload_url_shape():
    """OOB redirect payload value is <redirector>?to=<proto>://<uniq>.<collab>/."""
    collab = _make_collab()
    seen_payloads = []
    original = collab.payload_for.side_effect

    def _capture(payload, uniq):
        seen_payloads.append(payload)
        return original(payload, uniq)

    collab.payload_for.side_effect = _capture

    s = Scanner(
        target="http://example.com/x",
        params=["q"],
        ssrf_redirector="https://redir.example.com/r",
        collaborator=collab,
    )
    s._ssrf_phase("q", _summary(), quiet=True)

    oob = [p for p in seen_payloads if "redirect_oob" in p.name]
    assert len(oob) == 2, f"expected 2 OOB payloads, saw {[p.name for p in seen_payloads]}"

    rendered = [collab.payload_for(p, "u1") for p in oob]
    assert any(
        "https://redir.example.com/r?to=http://u1.collab.example.com/" == r
        for r in rendered
    ), rendered
    assert any(
        "https://redir.example.com/r?to=https://u1.collab.example.com/" == r
        for r in rendered
    ), rendered


def test_no_redirect_oob_without_redirector():
    """Without --ssrf-redirector, no ssrf_redirect_oob_* payload is issued."""
    collab = _make_collab()
    s = Scanner(
        target="http://example.com/x",
        params=["q"],
        collaborator=collab,
    )
    s._ssrf_phase("q", _summary(), quiet=True)
    called = [c.args[0] for c in collab.new_unique_id.call_args_list]
    assert not any("redirect_oob" in n for n in called), called


def test_redirect_oob_with_redirector_uses_collab():
    """With --ssrf-redirector, redirect OOB payloads still route through collaborator."""
    collab = _make_collab()
    s = Scanner(
        target="http://example.com/x",
        params=["q"],
        ssrf_redirector="https://redir.example.com/r",
        collaborator=collab,
    )
    s._ssrf_phase("q", _summary(), quiet=True)
    called = [c.args[0] for c in collab.new_unique_id.call_args_list]
    assert any("redirect_oob" in n for n in called), called
    # base SSRF payloads still issued
    assert any(n.startswith("ssrf_http") for n in called), called
