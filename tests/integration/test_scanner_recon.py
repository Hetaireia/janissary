"""Integration tests for scanner + WAF detector + adaptive pacer."""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock

from janissary.engine.scanner import Scanner
from janissary.recon.pacer import PacerConfig


class FakeResponse:
    def __init__(self, status=200, text="ok", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.content = (text or "").encode()
        self.elapsed = datetime.timedelta(seconds=0.01)
        self.url = "http://example.test/"


def _fake_session(responses):
    session = MagicMock()
    session.get.side_effect = list(responses)
    session.post.side_effect = list(responses)
    return session


def test_scanner_skips_waf_probe_when_disabled():
    responses = [FakeResponse()] * 200
    session = _fake_session(responses)
    sc = Scanner(
        target="http://example.test/?q=1",
        params=["q"],
        baseline_count=3,
        detect_waf=False,
        session=session,
        pacer_config=PacerConfig(base_delay=0.0, min_delay=0.0),
    )
    summary = sc.scan(quiet=True)
    assert summary.waf is not None
    assert summary.waf["detected"] is False
    assert summary.waf["probes"] == []


def test_scanner_runs_waf_probe_when_enabled():
    responses = [FakeResponse()] * 200
    session = _fake_session(responses)
    sc = Scanner(
        target="http://example.test/?q=1",
        params=["q"],
        baseline_count=3,
        detect_waf=True,
        session=session,
        pacer_config=PacerConfig(base_delay=0.0, min_delay=0.0),
    )
    summary = sc.scan(quiet=True)
    assert summary.waf is not None
    assert len(summary.waf["probes"]) > 0


def test_scanner_reports_pacer_stats():
    responses = [FakeResponse()] * 200
    session = _fake_session(responses)
    sc = Scanner(
        target="http://example.test/?q=1",
        params=["q"],
        baseline_count=3,
        detect_waf=False,
        session=session,
        pacer_config=PacerConfig(base_delay=0.0, min_delay=0.0),
    )
    summary = sc.scan(quiet=True)
    assert summary.pacer is not None
    assert "current_delay" in summary.pacer
    assert summary.pacer["events"] >= 0


def test_scanner_aborts_on_preflight_failure():
    import requests

    session = MagicMock()
    session.get.side_effect = requests.RequestException("no route")
    sc = Scanner(
        target="http://example.test/?q=1",
        params=["q"],
        detect_waf=False,
        session=session,
    )
    summary = sc.scan(quiet=True)
    assert summary.aborted is True
    assert "request error" in summary.abort_reason
    assert summary.total_requests == 1
