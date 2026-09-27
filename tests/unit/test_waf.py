"""Unit tests for the WAF detector."""

from __future__ import annotations

from unittest.mock import MagicMock

from janissary.recon.waf import (
    WAFDetector,
    WAFProfile,
    _body_vendor,
    _header_vendor,
)


class FakeResponse:
    def __init__(self, status=200, headers=None, text=""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text


def _session_returning(responses):
    """Return a fake session whose get() pops responses in order."""
    session = MagicMock()
    session.get.side_effect = list(responses)
    return session


# ---------------------------------------------------------------------------
# Signature helpers
# ---------------------------------------------------------------------------


def test_header_vendor_cloudflare():
    assert _header_vendor({"CF-RAY": "abc123"}) == "cloudflare"


def test_header_vendor_unknown():
    assert _header_vendor({"X-Foo": "bar"}) is None


def test_body_vendor_cloudflare():
    assert _body_vendor("Attention Required! | Cloudflare") == "cloudflare"


def test_body_vendor_none():
    assert _body_vendor("hello world") is None


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


def test_detector_flags_vendor_from_headers():
    headers = {"CF-RAY": "abc", "Server": "cloudflare"}
    resp = FakeResponse(status=200, headers=headers, text="ok")
    session = _session_returning([resp] * 6)

    det = WAFDetector(session=session, timeout=1.0)
    profile = det.detect("http://example.test/?q=1")

    assert isinstance(profile, WAFProfile)
    assert profile.detected is True
    assert profile.vendor == "cloudflare"
    assert profile.confidence > 0.0


def test_detector_flags_waf_from_blocked_probes():
    # No vendor signature, but multiple blocks.
    resp = FakeResponse(status=403, headers={}, text="forbidden")
    session = _session_returning([resp] * 6)

    det = WAFDetector(session=session, timeout=1.0)
    profile = det.detect("http://example.test/?q=1")

    assert profile.detected is True
    assert profile.vendor is None
    assert any("blocked" in n for n in profile.notes)


def test_detector_no_waf():
    resp = FakeResponse(status=200, headers={}, text="ok")
    session = _session_returning([resp] * 6)

    det = WAFDetector(session=session, timeout=1.0)
    profile = det.detect("http://example.test/?q=1")

    assert profile.detected is False
    assert profile.vendor is None


def test_detector_single_block_is_low_confidence():
    responses = [FakeResponse(status=403, headers={}, text="forbidden")]
    responses += [FakeResponse(status=200, headers={}, text="ok")] * 5
    session = _session_returning(responses)

    det = WAFDetector(session=session, timeout=1.0)
    profile = det.detect("http://example.test/?q=1")

    assert profile.detected is False
    assert profile.confidence <= 0.3


def test_detector_handles_request_exception():
    import requests

    session = MagicMock()
    session.get.side_effect = requests.RequestException("boom")

    det = WAFDetector(session=session, timeout=1.0)
    profile = det.detect("http://example.test/?q=1")

    assert profile.detected is False
    assert all(p.status is None for p in profile.probes)


def test_profile_to_dict_roundtrip():
    resp = FakeResponse(status=403, headers={"CF-RAY": "x"}, text="blocked")
    session = _session_returning([resp] * 6)

    det = WAFDetector(session=session, timeout=1.0)
    profile = det.detect("http://example.test/?q=1")
    d = profile.to_dict()

    assert d["detected"] is True
    assert d["vendor"] == "cloudflare"
    assert len(d["probes"]) == 6
    assert "confidence" in d
