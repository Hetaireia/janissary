"""Tests for Scanner._request injection modes and the length_anomaly

corroborator policy change.

The scanner previously placed payloads only in the URL query (GET) or the

request body (POST). Cookie-parameterized targets (OWASP Benchmark) were

unreachable. `inject_in` fixes that. Separately, `length_anomaly` was

unconditionally dropped as a corroborator; it now surfaces when the

baseline is stable 2xx and the payload response is also 2xx.

"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from janissary.engine.scanner import Scanner


def _scanner(method: str = "GET", inject_in: str = "auto") -> Scanner:

    return Scanner(

        target="http://example.test/x",

        params=["p"],

        method=method,

        detect_waf=False,

        inject_in=inject_in,

    )

def _record_session(scanner: Scanner) -> list[tuple[str, dict]]:

    calls: list[tuple[str, dict]] = []

    def fake_get(url, **kw):

        calls.append(("GET", {"url": url, **kw}))

        return MagicMock()

    def fake_post(url, **kw):

        calls.append(("POST", {"url": url, **kw}))

        return MagicMock()

    scanner.session.get = fake_get  # type: ignore[assignment]

    scanner.session.post = fake_post  # type: ignore[assignment]

    return calls

def test_auto_get_puts_payload_in_query():

    s = _scanner("GET", "auto")

    calls = _record_session(s)

    s._request(s.target, "p", "PAY")

    assert len(calls) == 1

    verb, kw = calls[0]

    assert verb == "GET"

    assert "p=PAY" in kw["url"]

    assert "data" not in kw and "cookies" not in kw

def test_auto_post_puts_payload_in_body():

    s = _scanner("POST", "auto")

    calls = _record_session(s)

    s._request(s.target, "p", "PAY")

    verb, kw = calls[0]

    assert verb == "POST"

    assert kw["data"] == {"p": "PAY"}

    assert "cookies" not in kw

def test_cookie_mode_post_sends_payload_as_cookie():

    s = _scanner("POST", "cookie")

    calls = _record_session(s)

    s._request(s.target, "p", "PAY")

    verb, kw = calls[0]

    assert verb == "POST"

    assert kw["cookies"] == {"p": "PAY"}

    assert "data" not in kw

def test_cookie_mode_get_sends_payload_as_cookie():

    s = _scanner("GET", "cookie")

    calls = _record_session(s)

    s._request(s.target, "p", "PAY")

    verb, kw = calls[0]

    assert verb == "GET"

    assert kw["cookies"] == {"p": "PAY"}

    assert "p=PAY" not in kw["url"]

def test_body_mode_get_still_posts_body():

    s = _scanner("GET", "body")

    calls = _record_session(s)

    s._request(s.target, "p", "PAY")

    verb, kw = calls[0]

    assert verb == "POST"

    assert kw["data"] == {"p": "PAY"}

def test_header_mode_get_sets_named_header():

    s = _scanner("GET", "header")

    calls = _record_session(s)

    s._request(s.target, "X-Bench", "PAY")

    verb, kw = calls[0]

    assert verb == "GET"

    assert kw["headers"].get("X-Bench") == "PAY"

    assert "cookies" not in kw and "data" not in kw

def test_header_mode_post_sets_named_header():

    s = _scanner("POST", "header")

    calls = _record_session(s)

    s._request(s.target, "X-Bench", "PAY")

    verb, kw = calls[0]

    assert verb == "POST"

    assert kw["headers"].get("X-Bench") == "PAY"

def test_param_name_mode_post_swaps_key_and_value():
    s = _scanner("POST", "param-name")
    calls = _record_session(s)
    s._request(s.target, "BenchmarkTest00035", "PAYLOAD")
    verb, kw = calls[0]
    assert verb == "POST"
    assert kw["data"] == {"PAYLOAD": "BenchmarkTest00035"}

def test_param_name_mode_get_swaps_key_and_value():
    s = _scanner("GET", "param-name")
    calls = _record_session(s)
    s._request(s.target, "BenchmarkTest00035", "PAYLOAD")
    verb, kw = calls[0]
    assert verb == "GET"
    assert "PAYLOAD=BenchmarkTest00035" in kw["url"]

def test_invalid_inject_in_rejected():

    with pytest.raises(ValueError):

        _scanner("GET", "nope")

# -- length_anomaly corroborator policy ----------------------------

#

# End-to-end through scan(): a scanner whose baseline is stable 2xx, and

# whose payload responses are 2xx but much larger. The prior code dropped

# length_anomaly unconditionally; the new code emits it. And the /traversal

# shape (baseline 200, payloads 500) must still suppress everything.

def _resp(status_code: int = 200, body: bytes = b"body") -> MagicMock:

    r = MagicMock(name=f"Response({status_code})")

    r.status_code = status_code

    r.content = body

    r.text = body.decode("utf-8", errors="replace")

    r.headers = {}

    r.elapsed = None

    # serialize_request reads response.request.url / .method / .headers

    req = MagicMock()

    req.url = "http://example.test/x"

    req.method = "POST"

    req.headers = {}

    r.request = req

    return r

def test_scan_suppresses_length_anomaly_on_stable_2xx(monkeypatch):
    """length_anomaly is a corroborator, not a detector. A large body
    delta on a reflecting target is not diagnostic of any category, so
    it must stay suppressed even when the baseline is stable 2xx and
    the payload response is also 2xx. Real detection for those cases
    requires content-signature gates."""
    s = _scanner("POST", "cookie")
    monkeypatch.setattr(s, "preflight", lambda: (True, ""))

    def paced(url, param, value):
        if value == "1":
            return _resp(200, b"tiny")
        return _resp(200, b"x" * 5000)

    monkeypatch.setattr(s, "_paced_request", paced)
    summary = s.scan(quiet=True)
    assert not summary.findings, [f.finding_type for f in summary.findings]

def test_scan_suppresses_corroborators_on_erroring_baseline(monkeypatch):

    """The original /traversal shape: baseline 200 on known input, but

    every payload returns 500. Corroborators must stay filtered so no

    finding carries a category label it did not earn."""

    s = _scanner("POST", "cookie")

    monkeypatch.setattr(s, "preflight", lambda: (True, ""))

    def paced(url, param, value):

        if value == "1":

            return _resp(200, b"readme.txt contents")

        return _resp(500, b"file not found")

    monkeypatch.setattr(s, "_paced_request", paced)

    summary = s.scan(quiet=True)

    assert not summary.findings, [f.finding_type for f in summary.findings]

