"""A01 / M73: OpenAPI query parameters must inject into VALUES.

The dispatch layer previously mapped query parameters to Scanner's
param-name mode, which sends the payload as the parameter NAME. That is
correct for OWASP Benchmark getParameterNames cases, but wrong for
OpenAPI query parameters, where the declared name must stay fixed and
the value must be fuzzed.

These tests verify the wire, not the mode string. They parse the outgoing
request URL and assert both the parameter name and its value, so a
regression that swaps name-for-value is caught even if the URL still
contains both substrings.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

from janissary.engine.scanner import Scanner


def _capture(inject_in):
    captured = []

    def fake_send(session_self, request, **kwargs):
        captured.append(request)
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "ok"
        resp.headers = {}
        resp.request = request
        return resp

    s = Scanner(
        target="https://example.test/items",
        params=["limit"],
        method="GET",
        inject_in=inject_in,
    )
    with patch("requests.Session.send", fake_send):
        s._request("https://example.test/items", "limit", "PAYLOAD")
    return captured


def _query_dicts(captured):
    out = []
    for req in captured:
        parsed = urlparse(req.url)
        out.append(parse_qs(parsed.query, keep_blank_values=True))
    return out


def test_query_mode_sends_payload_as_value_under_declared_name():
    """query mode must produce ?limit=PAYLOAD, never ?PAYLOAD=limit."""
    qs_list = _query_dicts(_capture("query"))
    assert qs_list, "No HTTP request captured during Scanner._request"
    matched = False
    for qs in qs_list:
        if "limit" in qs and any("PAYLOAD" in v for v in qs["limit"]):
            matched = True
            assert "PAYLOAD" not in qs, (
                "query mode keeps the declared name as key, but 'PAYLOAD' "
                "appeared as a key. Got query dict: " + repr(qs)
            )
    assert matched, (
        "Expected ?limit=PAYLOAD (declared name as key, payload as value). "
        "Got: " + repr(qs_list)
    )


def test_param_name_mode_sends_payload_as_parameter_name():
    """param-name mode must produce ?PAYLOAD=limit -- distinct from query mode."""
    qs_list = _query_dicts(_capture("param-name"))
    assert qs_list, "No HTTP request captured during Scanner._request"
    matched = False
    for qs in qs_list:
        if "PAYLOAD" in qs and any("limit" in v for v in qs["PAYLOAD"]):
            matched = True
            assert "limit" not in qs, (
                "param-name mode moves the payload into the key, but 'limit' "
                "appeared as a key. Got query dict: " + repr(qs)
            )
    assert matched, (
        "Expected ?PAYLOAD=limit (payload as key, declared name as value). "
        "Got: " + repr(qs_list)
    )
