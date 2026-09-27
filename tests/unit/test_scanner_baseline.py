"""Regression tests for Scanner.collect_baseline.

Covers the traversal-bench bug: rotating through distinct benign values made
the baseline a test of the payload list rather than the target. On endpoints
that 500 for unknown input, `modal_status` became 500, and both the status
and length gates bailed before any payload was sent.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from janissary.engine.scanner import Scanner


def _resp(status_code: int = 200, body: bytes = b"baseline-body") -> MagicMock:
    r = MagicMock(name=f"Response({status_code})")
    r.status_code = status_code
    r.content = body
    r.text = body.decode("utf-8", errors="replace")
    r.headers = {}
    r.elapsed = None  # ResponseSnapshot.from_response reads this; keep it a real None
    return r


@pytest.fixture
def make_scanner(monkeypatch):
    """Build a Scanner with preflight and _paced_request stubbed.

    `responses` is an optional callable (value -> (status_code, body)) that
    lets a test vary the reply per param value. Without it, every request
    returns the same status/body.
    """

    def _build(target: str, param: str, *, status_code: int = 200,
               body: bytes = b"baseline-body", responses=None):
        scanner = Scanner(
            target=target,
            params=[param],
            detect_waf=False,  # WAF detection would hit the real network
        )
        monkeypatch.setattr(scanner, "preflight", lambda: (True, ""))
        calls: list[tuple[str, str, str]] = []

        def fake_paced_request(url, param_, value):
            calls.append((url, param_, value))
            if responses is not None:
                code, resp_body = responses(value)
                return _resp(status_code=code, body=resp_body)
            return _resp(status_code=status_code, body=body)

        monkeypatch.setattr(scanner, "_paced_request", fake_paced_request)
        scanner._recorded_calls = calls  # type: ignore[attr-defined]
        return scanner

    return _build


def test_baseline_replays_url_value_when_present(make_scanner):
    scanner = make_scanner("http://example.test/traversal?f=readme.txt", "f")
    scanner.collect_baseline("f")

    assert scanner._recorded_calls, "collect_baseline made no requests"
    values = {value for _, _, value in scanner._recorded_calls}
    assert values == {"readme.txt"}, (
        f"expected baseline to replay the URL's value every sample, got {values}"
    )
    assert len(scanner._recorded_calls) == scanner.baseline_count


def test_baseline_falls_back_to_one_when_param_absent(make_scanner):
    """No `q` in the query string at all -> fall back to the literal '1'."""
    scanner = make_scanner("http://example.test/search", "q")
    scanner.collect_baseline("q")

    values = {value for _, _, value in scanner._recorded_calls}
    assert values == {"1"}, (
        f"expected fallback value '1' when URL has no param, got {values}"
    )
    assert len(scanner._recorded_calls) == scanner.baseline_count


def test_baseline_preserves_blank_value_when_url_says_so(make_scanner):
    """`?q=` means the user explicitly asked for empty; replay it, don't override.

    `keep_blank_values=True` in collect_baseline is what makes a bare `?q`
    (no `=`) survive as a blank value rather than being dropped. Both `?q`
    and `?q=` therefore replay '' -- the fallback to '1' only applies when
    the param is absent from the query string entirely.
    """
    scanner = make_scanner("http://example.test/search?q=", "q")
    scanner.collect_baseline("q")

    values = {value for _, _, value in scanner._recorded_calls}
    assert values == {""}, (
        f"expected blank value to be replayed verbatim, got {values}"
    )
    assert len(scanner._recorded_calls) == scanner.baseline_count


def test_baseline_is_stable_when_endpoint_500s_unknown_input(make_scanner):
    """The actual traversal bug: identical input -> stable baseline despite 500s."""
    scanner = make_scanner(
        "http://example.test/traversal?f=readme.txt", "f",
        status_code=500,
        body=b"file not found",
    )
    baseline = scanner.collect_baseline("f")

    assert baseline.is_stable_body is True


def test_500_on_unknown_input_does_not_misattribute_categories(make_scanner):
    """Reproduce the /traversal shape: known file 200s, anything else 500s.

    The baseline (readme.txt) succeeds, so the status gate is live; every
    payload 500s, so `_check_status` would fire. Those observations are
    category-agnostic -- they carry no evidence of sqli, xss, or cmdi --
    and are now suppressed as standalone findings by the scanner's
    CORROBORATOR_ONLY_TYPES filter. This test asserts no finding carries a
    category-specific label it did not earn.

    Categories are bare strings ('sqli', 'xss', 'cmdi', 'traversal'), not
    'sqli:sql_injection'.
    """
    def responses(value: str):
        if value == "readme.txt":
            return 200, b"file contents"
        return 500, b"file not found"

    scanner = make_scanner(
        "http://example.test/traversal?f=readme.txt", "f",
        responses=responses,
    )
    summary = scanner.scan(quiet=True)

    misattributed = [
        f.category for f in summary.findings
        if f.category in {"sqli", "xss", "cmdi"}
    ]
    assert not misattributed, (
        f"category-agnostic detector emitted category-specific findings: "
        f"{misattributed}"
    )
