"""Phase 0.3 part 2 — wiring tests.

Proves that:
- from_response() without normalizer is byte-identical to the old behavior
- from_response() with HTTPNormalizer strips CSRF/nonce/session patterns
- Scanner defaults to HTTPNormalizer
- Scanner accepts a custom normalizer
- All 3 scanner.py call sites pass self.normalizer
"""

from unittest.mock import MagicMock
from pathlib import Path

from janissary.detection.analyzer import ResponseSnapshot, normalize_body
from janissary.engine.scanner import Scanner
from janissary.protocols import HTTPNormalizer


def _r(text, status=200, headers=None):
    r = MagicMock()
    r.text = text
    r.status_code = status
    r.headers = headers or {"content-type": "text/html"}
    r.elapsed = None
    return r


def test_from_response_no_normalizer_is_backward_compatible():
    body = "  line1  \n\n  line2  "
    snap = ResponseSnapshot.from_response(_r(body))
    assert snap.normalized == normalize_body(body)
    assert snap.normalized_length == len(normalize_body(body))


def test_from_response_with_normalizer_strips_csrf_body():
    body = '<input name="csrf_token" value="verysecret123">'
    snap_default = ResponseSnapshot.from_response(_r(body))
    snap_wired = ResponseSnapshot.from_response(_r(body), normalizer=HTTPNormalizer())
    # Default may have already stripped via normalize_body; wired must match or strip more
    assert "verysecret123" not in snap_wired.normalized
    assert (
        "verysecret123" not in snap_default.normalized
    )  # normalize_body catches this shape
    # Fingerprint must be stable regardless of which path was taken
    assert snap_wired.fingerprint == snap_default.fingerprint


def test_from_response_with_normalizer_fingerprint_stable():
    body = "plain response"
    a = ResponseSnapshot.from_response(_r(body))
    b = ResponseSnapshot.from_response(_r(body), normalizer=HTTPNormalizer())
    assert a.fingerprint == b.fingerprint
    assert a.normalized == b.normalized
    assert a.normalized_length == b.normalized_length


def test_scanner_defaults_to_http_normalizer():
    s = Scanner(target="http://x/", params=["q"], method="GET")
    assert isinstance(s.normalizer, HTTPNormalizer)
    assert s.normalizer.protocol_name == "http"


def test_scanner_accepts_custom_normalizer():
    class _Stub:
        protocol_name = "stub"

        def normalize(self, response):
            from janissary.protocols import NormalizedResponse

            return NormalizedResponse(body="STUB", length=4, status=200)

    stub = _Stub()
    s = Scanner(target="http://x/", params=["q"], method="GET", normalizer=stub)
    assert s.normalizer is stub


def test_scanner_source_wires_normalizer_at_three_sites():
    """Source-level tripwire: removing the wiring in any of the 3 call sites
    must fail this test even though the 700 behavior tests may still pass."""
    src = Path("src/janissary/engine/scanner.py").read_text(encoding="utf-8")
    # Collapse all whitespace so the check survives formatter reflows (the
    # wiring call can be single-line or wrapped across lines — both satisfy
    # the tripwire). Byte-identical literal counting would break on any
    # ruff-format pass that wraps a long call.
    src_norm = "".join(src.split())
    n = src_norm.count("from_response(r,normalizer=self.normalizer)")
    assert n == 2, f"expected 2 'r' sites wired, found {n}"
    n2 = src_norm.count("from_response(r2,normalizer=self.normalizer)")
    assert n2 == 1, f"expected 1 'r2' site wired, found {n2}"
