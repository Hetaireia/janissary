from unittest.mock import MagicMock

from janissary.protocols import BaselineNormalizer, HTTPNormalizer, NormalizedResponse


def _r(text, status=200, headers=None):
    r = MagicMock()
    r.text = text
    r.status_code = status
    r.headers = headers or {}
    return r


def test_normalized_response_constructs():
    nr = NormalizedResponse(body="x", length=1, status=200)
    assert nr.body == "x" and nr.length == 1 and nr.status == 200
    assert nr.headers == {} and nr.stripped == ()


def test_stripped_is_tuple():
    nr = NormalizedResponse(body="x", length=1, status=200, stripped=("a", "b"))
    assert isinstance(nr.stripped, tuple)


def test_satisfies_protocol():
    assert isinstance(HTTPNormalizer(), BaselineNormalizer)
    assert HTTPNormalizer.protocol_name == "http"


def test_body_delegates_to_normalize_body():
    from janissary.detection.analyzer import normalize_body

    n = HTTPNormalizer()
    body = "  a\n\n  b  \t  c  "
    nr = n.normalize(_r(body))
    assert nr.body == normalize_body(body) and nr.length == len(nr.body)


def test_strips_csrf_from_body():
    n = HTTPNormalizer()
    nr = n.normalize(_r('<input name="csrf_token" value="abc123XYZ_-">'))
    assert "abc123XYZ_-" not in nr.body
    assert "[CSRF]" in nr.body or "[REDACTED]" in nr.body


def test_redacts_set_cookie_session():
    n = HTTPNormalizer()
    nr = n.normalize(_r("ok", headers={"Set-Cookie": "session=abc123def456; Path=/"}))
    c = nr.headers["Set-Cookie"]
    assert "abc123def456" not in c and "REDACTED" in c
    assert "header:set-cookie" in nr.stripped


def test_redacts_volatile_headers():
    n = HTTPNormalizer()
    nr = n.normalize(
        _r(
            "ok",
            headers={
                "X-CSRF-Token": "v",
                "X-Request-ID": "t",
                "Content-Type": "text/html",
            },
        )
    )
    assert nr.headers["X-CSRF-Token"] == "[REDACTED]"
    assert nr.headers["X-Request-ID"] == "[REDACTED]"
    assert nr.headers["Content-Type"] == "text/html"
    assert "header:x-csrf-token" in nr.stripped and "header:x-request-id" in nr.stripped


def test_non_volatile_passes_through():
    n = HTTPNormalizer()
    nr = n.normalize(_r("plain body", 200, {"Content-Type": "text/plain"}))
    assert nr.stripped == () and nr.status == 200 and nr.body == "plain body"
