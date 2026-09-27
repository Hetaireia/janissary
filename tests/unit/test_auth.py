"""Unit tests for janissary.auth."""

from __future__ import annotations

from janissary.auth import (
    REDACTED,
    AuthConfig,
    apply_to_session,
    auth_from_args,
    redact_headers,
    redact_raw_http,
)


class TestAuthConfig:
    def test_empty(self):
        a = AuthConfig()
        assert a.is_empty
        assert a.headers() == {}

    def test_cookie_only(self):
        a = AuthConfig(cookie="a=b; c=d")
        assert not a.is_empty
        assert a.headers() == {"Cookie": "a=b; c=d"}

    def test_bearer_only(self):
        a = AuthConfig(bearer="tok123")
        assert a.headers() == {"Authorization": "Bearer tok123"}

    def test_both(self):
        a = AuthConfig(cookie="s=x", bearer="t")
        h = a.headers()
        assert h["Cookie"] == "s=x"
        assert h["Authorization"] == "Bearer t"

    def test_to_dict_redacts(self):
        a = AuthConfig(cookie="secret", bearer="tok")
        d = a.to_dict()
        assert d["cookie"] == REDACTED
        assert d["bearer"] == REDACTED


class _FakeSession:
    def __init__(self):
        self.headers = {}


class TestApplyToSession:
    def test_empty_is_noop(self):
        s = _FakeSession()
        apply_to_session(s, AuthConfig())
        assert s.headers == {}

    def test_installs_headers(self):
        s = _FakeSession()
        apply_to_session(s, AuthConfig(cookie="c=1", bearer="t"))
        assert s.headers["Cookie"] == "c=1"
        assert s.headers["Authorization"] == "Bearer t"

    def test_none_config_ok(self):
        s = _FakeSession()
        apply_to_session(s, None)
        assert s.headers == {}


class TestRedactHeaders:
    def test_no_secrets_untouched(self):
        h = {"Content-Type": "text/html", "X-Trace": "abc"}
        assert redact_headers(h) == h

    def test_authorization_redacted(self):
        h = {"Authorization": "Bearer secret"}
        assert redact_headers(h)["Authorization"] == REDACTED

    def test_cookie_redacted_case_insensitive(self):
        h = {"cookie": "a=b", "COOKIE": "x=y"}
        out = redact_headers(h)
        assert out["cookie"] == REDACTED
        assert out["COOKIE"] == REDACTED

    def test_empty(self):
        assert redact_headers(None) == {}
        assert redact_headers({}) == {}


class TestRedactRawHttp:
    def test_authorization_header_redacted(self):
        raw = "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer secret\r\n\r\nbody"
        out = redact_raw_http(raw)
        assert "Bearer secret" not in out
        assert f"Authorization: {REDACTED}" in out
        assert "body" in out

    def test_cookie_header_redacted(self):
        raw = "GET / HTTP/1.1\r\nCookie: s=abc; t=def\r\n\r\n"
        out = redact_raw_http(raw)
        assert "s=abc" not in out
        assert f"Cookie: {REDACTED}" in out

    def test_body_untouched(self):
        raw = "POST / HTTP/1.1\r\nHost: x\r\n\r\nCookie=secret-in-body"
        out = redact_raw_http(raw)
        assert "secret-in-body" in out

    def test_no_secrets(self):
        raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        assert redact_raw_http(raw) == raw

    def test_none(self):
        assert redact_raw_http(None) is None

    def test_empty(self):
        assert redact_raw_http("") == ""


class TestAuthFromArgs:
    def test_from_namespace(self):
        class A:
            cookie = "c=1"
            bearer = "tok"

        a = auth_from_args(A())
        assert a.cookie == "c=1"
        assert a.bearer == "tok"

    def test_missing_attrs(self):
        class A:
            pass

        a = auth_from_args(A())
        assert a.cookie is None
        assert a.bearer is None
