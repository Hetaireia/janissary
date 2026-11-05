"""Unit tests for janissary.auth."""

from __future__ import annotations

import pytest

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


# --- M41: tri-session AuthConfig + SessionSpec + load_sessions_file ---


def test_sessionspec_is_frozen():
    from dataclasses import FrozenInstanceError
    from janissary.auth import SessionSpec
    s = SessionSpec(cookie="a=1")
    with pytest.raises(FrozenInstanceError):
        s.cookie = "b=2"


def test_sessionspec_headers_cookie_only():
    from janissary.auth import SessionSpec
    s = SessionSpec(cookie="x=1; y=2")
    assert s.headers() == {"Cookie": "x=1; y=2"}


def test_sessionspec_headers_both():
    from janissary.auth import SessionSpec
    s = SessionSpec(cookie="c=1", bearer="tok")
    h = s.headers()
    assert h["Cookie"] == "c=1"
    assert h["Authorization"] == "Bearer tok"


def test_authconfig_sessions_is_empty_false():
    from janissary.auth import AuthConfig, SessionSpec
    a = AuthConfig(sessions=[SessionSpec(cookie="a"), SessionSpec(cookie="b")])
    assert a.is_empty is False


def test_authconfig_sessions_headers_from_first():
    from janissary.auth import AuthConfig, SessionSpec
    a = AuthConfig(sessions=[SessionSpec(cookie="first"), SessionSpec(cookie="second")])
    assert a.headers() == {"Cookie": "first"}


def test_apply_to_session_clears_stale_cookie():
    from janissary.auth import AuthConfig, apply_to_session
    s = _FakeSession()
    s.headers["Cookie"] = "stale=1"
    apply_to_session(s, AuthConfig(bearer="tok"))
    assert "Cookie" not in s.headers
    assert s.headers["Authorization"] == "Bearer tok"


def test_apply_to_session_clears_stale_authorization():
    from janissary.auth import AuthConfig, apply_to_session
    s = _FakeSession()
    s.headers["Authorization"] = "Bearer old"
    apply_to_session(s, AuthConfig(cookie="new=1"))
    assert "Authorization" not in s.headers
    assert s.headers["Cookie"] == "new=1"


def test_to_dict_sessions_redacted_by_count():
    from janissary.auth import AuthConfig, REDACTED, SessionSpec
    a = AuthConfig(sessions=[SessionSpec(cookie="x"), SessionSpec(cookie="y"), SessionSpec(cookie="z")])
    d = a.to_dict()
    assert d["sessions"] == [REDACTED, REDACTED, REDACTED]


def test_load_sessions_file_ok(tmp_path):
    import json as _json
    from janissary.auth import load_sessions_file
    p = tmp_path / "sessions.json"
    p.write_text(_json.dumps([{"cookie": "a=1"}, {"bearer": "tok"}]), encoding="utf-8")
    specs = load_sessions_file(str(p))
    assert len(specs) == 2
    assert specs[0].cookie == "a=1" and specs[0].bearer is None
    assert specs[1].cookie is None and specs[1].bearer == "tok"


def test_load_sessions_file_rejects_single_entry(tmp_path):
    import json as _json
    from janissary.auth import load_sessions_file
    p = tmp_path / "sessions.json"
    p.write_text(_json.dumps([{"cookie": "a=1"}]), encoding="utf-8")
    with pytest.raises(ValueError, match="at least 2"):
        load_sessions_file(str(p))


def test_load_sessions_file_rejects_non_list(tmp_path):
    import json as _json
    from janissary.auth import load_sessions_file
    p = tmp_path / "sessions.json"
    p.write_text(_json.dumps({"cookie": "a"}), encoding="utf-8")
    with pytest.raises(ValueError, match="expected JSON array"):
        load_sessions_file(str(p))
