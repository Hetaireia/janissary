"""Unit test for ABORT-1: preflight follows redirects (Phase 4)."""
from __future__ import annotations


def test_preflight_passes_allow_redirects_true():
    from janissary.engine.scanner import Scanner

    scanner = Scanner(target="http://example/", params=["x"])
    seen = []

    def fake_request(url, param, value, allow_redirects=False):
        seen.append(allow_redirects)

        class R:
            pass

        r = R()
        if allow_redirects:
            r.status_code = 200
            r.text = "final body after redirect"
        else:
            r.status_code = 302
            r.text = ""
        return r

    scanner._request = fake_request
    ok, reason = scanner.preflight()
    assert ok is True, f"preflight should pass when redirect-followed body is non-empty; reason={reason!r}"
    assert reason == ""
    assert seen == [True], f"preflight must call _request(..., allow_redirects=True); got {seen}"


def test_preflight_still_aborts_on_empty_final_body():
    """If the redirect chain ends at an empty body, preflight still aborts (correct)."""
    from janissary.engine.scanner import Scanner

    scanner = Scanner(target="http://example/", params=["x"])

    def fake_request(url, param, value, allow_redirects=False):
        class R:
            pass
        r = R()
        r.status_code = 200
        r.text = ""
        return r

    scanner._request = fake_request
    ok, reason = scanner.preflight()
    assert ok is False
    assert "empty" in reason.lower()


def test_preflight_still_aborts_on_4xx():
    from janissary.engine.scanner import Scanner

    scanner = Scanner(target="http://example/", params=["x"])

    def fake_request(url, param, value, allow_redirects=False):
        class R:
            pass
        r = R()
        r.status_code = 404
        r.text = "not found"
        return r

    scanner._request = fake_request
    ok, reason = scanner.preflight()
    assert ok is False
    assert "404" in reason
