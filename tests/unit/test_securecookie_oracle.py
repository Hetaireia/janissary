"""Unit tests for the securecookie Set-Cookie oracle.

The OWASP Benchmark securecookie cases set a cookie that echoes the
injected marker. The vulnerable shape sets it WITHOUT the Secure
attribute; the non-vulnerable shape sets the SAME cookie WITH Secure.
Reflection alone is not diagnostic (both shapes reflect), so the
Secure attribute is the discriminator.

Negative tests are the point.
"""

from janissary.detection import Baseline, ResponseSnapshot
from janissary.detection.analyzer import check_securecookie_oracle


class _RawHeaders:
    def __init__(self, cookies):
        self._cookies = list(cookies)

    def get_all(self, name):
        if name.lower() == "set-cookie":
            return list(self._cookies)
        return []


class _Raw:
    def __init__(self, cookies):
        self.headers = _RawHeaders(cookies)


class FakeResponse:
    def __init__(self, status=200, text="", content_type="text/html",
                 elapsed=0.1, set_cookies=None):
        self.status_code = status
        self.text = text
        self.headers = {"content-type": content_type}
        self.raw = _Raw(set_cookies or [])
        self._elapsed = elapsed

    @property
    def elapsed(self):
        outer = self

        class Elapsed:
            def total_seconds(self):
                return outer._elapsed

        return Elapsed()


def resp(set_cookies=None):
    return FakeResponse(set_cookies=set_cookies)


def make_baseline(bodies):
    b = Baseline()
    for body in bodies:
        b.add(ResponseSnapshot.from_response(FakeResponse(text=body)))
    return b


MARK = "JNSRY_SC_deadbeef"
BENIGN = "Welcome to the benchmark page."

VULN_COOKIE = f"SomeCookie={MARK}; Path=/; HttpOnly; SameSite=Strict"
NONV_COOKIE = f"SomeCookie={MARK}; Path=/; Secure; HttpOnly; SameSite=Strict"
UNRELATED_COOKIE = "session=abc; Path=/; HttpOnly"
SECURED_UNRELATED = "session=abc; Path=/; Secure; HttpOnly"


def test_fires_on_reflected_cookie_without_secure():
    baseline = make_baseline([BENIGN])
    r = resp(set_cookies=[VULN_COOKIE])
    findings = check_securecookie_oracle(baseline, r, MARK)
    assert len(findings) == 1
    assert findings[0]["type"] == "securecookie_flag_oracle"
    assert findings[0]["severity"] == "medium"


def test_silent_on_reflected_cookie_with_secure():
    baseline = make_baseline([BENIGN])
    r = resp(set_cookies=[NONV_COOKIE])
    assert check_securecookie_oracle(baseline, r, MARK) == []


def test_silent_when_no_marker_in_cookie():
    baseline = make_baseline([BENIGN])
    r = resp(set_cookies=[UNRELATED_COOKIE])
    assert check_securecookie_oracle(baseline, r, MARK) == []


def test_silent_when_no_set_cookie():
    baseline = make_baseline([BENIGN])
    r = resp(set_cookies=[])
    assert check_securecookie_oracle(baseline, r, MARK) == []


def test_silent_when_marker_empty():
    baseline = make_baseline([BENIGN])
    r = resp(set_cookies=[VULN_COOKIE])
    assert check_securecookie_oracle(baseline, r, "") == []


def test_fires_on_second_cookie_when_first_is_secured():
    # Multiple Set-Cookie headers: skip the Secured reflected one,
    # fire on the unsecured reflected one.
    baseline = make_baseline([BENIGN])
    r = resp(set_cookies=[NONV_COOKIE, VULN_COOKIE])
    findings = check_securecookie_oracle(baseline, r, MARK)
    assert len(findings) == 1


def test_case_insensitive_secure_attribute():
    baseline = make_baseline([BENIGN])
    r = resp(set_cookies=[f"SomeCookie={MARK}; Path=/; secure; HttpOnly"])
    assert check_securecookie_oracle(baseline, r, MARK) == []


def test_handles_response_without_get_all():
    class Bare:
        headers = {}
        raw = None
    assert check_securecookie_oracle(None, Bare(), MARK) == []
