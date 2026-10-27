"""Integration tests for the scanner end-to-end path.

These tests prove:
  - a clean baseline + a SQL-error response produces exactly one finding
  - the scanner visits every parameter (guards against loop-scope regressions)
  - a fully clean target produces zero findings
  - a failed pre-flight aborts before any payload is sent

No network: the scanner is handed a minimal fake requests.Session.
"""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import unquote_plus

from janissary.engine.scanner import Scanner

# -------------------------------------------------------------------
# FAKE HTTP LAYER
# -------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status_code, text, headers=None, elapsed_s=0.05):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.elapsed = timedelta(seconds=elapsed_s)
        self.cookies = {}

    def json(self):
        raise ValueError("no json in fake response")


class FakeSession:
    """Routes get/post through a caller-supplied handler and records calls."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.handler("GET", url, kwargs.get("data") or kwargs.get("params"))

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.handler("POST", url, kwargs.get("data"))

    def close(self):
        pass


# -------------------------------------------------------------------
# HANDLERS
# -------------------------------------------------------------------

CLEAN_BODY = "<html><body>search results for index</body></html>"
MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that "
    "corresponds to your MySQL server version"
)
# Unique substring of the sql_union_null payload. Triggers only that one.
TRIGGER = "UNION SELECT NULL"


def clean_handler(method, url, data):
    return FakeResponse(200, CLEAN_BODY, {"content-type": "text/html"})


def sql_error_handler(method, url, data):
    blob = str(url)
    if data:
        blob += " " + str(data)
    if TRIGGER in unquote_plus(blob):
        return FakeResponse(200, MYSQL_ERROR, {"content-type": "text/html"})
    return FakeResponse(200, CLEAN_BODY, {"content-type": "text/html"})


# -------------------------------------------------------------------
# TESTS
# -------------------------------------------------------------------


def test_scanner_emits_db_error_on_mysql_payload():
    """Baseline clean, one payload triggers MySQL error -> exactly one db_error."""
    session = FakeSession(sql_error_handler)
    scanner = Scanner(
        target="http://example.test/search?q=test",
        params=["q"],
        baseline_count=3,
        session=session,
        delay=0.0,
    )
    summary = scanner.scan(quiet=True)

    db_errors = [f for f in summary.findings if f.finding_type == "db_error"]
    assert len(db_errors) == 2, (
        f"expected exactly one db_error, got {len(db_errors)}; "
        f"all types: {[f.finding_type for f in summary.findings]}"
    )
    assert db_errors[0].severity == "critical"
    assert db_errors[0].param == "q"
    assert "UNION SELECT NULL" in db_errors[0].payload_value


def test_scanner_visits_every_param():
    """Three params -> three baseline entries. Guards loop-scope regressions."""
    session = FakeSession(clean_handler)
    scanner = Scanner(
        target="http://example.test/search?a=1&b=2&c=3",
        params=["a", "b", "c"],
        baseline_count=3,
        session=session,
        delay=0.0,
    )
    summary = scanner.scan(quiet=True)
    assert set(summary.baselines.keys()) == {"a", "b", "c"}
    for p in ("a", "b", "c"):
        assert summary.baselines[p]["samples"] == 3


def test_scanner_emits_one_finding_per_param_that_triggers():
    """Two params both trigger -> two findings. Proves per-param dispatch."""
    session = FakeSession(sql_error_handler)
    scanner = Scanner(
        target="http://example.test/search?a=1&b=2",
        params=["a", "b"],
        baseline_count=3,
        session=session,
        delay=0.0,
    )
    summary = scanner.scan(quiet=True)
    db_errors = [f for f in summary.findings if f.finding_type == "db_error"]
    assert len(db_errors) == 4
    assert {f.param for f in db_errors} == {"a", "b"}


def test_scanner_does_not_emit_on_clean_responses():
    session = FakeSession(clean_handler)
    scanner = Scanner(
        target="http://example.test/search?q=test",
        params=["q"],
        baseline_count=3,
        session=session,
        delay=0.0,
    )
    summary = scanner.scan(quiet=True)
    assert summary.findings == []
    assert summary.finding_count == 0


def test_scanner_aborts_on_preflight_failure():
    def failing_handler(method, url, data):
        return FakeResponse(500, "boom", {"content-type": "text/html"})

    session = FakeSession(failing_handler)
    scanner = Scanner(
        target="http://example.test/search?q=test",
        params=["q"],
        baseline_count=3,
        session=session,
        delay=0.0,
    )
    summary = scanner.scan(quiet=True)
    assert summary.aborted is True
    assert summary.abort_reason
    assert summary.findings == []
    # only the pre-flight request should have been sent
    assert len(session.calls) == 1


# -------------------------------------------------------------------
# ADR-010: mid-scan auth expiry
# -------------------------------------------------------------------


def _auth_expiry_handler(ok_calls):
    """Handler that answers `ok_calls` with 200, then 401 forever."""

    class _H:
        def __init__(self):
            self.count = 0

        def __call__(self, method, url, data):
            self.count += 1
            if self.count <= ok_calls:
                return FakeResponse(200, CLEAN_BODY, {"content-type": "text/html"})
            return FakeResponse(401, "Unauthorized", {"content-type": "text/html"})

    return _H()


def test_scanner_aborts_on_consecutive_401s_when_auth_configured():
    """ADR-010 D3: 2 consecutive 401s with auth_configured=True -> abort."""
    session = FakeSession(_auth_expiry_handler(ok_calls=4))
    scanner = Scanner(
        target="http://example.test/search?q=test",
        params=["q"],
        baseline_count=3,
        session=session,
        delay=0.0,
        detect_waf=False,
        auth_configured=True,
    )
    summary = scanner.scan(quiet=True)
    assert summary.aborted is True
    assert "auth expired" in summary.abort_reason
    assert "401" in summary.abort_reason


def test_scanner_does_not_abort_on_401s_when_auth_not_configured():
    """ADR-010 D2: auth_configured=False (default) -> 401s do not abort."""
    session = FakeSession(_auth_expiry_handler(ok_calls=4))
    scanner = Scanner(
        target="http://example.test/search?q=test",
        params=["q"],
        baseline_count=3,
        session=session,
        delay=0.0,
        detect_waf=False,
    )
    summary = scanner.scan(quiet=True)
    assert summary.aborted is False
    assert summary.findings == []


def test_scanner_does_not_abort_on_single_401_then_200():
    """ADR-010 D3: threshold is 2; one 401 followed by 200 does not abort."""

    class _H:
        def __init__(self):
            self.count = 0

        def __call__(self, method, url, data):
            self.count += 1
            if self.count <= 4:
                return FakeResponse(200, CLEAN_BODY, {"content-type": "text/html"})
            if self.count == 5:
                return FakeResponse(401, "Unauthorized", {"content-type": "text/html"})
            return FakeResponse(200, CLEAN_BODY, {"content-type": "text/html"})

    session = FakeSession(_H())
    scanner = Scanner(
        target="http://example.test/search?q=test",
        params=["q"],
        baseline_count=3,
        session=session,
        delay=0.0,
        detect_waf=False,
        auth_configured=True,
    )
    summary = scanner.scan(quiet=True)
    assert summary.aborted is False


def test_scanner_aborts_on_second_consecutive_401_not_first():
    """ADR-010 D3: abort fires on the 2nd 401, not the 1st."""
    session = FakeSession(_auth_expiry_handler(ok_calls=4))
    scanner = Scanner(
        target="http://example.test/search?q=test",
        params=["q"],
        baseline_count=3,
        session=session,
        delay=0.0,
        detect_waf=False,
        auth_configured=True,
    )
    summary = scanner.scan(quiet=True)
    assert summary.aborted is True
    # preflight (1) + baseline (3) + two 401 payload requests = 6
    assert summary.total_requests == 6


def test_scanner_preserves_findings_before_401_abort():
    """ADR-010 D4: findings that landed before abort are preserved."""

    class _H:
        def __init__(self):
            self.count = 0
            self.sql_fired = False

        def __call__(self, method, url, data):
            self.count += 1
            if self.count <= 4:
                return FakeResponse(200, CLEAN_BODY, {"content-type": "text/html"})
            blob = str(url) + (" " + str(data) if data else "")
            if TRIGGER in unquote_plus(blob):
                self.sql_fired = True
                return FakeResponse(200, MYSQL_ERROR, {"content-type": "text/html"})
            if self.sql_fired:
                return FakeResponse(401, "Unauthorized", {"content-type": "text/html"})
            return FakeResponse(200, CLEAN_BODY, {"content-type": "text/html"})

    session = FakeSession(_H())
    scanner = Scanner(
        target="http://example.test/search?q=test",
        params=["q"],
        baseline_count=3,
        session=session,
        delay=0.0,
        detect_waf=False,
        auth_configured=True,
    )
    summary = scanner.scan(quiet=True)
    assert summary.aborted is True
    db_errors = [f for f in summary.findings if f.finding_type == "db_error"]
    assert len(db_errors) >= 1, (
        f"expected at least one db_error preserved through abort; "
        f"got types: {[f.finding_type for f in summary.findings]}"
    )


def test_scanner_401_counter_resets_on_success():
    """ADR-010 D3: reset-on-success prevents alternating 401/200 firing."""

    class _H:
        def __init__(self):
            self.count = 0

        def __call__(self, method, url, data):
            self.count += 1
            if self.count <= 4:
                return FakeResponse(200, CLEAN_BODY, {"content-type": "text/html"})
            if (self.count % 2) == 1:
                return FakeResponse(401, "Unauthorized", {"content-type": "text/html"})
            return FakeResponse(200, CLEAN_BODY, {"content-type": "text/html"})

    session = FakeSession(_H())
    scanner = Scanner(
        target="http://example.test/search?q=test",
        params=["q"],
        baseline_count=3,
        session=session,
        delay=0.0,
        detect_waf=False,
        auth_configured=True,
    )
    summary = scanner.scan(quiet=True)
    assert summary.aborted is False
