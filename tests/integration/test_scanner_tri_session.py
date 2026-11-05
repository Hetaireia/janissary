"""Integration tests for tri-session rotation (M41, ADR-023 D6)."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from janissary.auth import SessionSpec
from janissary.engine.scanner import Scanner


def _scanner(sessions=None):
    return Scanner(
        target="http://x/",
        params=["q"],
        auth_configured=True,
        auth_sessions=sessions,
    )


def _resp(status: int):
    r = MagicMock()
    r.status_code = status
    return r


def _summary():
    return SimpleNamespace(total_requests=0)


def test_no_rotator_returns_original_response():
    s = _scanner(sessions=None)
    r401 = _resp(401)
    out = s._try_rotate_on_401(r401, "q", "v", _summary())
    assert out is r401


def test_non_401_never_rotates():
    s = _scanner(sessions=[SessionSpec(cookie="a=1"), SessionSpec(cookie="b=2")])
    r200 = _resp(200)
    out = s._try_rotate_on_401(r200, "q", "v", _summary())
    assert out is r200
    assert s._session_rotator.current_index == 0


def test_rotates_on_401_and_returns_retry():
    s = _scanner(sessions=[
        SessionSpec(cookie="a=1"),
        SessionSpec(cookie="b=2"),
        SessionSpec(cookie="c=3"),
    ])
    summary = _summary()
    r401 = _resp(401)
    r200 = _resp(200)
    with patch.object(s, "_paced_request", return_value=r200) as p:
        out = s._try_rotate_on_401(r401, "q", "v", summary)
    assert out is r200
    assert p.call_count == 1
    assert s._session_rotator.current_index == 1
    assert s.session.headers.get("Cookie") == "b=2"
    assert summary.total_requests == 1


def test_retry_still_401_returns_retry_response():
    s = _scanner(sessions=[SessionSpec(cookie="a=1"), SessionSpec(cookie="b=2")])
    r401_first = _resp(401)
    r401_retry = _resp(401)
    with patch.object(s, "_paced_request", return_value=r401_retry):
        out = s._try_rotate_on_401(r401_first, "q", "v", _summary())
    assert out is r401_retry
    assert s._session_rotator.current_index == 1


def test_exhausted_rotator_returns_original_no_retry():
    s = _scanner(sessions=[SessionSpec(cookie="a=1"), SessionSpec(cookie="b=2")])
    s._session_rotator.rotate()  # to idx 1
    s._session_rotator.rotate()  # exhaust
    r401 = _resp(401)
    with patch.object(s, "_paced_request") as p:
        out = s._try_rotate_on_401(r401, "q", "v", _summary())
    assert out is r401
    assert p.call_count == 0


def test_rotation_clears_stale_cookie_when_switching_to_bearer():
    s = _scanner(sessions=[
        SessionSpec(cookie="old=1"),
        SessionSpec(bearer="newtok"),
    ])
    # Simulate first session having been applied before 401
    s.session.headers["Cookie"] = "old=1"
    s.session.headers["Authorization"] = "Bearer stale"
    r401 = _resp(401)
    r200 = _resp(200)
    with patch.object(s, "_paced_request", return_value=r200):
        out = s._try_rotate_on_401(r401, "q", "v", _summary())
    assert out is r200
    # Rotated to bearer-only: stale Cookie cleared, Authorization replaced
    assert "Cookie" not in s.session.headers
    assert s.session.headers.get("Authorization") == "Bearer newtok"
