"""Tests for SessionRotator (ADR-023 D2)."""

from __future__ import annotations

import pytest

from janissary.auth import SessionSpec
from janissary.engine.session_rotator import SessionRotator


def _three():
    return [
        SessionSpec(cookie="a=1"),
        SessionSpec(cookie="b=2"),
        SessionSpec(cookie="c=3"),
    ]


def test_requires_at_least_two_sessions():
    with pytest.raises(ValueError, match="requires >= 2"):
        SessionRotator([SessionSpec(cookie="a")])
    with pytest.raises(ValueError, match="requires >= 2"):
        SessionRotator([])


def test_current_starts_at_first():
    r = SessionRotator(_three())
    assert r.current().cookie == "a=1"
    assert r.current_index == 0


def test_can_rotate_true_initially():
    r = SessionRotator(_three())
    assert r.can_rotate() is True
    assert r.exhausted is False


def test_rotate_advances_to_next():
    r = SessionRotator(_three())
    nxt = r.rotate()
    assert nxt is not None
    assert nxt.cookie == "b=2"
    assert r.current().cookie == "b=2"
    assert r.current_index == 1


def test_rotate_returns_none_when_exhausted():
    r = SessionRotator(_three())
    r.rotate()  # to idx 1
    r.rotate()  # to idx 2
    assert r.exhausted is False
    assert r.can_rotate() is True
    assert r.rotate() is None  # third rotate exhausts
    assert r.exhausted is True
    assert r.can_rotate() is False
    assert r.rotate() is None  # idempotent when exhausted


def test_attempted_count_matches_current_plus_one():
    r = SessionRotator(_three())
    assert r.attempted_count == 1
    r.rotate()
    assert r.attempted_count == 2
    r.rotate()
    assert r.attempted_count == 3


def test_total_returns_session_count():
    assert SessionRotator(_three()).total == 3
    assert SessionRotator([SessionSpec(), SessionSpec()]).total == 2


def test_two_session_exhaust_after_one_rotate():
    r = SessionRotator([SessionSpec(cookie="x"), SessionSpec(cookie="y")])
    nxt = r.rotate()
    assert nxt is not None
    assert nxt.cookie == "y"
    # Second rotate exhausts (no more sessions)
    assert r.rotate() is None
    assert r.exhausted is True


def test_rotate_after_exhaust_is_noop():
    r = SessionRotator([SessionSpec(cookie="x"), SessionSpec(cookie="y")])
    r.rotate()
    r.rotate()
    before_index = r.current_index
    r.rotate()  # idempotent
    r.rotate()  # idempotent
    assert r.current_index == before_index
    assert r.exhausted is True
