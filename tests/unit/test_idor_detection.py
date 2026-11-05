"""Tests for detection/idor.py (M42, ADR-024 D5-D6)."""
from __future__ import annotations

import pytest

from janissary.detection.idor import is_idor_candidate, is_idor_testable_url
from janissary.heuristic.types import Observation


@pytest.mark.parametrize(
    "url",
    [
        "http://x/orders/42",
        "http://x/users/550e8400-e29b-41d4-a716-446655440000",
        "http://x/files/a1b2c3d4e5f6",
        "http://x/search?user_id=42",
        "http://x/page?ID=7",
    ],
)
def test_testable_urls(url):
    assert is_idor_testable_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "http://x/about",
        "http://x/index.html",
        "http://x/search?q=hello",
        "",
        "not-a-url",
    ],
)
def test_non_testable_urls(url):
    assert is_idor_testable_url(url) is False


def _a_obs(status=200, body="hello"):
    return Observation(url="http://x/orders/42", body=body, response_status=status)


def test_candidate_when_both_2xx_and_exact_body():
    assert is_idor_candidate(_a_obs(200, "same"), 200, "same") is True


def test_not_candidate_when_a_is_401():
    assert is_idor_candidate(_a_obs(401, "same"), 200, "same") is False


def test_not_candidate_when_b_is_403():
    assert is_idor_candidate(_a_obs(200, "same"), 403, "same") is False


def test_candidate_when_lengths_within_5_percent():
    a_body = "a" * 100
    b_body = "b" * 102
    assert is_idor_candidate(_a_obs(200, a_body), 200, b_body) is True


def test_not_candidate_when_lengths_beyond_5_percent():
    a_body = "a" * 100
    b_body = "b" * 200
    assert is_idor_candidate(_a_obs(200, a_body), 200, b_body) is False
