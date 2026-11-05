"""Integration tests for Scanner.run_idor (M42, ADR-024 D4-D7)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from janissary.auth import SessionSpec
from janissary.engine.scanner import Scanner
from janissary.heuristic.types import Observation


def _scanner_with_obs(observations, sessions=None):
    s = Scanner(
        target="http://x/",
        params=["q"],
        collect_observations=True,
    )
    s._observations = observations
    return s


def _obs(url, body, status=200):
    return Observation(
        url=url,
        body=body,
        response_status=status,
        param="id",
        method="GET",
    )


def _mock_response(status, body, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"content-type": "text/plain"}
    return r


def test_run_idor_empty_observations_returns_empty():
    s = _scanner_with_obs([])
    alt = SessionSpec(cookie="b=2")
    assert s.run_idor(alt) == []


def test_run_idor_none_alt_returns_empty():
    s = _scanner_with_obs([_obs("http://x/orders/42", "hello")])
    assert s.run_idor(None) == []


def test_run_idor_no_id_like_url_returns_empty():
    s = _scanner_with_obs([_obs("http://x/about", "hello")])
    alt = SessionSpec(cookie="b=2")
    with patch("janissary.engine.scanner.requests.Session") as mock_sess:
        mock_sess.return_value.get.return_value = _mock_response(200, "hello")
        findings = s.run_idor(alt)
    assert findings == []


def test_run_idor_emits_candidate_on_matching_body():
    s = _scanner_with_obs([_obs("http://x/orders/42", "same-body", 200)])
    alt = SessionSpec(cookie="b=2")
    with patch("janissary.engine.scanner.requests.Session") as mock_sess:
        mock_sess.return_value.get.return_value = _mock_response(200, "same-body")
        findings = s.run_idor(alt)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "idor"
    assert f.finding_type == "idor_candidate"
    assert f.verification_status == "unproven"
    assert f.verification_reason == "idor:cross_identity_match"


def test_run_idor_no_candidate_when_b_forbidden():
    s = _scanner_with_obs([_obs("http://x/orders/42", "secret", 200)])
    alt = SessionSpec(cookie="b=2")
    with patch("janissary.engine.scanner.requests.Session") as mock_sess:
        mock_sess.return_value.get.return_value = _mock_response(403, "forbidden")
        findings = s.run_idor(alt)
    assert findings == []
