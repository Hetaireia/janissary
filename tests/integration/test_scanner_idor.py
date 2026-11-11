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


# --- L06a: authorisation-boundary fixtures (2026-11-11) ---
# The detection predicate (detection/idor.py:is_idor_candidate) compares
# status + body only. It has no public/private resource signal. A 200/200
# matching-body response therefore emits an unproven candidate whether the
# resource is public or private. These fixtures pin that behaviour so a
# future design change (target-spec public flag, header signal) breaks them
# visibly rather than silently. Public-resource *suppression* is L06b --
# design work, not fixture work.


def test_run_idor_public_resource_shape_emits_unproven_not_verified():
    """Both identities get 200 with the same body: unproven, never verified.

    The scanner cannot distinguish a legitimately public resource from an
    IDOR. The honest boundary is that the finding is `unproven` -- reported
    for analyst triage, never promoted to `verified`.
    """
    s = _scanner_with_obs([_obs("http://x/orders/42", "public-body", 200)])
    alt = SessionSpec(cookie="b=2")
    with patch("janissary.engine.scanner.requests.Session") as mock_sess:
        mock_sess.return_value.get.return_value = _mock_response(200, "public-body")
        findings = s.run_idor(alt)
    assert len(findings) == 1
    assert findings[0].verification_status == "unproven"
    assert findings[0].verification_status != "verified"


def test_run_idor_body_similar_within_5pct_emits_candidate():
    """Bodies differ, lengths within 5%: still a candidate (predicate D6)."""
    a_body = "a" * 100
    b_body = "b" * 102
    s = _scanner_with_obs([_obs("http://x/orders/42", a_body, 200)])
    alt = SessionSpec(cookie="b=2")
    with patch("janissary.engine.scanner.requests.Session") as mock_sess:
        mock_sess.return_value.get.return_value = _mock_response(200, b_body)
        findings = s.run_idor(alt)
    assert len(findings) == 1
    assert findings[0].verification_status == "unproven"


def test_run_idor_body_divergent_beyond_5pct_no_candidate():
    """Bodies diverge by more than 5% length: B got a different resource."""
    a_body = "a" * 100
    b_body = "b" * 200
    s = _scanner_with_obs([_obs("http://x/orders/42", a_body, 200)])
    alt = SessionSpec(cookie="b=2")
    with patch("janissary.engine.scanner.requests.Session") as mock_sess:
        mock_sess.return_value.get.return_value = _mock_response(200, b_body)
        findings = s.run_idor(alt)
    assert findings == []


def test_run_idor_a_observation_non_2xx_no_candidate():
    """Identity A never reached the resource: nothing to compare."""
    s = _scanner_with_obs([_obs("http://x/orders/42", "err", 404)])
    alt = SessionSpec(cookie="b=2")
    with patch("janissary.engine.scanner.requests.Session") as mock_sess:
        mock_sess.return_value.get.return_value = _mock_response(200, "err")
        findings = s.run_idor(alt)
    assert findings == []


def test_run_idor_b_5xx_no_candidate():
    """B errored: not an authorisation success, not a candidate."""
    s = _scanner_with_obs([_obs("http://x/orders/42", "same", 200)])
    alt = SessionSpec(cookie="b=2")
    with patch("janissary.engine.scanner.requests.Session") as mock_sess:
        mock_sess.return_value.get.return_value = _mock_response(500, "same")
        findings = s.run_idor(alt)
    assert findings == []
