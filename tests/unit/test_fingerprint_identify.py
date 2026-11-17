"""B-8 stack fingerprint — behaviour pinning tests over the fixture corpus.

Every fixture is a header dict captured from a real deployment shape. The
expectations here are the contract, not a description of current output:
several of these fail until signatures.py is rewritten.

Rules under test:
  - a single strong signal classifies, at its declared confidence
  - two distinct strong labels in one sample => Ambiguous, 0.50
  - a front proxy (Via / X-Served-By / CDN marker) suppresses Server
  - X-Powered-By and server banners are strong; cookies and header order
    are weak and can never outvote a strong label
  - no signal at all yields None, never a guess
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from janissary.fingerprint.identify import identify
from janissary.fingerprint.signatures import (
    match_cdn,
    match_framework,
    match_language,
    match_server,
    match_waf,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "fingerprint"


class _Baseline:
    """Minimal Baseline stand-in: identify() only reads .headers."""

    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = [headers]


def _load(name: str) -> _Baseline:
    data = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    return _Baseline(data["headers"])


def _all_fixtures() -> list[str]:
    return sorted(p.stem for p in FIXTURES.glob("*.json"))


def test_corpus_is_present_and_complete() -> None:
    names = _all_fixtures()
    assert len(names) == 12, f"expected 12 fixtures, found {len(names)}: {names}"
    assert "unknown-minimal" in names


# --- server ---------------------------------------------------------------

@pytest.mark.parametrize(
    ("fixture", "value"),
    [
        ("apache-php", "apache"),
        ("iis-aspnet", "iis"),
        ("aws-alb", "aws-alb"),
        ("cloudflare-fronted", "cloudflare"),
        ("akamai-cdn", "akamai"),
        # front proxy: Server advertises the proxy, not the origin
        ("express-node", None),
        ("rails-puma", None),
        ("fastly-cdn", None),
        ("unknown-minimal", None),
    ],
)
def test_server(fixture: str, value: str | None) -> None:
    got = match_server(_load(fixture).headers[0])
    assert (got[0] if got else None) == value


def test_server_ambiguous_is_ambiguous_not_first_match() -> None:
    got = match_server(_load("ambiguous-dual").headers[0])
    assert got is not None
    assert got[0] == "Ambiguous"
    assert got[1] == 0.50


# --- framework ------------------------------------------------------------

@pytest.mark.parametrize(
    ("fixture", "value"),
    [
        ("express-node", "express"),
        ("iis-aspnet", "asp.net"),
        ("rails-puma", "rails"),
        ("django-gunicorn", "django"),
        ("nginx-go", None),
        ("unknown-minimal", None),
    ],
)
def test_framework(fixture: str, value: str | None) -> None:
    got = match_framework(_load(fixture).headers[0])
    assert (got[0] if got else None) == value


def test_framework_strong_beats_weak_cookie() -> None:
    """X-Powered-By is strong; a cookie alone is weak and must not tie it."""
    got = match_framework(_load("express-node").headers[0])
    assert got is not None
    assert got[1] >= 0.80


def test_framework_cookie_only_is_weak() -> None:
    """django-gunicorn has only a csrftoken cookie, no X-Powered-By."""
    got = match_framework(_load("django-gunicorn").headers[0])
    assert got is not None
    assert got[0] == "django"
    assert got[1] < 0.80


# --- language -------------------------------------------------------------

@pytest.mark.parametrize(
    ("fixture", "value"),
    [
        ("apache-php", "php"),
        ("iis-aspnet", "csharp"),
        ("express-node", "javascript"),
        ("django-gunicorn", "python"),
        ("nginx-go", None),
        ("unknown-minimal", None),
    ],
)
def test_language(fixture: str, value: str | None) -> None:
    got = match_language(_load(fixture).headers[0])
    assert (got[0] if got else None) == value


# --- waf ------------------------------------------------------------------

@pytest.mark.parametrize(
    ("fixture", "value"),
    [
        ("cloudflare-fronted", "cloudflare"),
        ("akamai-cdn", "akamai"),
        ("ambiguous-dual", "Ambiguous"),
        # Fastly is CDN-only; it must not be claimed as a WAF
        ("fastly-cdn", None),
        ("apache-php", None),
        ("unknown-minimal", None),
    ],
)
def test_waf(fixture: str, value: str | None) -> None:
    got = match_waf(_load(fixture).headers[0])
    assert (got[0] if got else None) == value


# --- cdn ------------------------------------------------------------------

@pytest.mark.parametrize(
    ("fixture", "value"),
    [
        ("fastly-cdn", "fastly"),
        ("apache-php", None),
        ("unknown-minimal", None),
    ],
)
def test_cdn(fixture: str, value: str | None) -> None:
    got = match_cdn(_load(fixture).headers[0])
    assert (got[0] if got else None) == value


def test_cdn_is_distinct_from_waf() -> None:
    """A CDN must never be reported through the waf field."""
    b = _load("fastly-cdn")
    waf = match_waf(b.headers[0])
    cdn = match_cdn(b.headers[0])
    assert (waf[0] if waf else None) != "fastly"
    assert (cdn[0] if cdn else None) == "fastly"


# --- empty and multi-sample ----------------------------------------------

def test_no_baselines_is_empty_profile() -> None:
    profile = identify([])
    assert profile.to_dict() == {
        "server": {"value": None, "confidence": 0.0, "evidence": []},
        "framework": {"value": None, "confidence": 0.0, "evidence": []},
        "language": {"value": None, "confidence": 0.0, "evidence": []},
        "waf": {"value": None, "confidence": 0.0, "evidence": []},
        "cdn": {"value": None, "confidence": 0.0, "evidence": []},
    }


def test_empty_headers_classify_as_none_not_guess() -> None:
    profile = identify([_Baseline({})])
    assert profile.server.value is None
    assert profile.framework.value is None


def test_agreement_across_samples_holds_confidence() -> None:
    """Every sample agreeing must not degrade confidence."""
    one = identify([_load("apache-php")])
    many = identify([_load("apache-php") for _ in range(20)])
    assert many.server.value == "apache"
    assert many.server.confidence == pytest.approx(one.server.confidence)


def test_lone_signal_among_many_drops_confidence() -> None:
    """One witness in twenty is weak evidence and must fall below STRONG."""
    baselines = [_load("unknown-minimal") for _ in range(19)] + [_load("apache-php")]
    got = identify(baselines).server
    assert got.value == "apache"
    assert got.confidence < 0.80


def test_conflict_across_samples_is_ambiguous() -> None:
    got = identify([_load("apache-php"), _load("iis-aspnet")]).server
    assert got.value == "Ambiguous"
    assert got.confidence == 0.50


def test_front_proxy_suppression_end_to_end() -> None:
    profile = identify([_load("fastly-cdn")])
    assert profile.server.value is None
    assert profile.cdn.value == "fastly"
    assert profile.waf.value is None