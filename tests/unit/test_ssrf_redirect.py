"""Tests for SSRF redirect-chain payloads (ADR-028, BL-1)."""

from __future__ import annotations

from janissary.engine.scanner import DEFAULT_PAYLOADS, SSRF_BODY_MARKERS, Scanner


def _payload_names(scanner: Scanner) -> set[str]:
    return {name for name, _, _, _ in scanner._payloads}


def test_no_redirector_no_extra_payloads():
    """When ssrf_redirector is None, no redirect payloads are added."""
    s = Scanner(target="http://example.com/x", params=["q"])
    names = _payload_names(s)
    assert not any(n.startswith("ssrf_redirect_") for n in names)


def test_redirector_adds_three_payloads():
    """When ssrf_redirector is set, three redirect payloads are added."""
    s = Scanner(
        target="http://example.com/x",
        params=["q"],
        ssrf_redirector="https://redir.example.com/r",
    )
    names = _payload_names(s)
    assert "ssrf_redirect_aws" in names
    assert "ssrf_redirect_gcp" in names
    assert "ssrf_redirect_azure" in names


def test_redirector_payload_contains_redirector_url():
    """The redirect payload value begins with the supplied redirector URL."""
    s = Scanner(
        target="http://example.com/x",
        params=["q"],
        ssrf_redirector="https://redir.example.com/r",
    )
    values = {name: val for name, val, _, _ in s._payloads}
    assert values["ssrf_redirect_aws"].startswith("https://redir.example.com/r?to=")
    assert values["ssrf_redirect_gcp"].startswith("https://redir.example.com/r?to=")
    assert values["ssrf_redirect_azure"].startswith("https://redir.example.com/r?to=")


def test_redirector_url_with_query_uses_ampersand():
    """If the redirector URL already has a query string, join with & not ?."""
    s = Scanner(
        target="http://example.com/x",
        params=["q"],
        ssrf_redirector="https://redir.example.com/r?k=v",
    )
    values = {name: val for name, val, _, _ in s._payloads}
    assert "?k=v&to=" in values["ssrf_redirect_aws"]


def test_redirector_trailing_slash_trimmed():
    """Trailing ? or & on the redirector URL is stripped before joining."""
    s = Scanner(
        target="http://example.com/x",
        params=["q"],
        ssrf_redirector="https://redir.example.com/r?",
    )
    values = {name: val for name, val, _, _ in s._payloads}
    assert values["ssrf_redirect_aws"].startswith("https://redir.example.com/r?to=")


def test_redirect_payloads_have_body_markers():
    """Each redirect payload name has entries in SSRF_BODY_MARKERS."""
    for name in ("ssrf_redirect_aws", "ssrf_redirect_gcp", "ssrf_redirect_azure"):
        assert name in SSRF_BODY_MARKERS, f"{name} missing from SSRF_BODY_MARKERS"
        assert len(SSRF_BODY_MARKERS[name]) >= 1


def test_redirect_payloads_are_ssrf_category():
    """Redirect payloads classify as ssrf with critical severity."""
    s = Scanner(
        target="http://example.com/x",
        params=["q"],
        ssrf_redirector="https://redir.example.com/r",
    )
    cats = {name: (cat, sev) for name, _, cat, sev in s._payloads}
    assert cats["ssrf_redirect_aws"] == ("ssrf", "critical")
    assert cats["ssrf_redirect_gcp"] == ("ssrf", "critical")
    assert cats["ssrf_redirect_azure"] == ("ssrf", "critical")
