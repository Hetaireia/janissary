"""Unit tests for the finding identity module."""

from __future__ import annotations

import pytest

from janissary.finding_identity import (
    FP_HEX_WIDTH,
    FP_PREFIX,
    VOLATILE_PARAMS,
    canonicalize_target,
    compute_fingerprint,
)

# ---------------------------------------------------------------------------
# canonicalize_target
# ---------------------------------------------------------------------------


def test_canonicalize_lowercases_scheme_and_host():
    assert canonicalize_target("HTTP://EXAMPLE.COM/a") == "http://example.com/a"


def test_canonicalize_preserves_path_case():
    assert canonicalize_target("http://x.com/API/Users") == "http://x.com/API/Users"


def test_canonicalize_drops_fragment():
    assert canonicalize_target("http://x.com/a#frag") == "http://x.com/a"


def test_canonicalize_sorts_query():
    assert canonicalize_target("http://x.com/a?b=2&a=1") == "http://x.com/a?a=1&b=2"


def test_canonicalize_preserves_blank_value():
    assert canonicalize_target("http://x.com/a?q=") == "http://x.com/a?q="


def test_canonicalize_drops_volatile_params():
    url = "http://x.com/a?q=1&sessionid=xyz&ts=123&nonce=abc"
    assert canonicalize_target(url) == "http://x.com/a?q=1"


def test_canonicalize_drops_each_volatile_param():
    for p in VOLATILE_PARAMS:
        url = f"http://x.com/a?{p}=xyz&q=1"
        assert canonicalize_target(url) == "http://x.com/a?q=1", p


def test_canonicalize_keeps_ambiguous_params():
    """``key``, ``auth``, ``token`` are NOT stripped - they carry identity."""
    for p in ("key", "auth", "token", "t", "sid"):
        url = f"http://x.com/a?{p}=xyz&q=1"
        assert p in canonicalize_target(url), p


def test_canonicalize_drops_excluded_param():
    assert (
        canonicalize_target("http://x.com/a?q='&other=1", exclude="q")
        == "http://x.com/a?other=1"
    )


def test_canonicalize_drops_empty_query():
    assert canonicalize_target("http://x.com/a?") == "http://x.com/a"


def test_canonicalize_non_url_falls_through():
    assert canonicalize_target("/etc/passwd") == "/etc/passwd"


def test_canonicalize_non_url_lowercases():
    assert canonicalize_target("/API/Users") == "/api/users"


def test_canonicalize_empty():
    assert canonicalize_target("") == ""
    assert canonicalize_target("   ") == ""


# ---------------------------------------------------------------------------
# compute_fingerprint - determinism and format
# ---------------------------------------------------------------------------


def test_fingerprint_stable_across_calls():
    args = {
        "target": "http://x/a?q=1",
        "discriminator": "q",
        "category": "sqli",
        "finding_type": "db_error",
    }
    assert compute_fingerprint(**args) == compute_fingerprint(**args)


def test_fingerprint_format():
    fp = compute_fingerprint(
        target="http://x/a",
        discriminator="q",
        category="sqli",
        finding_type="db_error",
    )
    assert fp.startswith(FP_PREFIX)
    assert len(fp) == len(FP_PREFIX) + FP_HEX_WIDTH
    hex_part = fp[len(FP_PREFIX) :]
    assert all(c in "0123456789abcdef" for c in hex_part)


# ---------------------------------------------------------------------------
# compute_fingerprint - field sensitivity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "variant",
    [
        {
            "target": "http://x/a",
            "discriminator": "name",
            "category": "sqli",
            "finding_type": "db_error",
        },
        {
            "target": "http://x/a",
            "discriminator": "q",
            "category": "xss",
            "finding_type": "db_error",
        },
        {
            "target": "http://x/a",
            "discriminator": "q",
            "category": "sqli",
            "finding_type": "status_change",
        },
        {
            "target": "http://x/b",
            "discriminator": "q",
            "category": "sqli",
            "finding_type": "db_error",
        },
    ],
)
def test_fingerprint_differs_on_field_change(variant):
    base = {
        "target": "http://x/a",
        "discriminator": "q",
        "category": "sqli",
        "finding_type": "db_error",
    }
    assert compute_fingerprint(**base) != compute_fingerprint(**variant)


# ---------------------------------------------------------------------------
# compute_fingerprint - stability across instability sources
# ---------------------------------------------------------------------------


def test_fingerprint_ignores_injected_payload():
    """Different payloads on same endpoint/param -> same fingerprint."""
    a = {
        "target": "http://x/a?q=' OR '1'='1",
        "discriminator": "q",
        "category": "sqli",
        "finding_type": "db_error",
    }
    b = {
        "target": "http://x/a?q=' UNION SELECT NULL--",
        "discriminator": "q",
        "category": "sqli",
        "finding_type": "db_error",
    }
    assert compute_fingerprint(**a) == compute_fingerprint(**b)


def test_fingerprint_ignores_volatile_query_params():
    a = {
        "target": "http://x/a?q=1&sessionid=abc&ts=999",
        "discriminator": "q",
        "category": "sqli",
        "finding_type": "db_error",
    }
    b = {
        "target": "http://x/a?q=2&sessionid=def&ts=111",
        "discriminator": "q",
        "category": "sqli",
        "finding_type": "db_error",
    }
    assert compute_fingerprint(**a) == compute_fingerprint(**b)


def test_fingerprint_ignores_host_case():
    a = {
        "target": "http://EXAMPLE.COM/a",
        "discriminator": "q",
        "category": "sqli",
        "finding_type": "db_error",
    }
    b = {
        "target": "http://example.com/a",
        "discriminator": "q",
        "category": "sqli",
        "finding_type": "db_error",
    }
    assert compute_fingerprint(**a) == compute_fingerprint(**b)


def test_fingerprint_ignores_query_order():
    a = {
        "target": "http://x/a?q=1&keep1=1&keep2=2",
        "discriminator": "q",
        "category": "sqli",
        "finding_type": "db_error",
    }
    b = {
        "target": "http://x/a?keep2=2&keep1=1&q=2",
        "discriminator": "q",
        "category": "sqli",
        "finding_type": "db_error",
    }
    assert compute_fingerprint(**a) == compute_fingerprint(**b)


# ---------------------------------------------------------------------------
# compute_fingerprint - edge cases
# ---------------------------------------------------------------------------


def test_fingerprint_empty_components():
    fp = compute_fingerprint(target="", discriminator="", category="", finding_type="")
    assert fp.startswith(FP_PREFIX)


def test_fingerprint_non_url_target():
    fp = compute_fingerprint(
        target="/etc/passwd",
        discriminator="",
        category="credential",
        finding_type="path",
    )
    assert fp.startswith(FP_PREFIX)


def test_fingerprint_field_boundary_safety():
    """Unit Separator prevents 'a|b'+'c' colliding with 'a'+'b|c'."""
    fp_a = compute_fingerprint(
        target="a|b", discriminator="c", category="x", finding_type="y"
    )
    fp_b = compute_fingerprint(
        target="a", discriminator="b|c", category="x", finding_type="y"
    )
    assert fp_a != fp_b
