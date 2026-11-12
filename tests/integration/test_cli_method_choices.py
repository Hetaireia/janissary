"""M74: --method must accept all verbs OpenAPI can import."""

from __future__ import annotations

import pytest

from janissary.cli import build_parser


@pytest.mark.parametrize(
    "verb",
    ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
def test_method_accepts_openapi_verbs(verb):
    parser = build_parser()
    ns = parser.parse_args(["scan", "--url", "http://x/", "--method", verb])
    assert ns.method == verb


def test_method_rejects_trace():
    """TRACE is not a scanner-appropriate verb; it must be rejected."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "--url", "http://x/", "--method", "TRACE"])
