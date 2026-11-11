"""Branding tests: banner, --version, --help all carry the brand line."""

import pytest

from janissary.cli import _print_banner, build_parser

BRAND = "SIGNAL OVER NOISE."


def test_banner_includes_tagline(capsys):
    _print_banner()
    out = capsys.readouterr().out
    assert BRAND in out
    assert "JANISSARY" in out


def test_version_includes_tagline(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--version"])
    out = capsys.readouterr().out
    assert "janissary" in out
    assert BRAND in out


def test_help_includes_tagline(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert BRAND in out
