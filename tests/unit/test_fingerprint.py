"""Unit tests for the platform fingerprinter."""

from __future__ import annotations

from unittest.mock import MagicMock

from janissary.recon.fingerprint import (
    Fingerprint,
    Fingerprinter,
    _classify_cookie,
    _extract_generator,
    _extract_title,
    _favicon_hash,
    _match_tech,
    fingerprint,
)


class FakeResp:
    def __init__(self, status=200, text="", headers=None, content=b"", cookies=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.content = content
        self.cookies = cookies or {}


def _session_from_map(mapping):
    """mapping: url -> FakeResp (or None for a transport error)."""
    s = MagicMock()

    def get(url, **kwargs):
        if url in mapping:
            val = mapping[url]
            if val is None:
                import requests

                raise requests.RequestException("boom")
            return val
        return FakeResp(status=404)

    s.get.side_effect = get
    return s


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_extract_title():
    assert _extract_title("<html><title>Hi</title></html>") == "Hi"


def test_extract_title_missing():
    assert _extract_title("<html></html>") is None


def test_extract_generator():
    body = '<meta name="generator" content="WordPress 6.4">'
    assert _extract_generator(body) == "WordPress 6.4"


def test_match_tech_server():
    assert "nginx" in _match_tech(
        "nginx/1.25",
        __import__(
            "janissary.recon.fingerprint", fromlist=["SERVER_SIGNATURES"]
        ).SERVER_SIGNATURES,
    )


def test_classify_cookie_wordpress():
    assert _classify_cookie("wordpress_logged_in_abc") == "wordpress"


def test_classify_cookie_unknown():
    assert _classify_cookie("random") is None


def test_favicon_hash_stable():
    assert _favicon_hash(b"abc") == _favicon_hash(b"abc")
    assert _favicon_hash(b"abc") != _favicon_hash(b"abcd")


# ---------------------------------------------------------------------------
# Fingerprinter.run
# ---------------------------------------------------------------------------


def test_fingerprint_wordpress_via_cookies_and_paths():
    home = FakeResp(
        status=200,
        text="<html><title>WP</title>"
        '<meta name="generator" content="WordPress 6.4"></html>',
        headers={"Server": "nginx/1.25"},
        cookies={"wordpress_logged_in_abc": "x", "wp-settings-1": "y"},
    )
    paths = {
        "http://t/wp-login.php": FakeResp(status=200),
        "http://t/wp-admin/": FakeResp(status=302),
        "http://t/wp-content/": FakeResp(status=403),
        "http://t/wp-includes/": FakeResp(status=404),
    }
    session = _session_from_map({"http://t/": home, **paths})
    fp = fingerprint("http://t/", session=session)
    assert fp.reachable is True
    assert fp.cms == "wordpress"
    assert fp.cms_confidence > 0.5
    assert fp.meta_generator == "WordPress 6.4"
    assert "nginx" in fp.technologies


def test_fingerprint_drupal_via_paths_only():
    home = FakeResp(status=200, text="<html></html>", headers={})
    paths = {
        "http://t/user/login": FakeResp(status=200),
        "http://t/core/install.php": FakeResp(status=403),
        "http://t/sites/default/": FakeResp(status=403),
        "http://t/CHANGELOG.txt": FakeResp(status=404),
    }
    session = _session_from_map({"http://t/": home, **paths})
    fp = fingerprint("http://t/", session=session)
    assert fp.cms == "drupal"


def test_fingerprint_server_only():
    home = FakeResp(status=200, text="<html></html>", headers={"Server": "Apache"})
    session = _session_from_map({"http://t/": home})
    fp = fingerprint("http://t/", session=session, probe_cms_paths=False)
    assert fp.reachable is True
    assert "apache" in fp.technologies
    assert fp.cms is None


def test_fingerprint_unreachable():
    session = _session_from_map({"http://t/": None})
    fp = fingerprint("http://t/", session=session)
    assert fp.reachable is False
    assert any("failed" in n for n in fp.notes)


def test_fingerprint_favicon():
    home = FakeResp(status=200, text="<html></html>")
    fav = FakeResp(status=200, content=b"\x00\x01\x02")
    session = _session_from_map(
        {
            "http://t/": home,
            "http://t/favicon.ico": fav,
        }
    )
    fp = fingerprint("http://t/", session=session, probe_cms_paths=False)
    assert fp.favicon_hash is not None


def test_fingerprint_favicon_missing():
    home = FakeResp(status=200, text="<html></html>")
    session = _session_from_map(
        {
            "http://t/": home,
            "http://t/favicon.ico": FakeResp(status=404),
        }
    )
    fp = fingerprint("http://t/", session=session, probe_cms_paths=False)
    assert fp.favicon_hash is None


def test_to_dict_roundtrip():
    fp = Fingerprint(target="http://t/", reachable=True, cms="wordpress")
    d = fp.to_dict()
    assert d["target"] == "http://t/"
    assert d["cms"] == "wordpress"
    assert "cms_confidence" in d


def test_fingerprinter_class_paths_disabled():
    home = FakeResp(
        status=200,
        text='<meta name="generator" content="Ghost 5">',
    )
    session = _session_from_map({"http://t/": home})
    f = Fingerprinter(
        "http://t/", session=session, probe_cms_paths=False, probe_favicon=False
    )
    fp = f.run()
    assert fp.meta_generator == "Ghost 5"
    assert fp.cms == "ghost"
    # No path probes ran.
    assert fp.paths_found == {}
