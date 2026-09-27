"""Unit tests for the admin panel probe."""

from __future__ import annotations

from unittest.mock import MagicMock

from janissary.recon import admin as a


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def _session_from_map(mapping):
    """mapping: url -> FakeResp or None."""
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


LOGIN_HTML = (
    "<html><head><title>Login</title></head>"
    "<body><form action='/login' method='post'>"
    "<input type='text' name='user'>"
    "<input type='password' name='pass'>"
    "</form></body></html>"
)

GENERIC_HTML = "<html><head><title>Home</title></head><body>Hello</body></html>"


# ---------------------------------------------------------------------------
# Table sanity
# ---------------------------------------------------------------------------


def test_admin_paths_has_expected_platforms():
    assert "wordpress" in a.ADMIN_PATHS
    assert "tomcat" in a.ADMIN_PATHS
    assert "jenkins" in a.ADMIN_PATHS


def test_all_paths_start_with_slash():
    for platform, paths in a.ADMIN_PATHS.items():
        for p in paths:
            assert p.startswith("/"), f"{platform}: {p}"


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def test_probe_unreachable_target():
    session = _session_from_map({"http://t/": None})
    profile = a.probe_admin("http://t/", session=session)
    assert profile.reachable is False
    assert any("baseline" in n for n in profile.notes)


def test_wordpress_login_form_detected():
    session = _session_from_map(
        {
            "http://t/": FakeResp(),
            "http://t/wp-admin/": FakeResp(status=200, text=LOGIN_HTML),
        }
    )
    profile = a.probe_admin("http://t/", session=session)
    wp = [h for h in profile.hits if h.platform == "wordpress"]
    assert len(wp) >= 1
    assert wp[0].is_login_form is True
    assert wp[0].title == "Login"


def test_redirect_to_login_counts_as_hit():
    session = _session_from_map(
        {
            "http://t/": FakeResp(),
            "http://t/wp-admin/": FakeResp(
                status=302, headers={"Location": "/wp-login.php"}
            ),
        }
    )
    profile = a.probe_admin("http://t/", session=session)
    wp = [h for h in profile.hits if h.path == "/wp-admin/"]
    assert wp
    assert wp[0].location == "/wp-login.php"


def test_redirect_unrelated_is_not_a_hit():
    session = _session_from_map(
        {
            "http://t/": FakeResp(),
            "http://t/admin/": FakeResp(
                status=302, headers={"Location": "/somewhere-else"}
            ),
        }
    )
    profile = a.probe_admin("http://t/", session=session)
    paths = [h.path for h in profile.hits]
    assert "/admin/" not in paths


def test_401_on_protected_platform_counts():
    session = _session_from_map(
        {
            "http://t/": FakeResp(),
            "http://t/manager/html": FakeResp(status=401),
        }
    )
    profile = a.probe_admin("http://t/", session=session)
    tomcat = [h for h in profile.hits if h.platform == "tomcat"]
    assert tomcat
    assert "access protected" in tomcat[0].notes


def test_401_on_generic_platform_does_not_count():
    # wordpress is not in PROTECTED_IS_HIT, so a 401 without redirect
    # should not be reported.
    session = _session_from_map(
        {
            "http://t/": FakeResp(),
            "http://t/wp-admin/": FakeResp(status=401),
        }
    )
    profile = a.probe_admin("http://t/", session=session)
    wp = [h for h in profile.hits if h.platform == "wordpress"]
    assert wp == []


def test_version_hint_from_generator():
    html = (
        "<html><head>"
        '<meta name="generator" content="WordPress 6.4.2">'
        "</head><body></body></html>"
    )
    session = _session_from_map(
        {
            "http://t/": FakeResp(),
            "http://t/wp-admin/": FakeResp(status=200, text=html),
        }
    )
    profile = a.probe_admin("http://t/", session=session)
    wp = [h for h in profile.hits if h.platform == "wordpress"]
    assert wp[0].version_hint == "WordPress 6.4.2"


def test_version_hint_from_body_regex():
    html = "<html><body>Version: 2.5.1</body></html>"
    session = _session_from_map(
        {
            "http://t/": FakeResp(),
            "http://t/graph": FakeResp(status=200, text=html),
        }
    )
    profile = a.probe_admin("http://t/", session=session)
    prom = [h for h in profile.hits if h.platform == "prometheus"]
    assert prom
    assert prom[0].version_hint == "2.5.1"


def test_version_hint_from_server_header():
    session = _session_from_map(
        {
            "http://t/": FakeResp(),
            "http://t/manage": FakeResp(status=200, headers={"Server": "Jetty 9.4.44"}),
        }
    )
    profile = a.probe_admin("http://t/", session=session)
    jenkins = [h for h in profile.hits if h.platform == "jenkins"]
    assert jenkins
    assert jenkins[0].version_hint == "9.4.44"


# ---------------------------------------------------------------------------
# Custom paths
# ---------------------------------------------------------------------------


def test_custom_paths_override_defaults():
    custom = {"mine": ("/myadmin/",)}
    session = _session_from_map(
        {
            "http://t/": FakeResp(),
            "http://t/myadmin/": FakeResp(status=200, text=GENERIC_HTML),
        }
    )
    profile = a.probe_admin("http://t/", session=session, custom_paths=custom)
    platforms = {h.platform for h in profile.hits}
    assert platforms == {"mine"}


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def test_profile_to_dict_roundtrip():
    session = _session_from_map(
        {
            "http://t/": FakeResp(),
            "http://t/wp-admin/": FakeResp(status=200, text=LOGIN_HTML),
        }
    )
    profile = a.probe_admin("http://t/", session=session)
    d = profile.to_dict()
    assert d["target"] == "http://t/"
    assert d["reachable"] is True
    assert d["paths_probed"] > 0
    assert isinstance(d["hits"], list)
