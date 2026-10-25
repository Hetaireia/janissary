"""Integration tests for admin probe structural gating (ADR-005, Phase 1.3c)."""

from __future__ import annotations

from datetime import timedelta

from janissary.recon.admin import ADMIN_PATHS, probe_admin


class FakeResponse:
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.elapsed = timedelta(seconds=0.01)
        self.cookies = {}


class FakeSession:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        return self.handler(url)

    def close(self):
        pass


SPA_INDEX = (
    "<html><body><div id='root'></div><script src='bundle.js'></script></body></html>"
)
SPA_CT = {"content-type": "text/html"}
LOGIN_HTML = '<html><body><form><input type="password" name="p"></form></body></html>'
TOTAL_PATHS = sum(len(paths) for paths in ADMIN_PATHS.values())


def _spa_only(url):
    return FakeResponse(200, SPA_INDEX, SPA_CT)


def _mixed(url):
    if url.endswith("/wp-admin/"):
        return FakeResponse(200, LOGIN_HTML, SPA_CT)
    return FakeResponse(200, SPA_INDEX, SPA_CT)


def _empty_root(url):
    if url == "http://t/":
        return FakeResponse(200, "", SPA_CT)
    return FakeResponse(200, SPA_INDEX, SPA_CT)


def test_spa_target_produces_zero_hits():
    session = FakeSession(_spa_only)
    profile = probe_admin("http://t/", session=session)
    assert profile.hits == []
    assert profile.arming["enabled"] is True
    assert profile.arming["discarded_count"] == TOTAL_PATHS
    assert (
        profile.arming["discarded_by_reason"].get("spa_catchall_admin", 0)
        == TOTAL_PATHS
    )
    assert len(session.calls) == 1 + TOTAL_PATHS


def test_mixed_target_suppresses_fakes_keeps_real():
    session = FakeSession(_mixed)
    profile = probe_admin("http://t/", session=session)
    wp = [
        h for h in profile.hits if h.platform == "wordpress" and h.path == "/wp-admin/"
    ]
    assert len(wp) == 1, f"expected 1 wordpress hit, got {profile.hits}"
    other = [
        h
        for h in profile.hits
        if not (h.platform == "wordpress" and h.path == "/wp-admin/")
    ]
    assert other == [], f"expected other paths suppressed, got {other}"
    assert profile.arming["discarded_count"] == TOTAL_PATHS - 1


def test_root_empty_body_disables_filter_passes_all_hits():
    session = FakeSession(_empty_root)
    profile = probe_admin("http://t/", session=session)
    assert profile.arming["enabled"] is False
    assert profile.arming["reason"] == "disabled_no_html_root"
    assert profile.arming["discarded_count"] == 0
    assert profile.arming["discarded_by_reason"] == {}
    assert len(profile.hits) == TOTAL_PATHS
    assert len(session.calls) == 1 + TOTAL_PATHS
