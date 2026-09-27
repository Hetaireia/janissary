"""Unit tests for janissary.scope."""

from __future__ import annotations

import pytest

from janissary.scope import Scope, ScopeError, parse_pattern


class TestParse:
    def test_any(self):
        assert parse_pattern("*").matches("https://anything.example/")

    def test_exact_host(self):
        p = parse_pattern("example.com")
        assert p.matches("https://example.com/")
        assert p.matches("http://example.com:8080/path")
        assert not p.matches("https://evil.com/")
        assert not p.matches("https://sub.example.com/")

    def test_glob_host(self):
        p = parse_pattern("*.example.com")
        assert p.matches("https://example.com/")
        assert p.matches("https://a.example.com/")
        assert p.matches("https://a.b.example.com/")
        assert not p.matches("https://notexample.com/")
        assert not p.matches("https://example.com.evil.net/")

    def test_dot_prefix_same_as_glob(self):
        p = parse_pattern(".example.com")
        assert p.matches("https://a.example.com/")
        assert p.matches("https://example.com/")

    def test_ip_exact(self):
        p = parse_pattern("10.0.0.5")
        assert p.matches("http://10.0.0.5/")
        assert not p.matches("http://10.0.0.6/")

    def test_cidr_v4(self):
        p = parse_pattern("10.0.0.0/8")
        assert p.matches("http://10.1.2.3/")
        assert not p.matches("http://11.0.0.1/")

    def test_cidr_v6(self):
        p = parse_pattern("2001:db8::/32")
        assert p.matches("http://[2001:db8::1]/")

    def test_path_prefix(self):
        p = parse_pattern("/api/")
        assert p.matches("https://x.com/api/v1")
        assert not p.matches("https://x.com/public")

    def test_url_prefix(self):
        p = parse_pattern("https://api.example.com/v1/")
        assert p.matches("https://api.example.com/v1/users")
        assert not p.matches("https://api.example.com/v2/")
        assert not p.matches("http://api.example.com/v1/")

    def test_empty_pattern_raises(self):
        with pytest.raises(ScopeError):
            parse_pattern("")


class TestScope:
    def test_empty_scope_allows_all(self):
        sc = Scope()
        assert sc.is_empty
        assert sc.allow("https://anything/")[0]

    def test_include_only(self):
        sc = Scope.from_strings(["example.com"], None)
        assert sc.allow("https://example.com/")[0]
        ok, why = sc.allow("https://other.com/")
        assert not ok
        assert "scope-include" in why

    def test_exclude_only(self):
        sc = Scope.from_strings(None, ["example.com"])
        assert sc.allow("https://other.com/")[0]
        assert not sc.allow("https://example.com/")[0]

    def test_deny_beats_allow(self):
        sc = Scope.from_strings(["*.example.com"], ["admin.example.com"])
        assert sc.allow("https://www.example.com/")[0]
        assert not sc.allow("https://admin.example.com/")[0]

    def test_require_raises(self):
        sc = Scope.from_strings(["example.com"], None)
        with pytest.raises(ScopeError):
            sc.require("https://other.com/")

    def test_require_ok(self):
        sc = Scope.from_strings(["example.com"], None)
        sc.require("https://example.com/")

    def test_to_dict(self):
        sc = Scope.from_strings(["a.com", "b.com"], ["x.a.com"])
        d = sc.to_dict()
        assert d["include"] == ["a.com", "b.com"]
        assert d["exclude"] == ["x.a.com"]

    def test_blank_entries_ignored(self):
        sc = Scope.from_strings(["", "  ", "example.com"], None)
        assert len(sc.include) == 1
