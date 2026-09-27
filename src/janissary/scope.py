"""URL scope enforcement for JANISSARY.

Purpose
-------
Hunters run against bug-bounty programs whose scope is contractual. A tool
that scans a URL outside that scope is a liability. This module implements
a two-list policy:

  --scope-include  allow list. If non-empty, target MUST match one entry.
  --scope-exclude  deny list. Always wins over allow.

Deny precedence is absolute. If both lists are empty, everything is allowed
(backwards-compatible with pre-scope JANISSARY).

Pattern syntax
--------------
  *                        any target
  example.com              exact hostname
  *.example.com            hostname or any subdomain of example.com
  .example.com             same as *.example.com
  10.0.0.5                 exact IPv4/IPv6 address as hostname
  10.0.0.0/8               IPv4/IPv6 CIDR block, matched against the hostname
  2001:db8::/32            IPv6 CIDR
  /api/                    path prefix on any host
  https://api.x.com/v1/    full URL prefix (scheme+host+path)

Hostname matching is literal: an include of 10.0.0.0/8 matches a target
URL that literally says http://10.0.0.5/. It does NOT resolve DNS. This is
deliberate: a DNS-rebinding SSRF must not walk out of scope because a
hostname happens to resolve to an allowed IP.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


class ScopeError(ValueError):
    """Target violates the configured scope."""


@dataclass(frozen=True)
class _Pattern:
    raw: str
    kind: str
    payload: Any = None  # str | IPv4Address | IPv6Address | IPv4Network | IPv6Network

    def matches(self, url: str) -> bool:
        try:
            parsed = urlsplit(url)
        except Exception:
            return False

        if self.kind == "any":
            return True

        host = (parsed.hostname or "").lower()

        if self.kind == "host":
            return host == self.payload

        if self.kind == "host_glob":
            suffix = self.payload
            return host == suffix or host.endswith("." + suffix)

        if self.kind == "ip":
            try:
                return ipaddress.ip_address(host) == self.payload
            except ValueError:
                return False

        if self.kind == "net":
            try:
                return ipaddress.ip_address(host) in self.payload
            except ValueError:
                return False

        if self.kind == "path":
            path = parsed.path or "/"
            return path.startswith(self.payload)

        if self.kind == "url":
            scheme = (parsed.scheme or "").lower()
            path = parsed.path or "/"
            target = f"{scheme}://{host}{path}"
            if parsed.query:
                target += "?" + parsed.query
            return target.startswith(self.payload)

        return False


def _looks_like_cidr(s: str) -> bool:
    if "/" not in s:
        return False
    head, _, tail = s.partition("/")
    if not tail.isdigit():
        return False
    try:
        ipaddress.ip_address(head)
        return True
    except ValueError:
        return False


def parse_pattern(raw: str) -> _Pattern:
    s = (raw or "").strip()
    if not s:
        raise ScopeError("empty scope pattern")

    if s == "*":
        return _Pattern(raw, "any", None)

    if "://" in s:
        parsed = urlsplit(s)
        if not parsed.hostname:
            raise ScopeError(f"scope pattern {raw!r} has no hostname")
        scheme = (parsed.scheme or "").lower()
        host = parsed.hostname.lower()
        path = parsed.path or "/"
        return _Pattern(raw, "url", f"{scheme}://{host}{path}")

    if _looks_like_cidr(s):
        try:
            return _Pattern(raw, "net", ipaddress.ip_network(s, strict=False))
        except ValueError as exc:
            raise ScopeError(f"bad CIDR {raw!r}: {exc}") from None

    try:
        return _Pattern(raw, "ip", ipaddress.ip_address(s))
    except ValueError:
        pass

    if s.startswith("*."):
        return _Pattern(raw, "host_glob", s[2:].lower().lstrip("."))
    if s.startswith("."):
        return _Pattern(raw, "host_glob", s[1:].lower())

    if s.startswith("/"):
        return _Pattern(raw, "path", s)

    return _Pattern(raw, "host", s.lower())


@dataclass
class Scope:
    include: list = field(default_factory=list)
    exclude: list = field(default_factory=list)

    @classmethod
    def from_strings(
        cls,
        includes: list | None = None,
        excludes: list | None = None,
    ) -> Scope:
        inc = [parse_pattern(s) for s in (includes or []) if s and s.strip()]
        exc = [parse_pattern(s) for s in (excludes or []) if s and s.strip()]
        return cls(include=inc, exclude=exc)

    @property
    def is_empty(self) -> bool:
        return not self.include and not self.exclude

    def allow(self, url: str) -> tuple:
        for p in self.exclude:
            if p.matches(url):
                return False, f"matched exclude {p.raw!r}"
        if not self.include:
            return True, ""
        for p in self.include:
            if p.matches(url):
                return True, ""
        return False, "not matched by any --scope-include pattern"

    def require(self, url: str) -> None:
        ok, why = self.allow(url)
        if not ok:
            raise ScopeError(f"refusing to scan {url!r}: {why}")

    def to_dict(self) -> dict:
        return {
            "include": [p.raw for p in self.include],
            "exclude": [p.raw for p in self.exclude],
        }


def scope_from_args(args) -> Scope:
    return Scope.from_strings(
        getattr(args, "scope_include", None),
        getattr(args, "scope_exclude", None),
    )


def add_scope_flags(parser) -> None:
    parser.add_argument(
        "--scope-include",
        action="append",
        default=None,
        metavar="PATTERN",
        help=(
            "Restrict scanning to URLs matching PATTERN. Repeatable. "
            "Syntax: example.com, *.example.com, 10.0.0.0/8, 10.0.0.5, "
            "/api/, https://api.example.com/v1/, or * for any."
        ),
    )
    parser.add_argument(
        "--scope-exclude",
        action="append",
        default=None,
        metavar="PATTERN",
        help=(
            "Refuse to scan URLs matching PATTERN. Repeatable. Deny beats "
            "allow. Same syntax as --scope-include."
        ),
    )
