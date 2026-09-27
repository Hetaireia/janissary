"""Platform knowledge base.

Static data describing known platforms and the attack surfaces each
one exposes. The agent consults this to decide which modules to run
against a target once it has been fingerprinted.

This module is pure data plus a thin lookup API. No network code, no
side effects, no dependencies beyond the standard library.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Surface definitions
# ---------------------------------------------------------------------------


@dataclass
class Surface:
    """One attack surface a platform exposes."""

    name: str
    module: str
    params: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "module": self.module,
            "params": list(self.params),
            "paths": list(self.paths),
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------

PLATFORMS: dict[str, list[Surface]] = {
    "wordpress": [
        Surface(
            name="wp-login",
            module="scan",
            params=["log", "pwd"],
            paths=["/wp-login.php"],
            notes="login form; test for auth bypass and SQLi",
        ),
        Surface(
            name="xmlrpc",
            module="xmlrpc",
            paths=["/xmlrpc.php"],
            notes="multicall amplification, pingback SSRF",
        ),
        Surface(
            name="admin",
            module="admin",
            paths=["/wp-admin/"],
            notes="version disclosure via generator meta",
        ),
    ],
    "drupal": [
        Surface(
            name="user-login",
            module="scan",
            params=["name", "pass"],
            paths=["/user/login"],
        ),
        Surface(
            name="xmlrpc",
            module="xmlrpc",
            paths=["/xmlrpc.php"],
        ),
        Surface(
            name="admin",
            module="admin",
            paths=["/admin/", "/admin/config"],
        ),
    ],
    "joomla": [
        Surface(
            name="admin",
            module="admin",
            paths=["/administrator/"],
        ),
        Surface(
            name="scan",
            module="scan",
            params=["id", "catid", "view"],
        ),
    ],
    "magento": [
        Surface(
            name="admin",
            module="admin",
            paths=["/admin/", "/downloader/"],
        ),
    ],
    "ghost": [
        Surface(
            name="admin",
            module="admin",
            paths=["/ghost/"],
        ),
    ],
    "typo3": [
        Surface(
            name="admin",
            module="admin",
            paths=["/typo3/"],
        ),
    ],
    "tomcat": [
        Surface(
            name="manager",
            module="admin",
            paths=["/manager/html", "/host-manager/html"],
            notes="default credentials commonly unchanged",
        ),
    ],
    "jenkins": [
        Surface(
            name="manage",
            module="admin",
            paths=["/manage", "/script"],
            notes="script console is RCE if exposed",
        ),
    ],
    "grafana": [
        Surface(
            name="login",
            module="admin",
            paths=["/login"],
        ),
        Surface(
            name="graphql",
            module="graphql",
            paths=["/graphql"],
        ),
    ],
    "graphql": [
        Surface(
            name="graphql",
            module="graphql",
            paths=["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"],
            notes="introspection, depth, aliasing, field enumeration",
        ),
    ],
    "websocket": [
        Surface(
            name="websocket",
            module="ws",
            notes="origin check, echo, auth handshake",
        ),
    ],
}

# ---------------------------------------------------------------------------
# Lookup API
# ---------------------------------------------------------------------------


def surfaces_for(platform: str) -> list[Surface]:
    """Return the surfaces for a platform, or [] if unknown."""
    return list(PLATFORMS.get((platform or "").lower(), []))


def modules_for(platform: str) -> list[str]:
    """Return the unique module names for a platform, in stable order."""
    seen: list[str] = []
    for s in surfaces_for(platform):
        if s.module not in seen:
            seen.append(s.module)
    return seen


def known_platforms() -> list[str]:
    return sorted(PLATFORMS.keys())


def plan_for(platforms: list[str]) -> list[str]:
    """Given a list of detected platforms, return the modules to run.

    Order is stable and de-duplicated. Unknown platforms are ignored.
    """
    seen: list[str] = []
    for p in platforms:
        for m in modules_for(p):
            if m not in seen:
                seen.append(m)
    return seen
