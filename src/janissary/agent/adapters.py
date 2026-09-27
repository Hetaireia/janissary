"""Real-world module adapters for the agent.

Each adapter wraps an existing JANISSARY module and returns a list of
Finding objects. The agent itself does not import these; the CLI wires
them in. That keeps the agent unit-testable and keeps the adapters
free to change shape without touching the orchestrator.
"""

from __future__ import annotations

from typing import Any

from .finding_store import Finding

# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------


def admin_adapter(target: str, context: dict) -> list[Finding]:
    """Run the admin panel probe and return findings for each hit."""
    from janissary.recon.admin import probe_admin

    profile = probe_admin(
        target,
        timeout=context.get("timeout", 10.0),
        proxies=context.get("proxies"),
    )
    findings: list[Finding] = []
    for hit in profile.hits:
        severity = "medium"
        if hit.is_login_form:
            severity = "low"  # a login page is expected, not a vuln
        if hit.version_hint:
            severity = "medium"
        findings.append(
            Finding(
                target=target,
                category="admin",
                severity=severity,
                finding_type="exposed-panel",
                discriminator=hit.path,
                detail=f"{hit.platform} {hit.path} -> HTTP {hit.status}"
                + (f" [{hit.version_hint}]" if hit.version_hint else ""),
                response_status=hit.status,
                extra={
                    "platform": hit.platform,
                    "is_login_form": hit.is_login_form,
                    "location": hit.location,
                    "version_hint": hit.version_hint,
                },
            )
        )
    return findings


def xmlrpc_adapter(target: str, context: dict) -> list[Finding]:
    """Run the XML-RPC detection probe and return findings for hits."""
    from janissary.integrations.xmlrpc import detect

    profile = detect(
        target,
        timeout=context.get("timeout", 10.0),
        proxies=context.get("proxies"),
    )
    findings: list[Finding] = []
    if not profile.reachable:
        return findings

    severity = "low"
    if profile.multicall_supported:
        severity = "medium"
    if profile.pingback_supported:
        severity = "high"

    findings.append(
        Finding(
            target=target,
            category="xmlrpc",
            severity=severity,
            finding_type="reachable",
            discriminator=profile.endpoint,
            detail=(
                f"XML-RPC endpoint reachable: {profile.endpoint} "
                f"(multicall={profile.multicall_supported}, "
                f"pingback={profile.pingback_supported}, "
                f"methods={len(profile.methods)})"
            ),
            extra={
                "multicall_supported": profile.multicall_supported,
                "pingback_supported": profile.pingback_supported,
                "method_count": len(profile.methods),
            },
        )
    )
    return findings


def graphql_adapter(target: str, context: dict) -> list[Finding]:
    """Run GraphQL detection and report exposure."""
    from janissary.integrations.graphql import detect

    profile = detect(
        target,
        timeout=context.get("timeout", 10.0),
        proxies=context.get("proxies"),
    )
    findings: list[Finding] = []
    if not profile.reachable:
        return findings

    severity = "low"
    if profile.introspection_enabled:
        severity = "medium"
    if profile.batched_queries:
        severity = "medium"

    findings.append(
        Finding(
            target=target,
            category="graphql",
            severity=severity,
            finding_type="exposed-endpoint",
            discriminator=profile.endpoint,
            detail=(
                f"GraphQL endpoint: {profile.endpoint} "
                f"(introspection={profile.introspection_enabled}, "
                f"batching={profile.batched_queries})"
            ),
            extra={
                "introspection_enabled": profile.introspection_enabled,
                "batched_queries": profile.batched_queries,
                "suggestions_supported": profile.suggestions_supported,
            },
        )
    )
    return findings


def fingerprint_adapter(target: str, context: dict) -> list[Finding]:
    """Record the fingerprint as informational findings."""
    from janissary.recon.fingerprint import fingerprint

    fp = fingerprint(
        target,
        timeout=context.get("timeout", 10.0),
        proxies=context.get("proxies"),
    )
    findings: list[Finding] = []
    if fp.cms:
        findings.append(
            Finding(
                target=target,
                category="fingerprint",
                severity="info",
                finding_type="cms",
                discriminator=fp.cms,
                detail=f"detected {fp.cms} (confidence {fp.cms_confidence:.2f})",
                extra={"technologies": fp.technologies, "server": fp.server},
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Default registry
# ---------------------------------------------------------------------------


def default_adapters() -> dict[str, Any]:
    """Return a mapping suitable for Agent(adapters=...)."""
    return {
        "admin": admin_adapter,
        "xmlrpc": xmlrpc_adapter,
        "graphql": graphql_adapter,
        "fingerprint": fingerprint_adapter,
    }
