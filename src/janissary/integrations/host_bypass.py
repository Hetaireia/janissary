"""Host-header ACL bypass detection (FN-20).

Enumerates string-distinct but listener-equivalent forms of the Host
header and detects ACL bypasses: baseline blocked, variant accepted.

See docs/PHASE-6-PLAN.md FN-20 for scope and verification criteria.
"""

from urllib.parse import urlparse

import requests

from janissary.verification import CandidateFinding

# Baseline must be denied; variant must be accepted for a bypass.
_BLOCKED_STATUSES = frozenset({401, 403})
_ACCEPTED_STATUSES = frozenset({200, 201, 202, 204})


def _variant_hosts(host: str, scheme: str) -> list[tuple[str, str]]:
    """Enumerate listener-equivalent Host variants for a baseline host.

    Returns an empty list if the host already carries a port, so we
    don't inject a second port against a target that already specifies
    a listener port (FN-20 verification criterion 5).
    """
    if ":" in host:
        return []
    variants: list[tuple[str, str]] = []
    if scheme == "https":
        variants.append(("explicit_port_443", f"{host}:443"))
    else:
        variants.append(("explicit_port_80", f"{host}:80"))
    variants.append(("trailing_dot", f"{host}."))
    return variants


def _baseline_host_from_url(url: str) -> str:
    """Extract a host suitable for use as a baseline Host header."""
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc
    if not host:
        raise ValueError(f"cannot derive host from URL: {url!r}")
    return host


def test_host_bypass(
    url: str,
    baseline_host: str | None = None,
    *,
    timeout: float = 5.0,
) -> list[CandidateFinding]:
    """Probe ``url`` for Host-header ACL bypass.

    Sends a baseline request with ``Host: baseline_host``. If the
    baseline is blocked (401/403), sends listener-equivalent variants
    (explicit port, trailing dot). Emits a CandidateFinding for each
    variant whose response is accepted (2xx) when the baseline was
    blocked.

    Returns an empty list if the baseline is not blocked, or if no
    variant bypasses.
    """
    if baseline_host is None:
        baseline_host = _baseline_host_from_url(url)

    scheme = urlparse(url).scheme or "http"

    try:
        baseline = requests.get(
            url,
            headers={"Host": baseline_host},
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException:
        return []

    if baseline.status_code not in _BLOCKED_STATUSES:
        return []

    findings: list[CandidateFinding] = []
    for name, value in _variant_hosts(baseline_host, scheme):
        try:
            resp = requests.get(
                url,
                headers={"Host": value},
                timeout=timeout,
                allow_redirects=False,
            )
        except requests.RequestException:
            continue
        if resp.status_code not in _ACCEPTED_STATUSES:
            continue
        findings.append(
            CandidateFinding(
                param="Host",
                payload_name=name,
                payload_value=value,
                category="host_header",
                severity="high",
                finding_type="host_header_acl_bypass",
                detail=(
                    f"Host-header ACL bypass via {name}: baseline Host "
                    f"{baseline_host!r} returned {baseline.status_code}, "
                    f"variant Host {value!r} returned {resp.status_code}. "
                    f"The ACL did not normalize the Host header before "
                    f"matching."
                ),
                url=url,
                method="GET",
                response_status=resp.status_code,
                response_length=len(resp.content),
            )
        )
    return findings
