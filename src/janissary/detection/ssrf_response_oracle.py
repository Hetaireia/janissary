"""SSRF response-body oracle (Phase 4, Session B).

Detects server-side fetch where the response body contains content
from the fetched URL. Payload reflection alone (the URL echoed back)
does NOT trigger - that is XSS-in-JSON, not SSRF. Only content from
the fetched service counts.

Requires:
  - Response status 2xx or 3xx
  - At least one fetch_marker present in the response body OUTSIDE
    the reflected payload (once stripped)
  - That marker absent from every baseline snapshot

Pure. No I/O.
"""

from __future__ import annotations

from janissary.detection.analyzer import Baseline, ResponseSnapshot
import urllib.parse


def check_ssrf_response_oracle(
    *,
    baseline: Baseline | None,
    snapshot: ResponseSnapshot,
    response_status: int,
    payload_value: str,
    payload_name: str,
    fetch_markers: list[str],
) -> list[dict]:
    """Return zero or one finding dict."""
    if not (200 <= response_status < 400):
        return []

    body = snapshot.body or ""
    if not body:
        return []

    if not fetch_markers:
        return []

    # Strip reflected payload once before marker search. A marker that
    # appears only inside the payload URL is XSS evidence, not SSRF.
    # Markers still present after stripping must have come from
    # somewhere else - typically the fetched response body.
    body_for_markers = body
    if payload_value:
        # Strip all encoding variants of the payload before marker
        # search. Targets commonly URL-encode query params in links
        # (e.g. redirect_to=X), sometimes double-encoding. Without
        # this, a reflected "http://mailhog:8025/" is missed and
        # markers inside the encoded URL trigger a false positive.
        _encoded_variants = {
            payload_value,
            urllib.parse.quote(payload_value, safe=""),
            urllib.parse.quote(urllib.parse.quote(payload_value, safe=""), safe=""),
            urllib.parse.quote(payload_value, safe="/:"),
            payload_value.replace("/", "%2F").replace(":", "%3A"),
        }
        for _v in _encoded_variants:
            if _v and _v in body_for_markers:
                body_for_markers = body_for_markers.replace(_v, "", 1)

    body_lower = body_for_markers.lower()
    hits = [m for m in fetch_markers if m and m.lower() in body_lower]
    if not hits:
        return []

    baseline_bodies: list[str] = []
    if baseline is not None:
        snapshots = getattr(baseline, "snapshots", None) or []
        baseline_bodies = [(s.body or "") for s in snapshots]
    baseline_joined = "\n".join(baseline_bodies).lower()

    novel_hits = [m for m in hits if m.lower() not in baseline_joined]
    if not novel_hits:
        return []

    return [
        {
            "type": "ssrf_response_oracle",
            "category": "ssrf",
            "severity": "critical",
            "reason": "ssrf_response_fetch",
            "markers": novel_hits,
            "detail": (
                f"SSRF: {payload_name}={payload_value[:60]!r} caused the "
                f"server to fetch and return content matching "
                f"{', '.join(novel_hits)} (marker(s) absent from baseline "
                f"and outside the reflected payload)"
            ),
        }
    ]
