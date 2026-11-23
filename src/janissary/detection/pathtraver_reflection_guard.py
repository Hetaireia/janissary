"""Payload-Reflection Guard for path-traversal differential oracles (ADR-036)."""

from __future__ import annotations

import html
import posixpath
import re
from urllib.parse import unquote

_TRAVERSAL_SEGMENT_RE = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%2e%2e\\)", re.IGNORECASE
)


def _decode_layers(value: str, max_depth: int = 3) -> set[str]:
    """Return raw, HTML-unescaped, and iteratively URL-decoded variants."""
    variants: set[str] = set()
    current = value
    for _ in range(max_depth + 1):
        if not current:
            break
        variants.add(current)
        variants.add(html.unescape(current))
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return variants


def _extract_probe_markers(payload: str) -> set[str]:
    """Extract distinctive traversal strings and normalized target suffixes."""
    markers: set[str] = set()
    for variant in _decode_layers(payload):
        cleaned = variant.strip()
        if len(cleaned) >= 4:
            markers.add(cleaned)

        slash_norm = cleaned.replace("\\", "/")
        if len(slash_norm) >= 4:
            markers.add(slash_norm)

        if _TRAVERSAL_SEGMENT_RE.search(cleaned):
            collapsed = posixpath.normpath(slash_norm).lstrip("./")
            if len(collapsed) >= 5 and "/" in collapsed:
                markers.add(collapsed)
    return markers


def is_payload_reflected(payload: str, response_body: str) -> bool:
    """Return True if the traversal payload is echoed in the response body."""
    if not payload or not response_body:
        return False

    body_lower = response_body.lower()
    body_unescaped_lower = html.unescape(response_body).lower()

    for marker in _extract_probe_markers(payload):
        needle = marker.lower()
        if needle in body_lower or needle in body_unescaped_lower:
            return True

    return False
